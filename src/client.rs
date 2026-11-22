//! User-side commands: status, lock, unlock, run.

use crate::bail;
use crate::error::{Error, Result};
use crate::gpgcache;
use crate::proto::{self, Answer, ExitInfo, Prompt, Request, Response, Status};
use crate::sops;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub const DEFAULT_SOCKET: &str = "/run/secret-broker/broker.sock";

/// gnupg bin dir baked in at build time (fallback when not on PATH).
const FALLBACK_GNUPG_BIN: Option<&str> = option_env!("SECRET_BROKER_GNUPG_BIN");

pub fn socket_path() -> String {
    std::env::var("SECRET_BROKER_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SOCKET.into())
}

fn dial() -> Result<UnixStream> {
    let p = socket_path();
    UnixStream::connect(&p).map_err(|e| {
        Error::msg(format!(
            "cannot reach broker at {p}: {e} (is services.secret-broker enabled, and are you in its group? log out/in after adding)"
        ))
    })
}

fn round_trip(req: &Request, key: Option<&[u8]>) -> Result<Response> {
    match key {
        Some(k) => round_trip_frames(req, &[(proto::T_KEY, k)]),
        None => round_trip_frames(req, &[]),
    }
}

fn round_trip_frames(req: &Request, frames: &[(u8, &[u8])]) -> Result<Response> {
    let mut s = dial()?;
    proto::write_json(&mut s, proto::T_JSON, req)?;
    for (t, b) in frames {
        proto::write_frame(&mut s, *t, b)?;
    }
    let resp: Response = proto::read_json(&mut s, proto::T_JSON)?;
    if !resp.ok {
        return Err(Error::msg(resp.error));
    }
    Ok(resp)
}

pub fn status() -> Result<Status> {
    round_trip(
        &Request {
            op: "status".into(),
            ..Default::default()
        },
        None,
    )?
    .status
    .ok_or_else(|| Error::msg("broker sent no status"))
}

/// Seal the session (or wipe it with `forget`).
pub fn lock(forget: bool) -> Result<()> {
    round_trip(
        &Request {
            op: "lock".into(),
            forget,
            ..Default::default()
        },
        None,
    )
    .map(|_| ())
}

/// Find a gnupg tool on PATH, else in the baked-in gnupg.
pub fn tool(name: &str) -> String {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(name);
            if cand.is_file() {
                return cand.to_string_lossy().into_owned();
            }
        }
    }
    match FALLBACK_GNUPG_BIN {
        Some(dir) => PathBuf::from(dir).join(name).to_string_lossy().into_owned(),
        None => name.to_string(),
    }
}

/// Check gpg-agent's cache settings against the broker's limits.
pub fn gpg_cache_problem(st: &Status) -> Result<()> {
    let settings = gpgcache::query(&tool("gpgconf"))
        .map_err(|e| e.context("cannot determine gpg-agent cache settings (refusing to guess)"))?;
    gpgcache::check(settings, st.gpg_cache_limits)
}

fn keygrips(fp: &str) -> Vec<String> {
    let out = Command::new(tool("gpg"))
        .args([
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--list-keys",
            "--",
            fp,
        ])
        .stderr(Stdio::null())
        .output();
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            match (f.first(), f.get(9)) {
                (Some(&"grp"), Some(g)) if !g.is_empty() => Some((*g).to_string()),
                _ => None,
            }
        })
        .collect()
}

/// Drop gpg-agent's cached passphrase for these keygrips, so the next
/// decryption goes through pinentry and nothing else can reuse the cache.
fn clear_cache(grips: &[String]) {
    for g in grips {
        let _ = Command::new(tool("gpg-connect-agent"))
            .args([
                "--no-autostart",
                &format!("CLEAR_PASSPHRASE --mode=normal {g}"),
                "/bye",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct ClearOnDrop(Vec<String>);
impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        clear_cache(&self.0);
    }
}

fn gpg_decrypt(enc: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut child = Command::new(tool("gpg"))
        .args(["--quiet", "--pinentry-mode", "ask", "--decrypt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::msg(format!("cannot run gpg: {e}")))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(enc.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let key = Zeroizing::new(out.stdout);
    if !out.status.success() {
        bail!("gpg: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(key)
}

pub struct UnlockOptions {
    pub ttl_seconds: Option<u64>,
    /// Leave the gpg passphrase in gpg-agent's cache afterwards.
    pub keep_gpg_cache: bool,
    /// Always use gpg, even if the session is sealed and a quick method exists.
    pub gpg: bool,
}

/// Unwrap the sops data key with gpg (pinentry) and hand it to `f`. The
/// gpg-agent cache for the key is cleared before and after unless `keep`.
fn with_data_key<T>(st: &Status, keep: bool, mut f: impl FnMut(&[u8]) -> Result<T>) -> Result<T> {
    gpg_cache_problem(st).map_err(|e| e.context("refusing to unlock"))?;
    let doc =
        std::fs::read(&st.secrets_file).map_err(|e| Error::from(e).context(&st.secrets_file))?;
    let keys = sops::read_metadata(&doc)?.pgp_keys();
    if keys.is_empty() {
        bail!("secrets file has no pgp recipients (encrypt it with sops --pgp <fingerprint>)");
    }
    // Point pinentry at this terminal / the current graphical session.
    let _ = Command::new(tool("gpg-connect-agent"))
        .args(["updatestartuptty", "/bye"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let grips: Vec<String> = keys.iter().flat_map(|k| keygrips(&k.fp)).collect();
    let _guard = if keep {
        None
    } else {
        clear_cache(&grips);
        Some(ClearOnDrop(grips))
    };
    let mut last = Error::msg("no pgp recipient could be decrypted");
    for k in &keys {
        eprintln!(
            "secret-broker: decrypting the data key with gpg key {} (approve in pinentry)...",
            k.fp
        );
        match gpg_decrypt(&k.enc) {
            Ok(key) => return f(&key),
            Err(e) => last = e,
        }
    }
    Err(last.context("could not decrypt the sops data key"))
}

pub fn unlock(o: &UnlockOptions) -> Result<Status> {
    let _ = crate::sys::set_non_dumpable();
    let _ = crate::sys::disable_core_dumps();
    let st = status()?;
    if st.restricted {
        bail!("unlocking is not allowed from inside an ai-run sandbox; run `secret-broker unlock` in your own terminal");
    }
    if st.state == "sealed" && !o.gpg && !st.methods.is_empty() {
        match approve_tty(o.ttl_seconds) {
            Ok(st) => return Ok(st),
            Err(e) if e.to_string().contains("unlock with gpg") => {
                eprintln!("secret-broker: {e}");
            }
            Err(e) => return Err(e),
        }
    }
    with_data_key(&st, o.keep_gpg_cache, |key| {
        let resp = round_trip(
            &Request {
                op: "unlock".into(),
                ttl_seconds: o.ttl_seconds,
                ..Default::default()
            },
            Some(key),
        )?;
        resp.status
            .ok_or_else(|| Error::msg("broker sent no status"))
    })
}

fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| Error::from(e).context("/dev/tty"))
}

fn trim_eol(line: &mut Zeroizing<Vec<u8>>) {
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
}

/// Where PINs are typed: the controlling terminal (echo off), or stdin when
/// there is none (scripts, tests; gpg is still required where it matters).
pub enum Input {
    Tty(std::fs::File),
    Stdin,
}

impl Input {
    pub fn open() -> Input {
        match open_tty() {
            Ok(f) => Input::Tty(f),
            Err(_) => Input::Stdin,
        }
    }

    pub fn prompt(&mut self, text: &str) {
        match self {
            Input::Tty(f) => {
                let _ = write!(f, "{text}");
                let _ = f.flush();
            }
            Input::Stdin => eprint!("{text}"),
        }
    }

    /// One line; `secret` turns echo off on a terminal.
    pub fn line(&mut self, secret: bool) -> Result<Zeroizing<Vec<u8>>> {
        use std::io::BufRead;
        let mut line = Zeroizing::new(Vec::new());
        match self {
            Input::Tty(f) => {
                use std::os::fd::AsRawFd;
                let guard = if secret {
                    Some(crate::sys::no_echo(f.as_raw_fd())?)
                } else {
                    None
                };
                std::io::BufReader::new(f.try_clone()?).read_until(b'\n', &mut line)?;
                drop(guard);
                if secret {
                    let _ = writeln!(f);
                }
            }
            Input::Stdin => {
                std::io::stdin().lock().read_until(b'\n', &mut line)?;
            }
        }
        if line.is_empty() {
            bail!("no input");
        }
        trim_eol(&mut line);
        Ok(line)
    }

    fn try_clone(&self) -> Result<Input> {
        Ok(match self {
            Input::Tty(f) => Input::Tty(f.try_clone()?),
            Input::Stdin => Input::Stdin,
        })
    }

    fn echo_guard(&self) -> Option<crate::sys::EchoGuard> {
        use std::os::fd::AsRawFd;
        match self {
            Input::Tty(f) => crate::sys::no_echo(f.as_raw_fd()).ok(),
            Input::Stdin => None,
        }
    }
}

/// Approve a sealed session from this terminal (PIN and/or hardware).
pub fn approve_tty(ttl_seconds: Option<u64>) -> Result<Status> {
    let mut s = dial()?;
    proto::write_json(
        &mut s,
        proto::T_JSON,
        &Request {
            op: "approve".into(),
            ttl_seconds,
            ..Default::default()
        },
    )?;
    let writer = std::sync::Arc::new(std::sync::Mutex::new(s.try_clone()?));
    let mut tty_guard: Option<crate::sys::EchoGuard> = None;
    loop {
        let (t, p) = proto::read_frame(&mut s)?;
        if t != proto::T_JSON {
            bail!("protocol: unexpected frame");
        }
        let v: serde_json::Value = serde_json::from_slice(&p)?;
        if v.get("kind").is_none() {
            drop(tty_guard);
            let resp: Response = serde_json::from_value(v)?;
            if !resp.ok {
                return Err(Error::msg(resp.error));
            }
            return resp
                .status
                .ok_or_else(|| Error::msg("broker sent no status"));
        }
        let pr: Prompt = serde_json::from_value(v)?;
        match pr.kind.as_str() {
            "request" => {
                eprintln!("secret-broker: the session is sealed; approve to open it.");
                if !pr.phrase.is_empty() {
                    eprintln!("  your phrase: {}", pr.phrase);
                }
                for h in &pr.hints {
                    eprintln!("  {h}");
                }
                if pr.methods.iter().any(|m| m == "pin") {
                    let mut input = Input::open();
                    tty_guard = input.echo_guard();
                    input.prompt("  or type your PIN: ");
                    let writer = std::sync::Arc::clone(&writer);
                    let id = pr.id;
                    let mut reader = input.try_clone()?;
                    std::thread::spawn(move || loop {
                        // echo is already off for the whole approval
                        let Ok(line) = reader.line(false) else { return };
                        if let Input::Tty(f) = &mut reader {
                            let _ = writeln!(f);
                        }
                        let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                        let sent = proto::write_json(
                            &mut *w,
                            proto::T_JSON,
                            &Answer {
                                kind: "pin".into(),
                                id,
                            },
                        )
                        .and_then(|()| proto::write_frame(&mut *w, proto::T_PIN, &line));
                        if sent.is_err() {
                            return;
                        }
                    });
                }
            }
            "update" => {
                eprintln!("  {}", pr.message);
                if tty_guard.is_some() {
                    eprint!("  PIN: ");
                }
            }
            "done" if !pr.ok => eprintln!("  {}", pr.message),
            _ => {}
        }
    }
}

/// `secret-broker set-pin`: gpg once, then store a PIN hash in the broker.
pub fn set_pin(remove: bool, ttl_seconds: Option<u64>) -> Result<()> {
    let _ = crate::sys::set_non_dumpable();
    let _ = crate::sys::disable_core_dumps();
    let st = status()?;
    if st.restricted {
        bail!("set-pin is not allowed from inside an ai-run sandbox");
    }
    let mut pin = Zeroizing::new(Vec::new());
    let mut phrase = String::new();
    if !remove {
        let mut input = Input::open();
        input.prompt("New PIN: ");
        let a = input.line(true)?;
        input.prompt("Repeat PIN: ");
        let b = input.line(true)?;
        if a.as_slice() != b.as_slice() {
            bail!("PINs do not match");
        }
        if a.is_empty() {
            bail!("empty PIN");
        }
        pin = a;
        input.prompt(
            "Security phrase shown in every genuine approval dialog\n(anything memorable, not secret; empty for none): ",
        );
        phrase = match input.line(false) {
            Ok(l) => String::from_utf8_lossy(&l).trim().to_string(),
            Err(_) => String::new(),
        };
    }
    with_data_key(&st, false, |key| {
        let req = Request {
            op: "set_pin".into(),
            ttl_seconds,
            forget: remove,
            phrase: phrase.clone(),
            ..Default::default()
        };
        if remove {
            round_trip_frames(&req, &[(proto::T_KEY, key)])
        } else {
            round_trip_frames(&req, &[(proto::T_KEY, key), (proto::T_PIN, &pin)])
        }
        .map(|_| ())
    })
}

fn fido2_tool(name: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("SECRET_BROKER_FIDO2_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join(name);
        }
    }
    if let Some(dir) = option_env!("SECRET_BROKER_FIDO2_DIR") {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from(name)
}

/// `secret-broker fido2-enroll`: make a credential on a security key (touch
/// it) and print the NixOS snippet with its id and public key.
pub fn fido2_enroll(device: Option<&str>, name: &str, rp: &str) -> Result<String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let dev = match device {
        Some(d) => d.to_string(),
        None => {
            let out = Command::new(fido2_tool("fido2-token"))
                .arg("-L")
                .stderr(Stdio::inherit())
                .output()
                .map_err(|e| Error::from(e).context("fido2-token"))?;
            let devs = crate::approve::parse_devices(&String::from_utf8_lossy(&out.stdout));
            match devs.as_slice() {
                [] => bail!("no FIDO2 security key found (plug one in; check `fido2-token -L`)"),
                [d] => d.clone(),
                _ => bail!("several keys found ({}); pick one with --device", devs.join(", ")),
            }
        }
    };
    let mut cdh = [0u8; 32];
    let mut uid = [0u8; 16];
    crate::sys::random(&mut cdh)?;
    crate::sys::random(&mut uid)?;
    let user = crate::sys::name_of(crate::sys::getuid()).unwrap_or_else(|_| "user".into());
    let input = format!(
        "{}\n{rp}\n{user}\n{}\n",
        B64.encode(cdh),
        B64.encode(uid)
    );
    eprintln!("Touch your security key ({dev}) to create the secret-broker credential...");
    let make = pipe_through(
        Command::new(fido2_tool("fido2-cred")).arg("-M").arg(&dev).arg("es256"),
        input.as_bytes(),
    )?;
    let verified = pipe_through(
        Command::new(fido2_tool("fido2-cred")).args(["-V", "es256"]),
        &make,
    )?;
    let text = String::from_utf8_lossy(&verified).into_owned();
    let mut lines = text.lines();
    let id = lines
        .next()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .ok_or_else(|| Error::msg("fido2-cred -V printed no credential id"))?
        .to_string();
    let pem: Vec<&str> = lines.collect();
    if !pem.first().is_some_and(|l| l.contains("BEGIN PUBLIC KEY")) {
        bail!("fido2-cred -V printed no public key");
    }
    Ok(format!(
        "  services.secret-broker.approval.fido2.credentials = [\n    {{\n      name = \"{name}\";\n      id = \"{id}\";\n      publicKey = ''\n{}\n      '';\n    }}\n  ];\n",
        pem.iter().map(|l| format!("        {l}")).collect::<Vec<_>>().join("\n")
    ))
}

fn pipe_through(cmd: &mut Command, input: &[u8]) -> Result<Vec<u8>> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Error::from(e).context("fido2-cred (libfido2)"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(input)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("fido2-cred failed ({})", out.status);
    }
    Ok(out.stdout)
}

pub fn run(profile: &str, args: &[String], force_stdin: bool, no_stdin: bool) -> Result<i32> {
    let mut s = dial()?;
    let fwd = !no_stdin && (force_stdin || !crate::sys::isatty(0));
    let req = Request {
        op: "exec".into(),
        profile: profile.into(),
        args: args.to_vec(),
        stdin: fwd,
        ..Default::default()
    };
    proto::write_json(&mut s, proto::T_JSON, &req)?;
    let resp: Response = proto::read_json(&mut s, proto::T_JSON)?;
    if !resp.ok {
        return Err(Error::msg(resp.error));
    }
    if fwd {
        let mut w = s.try_clone()?;
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = proto::write_frame(&mut w, proto::T_STDIN_EOF, &[]);
                        return;
                    }
                    Ok(n) => {
                        let chunk = buf.get(..n).unwrap_or(&[]);
                        if proto::write_frame(&mut w, proto::T_STDIN, chunk).is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    loop {
        let (t, p) = proto::read_frame(&mut s).map_err(|e| e.context("broker connection"))?;
        match t {
            proto::T_STDOUT => {
                let _ = out.write_all(&p);
                let _ = out.flush();
            }
            proto::T_STDERR => {
                let _ = err.write_all(&p);
            }
            proto::T_EXIT => {
                let info: ExitInfo = serde_json::from_slice(&p)?;
                if !info.error.is_empty() {
                    eprintln!("secret-broker: {}", info.error);
                }
                return Ok(info.code);
            }
            _ => {}
        }
    }
}
