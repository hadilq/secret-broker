//! User-side commands: status, lock, unlock, run.

use crate::bail;
use crate::error::{Error, Result};
use crate::gpgcache;
use crate::proto::{self, ExitInfo, Request, Response, Status};
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
    let mut s = dial()?;
    proto::write_json(&mut s, proto::T_JSON, req)?;
    if let Some(k) = key {
        proto::write_frame(&mut s, proto::T_KEY, k)?;
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

pub fn lock() -> Result<()> {
    round_trip(
        &Request {
            op: "lock".into(),
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
    pub keep_gpg_cache: bool,
}

/// Unwrap the sops data key with the user's gpg (pinentry prompt) and hand
/// only that key to the broker, which decrypts and MAC-verifies the
/// system-pinned secrets file itself.
pub fn unlock(o: &UnlockOptions) -> Result<Status> {
    let _ = crate::sys::set_non_dumpable();
    let _ = crate::sys::disable_core_dumps();
    let st = status()?;
    gpg_cache_problem(&st).map_err(|e| e.context("refusing to unlock"))?;

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
    let _guard = if o.keep_gpg_cache {
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
            Ok(key) => {
                let resp = round_trip(
                    &Request {
                        op: "unlock".into(),
                        ttl_seconds: o.ttl_seconds,
                        ..Default::default()
                    },
                    Some(&key),
                )?;
                return resp
                    .status
                    .ok_or_else(|| Error::msg("broker sent no status"));
            }
            Err(e) => last = e,
        }
    }
    Err(last.context("could not decrypt the sops data key"))
}

/// Run `profile` with `args` through the broker; returns the child's exit code.
pub fn run(profile: &str, args: &[String], force_stdin: bool, no_stdin: bool) -> Result<i32> {
    let mut s = dial()?;
    let fwd = !no_stdin && (force_stdin || !crate::sys::isatty(0));
    let req = Request {
        op: "exec".into(),
        profile: profile.into(),
        args: args.to_vec(),
        stdin: fwd,
        ttl_seconds: None,
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
