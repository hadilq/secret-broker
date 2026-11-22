//! The daemon. Runs as a dedicated system user, holds decrypted secrets only
//! in locked memory for a bounded time, and runs allowlisted commands with
//! those secrets in their environment. It never returns a secret value.

use crate::bail;
use crate::config::{self, Config, Profile};
use crate::error::{Error, Result};
use crate::proto::{self, ExitInfo, ProfileInfo, Request, Response, Status};
use crate::redact::Redactor;
use crate::secmem::{self, SecretBuf};
use crate::sops;
use crate::sys::{self, PeerCred};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Default)]
struct State {
    secrets: Option<HashMap<String, SecretBuf>>,
    expires: Option<Instant>,
    expires_unix: i64,
    generation: u64,
}

impl State {
    fn wipe(&mut self) {
        // Dropping SecretBufs zeroes and unmaps them.
        self.secrets = None;
        self.expires = None;
        self.expires_unix = 0;
        self.generation = self.generation.wrapping_add(1);
    }

    fn unlocked(&self) -> bool {
        self.secrets.is_some() && self.expires.is_some_and(|e| Instant::now() < e)
    }
}

pub struct Server {
    cfg: Config,
    allowed: HashSet<u32>,
    state: Mutex<State>,
}

fn lock_state(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}

impl Server {
    pub fn new(cfg: Config) -> Result<Arc<Self>> {
        let mut allowed = HashSet::new();
        for name in &cfg.allowed_users {
            allowed
                .insert(sys::uid_of(name).map_err(|e| e.context(format!("allowed user {name}")))?);
        }
        Ok(Arc::new(Server {
            cfg,
            allowed,
            state: Mutex::new(State::default()),
        }))
    }

    pub fn profile_count(&self) -> usize {
        self.cfg.profiles.len()
    }

    /// Wipe everything (SIGTERM, shutdown).
    pub fn wipe(&self, reason: &str) {
        lock_state(&self.state).wipe();
        log(format!("locked ({reason})"));
    }

    pub fn serve(self: &Arc<Self>, listener: UnixListener) -> Result<()> {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let srv = Arc::clone(self);
                    std::thread::spawn(move || srv.handle(stream));
                }
                Err(e) => {
                    log(format!("accept: {e}"));
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Ok(())
    }

    fn handle(self: Arc<Self>, mut stream: UnixStream) {
        let cred = match sys::peer_cred(stream.as_raw_fd()) {
            Ok(c) => c,
            Err(e) => {
                log(format!("peer credentials: {e}"));
                return;
            }
        };
        if !self.allowed.is_empty() && !self.allowed.contains(&cred.uid) {
            log(format!(
                "rejected uid {} (pid {}): not in allowed_users",
                cred.uid, cred.pid
            ));
            let _ = proto::write_json(
                &mut stream,
                proto::T_JSON,
                &Response::err("permission denied"),
            );
            return;
        }
        let req: Request = match proto::read_json(&mut stream, proto::T_JSON) {
            Ok(r) => r,
            Err(e) => {
                log(format!("uid {}: bad request: {e}", cred.uid));
                return;
            }
        };
        let result = match req.op.as_str() {
            "status" => {
                let st = self.status();
                proto::write_json(
                    &mut stream,
                    proto::T_JSON,
                    &Response {
                        ok: true,
                        error: String::new(),
                        status: Some(st),
                    },
                )
            }
            "lock" => {
                self.wipe(&format!("locked by uid {}", cred.uid));
                proto::write_json(
                    &mut stream,
                    proto::T_JSON,
                    &Response {
                        ok: true,
                        ..Default::default()
                    },
                )
            }
            "unlock" => {
                let resp = match self.unlock(&mut stream, req.ttl_seconds, cred) {
                    Ok(()) => Response {
                        ok: true,
                        error: String::new(),
                        status: Some(self.status()),
                    },
                    Err(e) => {
                        log(format!(
                            "unlock by uid {} (pid {}) failed: {e}",
                            cred.uid, cred.pid
                        ));
                        Response::err(e.to_string())
                    }
                };
                proto::write_json(&mut stream, proto::T_JSON, &resp)
            }
            "exec" => self.exec(stream.try_clone(), &mut stream, &req, cred),
            _ => proto::write_json(&mut stream, proto::T_JSON, &Response::err("unknown op")),
        };
        if let Err(e) = result {
            log(format!("uid {}: {}: {e}", cred.uid, req.op));
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    fn status(&self) -> Status {
        let st = lock_state(&self.state);
        let unlocked = st.unlocked();
        let mut out = Status {
            unlocked,
            secrets_file: self.cfg.secrets_file.clone(),
            default_ttl_seconds: self.cfg.default_ttl_seconds,
            max_ttl_seconds: self.cfg.max_ttl_seconds,
            gpg_cache_limits: self.cfg.gpg_cache_limits,
            ..Default::default()
        };
        if unlocked {
            out.expires_at_unix = st.expires_unix;
            out.remaining_seconds = st
                .expires
                .map(|e| e.saturating_duration_since(Instant::now()).as_secs())
                .unwrap_or(0);
            out.secret_count = st.secrets.as_ref().map(HashMap::len).unwrap_or(0);
        }
        for (name, p) in &self.cfg.profiles {
            let mut unresolved: Vec<String> = Vec::new();
            if let (true, Some(secrets)) = (unlocked, st.secrets.as_ref()) {
                for (env, key) in &p.env {
                    if !secrets.contains_key(key) {
                        unresolved.push(env.clone());
                    }
                }
            }
            out.profiles.push(ProfileInfo {
                name: name.clone(),
                description: p.description.clone(),
                command: p.command.clone(),
                fixed_args: p.fixed_args.clone(),
                env_vars: p.env.keys().cloned().collect(),
                allow: p.allow.clone(),
                deny: p.deny.clone(),
                unresolved,
            });
        }
        out
    }

    fn unlock(
        self: &Arc<Self>,
        stream: &mut UnixStream,
        ttl: Option<u64>,
        cred: PeerCred,
    ) -> Result<()> {
        let (t, key) = proto::read_frame(stream)?;
        let key = Zeroizing::new(key);
        if t != proto::T_KEY {
            bail!("expected data key frame");
        }
        let ttl_secs = ttl
            .filter(|t| *t > 0)
            .unwrap_or(self.cfg.default_ttl_seconds)
            .min(self.cfg.max_ttl_seconds);
        let path = Path::new(&self.cfg.secrets_file);
        config::check_trusted(path).map_err(|e| e.context("untrusted secrets file"))?;
        let doc = std::fs::read(path).map_err(|e| Error::from(e).context(path.display()))?;
        let plain = sops::decrypt(&doc, &key)?;
        let mut locked = HashMap::with_capacity(plain.len());
        for (k, mut v) in plain {
            locked.insert(k, SecretBuf::new(&mut v)?);
        }
        let count = locked.len();
        let ttl_dur = Duration::from_secs(ttl_secs);
        let expires = Instant::now()
            .checked_add(ttl_dur)
            .ok_or_else(|| Error::msg("ttl too large"))?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expires_unix = i64::try_from(now_unix.saturating_add(ttl_secs)).unwrap_or(i64::MAX);
        let generation = {
            let mut st = lock_state(&self.state);
            st.wipe();
            st.secrets = Some(locked);
            st.expires = Some(expires);
            st.expires_unix = expires_unix;
            st.generation
        };
        let srv = Arc::clone(self);
        std::thread::spawn(move || {
            std::thread::sleep(ttl_dur);
            let mut st = lock_state(&srv.state);
            if st.generation == generation && st.secrets.is_some() {
                st.wipe();
                drop(st);
                log("locked (ttl expired)");
            }
        });
        if secmem::mlock_failed() {
            log("warning: mlock failed; secrets may be swapped (raise LimitMEMLOCK)");
        }
        log(format!(
            "unlocked by uid {} (pid {}) for {ttl_secs}s, {count} values",
            cred.uid, cred.pid
        ));
        Ok(())
    }

    fn exec(
        &self,
        reader: std::io::Result<UnixStream>,
        stream: &mut UnixStream,
        req: &Request,
        cred: PeerCred,
    ) -> Result<()> {
        let deny = |stream: &mut UnixStream, msg: String| -> Result<()> {
            log(format!(
                "exec by uid {} (pid {}) profile {:?} denied: {msg}",
                cred.uid, cred.pid, req.profile
            ));
            proto::write_json(stream, proto::T_JSON, &Response::err(msg))
        };
        let Some(p) = self.cfg.profiles.get(&req.profile) else {
            return deny(stream, format!("unknown profile {:?}", req.profile));
        };
        if let Err(msg) = crate::policy::check(&p.allow, &p.deny, &req.args) {
            return deny(stream, msg);
        }
        let home: PathBuf = Path::new(&self.cfg.state_dir)
            .join("home")
            .join(&req.profile);
        if let Err(e) = std::fs::create_dir_all(&home) {
            return deny(stream, format!("state dir: {e}"));
        }

        // Copy the profile's secrets out of the store while holding the lock.
        let mut values: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
        {
            let st = lock_state(&self.state);
            if !st.unlocked() {
                drop(st);
                return deny(stream, "locked: run `secret-broker unlock` first".into());
            }
            let mut missing = Vec::new();
            if let Some(secrets) = st.secrets.as_ref() {
                for (env, key) in &p.env {
                    match secrets.get(key) {
                        Some(b) => {
                            values.push((env.clone(), Zeroizing::new(b.as_bytes().to_vec())))
                        }
                        None => missing.push(env.clone()),
                    }
                }
            }
            if !missing.is_empty() {
                drop(st);
                return deny(stream, format!("secrets file has no value for {missing:?}"));
            }
        }

        let mut child = match spawn(p, &req.profile, &home, &req.args, &values, req.stdin) {
            Ok(c) => c,
            Err(e) => return deny(stream, format!("start: {e}")),
        };
        let pid = child.id();
        log(format!(
            "exec by uid {} (pid {}): profile {:?} args {:?} -> pid {pid}",
            cred.uid, cred.pid, req.profile, req.args
        ));

        let done = Arc::new(AtomicBool::new(false));
        let timed_out = Arc::new(AtomicBool::new(false));
        let writer = Arc::new(Mutex::new(stream.try_clone()?));
        proto::write_json(
            &mut *lock_writer(&writer),
            proto::T_JSON,
            &Response {
                ok: true,
                ..Default::default()
            },
        )?;

        // Client -> child stdin; a read error means the client went away.
        let mut child_stdin = child.stdin.take();
        if let Ok(mut rd) = reader {
            let done = Arc::clone(&done);
            std::thread::spawn(move || loop {
                match proto::read_frame(&mut rd) {
                    Ok((proto::T_STDIN, b)) => {
                        if let Some(si) = child_stdin.as_mut() {
                            if si.write_all(&b).is_err() {
                                child_stdin = None;
                            }
                        }
                    }
                    Ok((proto::T_STDIN_EOF, _)) => child_stdin = None,
                    Ok(_) => {}
                    Err(_) => {
                        if !done.load(Ordering::SeqCst) {
                            sys::kill_group(pid);
                        }
                        return;
                    }
                }
            });
        }

        // Timeout watchdog.
        if p.timeout_seconds > 0 {
            let done = Arc::clone(&done);
            let timed_out = Arc::clone(&timed_out);
            let limit = Duration::from_secs(p.timeout_seconds);
            std::thread::spawn(move || {
                let start = Instant::now();
                while !done.load(Ordering::SeqCst) {
                    if start.elapsed() >= limit {
                        timed_out.store(true, Ordering::SeqCst);
                        sys::kill_group(pid);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
        }

        let redact_vals: Vec<Zeroizing<Vec<u8>>> = if self.cfg.redact_output {
            values.iter().map(|(_, v)| v.clone()).collect()
        } else {
            Vec::new()
        };
        drop(values);
        let pumps: Vec<_> = [
            child
                .stdout
                .take()
                .map(|r| (Box::new(r) as Box<dyn Read + Send>, proto::T_STDOUT)),
            child
                .stderr
                .take()
                .map(|r| (Box::new(r) as Box<dyn Read + Send>, proto::T_STDERR)),
        ]
        .into_iter()
        .flatten()
        .map(|(r, t)| {
            let writer = Arc::clone(&writer);
            let secrets = redact_vals.clone();
            std::thread::spawn(move || pump(r, t, &writer, &secrets, pid))
        })
        .collect();
        drop(redact_vals);
        for h in pumps {
            let _ = h.join();
        }
        let status = child.wait();
        done.store(true, Ordering::SeqCst);

        let mut info = ExitInfo::default();
        match status {
            Ok(s) => {
                info.code = match (s.code(), s.signal()) {
                    (Some(c), _) => c,
                    (None, Some(sig)) => sig.saturating_add(128),
                    (None, None) => 1,
                };
            }
            Err(e) => {
                info.code = 1;
                info.error = e.to_string();
            }
        }
        if timed_out.load(Ordering::SeqCst) {
            info.error = "timeout".into();
        }
        proto::write_json(&mut *lock_writer(&writer), proto::T_EXIT, &info)?;
        log(format!(
            "exec pid {pid} (profile {:?}) exited {}",
            req.profile, info.code
        ));
        Ok(())
    }
}

fn lock_writer(w: &Mutex<UnixStream>) -> MutexGuard<'_, UnixStream> {
    w.lock().unwrap_or_else(|p| p.into_inner())
}

fn spawn(
    p: &Profile,
    profile: &str,
    home: &Path,
    args: &[String],
    values: &[(String, Zeroizing<Vec<u8>>)],
    stdin: bool,
) -> std::io::Result<std::process::Child> {
    let path = if p.path.is_empty() {
        "/run/current-system/sw/bin"
    } else {
        p.path.as_str()
    };
    let mut cmd = Command::new(&p.command);
    cmd.args(&p.fixed_args)
        .args(args)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("LANG", "C.UTF-8")
        .env("SECRET_BROKER_PROFILE", profile)
        .envs(&p.extra_env)
        .current_dir(home)
        .process_group(0)
        .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in values {
        cmd.env(k, OsStr::from_bytes(v));
    }
    let child = cmd.spawn();
    drop(cmd);
    child
}

fn pump(
    mut r: Box<dyn Read + Send>,
    t: u8,
    writer: &Mutex<UnixStream>,
    secrets: &[Zeroizing<Vec<u8>>],
    pid: u32,
) {
    let mut red = if secrets.is_empty() {
        None
    } else {
        Some(Redactor::new(secrets))
    };
    let mut buf = vec![0u8; 32 * 1024];
    let send = |b: &[u8]| {
        if b.is_empty() {
            return;
        }
        if proto::write_frame(&mut *lock_writer(writer), t, b).is_err() {
            sys::kill_group(pid);
        }
    };
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or(&[]);
                match red.as_mut() {
                    Some(rd) => send(&rd.write(chunk)),
                    None => send(chunk),
                }
            }
        }
    }
    if let Some(rd) = red.as_mut() {
        send(&rd.flush());
    }
}

/// The systemd-activated socket (LISTEN_FDS) or a newly created one.
pub fn listener(path: Option<&str>) -> Result<UnixListener> {
    let pid_matches = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        == Some(sys::getpid());
    let fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if pid_matches && fds >= 1 {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
        // SAFETY: systemd passed us fd 3 as a listening unix socket
        // (LISTEN_PID matches); we take ownership of it exactly once.
        let l = unsafe { UnixListener::from_raw_fd(3) };
        return Ok(l);
    }
    let Some(path) = path else {
        bail!("not socket-activated and no --socket given");
    };
    let _ = std::fs::remove_file(path);
    let old = sys::umask(0o117);
    let l = UnixListener::bind(path);
    sys::umask(old);
    Ok(l?)
}
