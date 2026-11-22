//! The daemon. Runs as a dedicated system user, holds decrypted secrets only
//! in locked memory, and runs allowlisted commands with those secrets in
//! their environment. It never returns a secret value.
//!
//! Session states:
//!
//! - cold: nothing in memory (after boot, `lock --forget`, too many wrong
//!   PINs). Only a gpg unlock (the sops data key) opens it.
//! - open: commands run, until the TTL expires.
//! - sealed: secrets stay in locked memory but nothing runs until a quick
//!   approval (PIN, security key touch, fingerprint) verified here, in the
//!   broker. TTL expiry and `lock` seal when a quick method is configured;
//!   otherwise they wipe.
//!
//! Two sockets: the main one, and a restricted one that ai-run sandboxes get
//! instead. The restricted socket can run profiles (which may pop up an
//! approval dialog), check status and lock, but cannot unlock, approve, set
//! the PIN or act as the approval dialog.

use crate::approve::{Hw, HwEvent};
use crate::audit::{Audit, Event};
use crate::bail;
use crate::caller;
use crate::config::{self, Config, Profile};
use crate::error::{Error, Result};
use crate::pin;
use crate::proto::{
    self, Answer, Caller, ExitInfo, Owner, ProfileInfo, Prompt, Request, Requester, Response,
    SessionInfo, Status,
};
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cold,
    Sealed,
    Open,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Cold => "cold",
            Mode::Sealed => "sealed",
            Mode::Open => "open",
        }
    }
}

#[derive(Default)]
struct State {
    secrets: Option<HashMap<String, SecretBuf>>,
    /// PIN pepper derived from the data key at gpg unlock.
    pepper: Option<SecretBuf>,
    open_until: Option<Instant>,
    open_until_unix: i64,
    /// Bumped on every transition; timers only act on their own generation.
    generation: u64,
    pin_failures: u32,
    pin_not_before: Option<Instant>,
    pin_locked_out: bool,
    /// The gpg unlock that loaded the secrets.
    unlocked_by: Option<Owner>,
    /// The latest opening (gpg or quick approval).
    opened_by: Option<Owner>,
}

impl State {
    /// Back to cold: wipe everything (SecretBuf zeroes and unmaps on drop).
    fn forget(&mut self) {
        self.secrets = None;
        self.pepper = None;
        self.open_until = None;
        self.open_until_unix = 0;
        self.pin_failures = 0;
        self.pin_not_before = None;
        self.unlocked_by = None;
        self.opened_by = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Keep the secrets, refuse to run anything until approved.
    fn seal(&mut self) {
        self.open_until = None;
        self.open_until_unix = 0;
        self.generation = self.generation.wrapping_add(1);
    }

    fn is_open(&self) -> bool {
        self.secrets.is_some() && self.open_until.is_some_and(|e| Instant::now() < e)
    }

    fn mode(&self) -> Mode {
        if self.secrets.is_none() {
            Mode::Cold
        } else if self.is_open() {
            Mode::Open
        } else {
            Mode::Sealed
        }
    }
}

enum Incoming {
    Pin(u64, Zeroizing<Vec<u8>>),
    Deny(u64),
    /// The dialog could not show a window (no compositor, no font...).
    Unavailable(u64),
}

/// A connection that can answer approval requests: the registered dialog
/// (prompter) or a terminal running `secret-broker unlock`.
struct Channel {
    uid: u32,
    pid: i32,
    writer: Mutex<UnixStream>,
    rx: Mutex<Receiver<Incoming>>,
}

impl Channel {
    fn new(stream: &UnixStream, uid: u32, pid: i32) -> Result<Self> {
        let mut rd = stream.try_clone()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || loop {
            let (t, p) = match proto::read_frame(&mut rd) {
                Ok(f) => f,
                Err(_) => return,
            };
            let p = Zeroizing::new(p);
            if t != proto::T_JSON {
                continue;
            }
            let Ok(a) = serde_json::from_slice::<Answer>(&p) else {
                return;
            };
            let msg = match a.kind.as_str() {
                "pin" => match proto::read_frame(&mut rd) {
                    Ok((proto::T_PIN, pin)) => Incoming::Pin(a.id, Zeroizing::new(pin)),
                    _ => return,
                },
                "deny" => Incoming::Deny(a.id),
                "unavailable" => Incoming::Unavailable(a.id),
                _ => continue,
            };
            if tx.send(msg).is_err() {
                return;
            }
        });
        Ok(Channel {
            uid,
            pid,
            writer: Mutex::new(stream.try_clone()?),
            rx: Mutex::new(rx),
        })
    }

    fn send(&self, p: &Prompt) -> Result<()> {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        proto::write_json(&mut *w, proto::T_JSON, p)
    }

    /// Still connected (drains stale answers).
    fn alive(&self) -> bool {
        let rx = match self.rx.try_lock() {
            Ok(rx) => rx,
            // In use by a running approval: connected as far as we know.
            Err(std::sync::TryLockError::WouldBlock) => return true,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        };
        loop {
            match rx.try_recv() {
                Ok(_) => continue,
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Disconnected) => return false,
            }
        }
    }
}

enum PinCheck {
    Ok,
    Wrong(String),
    Fatal(String),
}

pub struct Server {
    cfg: Config,
    allowed: HashSet<u32>,
    state: Mutex<State>,
    prompter: Mutex<Option<Arc<Channel>>>,
    /// One approval at a time.
    gate: Mutex<()>,
    last_denied: Mutex<Option<Instant>>,
    next_id: AtomicU64,
    pin_path: PathBuf,
    /// Our own binary, for the `pam-check` helper.
    helper: PathBuf,
    audit: Audit,
    /// Reads /proc for caller details (see caller.rs); None: read directly.
    procs: Mutex<Option<caller::Helper>>,
}

fn lock_state(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_any<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Single line, printable, bounded: safe to show in a dialog or terminal.
pub fn sanitize(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

fn ok_response() -> Response {
    Response {
        ok: true,
        ..Default::default()
    }
}

impl Server {
    pub fn new(cfg: Config, procs: Option<caller::Helper>) -> Result<Arc<Self>> {
        let mut allowed = HashSet::new();
        for name in &cfg.allowed_users {
            allowed
                .insert(sys::uid_of(name).map_err(|e| e.context(format!("allowed user {name}")))?);
        }
        let pin_path = Path::new(&cfg.state_dir).join("auth").join("pin");
        let helper = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("secret-broker"));
        let audit = Audit::open(cfg.audit.clone());
        Ok(Arc::new(Server {
            cfg,
            allowed,
            state: Mutex::new(State::default()),
            prompter: Mutex::new(None),
            gate: Mutex::new(()),
            last_denied: Mutex::new(None),
            next_id: AtomicU64::new(1),
            pin_path,
            helper,
            audit,
            procs: Mutex::new(procs),
        }))
    }

    /// Record an audit entry, with every secret value in memory replaced by
    /// [REDACTED] in all of its strings (argv, reasons, caller details).
    /// Must not be called while holding the state lock.
    pub fn audit(&self, ev: Event) {
        let ev = {
            let st = lock_state(&self.state);
            match st.secrets.as_ref() {
                Some(sec) if !sec.is_empty() => ev.map_strings(&|s| redact_with(sec, s)),
                _ => ev,
            }
        };
        self.audit.record(ev);
    }

    fn redact_str(&self, s: &str) -> String {
        let st = lock_state(&self.state);
        match st.secrets.as_ref() {
            Some(sec) => redact_with(sec, s),
            None => s.to_string(),
        }
    }

    /// Who is on the other end of `stream`, snapshotted now.
    fn snapshot(&self, stream: &UnixStream, cred: PeerCred, restricted: bool) -> Caller {
        let pidfd = sys::peer_pidfd(stream.as_raw_fd());
        let mut c = {
            let mut h = lock_any(&self.procs);
            match h.as_mut().and_then(|h| h.query(cred.pid)) {
                Some(c) => c,
                None => {
                    if h.take().is_some() {
                        log("proc helper went away; reading /proc directly");
                    }
                    caller::collect(&caller::Roots::default(), cred.pid)
                }
            }
        };
        c.pid = cred.pid;
        c.uid = cred.uid;
        c.gid = cred.gid;
        c.user = sys::name_of(cred.uid).unwrap_or_default();
        c.socket = if restricted { "agent.sock" } else { "broker.sock" }.into();
        c.sandboxed = restricted;
        // The caller's own argv can contain a secret (`secret-run p <value>`):
        // it's shown in the dialog and logged, so redact it like output.
        c.argv = c.argv.iter().map(|a| self.redact_str(a)).collect();
        for p in &mut c.parents {
            p.argv = p.argv.iter().map(|a| self.redact_str(a)).collect();
        }
        match pidfd {
            Some(fd) => {
                c.verified = sys::pidfd_alive(&fd);
                if !c.verified {
                    c.notes
                        .push("the caller exited during the snapshot; its pid may be reused".into());
                }
            }
            None => c
                .notes
                .push("no SO_PEERPIDFD (kernel < 6.5): details are best effort".into()),
        }
        c
    }

    fn session_info(&self) -> Option<SessionInfo> {
        let st = lock_state(&self.state);
        let mode = st.mode();
        if mode == Mode::Cold {
            return None;
        }
        Some(SessionInfo {
            state: mode.as_str().into(),
            expires_at_unix: if mode == Mode::Open { st.open_until_unix } else { 0 },
            unlocked: st.unlocked_by.clone(),
            opened: st.opened_by.clone(),
        })
    }

    /// argv with any secret value in memory replaced by [REDACTED].
    fn redacted(&self, args: &[String]) -> Vec<String> {
        args.iter().map(|a| self.redact_str(a)).collect()
    }

    pub fn profile_count(&self) -> usize {
        self.cfg.profiles.len()
    }

    /// Wipe everything (SIGTERM, shutdown).
    pub fn wipe(&self, reason: &str) {
        let had = {
            let mut st = lock_state(&self.state);
            let had = st.secrets.is_some();
            st.forget();
            had
        };
        log(format!("forgotten ({reason})"));
        self.audit(
            Event::new("broker_stop", if had { "wiped" } else { "ok" }).field("reason", reason),
        );
    }

    fn pin_set(&self) -> bool {
        self.cfg.approval.pin.enable && self.pin_path.exists()
    }

    /// Quick methods that are configured (independent of state).
    fn configured_methods(&self) -> Vec<String> {
        let a = &self.cfg.approval;
        let mut m = Vec::new();
        if self.pin_set() {
            m.push("pin".to_string());
        }
        if !a.fido2.credentials.is_empty() {
            m.push("fido2".to_string());
        }
        for p in &a.pam {
            m.push(p.name.clone());
        }
        m
    }

    /// Seal on TTL expiry / lock when there is a way back without gpg.
    fn can_seal(&self) -> bool {
        !self.configured_methods().is_empty()
    }

    fn mode(&self) -> Mode {
        lock_state(&self.state).mode()
    }

    pub fn serve(self: &Arc<Self>, listener: UnixListener, restricted: bool) -> Result<()> {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let srv = Arc::clone(self);
                    std::thread::spawn(move || srv.handle(stream, restricted));
                }
                Err(e) => {
                    log(format!("accept: {e}"));
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Ok(())
    }

    fn handle(self: Arc<Self>, mut stream: UnixStream, restricted: bool) {
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
            let c = self.snapshot(&stream, cred, restricted);
            self.audit(
                Event::new("connect", "refused")
                    .caller(&c)
                    .field("reason", "uid not in allowed_users"),
            );
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
        // Snapshot the caller now (not for status: it's frequent and harmless).
        let caller = if req.op == "status" {
            Caller::default()
        } else {
            self.snapshot(&stream, cred, restricted)
        };
        let privileged = matches!(
            req.op.as_str(),
            "unlock" | "approve" | "set_pin" | "prompter" | "report"
        );
        if restricted && privileged {
            log(format!(
                "refused {} from the restricted socket (uid {}, pid {})",
                req.op, cred.uid, cred.pid
            ));
            self.audit(
                Event::new(&audit_op(&req.op), "refused")
                    .caller(&caller)
                    .field("reason", "not allowed from the sandbox socket (agent.sock)"),
            );
            let _ = proto::write_json(
                &mut stream,
                proto::T_JSON,
                &Response::err(format!(
                    "`{}` is not allowed from inside an ai-run sandbox; run it in your own terminal",
                    req.op
                )),
            );
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        let result = match req.op.as_str() {
            "status" => {
                let st = self.status(restricted);
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
                self.lock(req.forget, &caller);
                proto::write_json(&mut stream, proto::T_JSON, &ok_response())
            }
            "unlock" => {
                let resp = match self.unlock(&mut stream, req.ttl_seconds, &caller) {
                    Ok(()) => Response {
                        ok: true,
                        error: String::new(),
                        status: Some(self.status(restricted)),
                    },
                    Err(e) => {
                        log(format!(
                            "unlock by uid {} (pid {}) failed: {e}",
                            cred.uid, cred.pid
                        ));
                        self.audit(
                            Event::new("unlock", "failed")
                                .caller(&caller)
                                .field("method", "gpg")
                                .field("reason", e.to_string()),
                        );
                        Response::err(e.to_string())
                    }
                };
                proto::write_json(&mut stream, proto::T_JSON, &resp)
            }
            "set_pin" => {
                let resp = match self.set_pin(&mut stream, &req, &caller) {
                    Ok(()) => Response {
                        ok: true,
                        error: String::new(),
                        status: Some(self.status(restricted)),
                    },
                    Err(e) => {
                        log(format!("set_pin by uid {} failed: {e}", cred.uid));
                        self.audit(
                            Event::new(if req.forget { "remove_pin" } else { "set_pin" }, "failed")
                                .caller(&caller)
                                .field("reason", e.to_string()),
                        );
                        Response::err(e.to_string())
                    }
                };
                proto::write_json(&mut stream, proto::T_JSON, &resp)
            }
            "approve" => {
                let resp = match self.approve_here(&stream, &req, &caller) {
                    Ok(()) => Response {
                        ok: true,
                        error: String::new(),
                        status: Some(self.status(restricted)),
                    },
                    Err(e) => Response::err(e.to_string()),
                };
                proto::write_json(&mut stream, proto::T_JSON, &resp)
            }
            "prompter" => {
                // The connection stays open; the dialog answers requests on it.
                match self.register_prompter(&mut stream, &caller) {
                    Ok(()) => return,
                    Err(e) => Err(e),
                }
            }
            "exec" => self.exec(stream.try_clone(), &mut stream, &req, &caller),
            "report" => {
                let resp = match self.report(&req, &caller) {
                    Ok(()) => ok_response(),
                    Err(e) => Response::err(e.to_string()),
                };
                proto::write_json(&mut stream, proto::T_JSON, &resp)
            }
            _ => proto::write_json(&mut stream, proto::T_JSON, &Response::err("unknown op")),
        };
        if let Err(e) = result {
            log(format!("uid {}: {}: {e}", cred.uid, req.op));
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    fn status(&self, restricted: bool) -> Status {
        let st = lock_state(&self.state);
        let mode = st.mode();
        let unlocked = mode == Mode::Open;
        let pcfg = &self.cfg.approval.pin;
        let mut out = Status {
            unlocked,
            secrets_file: self.cfg.secrets_file.clone(),
            default_ttl_seconds: self.cfg.default_ttl_seconds,
            max_ttl_seconds: self.cfg.max_ttl_seconds,
            gpg_cache_limits: self.cfg.gpg_cache_limits,
            state: mode.as_str().to_string(),
            methods: self.configured_methods(),
            prompter: lock_any(&self.prompter).as_ref().is_some_and(|c| c.alive()),
            pin_set: self.pin_set(),
            pin_locked_out: st.pin_locked_out,
            pin_attempts_left: pcfg.max_attempts.saturating_sub(st.pin_failures),
            restricted,
            approval_timeout_seconds: self.cfg.approval.timeout_seconds,
            session: None,
            ..Default::default()
        };
        if mode != Mode::Cold {
            out.secret_count = st.secrets.as_ref().map(HashMap::len).unwrap_or(0);
        }
        if unlocked {
            out.expires_at_unix = st.open_until_unix;
            out.remaining_seconds = st
                .open_until
                .map(|e| e.saturating_duration_since(Instant::now()).as_secs())
                .unwrap_or(0);
        }
        for (name, p) in &self.cfg.profiles {
            let mut unresolved: Vec<String> = Vec::new();
            if let Some(secrets) = st.secrets.as_ref() {
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
        drop(st);
        out.session = self.session_info();
        out
    }

    /// `report`: something the client did itself, for the audit log.
    fn report(&self, req: &Request, caller: &Caller) -> Result<()> {
        if req.event != "fido2_enroll" {
            bail!("unknown report event {:?}", req.event);
        }
        let mut ev = Event::new(&req.event, "reported").caller(caller);
        for (k, v) in req.details.iter().take(8) {
            let k = sanitize(k, 32);
            if k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                ev = ev.field(&k, sanitize(v, 300));
            }
        }
        self.audit(ev);
        Ok(())
    }

    /// `lock`: seal (or forget when no quick method could reopen it).
    fn lock(self: &Arc<Self>, forget: bool, caller: &Caller) {
        let who = format!("uid {} pid {}", caller.uid, caller.pid);
        let ev = |outcome: &str| Event::new("lock", outcome).caller(caller).field("forget", forget);
        let mut st = lock_state(&self.state);
        if st.secrets.is_none() {
            drop(st);
            self.audit(ev("noop").field("reason", "already cold"));
            return;
        }
        if forget || !self.can_seal() {
            st.forget();
            drop(st);
            log(format!("forgotten (lock by {who})"));
            self.audit(ev("wiped"));
        } else {
            st.seal();
            let gen = st.generation;
            drop(st);
            log(format!("sealed (lock by {who})"));
            self.audit(ev("sealed"));
            self.schedule_forget(gen);
        }
    }

    fn ttl_secs(&self, ttl: Option<u64>) -> u64 {
        ttl.filter(|t| *t > 0)
            .unwrap_or(self.cfg.default_ttl_seconds)
            .min(self.cfg.max_ttl_seconds)
    }

    /// Open the session for `ttl_secs` and arm the expiry timer.
    fn open(self: &Arc<Self>, ttl_secs: u64, by: Option<Owner>) -> Result<()> {
        let ttl_dur = Duration::from_secs(ttl_secs);
        let until = Instant::now()
            .checked_add(ttl_dur)
            .ok_or_else(|| Error::msg("ttl too large"))?;
        let generation = {
            let mut st = lock_state(&self.state);
            if st.secrets.is_none() {
                bail!("secrets are no longer in memory; unlock with gpg");
            }
            st.open_until = Some(until);
            if let Some(o) = by {
                if o.method == "gpg" {
                    st.unlocked_by = Some(o.clone());
                }
                st.opened_by = Some(o);
            }
            st.open_until_unix =
                i64::try_from(now_unix().saturating_add(ttl_secs)).unwrap_or(i64::MAX);
            st.generation = st.generation.wrapping_add(1);
            st.generation
        };
        let srv = Arc::clone(self);
        std::thread::spawn(move || {
            std::thread::sleep(ttl_dur);
            let mut st = lock_state(&srv.state);
            if st.generation != generation || st.secrets.is_none() {
                return;
            }
            if srv.can_seal() {
                st.seal();
                let gen = st.generation;
                drop(st);
                log("sealed (ttl expired)");
                srv.audit(Event::new("expire", "sealed").field("reason", "ttl"));
                srv.schedule_forget(gen);
            } else {
                st.forget();
                drop(st);
                log("forgotten (ttl expired)");
                srv.audit(Event::new("expire", "wiped").field("reason", "ttl, no quick method configured"));
            }
        });
        Ok(())
    }

    /// Wipe a sealed session after approval.sealed_max_seconds, if set.
    fn schedule_forget(self: &Arc<Self>, generation: u64) {
        let secs = self.cfg.approval.sealed_max_seconds;
        if secs == 0 {
            return;
        }
        let srv = Arc::clone(self);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            let mut st = lock_state(&srv.state);
            if st.generation == generation && st.secrets.is_some() {
                st.forget();
                drop(st);
                log("forgotten (sealed too long)");
                srv.audit(Event::new("expire", "wiped").field("reason", "sealed longer than sealedTimeout"));
            }
        });
    }

    /// Verify the sops data key against the secrets file and load it.
    fn load_with_key(self: &Arc<Self>, key: &[u8], ttl_secs: u64, by: Owner) -> Result<usize> {
        let path = Path::new(&self.cfg.secrets_file);
        config::check_trusted(path).map_err(|e| e.context("untrusted secrets file"))?;
        let doc = std::fs::read(path).map_err(|e| Error::from(e).context(path.display()))?;
        let plain = sops::decrypt(&doc, key)?;
        let mut locked = HashMap::with_capacity(plain.len());
        for (k, mut v) in plain {
            locked.insert(k, SecretBuf::new(&mut v)?);
        }
        let count = locked.len();
        let mut pep = pin::pepper(key);
        let pepper = SecretBuf::new(&mut pep[..])?;
        {
            let mut st = lock_state(&self.state);
            st.forget();
            st.secrets = Some(locked);
            st.pepper = Some(pepper);
            st.pin_locked_out = false;
        }
        self.open(ttl_secs, Some(by))?;
        if secmem::mlock_failed() {
            log("warning: mlock failed; secrets may be swapped (raise LimitMEMLOCK)");
        }
        Ok(count)
    }

    fn read_key(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
        let (t, key) = proto::read_frame(stream)?;
        let key = Zeroizing::new(key);
        if t != proto::T_KEY {
            bail!("expected data key frame");
        }
        Ok(key)
    }

    fn unlock(
        self: &Arc<Self>,
        stream: &mut UnixStream,
        ttl: Option<u64>,
        caller: &Caller,
    ) -> Result<()> {
        let key = Self::read_key(stream)?;
        let ttl_secs = self.ttl_secs(ttl);
        let owner = Owner::from_caller(caller, "gpg", "gpg", sys::now_unix_i64());
        let count = self.load_with_key(&key, ttl_secs, owner)?;
        log(format!(
            "unlocked with gpg by uid {} (pid {}) for {ttl_secs}s, {count} values",
            caller.uid, caller.pid
        ));
        self.audit(
            Event::new("unlock", "ok")
                .caller(caller)
                .field("method", "gpg")
                .field("ttl_seconds", ttl_secs)
                .field("secret_count", count),
        );
        Ok(())
    }

    /// Set or remove the PIN. Requires the gpg-unwrapped data key, which also
    /// unlocks the session.
    fn set_pin(self: &Arc<Self>, stream: &mut UnixStream, req: &Request, caller: &Caller) -> Result<()> {
        let pcfg = &self.cfg.approval.pin;
        if !pcfg.enable {
            bail!("PIN approval is disabled in the broker config");
        }
        let key = Self::read_key(stream)?;
        let new_pin = if req.forget {
            None
        } else {
            let (t, p) = proto::read_frame(stream)?;
            let p = Zeroizing::new(p);
            if t != proto::T_PIN {
                bail!("expected PIN frame");
            }
            Some(p)
        };
        let ttl_secs = self.ttl_secs(req.ttl_seconds);
        let owner = Owner::from_caller(caller, "gpg", "gpg", sys::now_unix_i64());
        self.load_with_key(&key, ttl_secs, owner)?;
        self.audit(
            Event::new("unlock", "ok")
                .caller(caller)
                .field("method", "gpg")
                .field("ttl_seconds", ttl_secs)
                .field("reason", "set-pin"),
        );
        match new_pin {
            None => {
                pin::remove(&self.pin_path)?;
                log(format!("PIN removed by uid {}", caller.uid));
                self.audit(Event::new("remove_pin", "ok").caller(caller));
            }
            Some(p) => {
                if p.len() < pcfg.min_length {
                    bail!("PIN must be at least {} characters", pcfg.min_length);
                }
                let pep = pin::pepper(&key);
                let rec = pin::Record::create(&p, &pep[..], pcfg.cost(), &req.phrase)?;
                pin::save(&self.pin_path, &rec)?;
                log(format!("PIN set by uid {}", caller.uid));
                self.audit(Event::new("set_pin", "ok").caller(caller));
            }
        }
        Ok(())
    }

    fn register_prompter(self: &Arc<Self>, stream: &mut UnixStream, caller: &Caller) -> Result<()> {
        let ch = Arc::new(Channel::new(stream, caller.uid, caller.pid)?);
        proto::write_json(stream, proto::T_JSON, &ok_response())?;
        let old = lock_any(&self.prompter).replace(ch);
        self.audit(
            Event::new("prompter_register", "ok")
                .caller(caller)
                .field("replaced", old.is_some()),
        );
        if let Some(old) = old {
            let w = lock_any(&old.writer);
            let _ = w.shutdown(std::net::Shutdown::Both);
        }
        log(format!(
            "approval dialog registered (uid {}, pid {})",
            caller.uid, caller.pid
        ));
        Ok(())
    }

    fn current_prompter(&self) -> Option<Arc<Channel>> {
        let p = lock_any(&self.prompter);
        p.as_ref().filter(|c| c.alive()).map(Arc::clone)
    }

    /// For exec: if sealed, ask the registered dialog for a quick approval.
    fn ensure_open(self: &Arc<Self>, req: &Request, args: &[String], caller: &Caller) -> Result<()> {
        match self.mode() {
            Mode::Open => return Ok(()),
            Mode::Cold => bail!(
                "locked: secrets are not in memory (after boot or `lock --forget`); run `secret-broker unlock` in your terminal"
            ),
            Mode::Sealed => {}
        }
        let started = Instant::now();
        let _gate = lock_any(&self.gate);
        if self.mode() == Mode::Open {
            return Ok(());
        }
        if lock_any(&self.last_denied).is_some_and(|d| d > started) {
            bail!("session approval was denied");
        }
        let Some(ch) = self.current_prompter() else {
            bail!(
                "session sealed and no approval dialog is running; run `secret-broker unlock` in your terminal"
            );
        };
        let mut purpose = format!("secret-run {}", req.profile);
        for a in args {
            purpose.push(' ');
            purpose.push_str(a);
        }
        let method = self.run_approval(&ch, caller, &sanitize(&purpose, 300), None, "dialog")?;
        log(format!(
            "session approved via {method} for exec by uid {} (pid {}{})",
            caller.uid,
            caller.pid,
            if caller.sandboxed { ", sandboxed" } else { "" }
        ));
        Ok(())
    }

    /// `secret-broker unlock` on a sealed session: the terminal is the dialog.
    fn approve_here(self: &Arc<Self>, stream: &UnixStream, req: &Request, caller: &Caller) -> Result<()> {
        let _gate = lock_any(&self.gate);
        match self.mode() {
            Mode::Open => return Ok(()),
            Mode::Cold => bail!("secrets are not in memory; unlock with gpg"),
            Mode::Sealed => {}
        }
        let ch = Channel::new(stream, caller.uid, caller.pid)?;
        let method = self.run_approval(&ch, caller, "secret-broker unlock", req.ttl_seconds, "terminal")?;
        log(format!(
            "session approved via {method} in a terminal by uid {} (pid {})",
            caller.uid, caller.pid
        ));
        Ok(())
    }

    /// Methods usable right now (sealed session).
    fn available_methods(&self) -> (Vec<String>, String, u32) {
        let st = lock_state(&self.state);
        let a = &self.cfg.approval;
        let mut methods = Vec::new();
        let mut phrase = String::new();
        if self.pin_set() && st.pepper.is_some() && !st.pin_locked_out {
            if let Ok(Some(rec)) = pin::load(&self.pin_path) {
                methods.push("pin".to_string());
                phrase = rec.phrase;
            }
        }
        if !a.fido2.credentials.is_empty() {
            methods.push("fido2".to_string());
        }
        for p in &a.pam {
            methods.push(p.name.clone());
        }
        let left = a.pin.max_attempts.saturating_sub(st.pin_failures);
        (methods, phrase, left)
    }

    fn check_pin(&self, pin_in: &[u8]) -> PinCheck {
        let max = self.cfg.approval.pin.max_attempts;
        let pepper = {
            let st = lock_state(&self.state);
            if st.pin_locked_out {
                return PinCheck::Fatal("PIN locked out; unlock with gpg".into());
            }
            if let Some(nb) = st.pin_not_before {
                let now = Instant::now();
                if now < nb {
                    let wait = nb.saturating_duration_since(now).as_secs().saturating_add(1);
                    return PinCheck::Wrong(format!("Too fast: wait {wait}s and try again"));
                }
            }
            match st.pepper.as_ref() {
                Some(p) => Zeroizing::new(p.as_bytes().to_vec()),
                None => return PinCheck::Fatal("secrets are no longer in memory".into()),
            }
        };
        let rec = match pin::load(&self.pin_path) {
            Ok(Some(r)) => r,
            Ok(None) => return PinCheck::Fatal("no PIN is set".into()),
            Err(e) => return PinCheck::Fatal(format!("PIN file: {e}")),
        };
        let ok = rec.verify(pin_in, &pepper).unwrap_or(false);
        let mut st = lock_state(&self.state);
        if ok {
            st.pin_failures = 0;
            st.pin_not_before = None;
            return PinCheck::Ok;
        }
        st.pin_failures = st.pin_failures.saturating_add(1);
        if st.pin_failures >= max {
            st.forget();
            st.pin_locked_out = true;
            drop(st);
            log("too many wrong PINs: secrets forgotten");
            self.audit(
                Event::new("pin_lockout", "wiped")
                    .field("reason", format!("{max} wrong PINs; gpg needed again")),
            );
            return PinCheck::Fatal(
                "Too many wrong PINs: secrets wiped from memory. Unlock with gpg (`secret-broker unlock`)."
                    .into(),
            );
        }
        let left = max.saturating_sub(st.pin_failures);
        st.pin_not_before = Instant::now().checked_add(pin::backoff(st.pin_failures));
        drop(st);
        log(format!("wrong PIN ({left} attempts left)"));
        self.audit(Event::new("pin_wrong", "failed").field("attempts_left", left));
        PinCheck::Wrong(format!("Wrong PIN, {left} attempts left"))
    }

    /// Ask `ch` to approve; first verified method wins. Caller holds `gate`.
    fn run_approval(
        self: &Arc<Self>,
        ch: &Channel,
        caller: &Caller,
        purpose: &str,
        ttl: Option<u64>,
        via: &str,
    ) -> Result<String> {
        let (methods, phrase, attempts_left) = self.available_methods();
        let ev = |outcome: &str| {
            Event::new("approval", outcome)
                .caller(caller)
                .field("via", via)
                .field("purpose", purpose)
                .field("approver_uid", ch.uid)
                .field("approver_pid", ch.pid)
        };
        if methods.is_empty() {
            self.audit(ev("failed").field("reason", "no quick approval method available"));
            bail!("no quick approval method available; unlock with gpg");
        }
        let who = Requester {
            pid: caller.pid,
            uid: caller.uid,
            user: caller.user.clone(),
            sandboxed: caller.sandboxed,
        };
        let a = &self.cfg.approval;
        let ttl_secs = self.ttl_secs(ttl);
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut hints = Vec::new();
        let hw = Hw::new();
        if methods.iter().any(|m| m == "fido2") {
            hints.push("Touch your security key".to_string());
            if let Err(e) = hw.start_fido2(&a.fido2, id, purpose) {
                log(format!("fido2: {e}"));
            }
        }
        let approver = sys::name_of(ch.uid).unwrap_or_default();
        for m in &a.pam {
            hints.push(m.label.clone());
            hw.start_pam(m, &self.helper, &approver);
        }
        let timeout = Duration::from_secs(a.timeout_seconds);
        ch.send(&Prompt {
            kind: "request".into(),
            id,
            requester: Some(who),
            purpose: purpose.to_string(),
            ttl_seconds: ttl_secs,
            methods: methods.clone(),
            hints,
            phrase,
            attempts_left,
            timeout_seconds: a.timeout_seconds,
            caller: Some(caller.clone()),
            session: self.session_info(),
            ..Default::default()
        })?;
        let update = |msg: String| {
            let _ = ch.send(&Prompt {
                kind: "update".into(),
                id,
                message: msg,
                ..Default::default()
            });
        };
        let start = Instant::now();
        let rx = lock_any(&ch.rx);
        let mut denied = false;
        let mut kind = "failed";
        let outcome: std::result::Result<String, String> = 'wait: loop {
            if start.elapsed() >= timeout {
                kind = "timeout";
                break 'wait Err("approval timed out".into());
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Incoming::Pin(aid, p)) if aid == id => {
                    if !methods.iter().any(|m| m == "pin") {
                        update("PIN is not enabled".into());
                    } else {
                        match self.check_pin(&p) {
                            PinCheck::Ok => break 'wait Ok("pin".into()),
                            PinCheck::Wrong(msg) => update(msg),
                            PinCheck::Fatal(msg) => break 'wait Err(msg),
                        }
                    }
                }
                Ok(Incoming::Deny(aid)) if aid == id => {
                    denied = true;
                    kind = "denied";
                    break 'wait Err("denied in the approval dialog".into());
                }
                Ok(Incoming::Unavailable(aid)) if aid == id => {
                    kind = "unavailable";
                    break 'wait Err(
                        "the approval dialog could not open a window; run `secret-broker unlock` in a terminal"
                            .into(),
                    );
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    break 'wait Err("approval dialog went away".into())
                }
            }
            while let Some(ev) = hw.try_recv() {
                match ev {
                    HwEvent::Approved(m) => break 'wait Ok(m),
                    HwEvent::Info(msg) => update(msg),
                }
            }
        };
        drop(rx);
        drop(hw);
        let outcome = outcome.and_then(|m| {
            let owner = Owner::from_caller(caller, &m, via, sys::now_unix_i64());
            self.open(ttl_secs, Some(owner)).map(|()| m).map_err(|e| e.to_string())
        });
        match &outcome {
            Ok(m) => self.audit(ev("granted").field("method", m.as_str()).field("ttl_seconds", ttl_secs)),
            Err(e) => self.audit(ev(kind).field("reason", e.as_str())),
        }
        let (ok, message) = match &outcome {
            Ok(m) => (true, format!("Approved ({m})")),
            Err(e) => (false, e.clone()),
        };
        let _ = ch.send(&Prompt {
            kind: "done".into(),
            id,
            ok,
            message,
            ..Default::default()
        });
        if denied {
            *lock_any(&self.last_denied) = Some(Instant::now());
        }
        outcome.map_err(Error::msg)
    }

    fn exec(
        self: &Arc<Self>,
        reader: std::io::Result<UnixStream>,
        stream: &mut UnixStream,
        req: &Request,
        caller: &Caller,
    ) -> Result<()> {
        // argv as logged/shown: secret values replaced.
        let args = self.redacted(&req.args);
        let deny = |stream: &mut UnixStream, msg: String| -> Result<()> {
            // Policy messages quote the arguments.
            let msg = self.redact_str(&msg);
            log(format!(
                "exec by uid {} (pid {}) profile {:?} denied: {msg}",
                caller.uid, caller.pid, req.profile
            ));
            self.audit(
                Event::new("exec", "refused")
                    .caller(caller)
                    .field("profile", req.profile.as_str())
                    .field("args", args.clone())
                    .field("reason", msg.as_str()),
            );
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

        // A sealed session needs a quick approval in the dialog first.
        if let Err(e) = self.ensure_open(req, &args, caller) {
            return deny(stream, e.to_string());
        }

        // Copy the profile's secrets out of the store while holding the lock.
        let mut values: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
        {
            let st = lock_state(&self.state);
            if !st.is_open() {
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
        let started = Instant::now();
        log(format!(
            "exec by uid {} (pid {}): profile {:?} -> pid {pid}",
            caller.uid, caller.pid, req.profile
        ));
        let exec_ev = |outcome: &str| {
            Event::new(if outcome == "started" { "exec_start" } else { "exec_end" }, outcome)
                .caller(caller)
                .field("profile", req.profile.as_str())
                .field("args", args.clone())
                .field("child_pid", pid)
        };
        self.audit(exec_ev("started"));

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
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.audit(
            exec_ev(if info.code == 0 { "ok" } else { "failed" })
                .field("exit_code", info.code)
                .field("duration_ms", duration_ms)
                .opt("error", &info.error),
        );
        proto::write_json(&mut *lock_writer(&writer), proto::T_EXIT, &info)?;
        log(format!(
            "exec pid {pid} (profile {:?}) exited {}",
            req.profile, info.code
        ));
        Ok(())
    }
}

/// Audit event name for a request op.
fn audit_op(op: &str) -> String {
    match op {
        "unlock" | "approve" => "unlock".into(),
        "prompter" => "prompter_register".into(),
        other => sanitize(other, 32),
    }
}

fn redact_with(secrets: &HashMap<String, SecretBuf>, s: &str) -> String {
    let mut b = s.as_bytes().to_vec();
    for v in secrets.values() {
        b = replace_all(&b, v.as_bytes(), b"[REDACTED]");
    }
    String::from_utf8_lossy(&b).into_owned()
}

/// Replace every occurrence of `needle` (if at least 4 bytes) in `hay`.
fn replace_all(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.len() < 4 || hay.len() < needle.len() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0usize;
    while i < hay.len() {
        if hay.get(i..i.saturating_add(needle.len())) == Some(needle) {
            out.extend_from_slice(with);
            i = i.saturating_add(needle.len());
        } else {
            if let Some(b) = hay.get(i) {
                out.push(*b);
            }
            i = i.saturating_add(1);
        }
    }
    out
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

/// The systemd-activated sockets (LISTEN_FDS: fd 3 = main socket, fd 4 =
/// restricted socket for sandboxes) or newly created ones.
pub fn listeners(
    path: Option<&str>,
    agent_path: Option<&str>,
) -> Result<(UnixListener, Option<UnixListener>)> {
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
        // SAFETY: systemd passed us fd 3 (and fd 4 when LISTEN_FDS >= 2) as
        // listening unix sockets (LISTEN_PID matches); we take ownership of
        // each exactly once.
        let main = unsafe { UnixListener::from_raw_fd(3) };
        // systemd passes them without FD_CLOEXEC: profile commands must not
        // inherit the broker's listening sockets.
        sys::set_cloexec(3)?;
        if fds >= 2 {
            sys::set_cloexec(4)?;
        }
        let agent = if fds >= 2 {
            // SAFETY: as above.
            Some(unsafe { UnixListener::from_raw_fd(4) })
        } else {
            None
        };
        return Ok((main, agent));
    }
    let Some(path) = path else {
        bail!("not socket-activated and no --socket given");
    };
    let bind = |p: &str| -> Result<UnixListener> {
        let _ = std::fs::remove_file(p);
        let old = sys::umask(0o117);
        let l = UnixListener::bind(p);
        sys::umask(old);
        Ok(l?)
    };
    let main = bind(path)?;
    let agent = match agent_path {
        Some(p) => Some(bind(p)?),
        None => None,
    };
    Ok((main, agent))
}
