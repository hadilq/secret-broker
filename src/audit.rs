//! Audit log: every lock/unlock/approval/exec/refusal, with who asked.
//!
//! Two sinks:
//! - journald (native protocol), SYSLOG_IDENTIFIER=secret-broker with
//!   structured fields AUDIT_EVENT, AUDIT_OUTCOME, AUDIT_SEQ, AUDIT_HASH,
//!   CALLER_UID/USER/PID/EXE/UNIT, ... and the whole entry in AUDIT_JSON;
//! - an append-only JSON-lines file, `<dir>/audit.jsonl`, written only by the
//!   broker (agent-secrets), readable by the secret-broker group. Rotated by
//!   size into audit.jsonl.1 .. .N.
//!
//! Each entry carries `prev`, the SHA-256 of the previous line (genesis: 64
//! zeros), across rotations. Editing, inserting or deleting an entry breaks
//! the chain; `secret-broker log verify` finds it. Someone with root can
//! rewrite the whole chain, which is why each entry's hash also goes to the
//! journal (`log verify --journal` compares both) and `log head` prints the
//! latest hash to write down elsewhere.
//!
//! Never logged: secret values, environment values, PINs. argv is logged,
//! with any secret value that appears in it replaced by [REDACTED].

use crate::bail;
use crate::error::{Error, Result};
use crate::proto::Caller;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub const FILE: &str = "audit.jsonl";
pub const DEFAULT_DIR: &str = "/var/log/secret-broker";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct AuditConfig {
    pub enable: bool,
    pub directory: String,
    /// Rotate when the file would grow past this.
    pub max_file_bytes: u64,
    /// Rotated files kept (audit.jsonl.1 .. .N); older ones are deleted.
    pub keep_files: u32,
    /// Also send every entry to journald.
    pub journal: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enable: true,
            directory: DEFAULT_DIR.into(),
            max_file_bytes: 10 * 1024 * 1024,
            keep_files: 9,
            journal: true,
        }
    }
}

/// One audit entry under construction.
#[derive(Debug, Clone)]
pub struct Event {
    event: String,
    outcome: String,
    caller: Option<Value>,
    fields: Map<String, Value>,
}

fn map_value(v: &mut Value, f: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| map_value(x, f)),
        Value::Object(o) => o.values_mut().for_each(|x| map_value(x, f)),
        _ => {}
    }
}

impl Event {
    pub fn new(event: &str, outcome: &str) -> Event {
        Event {
            event: event.into(),
            outcome: outcome.into(),
            caller: None,
            fields: Map::new(),
        }
    }

    pub fn caller(mut self, c: &Caller) -> Event {
        self.caller = serde_json::to_value(c).ok();
        self
    }

    /// Apply `f` to every string value (redaction).
    pub fn map_strings(mut self, f: &dyn Fn(&str) -> String) -> Event {
        for v in self.fields.values_mut() {
            map_value(v, f);
        }
        if let Some(c) = self.caller.as_mut() {
            map_value(c, f);
        }
        self
    }

    pub fn field(mut self, k: &str, v: impl Into<Value>) -> Event {
        self.fields.insert(k.into(), v.into());
        self
    }

    /// Only set when non-empty.
    pub fn opt(self, k: &str, v: &str) -> Event {
        if v.is_empty() {
            self
        } else {
            self.field(k, v)
        }
    }
}

pub fn hash_line(line: &[u8]) -> String {
    let d = Sha256::digest(line);
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

struct Inner {
    file: Option<File>,
    size: u64,
    seq: u64,
    prev: String,
    warned: bool,
}

pub struct Audit {
    cfg: AuditConfig,
    inner: Mutex<Inner>,
}

fn rotated(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("{FILE}.{n}"))
}

/// audit.jsonl.N (oldest) .. audit.jsonl.1, audit.jsonl.
pub fn files_oldest_first(dir: &Path) -> Vec<PathBuf> {
    let mut nums: Vec<u32> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    name.strip_prefix(&format!("{FILE}."))
                        .and_then(|n| n.parse::<u32>().ok())
                })
                .collect()
        })
        .unwrap_or_default();
    nums.sort_unstable_by(|a, b| b.cmp(a));
    let mut out: Vec<PathBuf> = nums.into_iter().map(|n| rotated(dir, n)).collect();
    let cur = dir.join(FILE);
    if cur.exists() {
        out.push(cur);
    }
    out
}

/// (seq, hash) of the last line of the newest non-empty file.
fn resume_point(dir: &Path) -> (u64, String) {
    for f in files_oldest_first(dir).iter().rev() {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        let Some(last) = lines.last() else { continue };
        // Last parseable seq, plus any unparseable lines after it.
        let mut seq = 0u64;
        let mut extra = 0u64;
        for l in lines.iter().rev() {
            match serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| v.get("seq").and_then(Value::as_u64))
            {
                Some(s) => {
                    seq = s;
                    break;
                }
                None => extra = extra.saturating_add(1),
            }
        }
        return (seq.saturating_add(extra), hash_line(last.as_bytes()));
    }
    (0, GENESIS.into())
}

fn warn(inner: &mut Inner, msg: String) {
    if !inner.warned {
        eprintln!("audit: {msg}");
        inner.warned = true;
    }
}

impl Audit {
    pub fn open(cfg: AuditConfig) -> Audit {
        let (seq, prev) = if cfg.enable {
            resume_point(Path::new(&cfg.directory))
        } else {
            (0, GENESIS.into())
        };
        Audit {
            cfg,
            inner: Mutex::new(Inner {
                file: None,
                size: 0,
                seq,
                prev,
                warned: false,
            }),
        }
    }

    pub fn disabled() -> Audit {
        Audit::open(AuditConfig {
            enable: false,
            ..Default::default()
        })
    }

    fn dir(&self) -> &Path {
        Path::new(&self.cfg.directory)
    }

    fn ensure_file(&self, inner: &mut Inner) -> Result<()> {
        if inner.file.is_some() {
            return Ok(());
        }
        let dir = self.dir();
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(dir)?;
        }
        let path = dir.join(FILE);
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| Error::from(e).context(path.display()))?;
        // UMask=0077 in the unit: widen to group-read explicitly.
        f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        inner.size = f.metadata().map(|m| m.size()).unwrap_or(0);
        inner.file = Some(f);
        Ok(())
    }

    fn rotate(&self, inner: &mut Inner) -> Result<()> {
        inner.file = None;
        let dir = self.dir();
        let keep = self.cfg.keep_files;
        if keep == 0 {
            std::fs::remove_file(dir.join(FILE))?;
            return Ok(());
        }
        let _ = std::fs::remove_file(rotated(dir, keep));
        let mut n = keep;
        while n > 1 {
            let from = rotated(dir, n.saturating_sub(1));
            if from.exists() {
                std::fs::rename(&from, rotated(dir, n))?;
            }
            n = n.saturating_sub(1);
        }
        std::fs::rename(dir.join(FILE), rotated(dir, 1))?;
        // Drop anything beyond `keep` (e.g. after lowering keepFiles).
        for f in files_oldest_first(dir) {
            let beyond = f
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix(&format!("{FILE}.")))
                .and_then(|n| n.parse::<u32>().ok())
                .is_some_and(|n| n > keep);
            if beyond {
                let _ = std::fs::remove_file(f);
            }
        }
        Ok(())
    }

    /// Append one entry (and send it to journald). Never fails the caller.
    pub fn record(&self, ev: Event) {
        if !self.cfg.enable {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let seq = inner.seq.saturating_add(1);
        let ms = crate::sys::now_unix_ms();
        let mut m = Map::new();
        m.insert("v".into(), Value::from(1));
        m.insert("seq".into(), Value::from(seq));
        m.insert("ts".into(), Value::from(crate::sys::utc_time_ms(ms)));
        m.insert("ts_unix_ms".into(), Value::from(ms));
        m.insert("event".into(), Value::from(ev.event.clone()));
        m.insert("outcome".into(), Value::from(ev.outcome.clone()));
        for (k, v) in ev.fields {
            m.insert(k, v);
        }
        if let Some(c) = ev.caller {
            m.insert("caller".into(), c);
        }
        m.insert("prev".into(), Value::from(inner.prev.clone()));
        let v = Value::Object(m);
        let line = match serde_json::to_string(&v) {
            Ok(l) => l,
            Err(e) => {
                warn(&mut inner, format!("serialize: {e}"));
                return;
            }
        };
        let hash = hash_line(line.as_bytes());
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX).saturating_add(1);
        let written = (|| -> Result<()> {
            self.ensure_file(&mut inner)?;
            if inner.size > 0 && inner.size.saturating_add(len) > self.cfg.max_file_bytes {
                self.rotate(&mut inner)?;
                self.ensure_file(&mut inner)?;
            }
            let Some(f) = inner.file.as_mut() else {
                bail!("not open");
            };
            let mut b = line.clone().into_bytes();
            b.push(b'\n');
            f.write_all(&b)?;
            let _ = f.sync_data();
            Ok(())
        })();
        match written {
            Ok(()) => {
                inner.size = inner.size.saturating_add(len);
                inner.warned = false;
            }
            Err(e) => {
                inner.file = None;
                warn(&mut inner, format!("{}: {e}", self.cfg.directory));
            }
        }
        // The chain advances even if the file write failed: the journal copy
        // then shows the gap.
        inner.seq = seq;
        let prev = std::mem::replace(&mut inner.prev, hash.clone());
        drop(inner);
        if self.cfg.journal {
            journal_send(&v, &line, seq, &hash, &prev);
        }
    }
}

fn journal_send(v: &Value, line: &str, seq: u64, hash: &str, prev: &str) {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let c = v.get("caller");
    let cs = |k: &str| {
        c.and_then(|c| c.get(k))
            .map(|x| match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    let outcome = s("outcome");
    let priority = match outcome.as_str() {
        "refused" | "denied" | "failed" | "timeout" | "wiped" => "4",
        _ => "5",
    };
    let fields: Vec<(&str, String)> = vec![
        ("MESSAGE", summary(v)),
        ("PRIORITY", priority.into()),
        ("SYSLOG_IDENTIFIER", "secret-broker".into()),
        ("AUDIT_EVENT", s("event")),
        ("AUDIT_OUTCOME", outcome),
        ("AUDIT_SEQ", seq.to_string()),
        ("AUDIT_HASH", hash.into()),
        ("AUDIT_PREV", prev.into()),
        ("AUDIT_METHOD", s("method")),
        ("AUDIT_PROFILE", s("profile")),
        ("AUDIT_SOCKET", cs("socket")),
        ("AUDIT_SANDBOX_PROFILE", cs("ai_run_profile")),
        ("CALLER_UID", cs("uid")),
        ("CALLER_USER", cs("user")),
        ("CALLER_PID", cs("pid")),
        ("CALLER_EXE", cs("exe")),
        ("CALLER_CWD", cs("cwd")),
        ("CALLER_UNIT", cs("unit")),
        ("CALLER_SESSION", cs("login_session")),
        ("AUDIT_JSON", line.into()),
    ];
    let mut buf: Vec<u8> = Vec::new();
    for (k, val) in fields.iter().filter(|(_, v)| !v.is_empty()) {
        // Binary-safe form: KEY \n <u64 le length> VALUE \n
        buf.extend_from_slice(k.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(&u64::try_from(val.len()).unwrap_or(0).to_le_bytes());
        buf.extend_from_slice(val.as_bytes());
        buf.push(b'\n');
    }
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(&buf, JOURNAL_SOCKET);
    }
}

fn gs<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// One human line for an entry.
pub fn summary(v: &Value) -> String {
    let mut s = format!("{} {}", gs(v, "event"), gs(v, "outcome"));
    for k in ["method", "via", "profile"] {
        let x = gs(v, k);
        if !x.is_empty() {
            s.push_str(&format!(" {k}={x}"));
        }
    }
    if let Some(a) = v.get("args").and_then(Value::as_array) {
        let a: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
        s.push_str(&format!(" args=[{}]", a.join(" ")));
    }
    if let Some(code) = v.get("exit_code").and_then(Value::as_i64) {
        s.push_str(&format!(" exit={code}"));
    }
    if let Some(d) = v.get("duration_ms").and_then(Value::as_u64) {
        s.push_str(&format!(" {d}ms"));
    }
    let r = gs(v, "reason");
    if !r.is_empty() {
        s.push_str(&format!(" reason=\"{r}\""));
    }
    if let Some(c) = v.get("caller") {
        let user = gs(c, "user");
        let pid = c.get("pid").and_then(Value::as_i64).unwrap_or(0);
        let cmd: Vec<&str> = c
            .get("argv")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        s.push_str(&format!(" by {user} pid {pid}"));
        if !cmd.is_empty() {
            let cmd = cmd.join(" ");
            s.push_str(&format!(" `{}`", crate::server::sanitize(&cmd, 120)));
        }
        let app = gs(c, "app");
        let unit = gs(c, "unit");
        if !app.is_empty() {
            s.push_str(&format!(" app={app}"));
        } else if !unit.is_empty() {
            s.push_str(&format!(" unit={unit}"));
        }
        let sock = gs(c, "socket");
        if !sock.is_empty() {
            s.push_str(&format!(" via {sock}"));
        }
        let ai = gs(c, "ai_run_profile");
        if !ai.is_empty() {
            s.push_str(&format!(" ai-run={ai}"));
        }
    }
    s
}

#[derive(Debug, Clone)]
pub struct Line {
    pub file: PathBuf,
    pub lineno: usize,
    pub raw: String,
    pub value: Option<Value>,
}

pub fn read_file(path: &Path, out: &mut Vec<Line>) -> Result<()> {
    let f = File::open(path).map_err(|e| Error::from(e).context(path.display()))?;
    for (i, l) in BufReader::new(f).lines().enumerate() {
        let raw = l?;
        if raw.is_empty() {
            continue;
        }
        out.push(Line {
            file: path.to_path_buf(),
            lineno: i.saturating_add(1),
            value: serde_json::from_str(&raw).ok(),
            raw,
        });
    }
    Ok(())
}

pub fn read_all(dir: &Path) -> Result<Vec<Line>> {
    let mut out = Vec::new();
    let files = files_oldest_first(dir);
    if files.is_empty() {
        bail!("no audit log in {}", dir.display());
    }
    for f in files {
        read_file(&f, &mut out)?;
    }
    Ok(out)
}

#[derive(Debug, Default)]
pub struct Verify {
    pub entries: usize,
    pub first_seq: u64,
    pub last_seq: u64,
    pub head: String,
    /// The oldest entries were rotated away (chain starts mid-way).
    pub truncated_start: bool,
    pub problems: Vec<String>,
}

pub fn verify(lines: &[Line]) -> Verify {
    let mut r = Verify {
        head: GENESIS.into(),
        ..Default::default()
    };
    let mut prev_hash: Option<String> = None;
    let mut prev_seq: Option<u64> = None;
    for l in lines {
        let at = format!("{}:{}", l.file.display(), l.lineno);
        r.entries = r.entries.saturating_add(1);
        let hash = hash_line(l.raw.as_bytes());
        let Some(v) = &l.value else {
            r.problems.push(format!("{at}: not valid JSON (truncated or edited)"));
            prev_hash = Some(hash);
            prev_seq = prev_seq.map(|s| s.saturating_add(1));
            continue;
        };
        let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let prev = gs(v, "prev");
        match &prev_hash {
            Some(h) if h != prev => r.problems.push(format!(
                "{at} (seq {seq}): prev hash does not match the line before: an entry was changed, inserted or removed"
            )),
            Some(_) => {}
            None => {
                r.first_seq = seq;
                if seq <= 1 {
                    if prev != GENESIS {
                        r.problems.push(format!("{at}: first entry does not start the chain"));
                    }
                } else {
                    r.truncated_start = true;
                }
            }
        }
        if let Some(ps) = prev_seq {
            if Some(seq) != ps.checked_add(1) {
                r.problems.push(format!("{at}: seq jumps from {ps} to {seq}"));
            }
        }
        prev_seq = Some(seq);
        r.last_seq = seq;
        prev_hash = Some(hash.clone());
        r.head = hash;
    }
    r
}

/// Compare with the hashes journald received (AUDIT_SEQ -> AUDIT_HASH).
pub fn cross_check(lines: &[Line], journal: &[(u64, String)]) -> Vec<String> {
    use std::collections::HashMap;
    let file: HashMap<u64, String> = lines
        .iter()
        .filter_map(|l| {
            let seq = l.value.as_ref()?.get("seq")?.as_u64()?;
            Some((seq, hash_line(l.raw.as_bytes())))
        })
        .collect();
    let (lo, hi) = (
        file.keys().min().copied().unwrap_or(0),
        file.keys().max().copied().unwrap_or(0),
    );
    let mut problems = Vec::new();
    for (seq, h) in journal {
        match file.get(seq) {
            Some(fh) if fh != h => problems.push(format!("seq {seq}: file entry differs from the journal's copy")),
            None if *seq >= lo && *seq <= hi => problems.push(format!("seq {seq}: in the journal but missing from the file")),
            None if *seq > hi => problems.push(format!("seq {seq}: in the journal, newer than the file's last entry (file truncated?)")),
            _ => {}
        }
    }
    problems
}

fn journal_hashes() -> Result<Vec<(u64, String)>> {
    let out = std::process::Command::new("journalctl")
        .args([
            "--no-pager",
            "-o",
            "json",
            "--output-fields=AUDIT_SEQ,AUDIT_HASH",
            "SYSLOG_IDENTIFIER=secret-broker",
        ])
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| Error::msg(format!("journalctl: {e}")))?;
    let mut v = Vec::new();
    for l in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(j) = serde_json::from_str::<Value>(l) else { continue };
        let seq = j.get("AUDIT_SEQ").and_then(Value::as_str).and_then(|s| s.parse().ok());
        let h = j.get("AUDIT_HASH").and_then(Value::as_str);
        if let (Some(seq), Some(h)) = (seq, h) {
            v.push((seq, h.to_string()));
        }
    }
    Ok(v)
}

/// `--since`: 30m / 2h / 3d / 1w ago, YYYY-MM-DD[ HH:MM[:SS]] local, or @unix.
pub fn parse_since(s: &str, now: i64) -> Result<i64> {
    let s = s.trim();
    if let Some(u) = s.strip_prefix('@') {
        return u.parse().map_err(|_| Error::msg(format!("bad --since {s:?}")));
    }
    let unit = s.chars().last().unwrap_or(' ');
    let mult: Option<i64> = match unit {
        's' => Some(1),
        'm' => Some(60),
        'h' => Some(3600),
        'd' => Some(86400),
        'w' => Some(7 * 86400),
        _ => None,
    };
    if let Some(m) = mult {
        if let Some(n) = s.strip_suffix(unit).and_then(|n| n.parse::<i64>().ok()) {
            return n
                .checked_mul(m)
                .and_then(|d| now.checked_sub(d))
                .ok_or_else(|| Error::msg("--since out of range"));
        }
    }
    let (date, time) = s.split_once([' ', 'T']).unwrap_or((s, "00:00:00"));
    let d: Vec<i32> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<i32> = time.split(':').filter_map(|x| x.parse().ok()).collect();
    match (d.as_slice(), t.as_slice()) {
        ([y, mo, da], [h, mi, rest @ ..]) => crate::sys::local_to_unix(*y, *mo, *da, *h, *mi, rest.first().copied().unwrap_or(0))
            .ok_or_else(|| Error::msg(format!("bad --since {s:?}"))),
        _ => bail!("bad --since {s:?} (use 2h, 3d, 2026-11-22, '2026-11-22 09:00' or @UNIX)"),
    }
}

#[derive(Debug, Default)]
pub struct Filter {
    pub since_ms: Option<u64>,
    pub events: Vec<String>,
}

impl Filter {
    pub fn matches(&self, v: &Value) -> bool {
        if let Some(since) = self.since_ms {
            if v.get("ts_unix_ms").and_then(Value::as_u64).unwrap_or(0) < since {
                return false;
            }
        }
        if !self.events.is_empty() {
            let e = gs(v, "event");
            if !self.events.iter().any(|x| x == e || (x.ends_with('*') && e.starts_with(x.trim_end_matches('*')))) {
                return false;
            }
        }
        true
    }
}

fn print_line(l: &Line, json: bool, out: &mut impl Write) -> std::io::Result<()> {
    if json {
        return writeln!(out, "{}", l.raw);
    }
    match &l.value {
        Some(v) => {
            let ms = v.get("ts_unix_ms").and_then(Value::as_u64).unwrap_or(0);
            let t = crate::sys::local_time(i64::try_from(ms.checked_div(1000).unwrap_or(0)).unwrap_or(0));
            let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
            writeln!(out, "{t}  #{seq:<5} {}", crate::server::sanitize(&summary(v), 2000))
        }
        None => writeln!(out, "(unparseable line {}:{})", l.file.display(), l.lineno),
    }
}

pub fn default_dir() -> PathBuf {
    std::env::var_os("SECRET_BROKER_AUDIT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

/// `secret-broker log ...`. Returns the exit code.
pub fn cli(args: &[String]) -> Result<u8> {
    let mut dir = default_dir();
    let mut json = false;
    let mut follow = false;
    let mut with_journal = false;
    let mut sub = "show";
    let mut filter = Filter::default();
    let mut last: Option<usize> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "verify" | "head" if sub == "show" => {
                sub = if a == "verify" { "verify" } else { "head" }
            }
            "--json" => json = true,
            "-f" | "--follow" => follow = true,
            "--journal" => with_journal = true,
            "--dir" => dir = PathBuf::from(it.next().ok_or_else(|| Error::msg("--dir needs a path"))?),
            "-n" | "--lines" => {
                last = Some(
                    it.next()
                        .and_then(|n| n.parse().ok())
                        .ok_or_else(|| Error::msg("-n needs a number"))?,
                )
            }
            "--since" => {
                let s = it.next().ok_or_else(|| Error::msg("--since needs a value"))?;
                let t = parse_since(s, crate::sys::now_unix_i64())?;
                filter.since_ms = Some(u64::try_from(t).unwrap_or(0).saturating_mul(1000));
            }
            "--event" => {
                let e = it.next().ok_or_else(|| Error::msg("--event needs a name"))?;
                filter.events.extend(e.split(',').map(str::to_string));
            }
            other => bail!("log: unknown option {other}"),
        }
    }
    let lines = read_all(&dir)?;
    match sub {
        "head" => {
            let r = verify(&lines);
            println!("seq {} {}", r.last_seq, r.head);
            Ok(0)
        }
        "verify" => {
            let r = verify(&lines);
            let mut problems = r.problems.clone();
            if with_journal {
                let j = journal_hashes()?;
                println!("journal: {} entries with hashes", j.len());
                problems.extend(cross_check(&lines, &j));
            }
            println!(
                "{} entries, seq {}..{}, head {}{}",
                r.entries,
                r.first_seq,
                r.last_seq,
                r.head,
                if r.truncated_start {
                    " (older entries rotated away)"
                } else {
                    ""
                }
            );
            if problems.is_empty() {
                println!("chain OK");
                Ok(0)
            } else {
                for p in &problems {
                    println!("PROBLEM: {p}");
                }
                Ok(1)
            }
        }
        _ => {
            let mut out = std::io::stdout().lock();
            let shown: Vec<&Line> = lines
                .iter()
                .filter(|l| l.value.as_ref().map_or(true, |v| filter.matches(v)))
                .collect();
            let skip = last.map_or(0, |n| shown.len().saturating_sub(n));
            for l in shown.iter().skip(skip) {
                print_line(l, json, &mut out)?;
            }
            out.flush()?;
            if follow {
                drop(out);
                follow_file(&dir.join(FILE), json, &filter)?;
            }
            Ok(0)
        }
    }
}

/// Print new lines as they're appended; reopen after a rotation.
fn follow_file(path: &Path, json: bool, filter: &Filter) -> Result<()> {
    let mut f = File::open(path)?;
    let mut ino = f.metadata()?.ino();
    let mut pos = f.seek(SeekFrom::End(0))?;
    let mut pending = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(m) = std::fs::metadata(path) {
            if m.ino() != ino {
                f = File::open(path)?;
                ino = m.ino();
                pos = 0;
            }
        }
        f.seek(SeekFrom::Start(pos))?;
        let mut buf = String::new();
        let n = f.read_to_string(&mut buf)?;
        pos = pos.saturating_add(u64::try_from(n).unwrap_or(0));
        pending.push_str(&buf);
        while let Some(i) = pending.find('\n') {
            let raw: String = pending.drain(..=i).collect();
            let raw = raw.trim_end().to_string();
            if raw.is_empty() {
                continue;
            }
            let l = Line {
                file: path.to_path_buf(),
                lineno: 0,
                value: serde_json::from_str(&raw).ok(),
                raw,
            };
            if l.value.as_ref().map_or(true, |v| filter.matches(v)) {
                let mut out = std::io::stdout().lock();
                print_line(&l, json, &mut out)?;
                out.flush()?;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sb-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn cfg(dir: &Path, max: u64, keep: u32) -> AuditConfig {
        AuditConfig {
            enable: true,
            directory: dir.to_string_lossy().into_owned(),
            max_file_bytes: max,
            keep_files: keep,
            journal: false,
        }
    }

    #[test]
    fn chain_rotation_and_tamper() {
        let d = tmp("chain");
        let a = Audit::open(cfg(&d, 600, 3));
        let c = Caller {
            pid: 42,
            uid: 1000,
            user: "hadi".into(),
            socket: "agent.sock".into(),
            argv: vec!["secret-run".into(), "gh".into()],
            ..Default::default()
        };
        for i in 0..12 {
            a.record(Event::new("exec_end", "ok").caller(&c).field("exit_code", i));
        }
        let mode = std::fs::metadata(d.join(FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert!(files_oldest_first(&d).len() >= 3, "rotated");
        assert!(files_oldest_first(&d).len() <= 4, "keep 3 + current");
        let lines = read_all(&d).unwrap();
        let r = verify(&lines);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(r.truncated_start);
        assert_eq!(r.last_seq, 12);

        // A restarted broker continues the chain.
        drop(a);
        let a = Audit::open(cfg(&d, 600, 3));
        a.record(Event::new("broker_start", "ok"));
        let lines = read_all(&d).unwrap();
        let r = verify(&lines);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert_eq!(r.last_seq, 13);

        // Editing an entry breaks the chain at the next one.
        let cur = d.join(FILE);
        let text = std::fs::read_to_string(&cur).unwrap();
        let edited = text.replacen("\"exit_code\":", "\"exit_code\":1", 1);
        if edited != text {
            std::fs::write(&cur, edited).unwrap();
            let r = verify(&read_all(&d).unwrap());
            assert!(!r.problems.is_empty());
        }
        // Deleting a line too.
        let d2 = tmp("del");
        let a = Audit::open(cfg(&d2, 1 << 20, 3));
        for _ in 0..4 {
            a.record(Event::new("lock", "sealed"));
        }
        let cur = d2.join(FILE);
        let text = std::fs::read_to_string(&cur).unwrap();
        let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| l).collect();
        std::fs::write(&cur, kept.join("\n") + "\n").unwrap();
        let r = verify(&read_all(&d2).unwrap());
        assert!(r.problems.iter().any(|p| p.contains("prev hash")), "{:?}", r.problems);
        assert!(r.problems.iter().any(|p| p.contains("seq jumps")));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }

    #[test]
    fn journal_cross_check() {
        let d = tmp("cross");
        let a = Audit::open(cfg(&d, 1 << 20, 3));
        for _ in 0..3 {
            a.record(Event::new("lock", "sealed"));
        }
        let lines = read_all(&d).unwrap();
        let j: Vec<(u64, String)> = lines
            .iter()
            .map(|l| (l.value.as_ref().unwrap()["seq"].as_u64().unwrap(), hash_line(l.raw.as_bytes())))
            .collect();
        assert!(cross_check(&lines, &j).is_empty());
        let mut bad = j.clone();
        bad[1].1 = GENESIS.into();
        bad.push((9, GENESIS.into()));
        assert_eq!(cross_check(&lines, &bad).len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn since_and_filter() {
        assert_eq!(parse_since("2h", 10_000).unwrap(), 10_000 - 7200);
        assert_eq!(parse_since("@5", 0).unwrap(), 5);
        assert!(parse_since("2026-11-22", 0).is_ok());
        assert!(parse_since("2026-11-22 09:30", 0).is_ok());
        assert!(parse_since("yesterday", 0).is_err());
        let f = Filter {
            since_ms: Some(1000),
            events: vec!["exec*".into(), "unlock".into()],
        };
        assert!(f.matches(&serde_json::json!({"event":"exec_end","ts_unix_ms":2000})));
        assert!(f.matches(&serde_json::json!({"event":"unlock","ts_unix_ms":2000})));
        assert!(!f.matches(&serde_json::json!({"event":"lock","ts_unix_ms":2000})));
        assert!(!f.matches(&serde_json::json!({"event":"unlock","ts_unix_ms":10})));
    }

    #[test]
    fn summary_line() {
        let v = serde_json::json!({"event":"exec_end","outcome":"ok","profile":"gh","args":["pr","list"],"exit_code":0,
            "caller":{"user":"hadi","pid":7,"argv":["secret-run","gh"],"app":"foot (via Hyprland)","socket":"agent.sock","ai_run_profile":"grok-bot"}});
        let s = summary(&v);
        assert!(s.contains("exec_end ok profile=gh args=[pr list] exit=0 by hadi pid 7"), "{s}");
        assert!(s.contains("ai-run=grok-bot"));
    }
}
