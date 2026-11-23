//! `secret-broker-dialog prompter`: stays connected to the broker as its
//! approval dialog and shows a window for each request.

use crate::ui::{Tone, Ui, UiEvent, View};
use crate::{procinfo, Opts};
use secret_broker::proto::{self, Answer, Caller, Owner, Prompt, Request, Response, SessionInfo};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

fn send(s: &mut UnixStream, kind: &str, id: u64) -> Result<(), String> {
    proto::write_json(s, proto::T_JSON, &Answer { kind: kind.into(), id }).map_err(|e| e.to_string())
}

fn human(secs: u64) -> String {
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    match (h, m) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

fn clock(unix: i64) -> String {
    secret_broker::sys::local_time(unix)
}

/// "07:09" today, else "2026-11-21 07:09".
fn short_clock(unix: i64) -> String {
    let full = clock(unix);
    let today = clock(secret_broker::sys::now_unix_i64());
    let (date, time) = full.split_once(' ').unwrap_or((full.as_str(), ""));
    let hm: String = time.chars().take(5).collect();
    if today.starts_with(date) {
        hm
    } else {
        format!("{date} {hm}")
    }
}

fn owner_line(o: &Owner) -> String {
    let mut s = format!("{} by {} with {}", short_clock(o.at_unix), o.user, o.method);
    if !o.app.is_empty() {
        s.push_str(&format!(" in {}", o.app));
    }
    if o.sandboxed {
        s.push_str(" [sandbox]");
    }
    s
}

fn owner_detail(o: &Owner) -> String {
    format!(
        "{} — {} ({}) by {} uid {} pid {}: {}{}{}",
        clock(o.at_unix),
        o.method,
        o.via,
        o.user,
        o.uid,
        o.pid,
        o.command,
        if o.app.is_empty() { String::new() } else { format!(" — {}", o.app) },
        if o.socket.is_empty() { String::new() } else { format!(" — {}", o.socket) },
    )
}

/// The full picture, for the Tab panel.
pub fn details_for(c: &Caller, session: Option<&SessionInfo>) -> Vec<(String, String, Tone)> {
    let mut d: Vec<(String, String, Tone)> = Vec::new();
    let mut add = |l: &str, v: String, t: Tone| {
        if !v.is_empty() {
            d.push((l.to_string(), v, t));
        }
    };
    add("User", format!("{} (uid {}, gid {})", c.user, c.uid, c.gid), Tone::Normal);
    add(
        "PID",
        if c.verified {
            format!("{} (pinned by pidfd: still the same process)", c.pid)
        } else {
            format!("{} (not verified: it may have exited and the pid been reused)", c.pid)
        },
        if c.verified { Tone::Normal } else { Tone::Warn },
    );
    add("Command", c.argv.join(" "), Tone::Accent);
    add("Executable", c.exe.clone(), Tone::Normal);
    add("Working dir", c.cwd.clone(), Tone::Normal);
    add(
        "Socket",
        if c.sandboxed {
            format!("{} (restricted: sandbox socket)", c.socket)
        } else {
            format!("{} (full access)", c.socket)
        },
        if c.sandboxed { Tone::Warn } else { Tone::Normal },
    );
    add("ai-run", c.ai_run_profile.clone(), Tone::Warn);
    add("App", c.app_label(), Tone::Normal);
    add("Unit", c.unit.clone(), Tone::Muted);
    add("Cgroup", c.cgroup.clone(), Tone::Muted);
    let mut login = Vec::new();
    if !c.login_session.is_empty() {
        login.push(format!("session {}", c.login_session));
    }
    if !c.seat.is_empty() {
        login.push(c.seat.clone());
    }
    if !c.session_type.is_empty() {
        login.push(c.session_type.clone());
    }
    add("Login", login.join(", "), Tone::Normal);
    add("TTY", c.tty.clone(), Tone::Normal);
    if let Some(a) = c.audit_session {
        add("Audit session", a.to_string(), Tone::Muted);
    }
    for (i, p) in c.parents.iter().enumerate() {
        let mut v = format!("{} [pid {}", p.comm, p.pid);
        if p.uid != c.uid {
            v.push_str(&format!(", uid {}", p.uid));
        }
        v.push(']');
        if !p.exe.is_empty() {
            v.push_str(&format!(" {}", p.exe));
        }
        if !p.argv.is_empty() {
            v.push_str(&format!(" — {}", p.argv.join(" ")));
        }
        add(if i == 0 { "Parents" } else { "" }, v, Tone::Normal);
    }
    if let Some(s) = session {
        add("Session", s.state.clone(), Tone::Normal);
        if let Some(o) = &s.unlocked {
            add("Unlocked", owner_detail(o), Tone::Normal);
        }
        if let Some(o) = &s.opened {
            if s.unlocked.as_ref().map(|u| u.at_unix) != Some(o.at_unix) {
                add("Last opened", owner_detail(o), Tone::Normal);
            }
        }
    }
    add(
        "Snapshot",
        format!(
            "taken by the broker at {}; parents are not pinned and their pids can be reused",
            clock(c.snapshot_unix)
        ),
        Tone::Muted,
    );
    for n in &c.notes {
        add("Note", n.clone(), Tone::Warn);
    }
    d
}

pub fn view_for(p: &Prompt) -> View {
    let mut rows = Vec::new();
    let mut details = Vec::new();
    if let Some(c) = &p.caller {
        let mut who = format!("{}  [pid {}]", c.command(), c.pid);
        if !c.verified {
            who.push_str("  (unverified)");
        }
        rows.push(("Requested by".to_string(), who, if c.verified { Tone::Normal } else { Tone::Warn }));
        let app = c.app_label();
        if !app.is_empty() {
            rows.push(("App".to_string(), app, Tone::Normal));
        }
        if c.sandboxed {
            let prof = if c.ai_run_profile.is_empty() {
                String::new()
            } else {
                format!(" \"{}\"", c.ai_run_profile)
            };
            rows.push((
                "Context".to_string(),
                format!("ai-run sandbox{prof} via {} ({})", c.socket, c.user),
                Tone::Warn,
            ));
        } else {
            rows.push((
                "Context".to_string(),
                format!("no sandbox, via {} ({})", c.socket, c.user),
                Tone::Normal,
            ));
        }
        details = details_for(c, p.session.as_ref());
    } else if let Some(r) = &p.requester {
        // Older broker: read /proc ourselves.
        let who = procinfo::cmdline(r.pid).unwrap_or_else(|| "(process gone)".into());
        rows.push(("Requested by".to_string(), format!("{who}  [pid {}]", r.pid), Tone::Normal));
        let chain = procinfo::chain(r.pid, 6);
        if !chain.is_empty() {
            rows.push(("Parents".to_string(), chain, Tone::Muted));
        }
        if r.sandboxed {
            rows.push(("Context".to_string(), format!("inside an ai-run sandbox ({})", r.user), Tone::Warn));
        } else {
            rows.push(("Context".to_string(), format!("outside any sandbox ({})", r.user), Tone::Normal));
        }
    }
    if !p.purpose.is_empty() {
        rows.push(("Will run".to_string(), p.purpose.clone(), Tone::Accent));
    }
    rows.push(("Opens for".to_string(), human(p.ttl_seconds), Tone::Normal));
    if let Some(o) = p.session.as_ref().and_then(|s| s.unlocked.as_ref()) {
        rows.push(("Unlocked".to_string(), owner_line(o), Tone::Muted));
    }
    let pin = p.methods.iter().any(|m| m == "pin");
    let tab = if details.is_empty() { "" } else { "Tab  details      " };
    View {
        title: "Approve secret session".into(),
        rows,
        phrase: p.phrase.clone(),
        field: pin.then(|| "PIN".to_string()),
        hints: p.hints.clone(),
        message: if pin && p.attempts_left > 0 && p.attempts_left < 3 {
            Some((format!("{} attempts left", p.attempts_left), Tone::Warn))
        } else {
            None
        },
        footer: if pin {
            format!("Enter  submit PIN      {tab}Esc  deny")
        } else {
            format!("{tab}Esc  deny")
        },
        deadline: Instant::now().checked_add(Duration::from_secs(p.timeout_seconds)),
        details,
        ..Default::default()
    }
}

fn handle(opts: &Opts, s: &mut UnixStream, p: &Prompt) -> Result<(), String> {
    let fonts = match crate::load_fonts(opts) {
        Ok(f) => f,
        Err(e) => {
            send(s, "unavailable", p.id)?;
            return Err(e);
        }
    };
    let theme = crate::theme::load(opts.theme.as_deref());
    let mut ui = match Ui::open(theme, fonts, opts.size()) {
        Ok(u) => u,
        Err(e) => {
            send(s, "unavailable", p.id)?;
            return Err(e);
        }
    };
    ui.set_view(view_for(p));
    let fd = s.as_raw_fd();
    let mut closing: Option<Instant> = None;
    loop {
        if closing.is_some_and(|t| t.elapsed() > Duration::from_millis(1600)) {
            return Ok(());
        }
        match ui.wait(Some(fd))? {
            UiEvent::Submit(pin) => {
                if closing.is_some() {
                    return Ok(());
                }
                if ui.view_mut().field.is_none() || pin.is_empty() {
                    continue;
                }
                send(s, "pin", p.id)?;
                proto::write_frame(s, proto::T_PIN, pin.as_bytes()).map_err(|e| e.to_string())?;
                let v = ui.view_mut();
                v.busy = true;
                v.message = Some(("Checking…".into(), Tone::Muted));
            }
            UiEvent::Cancel | UiEvent::Closed => {
                if closing.is_none() {
                    send(s, "deny", p.id)?;
                }
                return Ok(());
            }
            UiEvent::Readable => {
                let m: Prompt = proto::read_json(s, proto::T_JSON).map_err(|e| e.to_string())?;
                if m.id != p.id {
                    continue;
                }
                match m.kind.as_str() {
                    "update" => {
                        let v = ui.view_mut();
                        v.busy = false;
                        let tone = if m.message.starts_with("Wrong") || m.message.contains("giving up") {
                            Tone::Error
                        } else {
                            Tone::Warn
                        };
                        v.message = Some((m.message, tone));
                    }
                    "done" => {
                        if m.ok {
                            return Ok(());
                        }
                        let v = ui.view_mut();
                        v.busy = true;
                        v.field = None;
                        v.hints.clear();
                        v.footer = "Esc  close".into();
                        v.message = Some((m.message, Tone::Error));
                        closing = Some(Instant::now());
                    }
                    _ => {}
                }
            }
            UiEvent::Tick => {}
        }
    }
}

fn session(opts: &Opts) -> Result<(), String> {
    let path = secret_broker::client::socket_path();
    let mut s = UnixStream::connect(&path).map_err(|e| format!("{path}: {e}"))?;
    proto::write_json(
        &mut s,
        proto::T_JSON,
        &Request {
            op: "prompter".into(),
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    let r: Response = proto::read_json(&mut s, proto::T_JSON).map_err(|e| e.to_string())?;
    if !r.ok {
        return Err(format!("broker refused: {}", r.error));
    }
    eprintln!("secret-broker-dialog: connected to {path}");
    loop {
        let p: Prompt = proto::read_json(&mut s, proto::T_JSON).map_err(|e| format!("broker connection: {e}"))?;
        if p.kind == "request" {
            if let Err(e) = handle(opts, &mut s, &p) {
                eprintln!("secret-broker-dialog: {e}");
            }
        }
    }
}

pub fn run(opts: &Opts) -> std::process::ExitCode {
    let mut delay = 1u64;
    loop {
        let started = Instant::now();
        if let Err(e) = session(opts) {
            eprintln!("secret-broker-dialog: {e}");
        }
        if started.elapsed() > Duration::from_secs(30) {
            delay = 1;
        }
        let _ = std::io::stderr().flush();
        std::thread::sleep(Duration::from_secs(delay));
        delay = delay.saturating_mul(2).min(30);
    }
}
