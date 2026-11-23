//! secret-broker-dialog: the approval dialog for secret-broker.
//!
//! - `prompter` (default): runs in your graphical session (systemd user
//!   service), registers with the broker as its approval dialog, and shows a
//!   layer-shell overlay for each request. It only collects input; the
//!   broker verifies the PIN / security key / fingerprint itself.
//! - `pinentry`: a gpg pinentry with the same look (first unlock after boot).
//! - `demo`: render a sample dialog (to a PPM file, or in a window).

//!
//! Wayland only (Linux). On macOS it builds but the GUI modes exit with an
//! error; `pinentry --fallback PROG` execs PROG (e.g. pinentry-mac) instead.

// Editing logic is portable (and tested everywhere); the rest is Wayland.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod edit;
#[cfg(target_os = "linux")]
mod pinentry;
#[cfg(target_os = "linux")]
mod procinfo;
#[cfg(target_os = "linux")]
mod prompter;
#[cfg(target_os = "linux")]
mod render;
#[cfg(target_os = "linux")]
mod theme;
#[cfg(target_os = "linux")]
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage:
  secret-broker-dialog [prompter] [--font FILE] [--font-bold FILE] [--theme colors.toml] [--size 0.75]
  secret-broker-dialog pinentry [--fallback /path/to/pinentry-curses] [--font FILE] ...
  secret-broker-dialog demo [--out FILE.ppm] [--scale N] [--pinentry] [--details] [--reveal] [--unfocused] [--cursor N] [--window]
";

#[derive(Debug, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Opts {
    pub font: Option<PathBuf>,
    pub font_bold: Option<PathBuf>,
    pub theme: Option<PathBuf>,
    pub fallback: Option<String>,
    /// `--size` (or SECRET_BROKER_DIALOG_SIZE): scales fonts and the box.
    pub size: Option<f32>,
}

#[cfg(target_os = "linux")]
impl Opts {
    pub fn size(&self) -> f32 {
        let env = || std::env::var("SECRET_BROKER_DIALOG_SIZE").ok().and_then(|v| v.trim().parse().ok());
        ui::clamp_size(self.size.or_else(env).unwrap_or(ui::DEFAULT_SIZE))
    }
}

#[cfg(target_os = "linux")]
fn fc_match(pattern: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("fc-match")
        .args(["--format=%{file}", pattern])
        .output()
        .ok()?;
    let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    p.is_file().then_some(p)
}

#[cfg(target_os = "linux")]
pub fn load_fonts(o: &Opts) -> Result<render::Fonts, String> {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let regular = o
        .font
        .clone()
        .or_else(|| env("SECRET_BROKER_DIALOG_FONT"))
        .or_else(|| fc_match("sans:style=Regular"))
        .ok_or("no font: pass --font FILE")?;
    let bold = o
        .font_bold
        .clone()
        .or_else(|| env("SECRET_BROKER_DIALOG_FONT_BOLD"))
        .or_else(|| fc_match("sans:style=Bold"));
    let r = std::fs::read(&regular).map_err(|e| format!("{}: {e}", regular.display()))?;
    let b = bold.and_then(|p| std::fs::read(p).ok());
    render::Fonts::load(&r, b.as_deref())
}

#[cfg(target_os = "linux")]
fn demo_prompt() -> secret_broker::proto::Prompt {
    use secret_broker::proto::{Caller, Owner, ProcInfo, SessionInfo};
    let now = secret_broker::sys::now_unix_i64();
    let store = "/nix/store/0lk2sj7ry4m754mv16kapc1a71i2ma66";
    let caller = Caller {
        pid: 48213,
        uid: 1000,
        gid: 100,
        user: "hadi".into(),
        socket: "agent.sock".into(),
        sandboxed: true,
        ai_run_profile: "grok-bot".into(),
        comm: "secret-run".into(),
        exe: format!("{store}-secret-broker-0.2.0/bin/secret-broker"),
        cwd: "/home/hadi/dev/secret-broker".into(),
        argv: ["secret-run", "gh", "pr", "list", "--repo", "hadilq/secret-broker"].iter().map(|s| s.to_string()).collect(),
        cgroup: "/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-grok\\x2dbot-3141.scope".into(),
        unit: "app-Hyprland-grok\\x2dbot-3141.scope".into(),
        app: "grok-bot".into(),
        launcher: "Hyprland".into(),
        login_session: "2".into(),
        seat: "seat0".into(),
        tty: "tty1".into(),
        session_type: "wayland/user".into(),
        audit_session: Some(2),
        loginuid: Some(1000),
        start_time: 1,
        parents: vec![
            ProcInfo { pid: 48190, uid: 1000, comm: "bash".into(), exe: format!("{store}-bash-5.3/bin/bash"), argv: vec!["bash".into(), "-c".into(), "secret-run gh pr list".into()] },
            ProcInfo { pid: 47002, uid: 1000, comm: "grok-bot".into(), exe: format!("{store}-grok-bot/bin/grok-bot"), argv: vec!["grok-bot".into()] },
            ProcInfo { pid: 47001, uid: 1000, comm: "bwrap".into(), exe: format!("{store}-bubblewrap-0.11/bin/bwrap"), argv: vec!["bwrap".into(), "--die-with-parent".into(), "--unshare-pid".into(), "…".into()] },
            ProcInfo { pid: 46990, uid: 1000, comm: "bwrap".into(), exe: format!("{store}-bubblewrap-0.11/bin/bwrap"), argv: vec!["bwrap".into(), "…".into()] },
            ProcInfo { pid: 2210, uid: 1000, comm: "systemd".into(), exe: format!("{store}-systemd-258/lib/systemd/systemd"), argv: vec!["/run/current-system/systemd/lib/systemd/systemd".into(), "--user".into()] },
        ],
        snapshot_unix: now,
        verified: true,
        notes: Vec::new(),
    };
    let owner = Owner {
        user: "hadi".into(),
        uid: 1000,
        pid: 3317,
        command: "secret-broker unlock".into(),
        exe: format!("{store}-secret-broker-0.2.0/bin/secret-broker"),
        app: "foot (via Hyprland)".into(),
        socket: "broker.sock".into(),
        sandboxed: false,
        method: "gpg".into(),
        via: "gpg".into(),
        at_unix: now.saturating_sub(5 * 3600),
    };
    let mut opened = owner.clone();
    opened.method = "pin".into();
    opened.via = "dialog".into();
    opened.at_unix = now.saturating_sub(3600);
    opened.command = "secret-run gh pr view 12".into();
    opened.app = "grok-bot (via Hyprland)".into();
    opened.sandboxed = true;
    opened.socket = "agent.sock".into();
    secret_broker::proto::Prompt {
        kind: "request".into(),
        id: 1,
        purpose: "secret-run gh pr list --repo hadilq/secret-broker".into(),
        ttl_seconds: 8 * 3600,
        methods: vec!["pin".into(), "fido2".into()],
        hints: vec!["Touch your security key".into()],
        phrase: "blue otter".into(),
        attempts_left: 5,
        timeout_seconds: 120,
        caller: Some(caller),
        session: Some(SessionInfo {
            state: "sealed".into(),
            expires_at_unix: 0,
            unlocked: Some(owner),
            opened: Some(opened),
        }),
        ..Default::default()
    }
}

#[cfg(target_os = "linux")]
fn demo(o: &Opts, args: &[String]) -> Result<(), String> {
    let mut out = PathBuf::from("secret-broker-dialog.ppm");
    let mut scale = 1i32;
    let mut window = false;
    let mut pin_mode = false;
    let mut details = false;
    let mut reveal = false;
    let mut unfocused = false;
    let mut cursor: Option<usize> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().map(PathBuf::from).ok_or("--out FILE")?,
            "--scale" => scale = it.next().and_then(|v| v.parse().ok()).ok_or("--scale N")?,
            "--window" => window = true,
            "--pinentry" => pin_mode = true,
            "--details" => details = true,
            "--reveal" => reveal = true,
            "--unfocused" => unfocused = true,
            "--cursor" => cursor = it.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let view = if pin_mode {
        ui::View {
            title: "Unlock OpenPGP key".into(),
            body: "Please enter the passphrase to unlock the OpenPGP secret key:\n\"Hadi <hadi@example.com>\"\n255-bit EDDSA key, ID 0123456789ABCDEF".into(),
            field: Some("Passphrase".into()),
            footer: "Enter  OK      Esc  cancel".into(),
            ..Default::default()
        }
    } else {
        let mut v = prompter::view_for(&demo_prompt());
        v.message = Some(("Wrong PIN, 4 attempts left".into(), ui::Tone::Error));
        v.show_details = details;
        v
    };
    let fonts = load_fonts(o)?;
    let theme = theme::load(o.theme.as_deref());
    if window {
        let mut u = ui::Ui::open(theme, fonts, o.size())?;
        u.set_view(view);
        loop {
            match u.wait(None)? {
                ui::UiEvent::Submit(s) => {
                    println!("submitted {} chars", s.chars().count());
                    return Ok(());
                }
                ui::UiEvent::Cancel | ui::UiEvent::Closed => {
                    println!("cancelled");
                    return Ok(());
                }
                _ => {}
            }
        }
    }
    // A made-up value, only for the screenshot of the revealed field.
    let sample = if pin_mode { "correct horse battery" } else { "424242" };
    let field = ui::Field {
        len: sample.chars().count(),
        cursor: cursor.unwrap_or(usize::MAX).min(sample.chars().count()),
        plain: reveal.then_some(sample),
        focused: !unfocused,
    };
    let (w, h, rgba) = ui::Ui::render_offscreen(theme, fonts, view, field, scale, o.size());
    // PPM over the theme's dark background (alpha composited).
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    for px in rgba.chunks_exact(4) {
        if let [b, g, r, a] = px {
            let inv = 255u16.saturating_sub(u16::from(*a));
            let bg = |c: u8, base: u16| {
                let v = u16::from(c).saturating_add(base.saturating_mul(inv) / 255);
                u8::try_from(v.min(255)).unwrap_or(255)
            };
            ppm.extend_from_slice(&[bg(*r, 0x10), bg(*g, 0x10), bg(*b, 0x10)]);
        }
    }
    std::fs::write(&out, ppm).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("wrote {} ({w}x{h})", out.display());
    Ok(())
}

fn main() -> ExitCode {
    let _ = secret_broker::sys::set_non_dumpable();
    let _ = secret_broker::sys::disable_core_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, rest) = match args.first().map(String::as_str) {
        Some(m @ ("prompter" | "pinentry" | "demo")) => (m.to_string(), args.get(1..).unwrap_or(&[]).to_vec()),
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => ("prompter".to_string(), args.clone()),
    };
    let mut o = Opts::default();
    let mut passthrough = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--font" => o.font = it.next().map(PathBuf::from),
            "--font-bold" => o.font_bold = it.next().map(PathBuf::from),
            "--theme" => o.theme = it.next().map(PathBuf::from),
            "--fallback" => o.fallback = it.next().cloned(),
            "--size" => o.size = it.next().and_then(|v| v.parse().ok()),
            other => passthrough.push(other.to_string()),
        }
    }
    run(&mode, &o, &passthrough)
}

#[cfg(target_os = "linux")]
fn run(mode: &str, o: &Opts, passthrough: &[String]) -> ExitCode {
    match mode {
        "pinentry" => pinentry::run(o, passthrough),
        "demo" => match demo(o, passthrough) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("secret-broker-dialog: {e}");
                ExitCode::from(1)
            }
        },
        _ => prompter::run(o),
    }
}

/// No Wayland here: the pinentry can hand over to a native one (gpg-agent's
/// pipes are inherited by exec); the approval dialog is not available.
#[cfg(not(target_os = "linux"))]
fn run(mode: &str, o: &Opts, passthrough: &[String]) -> ExitCode {
    if mode == "pinentry" {
        if let Some(fb) = &o.fallback {
            use std::os::unix::process::CommandExt;
            let e = std::process::Command::new(fb).args(passthrough).exec();
            eprintln!("secret-broker-dialog: exec {fb}: {e}");
            return ExitCode::from(1);
        }
        eprintln!("secret-broker-dialog: the built-in pinentry needs Wayland (Linux); pass --fallback /path/to/pinentry-mac");
        return ExitCode::from(1);
    }
    eprintln!(
        "secret-broker-dialog: the {mode} dialog needs Wayland and is not supported on this OS yet; \
         run `secret-broker unlock` in a terminal to approve instead"
    );
    ExitCode::from(2)
}
