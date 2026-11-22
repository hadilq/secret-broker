//! `secret-broker` / `secret-run` command line.

use secret_broker::{client, config, proto::Status, server, sys, Error, Result};
use std::process::ExitCode;

mod pam;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage:
  secret-broker status [--json]          show lock state, expiry and profiles (never values)
  secret-broker unlock [--ttl 8h] [--gpg] [--keep-gpg-cache]
                                         open a session. First time after boot (or after
                                         `lock --forget`): gpg/pinentry. When sealed: PIN,
                                         security key or fingerprint (--gpg forces gpg)
  secret-broker lock [--forget]          seal the session now (--forget: wipe secrets from
                                         memory; the next unlock needs gpg)
  secret-broker set-pin [--remove]       set (or remove) the quick-approval PIN; asks gpg once
  secret-broker fido2-enroll [--device /dev/hidrawN] [--name yubikey] [--rp secret-broker]
                                         create a security-key credential, print the NixOS snippet
  secret-broker log [-f] [--since 2h|2026-11-22] [--event unlock,exec*] [-n N] [--json]
                                         show the audit log (who locked/unlocked/ran what)
  secret-broker log verify [--journal]   check the log's hash chain (and against journald)
  secret-broker log head                 print the latest entry's hash (write it down)
  secret-broker run <profile> [args...]  run an allowlisted command (same as secret-run)
  secret-run [--stdin|--no-stdin] <profile> [args...]
  secret-broker daemon --config FILE [--socket PATH] [--agent-socket PATH]   (system service)
  secret-broker version
";

fn fail(code: u8, e: impl std::fmt::Display) -> ExitCode {
    eprintln!("secret-broker: {e}");
    ExitCode::from(code)
}

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().collect();
    let argv0 = if args.is_empty() {
        String::new()
    } else {
        args.remove(0)
    };
    let invoked_as = std::path::Path::new(&argv0)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if invoked_as == "secret-run" {
        return run_cmd(&args);
    }
    let Some((cmd, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    match cmd.as_str() {
        "daemon" => match daemon(rest) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(1, e),
        },
        "status" => status_cmd(rest),
        "unlock" => unlock_cmd(rest),
        "lock" => {
            let forget = rest.iter().any(|a| a == "--forget");
            if let Some(bad) = rest.iter().find(|a| *a != "--forget") {
                return fail(2, format!("unknown option {bad}"));
            }
            match client::lock(forget) {
                Ok(()) => {
                    println!("{}", if forget { "forgotten (next unlock needs gpg)" } else { "locked" });
                    ExitCode::SUCCESS
                }
                Err(e) => fail(1, e),
            }
        }
        "set-pin" => set_pin_cmd(rest),
        "fido2-enroll" => fido2_enroll_cmd(rest),
        "proc-helper" => match secret_broker::caller::helper_main() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(1, e),
        },
        "log" => match secret_broker::audit::cli(rest) {
            Ok(code) => ExitCode::from(code),
            Err(e) => fail(1, e),
        },
        "pam-check" => match rest {
            [service, user] => match pam::check(service, user) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(1, e),
            },
            _ => fail(2, "usage: secret-broker pam-check SERVICE USER"),
        },
        "run" => run_cmd(rest),
        "version" | "--version" => {
            println!("secret-broker {VERSION}");
            ExitCode::SUCCESS
        }
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// "8h", "30m", "90s", "1h30m", "3600" (seconds).
fn parse_duration(s: &str) -> Result<u64> {
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }
    let mut total: u64 = 0;
    let mut num: u64 = 0;
    let mut have = false;
    let overflow = || Error::msg(format!("duration too large: {s}"));
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            num = num
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(d)))
                .ok_or_else(overflow)?;
            have = true;
            continue;
        }
        let mult: u64 = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => {
                return Err(Error::msg(format!(
                    "invalid duration {s:?} (use e.g. 8h, 30m, 1h30m)"
                )))
            }
        };
        if !have {
            return Err(Error::msg(format!("invalid duration {s:?}")));
        }
        total = num
            .checked_mul(mult)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(overflow)?;
        num = 0;
        have = false;
    }
    if have || total == 0 {
        return Err(Error::msg(format!(
            "invalid duration {s:?} (use e.g. 8h, 30m, 1h30m)"
        )));
    }
    Ok(total)
}

fn fmt_secs(s: u64) -> String {
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{sec:02}s")
    } else {
        format!("{sec}s")
    }
}

fn status_cmd(args: &[String]) -> ExitCode {
    let json = args.iter().any(|a| a == "--json");
    let st = match client::status() {
        Ok(s) => s,
        Err(e) => return fail(1, e),
    };
    let gpg = client::gpg_cache_problem(&st);
    if json {
        return match serde_json::to_string_pretty(&st) {
            Ok(s) => {
                println!("{s}");
                if let Err(e) = gpg {
                    eprintln!("WARNING: {e}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(1, e),
        };
    }
    print_status(&st);
    if let Err(e) = gpg {
        println!("\nWARNING: unlock will be refused: {e}");
    }
    ExitCode::SUCCESS
}

fn print_status(st: &Status) {
    match st.state.as_str() {
        "open" => println!(
            "state:    unlocked, {} values, expires {} (in {})",
            st.secret_count,
            sys::local_time(st.expires_at_unix),
            fmt_secs(st.remaining_seconds)
        ),
        "sealed" => println!(
            "state:    sealed ({} values in memory; quick approval opens it)",
            st.secret_count
        ),
        _ => println!("state:    locked (not in memory; unlock needs gpg)"),
    }
    if st.methods.is_empty() {
        println!("approval: gpg only (no quick method configured)");
    } else {
        println!(
            "approval: {}{}",
            st.methods.join(", "),
            if st.prompter { "; dialog connected" } else { "; no dialog connected" }
        );
    }
    if let Some(s) = &st.session {
        let who = |o: &secret_broker::proto::Owner| {
            format!(
                "{} ({}) by {} pid {} `{}`{}{}",
                sys::local_time(o.at_unix),
                o.method,
                o.user,
                o.pid,
                server::sanitize(&o.command, 80),
                if o.app.is_empty() { String::new() } else { format!(" in {}", o.app) },
                if o.sandboxed { " [sandbox]" } else { "" }
            )
        };
        if let Some(o) = &s.unlocked {
            println!("owner:    {}", who(o));
        }
        if let Some(o) = &s.opened {
            if s.unlocked.as_ref().map(|u| u.at_unix) != Some(o.at_unix) {
                println!("reopened: {}", who(o));
            }
        }
    }
    if st.pin_locked_out {
        println!("PIN:      locked out after too many attempts (unlock with gpg)");
    }
    if st.restricted {
        println!("socket:   restricted (inside ai-run): cannot unlock or approve from here");
    }
    println!("secrets:  {}", st.secrets_file);
    println!(
        "ttl:      default {}, max {}",
        fmt_secs(st.default_ttl_seconds),
        fmt_secs(st.max_ttl_seconds)
    );
    println!(
        "gpg cache limits: default-cache-ttl <= {}s, max-cache-ttl <= {}s",
        st.gpg_cache_limits.default_cache_ttl, st.gpg_cache_limits.max_cache_ttl
    );
    println!("profiles:");
    for p in &st.profiles {
        println!("  {:<12} {} {}", p.name, p.command, p.fixed_args.join(" "));
        if !p.description.is_empty() {
            println!("               {}", p.description);
        }
        println!("               env: {}", p.env_vars.join(", "));
        for a in &p.allow {
            println!("               allow: {}", a.join(" "));
        }
        for d in &p.deny {
            println!("               deny:  {}", d.join(" "));
        }
        if !p.unresolved.is_empty() {
            println!(
                "               MISSING in secrets file: {}",
                p.unresolved.join(", ")
            );
        }
    }
}

fn unlock_cmd(args: &[String]) -> ExitCode {
    let mut ttl = None;
    let mut keep = false;
    let mut gpg = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gpg" => gpg = true,
            "--ttl" => match it.next().map(|v| parse_duration(v)) {
                Some(Ok(v)) => ttl = Some(v),
                Some(Err(e)) => return fail(2, e),
                None => return fail(2, "--ttl needs a value"),
            },
            "--keep-gpg-cache" => keep = true,
            other => match other.strip_prefix("--ttl=") {
                Some(v) => match parse_duration(v) {
                    Ok(v) => ttl = Some(v),
                    Err(e) => return fail(2, e),
                },
                None => return fail(2, format!("unknown option {other}")),
            },
        }
    }
    match client::unlock(&client::UnlockOptions {
        ttl_seconds: ttl,
        keep_gpg_cache: keep,
        gpg,
    }) {
        Ok(st) => {
            println!(
                "unlocked until {} ({} values)",
                sys::local_time(st.expires_at_unix),
                st.secret_count
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(1, e),
    }
}

fn set_pin_cmd(args: &[String]) -> ExitCode {
    let mut remove = false;
    let mut ttl = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--remove" => remove = true,
            "--ttl" => match it.next().map(|v| parse_duration(v)) {
                Some(Ok(v)) => ttl = Some(v),
                Some(Err(e)) => return fail(2, e),
                None => return fail(2, "--ttl needs a value"),
            },
            other => return fail(2, format!("unknown option {other}")),
        }
    }
    match client::set_pin(remove, ttl) {
        Ok(()) => {
            println!(
                "{}",
                if remove {
                    "PIN removed (session unlocked)"
                } else {
                    "PIN set (session unlocked). A sealed session now opens with this PIN."
                }
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(1, e),
    }
}

fn fido2_enroll_cmd(args: &[String]) -> ExitCode {
    let (mut device, mut name, mut rp) = (None, "yubikey".to_string(), "secret-broker".to_string());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = match a.as_str() {
            "--device" | "--name" | "--rp" => match it.next() {
                Some(v) => v.clone(),
                None => return fail(2, format!("{a} needs a value")),
            },
            other => return fail(2, format!("unknown option {other}")),
        };
        match a.as_str() {
            "--device" => device = Some(v),
            "--name" => name = v,
            _ => rp = v,
        }
    }
    match client::fido2_enroll(device.as_deref(), &name, &rp) {
        Ok(snippet) => {
            println!("Add this to your NixOS config (public data only), then rebuild:\n");
            print!("{snippet}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(1, e),
    }
}

fn run_cmd(args: &[String]) -> ExitCode {
    let (mut force, mut none) = (false, false);
    let mut rest = args;
    while let Some((first, tail)) = rest.split_first() {
        match first.as_str() {
            "--stdin" => force = true,
            "--no-stdin" => none = true,
            "--" => break,
            s if s.starts_with("--") => {
                return fail(
                    2,
                    format!("unknown option {s} (options go before the profile)"),
                )
            }
            _ => break,
        }
        rest = tail;
    }
    let Some((profile, mut cmd_args)) = rest.split_first() else {
        eprintln!("usage: secret-run [--stdin|--no-stdin] <profile> [args...]");
        return ExitCode::from(2);
    };
    if let Some((first, tail)) = cmd_args.split_first() {
        if first == "--" {
            cmd_args = tail;
        }
    }
    match client::run(profile, cmd_args, force, none) {
        Ok(code) => exit_code(code),
        Err(e) => {
            eprintln!("secret-run: {e}");
            let refused = e.to_string().starts_with("locked")
                || e.to_string().contains("allow rule")
                || e.to_string().contains("deny rule")
                || e.to_string().contains("unknown profile");
            ExitCode::from(if refused { 126 } else { 125 })
        }
    }
}

fn daemon(args: &[String]) -> Result<()> {
    let mut cfg_path = None;
    let mut sock = None;
    let mut agent_sock = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => cfg_path = it.next().cloned(),
            "--socket" => sock = it.next().cloned(),
            "--agent-socket" => agent_sock = it.next().cloned(),
            other => return Err(Error::msg(format!("unknown option {other}"))),
        }
    }
    let cfg_path = cfg_path.ok_or_else(|| Error::msg("--config is required"))?;
    // The unit may grant CAP_SYS_PTRACE (ambient) for the /proc helper only:
    // start it first, then drop every capability before any thread exists,
    // so neither the broker nor the commands it runs keep it.
    let caps_before = sys::effective_caps().unwrap_or(0);
    let procs = match std::env::current_exe()
        .map_err(Error::from)
        .and_then(|exe| secret_broker::caller::Helper::spawn(&exe))
    {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("warning: no /proc helper ({e}); caller details will be partial");
            None
        }
    };
    sys::drop_all_caps()?;
    if sys::effective_caps().unwrap_or(0) != 0 {
        return Err(Error::msg("capabilities still present after dropping them"));
    }
    if let Err(e) = sys::set_non_dumpable() {
        eprintln!("warning: {e}");
    }
    if let Err(e) = sys::disable_core_dumps() {
        eprintln!("warning: {e}");
    }
    let cfg = config::load(&cfg_path)?;
    let secrets_file = cfg.secrets_file.clone();
    let srv = server::Server::new(cfg, procs)?;
    let (listener, agent) = server::listeners(sock.as_deref(), agent_sock.as_deref())?;
    install_signal_handler(std::sync::Arc::clone(&srv))?;
    eprintln!(
        "secret-broker {VERSION}: {} profiles, secrets file {secrets_file}{}",
        srv.profile_count(),
        if agent.is_some() { ", restricted socket for sandboxes" } else { "" }
    );
    srv.audit(
        secret_broker::audit::Event::new("broker_start", "ok")
            .field("version", VERSION)
            .field("profiles", srv.profile_count())
            .field("restricted_socket", agent.is_some())
            .field("proc_helper_caps", format!("{caps_before:x}")),
    );
    if let Some(agent) = agent {
        let srv = std::sync::Arc::clone(&srv);
        std::thread::spawn(move || srv.serve(agent, true));
    }
    srv.serve(listener, false)
}

/// SIGTERM/SIGINT/SIGHUP: wipe secrets, then exit (via a self-pipe thread, so
/// nothing non-async-signal-safe runs in the handler).
fn install_signal_handler(srv: std::sync::Arc<server::Server>) -> Result<()> {
    use std::sync::atomic::{AtomicI32, Ordering};
    static PIPE_W: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn on_signal(_sig: libc::c_int) {
        let fd = PIPE_W.load(Ordering::Relaxed);
        if fd >= 0 {
            let b = [1u8];
            // SAFETY: write(2) is async-signal-safe; b is a valid 1-byte buffer.
            unsafe {
                libc::write(fd, b.as_ptr().cast(), 1);
            }
        }
    }

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is a valid 2-element array for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::msg(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    let [r, w] = fds;
    PIPE_W.store(w, Ordering::Relaxed);
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: on_signal only performs an async-signal-safe write(2).
        unsafe {
            libc::signal(
                sig,
                on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
            );
        }
    }
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        // SAFETY: r is the read end of our pipe; b is a valid buffer.
        unsafe {
            libc::read(r, b.as_mut_ptr().cast(), 1);
        }
        srv.wipe("signal");
        // SAFETY: _exit terminates immediately; secrets were wiped above.
        unsafe { libc::_exit(0) }
    });
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("8h").unwrap(), 28800);
        assert_eq!(parse_duration("1h30m").unwrap(), 5400);
        assert_eq!(parse_duration("3s").unwrap(), 3);
        assert_eq!(parse_duration("120").unwrap(), 120);
        for bad in ["", "h", "8x", "8h3", "99999999999999999999h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
