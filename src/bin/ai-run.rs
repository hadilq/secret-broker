//! `ai-run`: run an AI agent (or anything) in a bubblewrap sandbox.
//! See `secret_broker::sandbox` for what the sandbox contains.

use secret_broker::sandbox::{self, Config, Ctx, RealFs};
use secret_broker::{bail, sys, Error, Result};
use std::io::Read;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const USAGE: &str =
    "usage: ai-run --config FILE [--profile NAME] [--print] [--] [COMMAND [ARGS...]]
       ai-run --config FILE --list
Runs COMMAND (default: $SHELL) in a bubblewrap sandbox: credential paths
masked, $HOME read-only except the configured writable paths, no session
bus/gpg-agent/keyring/compositor IPC, own pid namespace. The secret-broker
socket stays reachable, so `secret-run` works inside.
The Home Manager module installs `ai-run` with --config already set.
";

struct Opts {
    config: Option<String>,
    profile: String,
    print: bool,
    list: bool,
    cmd: Vec<String>,
}

fn parse(args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        config: None,
        profile: "default".into(),
        print: false,
        list: false,
        cmd: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => o.config = it.next().cloned(),
            "--profile" | "-p" => match it.next() {
                Some(p) => o.profile = p.clone(),
                None => bail!("--profile needs a value"),
            },
            "--print" => o.print = true,
            "--list" => o.list = true,
            "-h" | "--help" => bail!("{USAGE}"),
            "--" => {
                o.cmd.extend(it.by_ref().cloned());
            }
            x if x.starts_with("--config=") => {
                o.config = x.strip_prefix("--config=").map(String::from)
            }
            x if x.starts_with("--profile=") => {
                o.profile = x.strip_prefix("--profile=").unwrap_or_default().to_string();
            }
            x if x.starts_with('-') && o.cmd.is_empty() => bail!("unknown option {x}\n{USAGE}"),
            _ => {
                o.cmd.push(a.clone());
                o.cmd.extend(it.by_ref().cloned());
            }
        }
    }
    Ok(o)
}

fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:,+@%".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

fn mkdirs(dirs: &[PathBuf]) -> Result<()> {
    for d in dirs {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(d)
            .map_err(|e| Error::msg(format!("mkdir {}: {e}", d.display())))?;
    }
    Ok(())
}

/// Remove proxy-<pid> directories of sandboxes that are gone.
fn clean_stale(profile_dir: &Path) {
    let Ok(rd) = std::fs::read_dir(profile_dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(pid) = name
            .strip_prefix("proxy-")
            .and_then(|p| p.parse::<i32>().ok())
        {
            if !sys::pid_alive(pid) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    let o = parse(args)?;
    let Some(cfg_path) = o.config else {
        bail!("no --config given\n{USAGE}");
    };
    let cfg = Config::parse(
        &std::fs::read(&cfg_path).map_err(|e| Error::msg(format!("{cfg_path}: {e}")))?,
    )
    .map_err(|e| e.context(&cfg_path))?;
    if o.list {
        for (n, p) in &cfg.profiles {
            println!("{n}\t{}", p.description);
        }
        return Ok(ExitCode::SUCCESS);
    }
    let env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let uid = sys::getuid();
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .or_else(|| Some(PathBuf::from(format!("/run/user/{uid}"))).filter(|p| p.is_dir()));
    let legacy_tiocsti = std::fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti")
        .map(|s| s.trim() != "0")
        .unwrap_or(true);
    let ctx = Ctx {
        home: sys::home_of(uid)?,
        runtime_dir,
        env,
        legacy_tiocsti,
    };
    let mut plan = sandbox::plan(&cfg, &o.profile, &ctx, &RealFs)?;
    // Lets wrappers inside the sandbox (e.g. Grok Bot's $SHELL) nest a
    // stricter profile from the same config.
    let abs_cfg = std::fs::canonicalize(&cfg_path).unwrap_or_else(|_| PathBuf::from(&cfg_path));
    plan.env.retain(|(k, _)| k != "AI_RUN_CONFIG");
    plan.env.push((
        "AI_RUN_CONFIG".into(),
        abs_cfg.to_string_lossy().into_owned(),
    ));
    let mut cmd = o.cmd;
    if cmd.is_empty() {
        cmd.push(std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));
    }

    if o.print {
        let mut line = vec![quote(&cfg.bwrap)];
        line.extend(plan.args.iter().map(|a| quote(a)));
        line.push("--".into());
        line.extend(cmd.iter().map(|a| quote(a)));
        println!("{}", line.join(" "));
        if let Some((d, sock)) = &plan.proxy {
            println!(
                "# dbus proxy on {}: {}",
                sock.display(),
                d.proxy_args().join(" ")
            );
        }
        for (k, _) in &plan.env {
            println!("# env {k}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    mkdirs(&plan.create_dirs)?;
    let mut bwrap_args = plan.args.clone();
    // The proxy's sync pipe must outlive this scope: its read end is handed
    // to bwrap (--sync-fd) and the proxy exits when bwrap does.
    if let Some((dbus, sock)) = &plan.proxy {
        let Some(proxy) = &cfg.dbus_proxy else {
            bail!("dbus_proxy not configured");
        };
        let Some(bus) = ctx
            .env
            .iter()
            .find(|(k, _)| k == "DBUS_SESSION_BUS_ADDRESS")
            .map(|(_, v)| v.clone())
        else {
            bail!(
                "profile {:?} wants D-Bus but DBUS_SESSION_BUS_ADDRESS is not set",
                o.profile
            );
        };
        if let Some(dir) = sock.parent().and_then(Path::parent) {
            clean_stale(dir);
        }
        let (rd, wr) = sys::pipe()?;
        let wfd = wr.as_raw_fd();
        let mut pc = Command::new(proxy);
        pc.arg(&bus)
            .arg(sock)
            .args(dbus.proxy_args())
            .arg(format!("--fd={wfd}"))
            .stdin(Stdio::null());
        // SAFETY: the closure only calls fcntl, which is async-signal-safe.
        unsafe {
            pc.pre_exec(move || sys::clear_cloexec(wfd));
        }
        let mut child = pc
            .spawn()
            .map_err(|e| Error::msg(format!("starting {proxy}: {e}")))?;
        drop(wr);
        let mut rdf = std::fs::File::from(rd);
        let mut b = [0u8; 1];
        let n = rdf
            .read(&mut b)
            .map_err(|e| Error::msg(format!("dbus proxy: {e}")))?;
        if n != 1 {
            let _ = child.kill();
            bail!("xdg-dbus-proxy failed to start");
        }
        let fd = rdf.into_raw_fd();
        sys::clear_cloexec(fd)?;
        bwrap_args.extend(["--sync-fd".into(), fd.to_string()]);
    }

    let err = Command::new(&cfg.bwrap)
        .args(&bwrap_args)
        .arg("--")
        .args(&cmd)
        .env_clear()
        .envs(plan.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .exec();
    bail!("exec {}: {err}", cfg.bwrap)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // bubblewrap is Linux-only. Refuse rather than run the agent unsandboxed;
    // a macOS backend (sandbox-exec / Seatbelt profile) is not written yet.
    if !cfg!(target_os = "linux") && !args
            .iter()
            .take_while(|a| *a != "--")
            .any(|a| a == "--print" || a == "--list") {
        eprintln!("ai-run: not supported on this OS yet (needs bubblewrap; a macOS sandbox-exec backend is planned). Refusing to run unsandboxed.");
        return ExitCode::from(125);
    }
    match run(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ai-run: {e}");
            ExitCode::from(125)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn args() {
        let o = parse(&v(&[
            "--config",
            "/c",
            "-p",
            "grok",
            "grok",
            "--permission-mode",
            "x",
        ]))
        .unwrap();
        assert_eq!(o.config.as_deref(), Some("/c"));
        assert_eq!(o.profile, "grok");
        assert_eq!(o.cmd, v(&["grok", "--permission-mode", "x"]));
        let o = parse(&v(&["--config=/c", "--", "--weird", "a"])).unwrap();
        assert_eq!(o.cmd, v(&["--weird", "a"]));
        assert!(parse(&v(&["--bogus"])).is_err());
        assert!(parse(&v(&["--profile"])).is_err());
        assert_eq!(quote("a b'c"), r"'a b'\''c'");
        assert_eq!(quote("/x/y"), "/x/y");
    }
}
