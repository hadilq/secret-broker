//! Who is calling: a snapshot of the peer process, read from /proc and
//! logind's /run/systemd files when a request arrives.
//!
//! The broker itself runs with ProtectProc=invisible and can't see your
//! processes. A small helper (`secret-broker proc-helper`, spawned at start
//! before the daemon drops every capability) keeps CAP_SYS_PTRACE only to
//! read /proc/<pid>/{exe,cwd,cmdline,stat,cgroup} of callers; it reads one
//! pid per line on stdin and answers with one JSON line. It never reads
//! environ or memory, and holds no secrets.
//!
//! macOS: there is no /proc; `collect_live` reads the same details with
//! libproc (proc_pidinfo/proc_pidpath) and sysctl(KERN_PROCARGS2), see
//! `darwin` below. No helper is needed there, but macOS only lets root (or
//! the same user) read another process's argv/cwd, so a broker running as
//! its own user gets uid/comm/parents and possibly not argv/cwd.
//!
//! Limits: a pid is only a name. The broker pins the caller with a pidfd
//! (SO_PEERPIDFD) and checks it is still alive after the snapshot
//! (`verified`), but parents are not pinned: one may exit and its pid be
//! reused (we stop the chain when a "parent" started after its child).

use crate::error::{Error, Result};
use crate::proto::{Caller, ProcInfo};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const MAX_ARG: usize = 512;
const MAX_ARGS: usize = 64;
const MAX_PARENT_ARGS: usize = 12;
const MAX_PARENT_ARG: usize = 160;
const MAX_PARENTS: usize = 16;

#[derive(Debug, Clone)]
pub struct Roots {
    pub proc: PathBuf,
    pub run: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            proc: PathBuf::from("/proc"),
            run: PathBuf::from("/run"),
        }
    }
}

fn clean(s: &str, max: usize) -> String {
    crate::server::sanitize(s, max)
}

fn pid_path(r: &Roots, pid: i32, name: &str) -> PathBuf {
    r.proc.join(pid.to_string()).join(name)
}

/// argv from /proc/<pid>/cmdline (all args, then bounded by `clip`).
fn read_argv(r: &Roots, pid: i32) -> Vec<String> {
    let Ok(raw) = std::fs::read(pid_path(r, pid, "cmdline")) else {
        return Vec::new();
    };
    let raw = raw.strip_suffix(&[0u8]).unwrap_or(&raw);
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|b| *b == 0)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect()
}

fn clip(argv: &[String], max_args: usize, max_len: usize) -> Vec<String> {
    let mut out: Vec<String> = argv
        .iter()
        .take(max_args)
        .map(|a| clean(a, max_len))
        .collect();
    if argv.len() > max_args {
        out.push(format!("… (+{} more)", argv.len().saturating_sub(max_args)));
    }
    out
}

fn readlink(r: &Roots, pid: i32, name: &str) -> String {
    std::fs::read_link(pid_path(r, pid, name))
        .map(|p| clean(&p.to_string_lossy(), MAX_ARG))
        .unwrap_or_default()
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stat {
    pub comm: String,
    pub ppid: i32,
    pub tty_nr: u64,
    pub start_time: u64,
}

/// Parse /proc/<pid>/stat ("pid (comm) S ppid pgrp session tty_nr ...").
pub fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open.checked_add(1)?..close)?;
    let rest: Vec<&str> = text.get(close.checked_add(1)?..)?.split_whitespace().collect();
    // rest[0] is field 3 (state): field n is rest[n - 3].
    Some(Stat {
        comm: clean(comm, 32),
        ppid: rest.get(1)?.parse().ok()?,
        tty_nr: rest.get(4)?.parse::<i64>().ok().and_then(|v| u64::try_from(v).ok()).unwrap_or(0),
        start_time: rest.get(19)?.parse().ok()?,
    })
}

fn stat(r: &Roots, pid: i32) -> Option<Stat> {
    parse_stat(&std::fs::read_to_string(pid_path(r, pid, "stat")).ok()?)
}

fn real_uid(r: &Roots, pid: i32) -> Option<u32> {
    let text = std::fs::read_to_string(pid_path(r, pid, "status")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

fn read_u32(r: &Roots, pid: i32, name: &str) -> Option<u32> {
    let v: u32 = std::fs::read_to_string(pid_path(r, pid, name))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (v != u32::MAX).then_some(v)
}

fn cgroup(r: &Roots, pid: i32) -> String {
    std::fs::read_to_string(pid_path(r, pid, "cgroup"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("0::"))
                .map(|v| clean(v, MAX_ARG))
        })
        .unwrap_or_default()
}

/// Undo systemd's unit-name escaping (\x2d etc.).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'\\' && b.get(i.saturating_add(1)) == Some(&b'x') {
            let hex = s.get(i.saturating_add(2)..i.saturating_add(4));
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i = i.saturating_add(4);
                continue;
            }
        }
        out.push(c);
        i = i.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// "app-Hyprland-foot-1234.scope" -> ("foot", "Hyprland") following the
/// XDG/systemd convention app[-<launcher>]-<id>[-<random>].scope /
/// app[-<launcher>]-<id>[@<random>].service.
pub fn parse_app_unit(unit: &str) -> Option<(String, String)> {
    let (base, scope) = if let Some(b) = unit.strip_suffix(".scope") {
        (b, true)
    } else {
        (unit.strip_suffix(".service")?, false)
    };
    let body = base.strip_prefix("app-")?;
    let body = body.split('@').next().unwrap_or(body);
    let mut parts: Vec<&str> = body.split('-').filter(|p| !p.is_empty()).collect();
    if scope && parts.len() >= 2 {
        parts.pop();
    }
    let (launcher, app) = match parts.as_slice() {
        [] => return None,
        [only] => ("", vec![*only]),
        [first, rest @ ..] => (*first, rest.to_vec()),
    };
    Some((unescape(&app.join("-")), unescape(launcher)))
}

/// Innermost unit of a cgroup path, and app/launcher if it's an app unit.
pub fn unit_of(cgroup: &str) -> (String, String, String) {
    let unit = cgroup
        .rsplit('/')
        .find(|c| c.ends_with(".scope") || c.ends_with(".service"))
        .unwrap_or("")
        .to_string();
    let (app, launcher) = parse_app_unit(&unit).unwrap_or_default();
    (unit, app, launcher)
}

fn session_of_cgroup(cgroup: &str) -> Option<String> {
    cgroup.split('/').find_map(|c| {
        c.strip_prefix("session-")
            .and_then(|s| s.strip_suffix(".scope"))
            .map(str::to_string)
    })
}

fn kv_file(path: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), clean(v, 128)))
                .collect()
        })
        .unwrap_or_default()
}

fn safe_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// /dev name of a tty_nr from /proc/<pid>/stat.
pub fn tty_name(nr: u64) -> String {
    if nr == 0 {
        return String::new();
    }
    let major = nr.wrapping_shr(8) & 0xfff;
    let minor = (nr & 0xff) | (nr.wrapping_shr(12) & 0xfff00);
    match major {
        136..=143 => major
            .checked_sub(136)
            .and_then(|m| m.checked_mul(256))
            .and_then(|m| m.checked_add(minor))
            .map(|n| format!("/dev/pts/{n}"))
            .unwrap_or_default(),
        4 if minor < 64 => format!("/dev/tty{minor}"),
        4 => format!("/dev/ttyS{}", minor.saturating_sub(64)),
        _ => format!("tty {major}:{minor}"),
    }
}

/// `--setenv AI_RUN_PROFILE <name>` in a bwrap command line.
fn ai_run_profile(argv: &[String]) -> Option<String> {
    argv.windows(3).find_map(|w| match w {
        [a, b, c] if a == "--setenv" && b == "AI_RUN_PROFILE" => Some(clean(c, 64)),
        _ => None,
    })
}

fn is_bwrap(comm: &str, argv: &[String]) -> bool {
    comm == "bwrap" || argv.first().is_some_and(|a| a.ends_with("/bwrap") || a == "bwrap")
}

/// Snapshot of `pid` (uid/user/socket are filled in by the broker).
pub fn collect(r: &Roots, pid: i32) -> Caller {
    let mut c = Caller {
        pid,
        snapshot_unix: crate::sys::now_unix_i64(),
        ..Default::default()
    };
    let Some(st) = stat(r, pid) else {
        c.notes
            .push("process details unreadable (process gone, or no access to /proc)".into());
        return c;
    };
    let argv = read_argv(r, pid);
    c.comm = st.comm.clone();
    c.start_time = st.start_time;
    c.exe = readlink(r, pid, "exe");
    c.cwd = readlink(r, pid, "cwd");
    c.argv = clip(&argv, MAX_ARGS, MAX_ARG);
    if c.exe.is_empty() || c.cwd.is_empty() {
        c.notes
            .push("exe/cwd unreadable (the broker's /proc helper lacks CAP_SYS_PTRACE)".into());
    }
    c.cgroup = cgroup(r, pid);
    let (unit, app, launcher) = unit_of(&c.cgroup);
    c.unit = unit;
    c.app = app;
    c.launcher = launcher;
    c.audit_session = read_u32(r, pid, "sessionid");
    c.loginuid = read_u32(r, pid, "loginuid");
    c.tty = tty_name(st.tty_nr);
    if is_bwrap(&st.comm, &argv) {
        c.ai_run_profile = ai_run_profile(&argv).unwrap_or_default();
    }

    // Parents, nearest first. A parent can't have started after its child:
    // if it did, its pid was reused and the chain is meaningless from there.
    let mut child_start = st.start_time;
    let mut cur = st.ppid;
    while cur > 0 && c.parents.len() < MAX_PARENTS {
        let Some(ps) = stat(r, cur) else { break };
        if ps.start_time > child_start {
            c.notes
                .push(format!("parent pid {cur} started after its child (pid reused); chain cut"));
            break;
        }
        let pargv = read_argv(r, cur);
        if c.ai_run_profile.is_empty() && is_bwrap(&ps.comm, &pargv) {
            c.ai_run_profile = ai_run_profile(&pargv).unwrap_or_default();
        }
        c.parents.push(ProcInfo {
            pid: cur,
            uid: real_uid(r, cur).unwrap_or(u32::MAX),
            comm: ps.comm.clone(),
            exe: readlink(r, cur, "exe"),
            argv: clip(&pargv, MAX_PARENT_ARGS, MAX_PARENT_ARG),
        });
        if cur == 1 {
            break;
        }
        child_start = ps.start_time;
        cur = ps.ppid;
    }

    // logind: the session scope we're in, else the user's display session.
    let mut sid = session_of_cgroup(&c.cgroup).unwrap_or_default();
    if sid.is_empty() {
        if let Some(uid) = real_uid(r, pid) {
            let u = kv_file(&r.run.join("systemd/users").join(uid.to_string()));
            sid = u.get("DISPLAY").cloned().unwrap_or_default();
        }
    }
    if safe_id(&sid) {
        let s = kv_file(&r.run.join("systemd/sessions").join(&sid));
        c.seat = s.get("SEAT").cloned().unwrap_or_default();
        if c.tty.is_empty() {
            c.tty = s.get("TTY").cloned().unwrap_or_default();
        }
        let ty = s.get("TYPE").cloned().unwrap_or_default();
        let class = s.get("CLASS").cloned().unwrap_or_default();
        c.session_type = match (ty.is_empty(), class.is_empty()) {
            (false, false) => format!("{ty}/{class}"),
            (false, true) => ty,
            _ => class,
        };
        c.login_session = sid;
    }
    c
}

/// Snapshot of a live process on this machine (uid/user/socket are filled
/// in by the broker).
pub fn collect_live(pid: i32) -> Caller {
    #[cfg(target_os = "linux")]
    {
        collect(&Roots::default(), pid)
    }
    #[cfg(target_os = "macos")]
    {
        darwin::collect(pid)
    }
}

/// macOS tty device number -> /dev name (major 16 = pty slaves "ttysNNN";
/// dev_t is major<<24 | minor).
pub fn darwin_tty_name(dev: u32) -> String {
    if dev == 0 || dev == u32::MAX {
        return String::new();
    }
    let major = dev.wrapping_shr(24) & 0xff;
    let minor = dev & 0x00ff_ffff;
    match major {
        16 => format!("/dev/ttys{minor:03}"),
        0 => "/dev/console".into(),
        _ => format!("tty {major}:{minor}"),
    }
}

/// "/Applications/iTerm.app/Contents/MacOS/iTerm2" -> "iTerm": the
/// outermost .app bundle in an executable path.
pub fn app_bundle(exe: &str) -> Option<String> {
    exe.split('/')
        .find_map(|c| c.strip_suffix(".app").filter(|n| !n.is_empty()))
        .map(|n| clean(n, 64))
}

/// Parse a KERN_PROCARGS2 buffer: argc (native int), the exec path,
/// NUL padding, then argc NUL-terminated args. The environment that
/// follows is never looked at.
pub fn parse_procargs(buf: &[u8]) -> Vec<String> {
    let Some((head, rest)) = buf.split_first_chunk::<4>() else {
        return Vec::new();
    };
    let argc = usize::try_from(i32::from_ne_bytes(*head)).unwrap_or(0);
    let mut parts = rest.split(|b| *b == 0);
    // exec path, then padding (empty pieces)
    let _ = parts.next();
    parts
        .skip_while(|p| p.is_empty())
        .take(argc)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect()
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::{app_bundle, clean, clip, darwin_tty_name, parse_procargs, MAX_ARG, MAX_ARGS, MAX_PARENTS, MAX_PARENT_ARG, MAX_PARENT_ARGS};
    use crate::proto::{Caller, ProcInfo};
    use std::mem::size_of;
    use zeroize::Zeroizing;

    struct Bsd {
        comm: String,
        ppid: i32,
        ruid: u32,
        tdev: u32,
        /// Start time in microseconds since the epoch.
        start: u64,
    }

    fn c_chars(v: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = v
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn bsd(pid: i32) -> Option<Bsd> {
        // SAFETY: proc_bsdinfo is a plain C struct; all-zero is valid.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: info is a writable buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if n != size {
            return None;
        }
        let name = c_chars(&info.pbi_name);
        let comm = if name.is_empty() { c_chars(&info.pbi_comm) } else { name };
        Some(Bsd {
            comm: clean(&comm, 32),
            ppid: i32::try_from(info.pbi_ppid).unwrap_or(0),
            ruid: info.pbi_ruid,
            tdev: info.e_tdev,
            start: info
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec),
        })
    }

    fn exe(pid: i32) -> String {
        let mut buf = vec![0u8; 4096];
        let len = u32::try_from(buf.len()).unwrap_or(0);
        // SAFETY: buf is writable for `len` bytes.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), len) };
        let n = usize::try_from(n).unwrap_or(0);
        buf.get(..n)
            .map(|b| clean(&String::from_utf8_lossy(b), MAX_ARG))
            .unwrap_or_default()
    }

    fn cwd(pid: i32) -> String {
        // SAFETY: proc_vnodepathinfo is a plain C struct; all-zero is valid.
        let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
        let Ok(size) = libc::c_int::try_from(size_of::<libc::proc_vnodepathinfo>()) else {
            return String::new();
        };
        // SAFETY: info is a writable buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&mut info as *mut libc::proc_vnodepathinfo).cast(),
                size,
            )
        };
        if n != size {
            return String::new();
        }
        let flat: Vec<libc::c_char> = info.pvi_cdir.vip_path.iter().flatten().copied().collect();
        clean(&c_chars(&flat), MAX_ARG)
    }

    fn argmax() -> usize {
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let mut v: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>();
        // SAFETY: mib/v/len are valid locals of the sizes passed.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&mut v as *mut libc::c_int).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return 1 << 20;
        }
        usize::try_from(v).unwrap_or(1 << 20).clamp(4096, 4 << 20)
    }

    fn argv(pid: i32) -> Vec<String> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        // Holds the process's environment too (possibly secrets): zeroized
        // on drop.
        let mut buf = Zeroizing::new(vec![0u8; argmax()]);
        let mut len = buf.len();
        // SAFETY: mib is 3 ints; buf is writable for `len` bytes.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return Vec::new();
        }
        buf.get(..len).map(parse_procargs).unwrap_or_default()
    }

    pub fn collect(pid: i32) -> Caller {
        let mut c = Caller {
            pid,
            snapshot_unix: crate::sys::now_unix_i64(),
            ..Default::default()
        };
        let Some(st) = bsd(pid) else {
            c.notes.push(
                "process details unreadable (process gone, or another user's process: macOS only shows those to root)"
                    .into(),
            );
            return c;
        };
        let args = argv(pid);
        c.comm = st.comm.clone();
        c.start_time = st.start;
        c.exe = exe(pid);
        c.cwd = cwd(pid);
        c.argv = clip(&args, MAX_ARGS, MAX_ARG);
        if c.exe.is_empty() || c.cwd.is_empty() || args.is_empty() {
            c.notes
                .push("exe/cwd/argv partly unreadable (macOS: another user's process)".into());
        }
        c.tty = darwin_tty_name(st.tdev);

        let mut child_start = st.start;
        let mut cur = st.ppid;
        while cur > 0 && c.parents.len() < MAX_PARENTS {
            let Some(ps) = bsd(cur) else { break };
            if ps.start > child_start {
                c.notes
                    .push(format!("parent pid {cur} started after its child (pid reused); chain cut"));
                break;
            }
            let pexe = exe(cur);
            c.parents.push(ProcInfo {
                pid: cur,
                uid: ps.ruid,
                comm: ps.comm.clone(),
                exe: pexe,
                argv: clip(&argv(cur), MAX_PARENT_ARGS, MAX_PARENT_ARG),
            });
            if cur == 1 {
                break;
            }
            child_start = ps.start;
            cur = ps.ppid;
        }
        // No systemd units on macOS: name the app by the nearest .app bundle
        // (the terminal or IDE the command runs in).
        if let Some(app) = std::iter::once(c.exe.as_str())
            .chain(c.parents.iter().map(|p| p.exe.as_str()))
            .find_map(app_bundle)
        {
            c.app = app;
        }
        c
    }
}

/// The broker's end of the /proc helper.
pub struct Helper {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Helper {
    pub fn spawn(exe: &Path) -> Result<Helper> {
        let mut child = Command::new(exe)
            .arg("proc-helper")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| Error::msg(format!("spawn proc-helper: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::msg("proc-helper stdin"))?;
        let out = child
            .stdout
            .take()
            .ok_or_else(|| Error::msg("proc-helper stdout"))?;
        Ok(Helper {
            child,
            stdin,
            out: BufReader::new(out),
        })
    }

    pub fn query(&mut self, pid: i32) -> Option<Caller> {
        writeln!(self.stdin, "{pid}").ok()?;
        self.stdin.flush().ok()?;
        let mut line = String::new();
        let n = self.out.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        serde_json::from_str(&line).ok()
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `secret-broker proc-helper`: answer pid lines with Caller JSON lines.
pub fn helper_main() -> Result<()> {
    let _ = crate::sys::set_non_dumpable();
    // Inherited from the daemon (systemd's listening sockets): not ours.
    crate::sys::close_from(3);
    let roots = Roots::default();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let pid: i32 = line.trim().parse().unwrap_or(0);
        let c = if pid > 0 {
            collect(&roots, pid)
        } else {
            Caller::default()
        };
        let mut b = serde_json::to_vec(&c)?;
        b.push(b'\n');
        out.write_all(&b)?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing() {
        let s = "1234 (my (odd) prog) S 1000 1234 1234 34817 1234 4194560 1 0 0 0 0 0 0 0 20 0 1 0 98765 1000 100";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.comm, "my (odd) prog");
        assert_eq!(st.ppid, 1000);
        assert_eq!(st.tty_nr, 34817);
        assert_eq!(st.start_time, 98765);
        assert!(parse_stat("garbage").is_none());
    }

    #[test]
    fn ttys() {
        assert_eq!(tty_name(34817), "/dev/pts/1"); // 136:1
        assert_eq!(tty_name((4 << 8) | 2), "/dev/tty2");
        assert_eq!(tty_name(0), "");
    }

    #[test]
    fn app_units() {
        assert_eq!(
            parse_app_unit("app-Hyprland-foot-1234.scope"),
            Some(("foot".into(), "Hyprland".into()))
        );
        assert_eq!(
            parse_app_unit("app-Hyprland-org.gnome.Nautilus@ab12.service"),
            Some(("org.gnome.Nautilus".into(), "Hyprland".into()))
        );
        assert_eq!(
            parse_app_unit("app-grok\\x2dbot-5.scope"),
            Some(("grok-bot".into(), "".into()))
        );
        assert_eq!(parse_app_unit("session-2.scope"), None);
        let (u, a, l) = unit_of("/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-foot-99.scope");
        assert_eq!((u.as_str(), a.as_str(), l.as_str()), ("app-Hyprland-foot-99.scope", "foot", "Hyprland"));
        assert_eq!(session_of_cgroup("/user.slice/user-1000.slice/session-3.scope"), Some("3".into()));
    }

    #[test]
    fn bwrap_profile() {
        let a: Vec<String> = ["bwrap", "--die-with-parent", "--setenv", "AI_RUN_PROFILE", "grok-bot", "--", "sh"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(ai_run_profile(&a), Some("grok-bot".into()));
        assert!(is_bwrap("bwrap", &a));
    }

    #[test]
    fn darwin_helpers() {
        assert_eq!(darwin_tty_name((16 << 24) | 3), "/dev/ttys003");
        assert_eq!(darwin_tty_name(0), "");
        assert_eq!(darwin_tty_name(u32::MAX), "");
        assert_eq!(app_bundle("/Applications/iTerm.app/Contents/MacOS/iTerm2"), Some("iTerm".into()));
        assert_eq!(
            app_bundle("/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper"),
            Some("Visual Studio Code".into())
        );
        assert_eq!(app_bundle("/nix/store/x-zsh/bin/zsh"), None);
    }

    #[test]
    fn procargs_parsing() {
        let mut b = 3i32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/bin/secret-run\0\0\0\0secret-run\0gh\0pr list\0HOME=/Users/h\0TOKEN=s3cret\0");
        assert_eq!(parse_procargs(&b), vec!["secret-run", "gh", "pr list"]);
        assert!(parse_procargs(&[1, 0]).is_empty());
    }

    #[test]
    fn own_process_live() {
        let me = i32::try_from(std::process::id()).unwrap();
        let c = collect_live(me);
        assert!(c.start_time > 0, "{:?}", c.notes);
        assert!(!c.comm.is_empty());
        assert!(!c.argv.is_empty(), "{:?}", c.notes);
        assert!(!c.exe.is_empty(), "{:?}", c.notes);
        assert!(!c.cwd.is_empty(), "{:?}", c.notes);
        assert!(!c.parents.is_empty());
        assert!(!collect_live(i32::MAX).notes.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_process() {
        let me = i32::try_from(std::process::id()).unwrap();
        let c = collect(&Roots::default(), me);
        assert!(c.start_time > 0);
        assert!(!c.argv.is_empty());
        assert!(!c.exe.is_empty(), "{:?}", c.notes);
        assert!(!c.cwd.is_empty());
        assert!(!c.parents.is_empty());
        let gone = collect(&Roots::default(), i32::MAX);
        assert!(!gone.notes.is_empty());
    }

    #[test]
    fn fake_proc_tree() {
        let d = std::env::temp_dir().join(format!("sb-caller-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mk = |pid: i32, stat: &str, cmd: &[u8], cg: &str| {
            let p = d.join("proc").join(pid.to_string());
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("stat"), stat).unwrap();
            std::fs::write(p.join("cmdline"), cmd).unwrap();
            std::fs::write(p.join("cgroup"), format!("0::{cg}\n")).unwrap();
            std::fs::write(p.join("status"), "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n").unwrap();
            std::fs::write(p.join("sessionid"), "4294967295").unwrap();
        };
        let cg = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-foot-7.scope";
        mk(30, "30 (secret-run) S 20 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 300 0 0", b"secret-run\0gh\0pr\0list\0", cg);
        mk(20, "20 (bwrap) S 10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 200 0 0", b"/nix/store/x-bubblewrap/bin/bwrap\0--setenv\0AI_RUN_PROFILE\0grok-bot\0--\0zsh\0", cg);
        // pid 10 was reused: it started after pid 20
        mk(10, "10 (zsh) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 900 0 0", b"zsh\0", cg);
        let users = d.join("run/systemd/users");
        std::fs::create_dir_all(&users).unwrap();
        std::fs::write(users.join("1000"), "NAME=hadi\nDISPLAY=2\n").unwrap();
        let sessions = d.join("run/systemd/sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("2"), "SEAT=seat0\nTTY=tty1\nTYPE=wayland\nCLASS=user\n").unwrap();
        let r = Roots {
            proc: d.join("proc"),
            run: d.join("run"),
        };
        let c = collect(&r, 30);
        assert_eq!(c.argv, vec!["secret-run", "gh", "pr", "list"]);
        assert_eq!(c.command(), "secret-run gh pr list");
        assert_eq!(c.app_label(), "foot (via Hyprland)");
        assert_eq!(c.ai_run_profile, "grok-bot");
        assert_eq!(c.parents.len(), 1);
        assert!(c.notes.iter().any(|n| n.contains("pid reused")), "{:?}", c.notes);
        assert_eq!(c.login_session, "2");
        assert_eq!(c.seat, "seat0");
        assert_eq!(c.tty, "tty1");
        assert_eq!(c.session_type, "wayland/user");
        assert_eq!(c.audit_session, None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
