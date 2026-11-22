//! Thin, checked wrappers around the few libc calls we need.

use crate::bail;
use crate::error::{Error, Result};
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

fn last_os_error(what: &str) -> Error {
    Error::msg(format!("{what}: {}", std::io::Error::last_os_error()))
}

/// Mark the process non-dumpable: no core dumps, and other processes of the
/// same uid can no longer ptrace it or open /proc/<pid>/{mem,environ}.
pub fn set_non_dumpable() -> Result<()> {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers.
    let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if r != 0 {
        return Err(last_os_error("prctl(PR_SET_DUMPABLE)"));
    }
    Ok(())
}

/// RLIMIT_CORE = 0.
pub fn disable_core_dumps() -> Result<()> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid rlimit for the duration of the call.
    let r = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if r != 0 {
        return Err(last_os_error("setrlimit(RLIMIT_CORE)"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// SO_PEERCRED of a connected unix socket.
pub fn peer_cred(fd: RawFd) -> Result<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| Error::msg("ucred size"))?;
    // SAFETY: cred/len point to properly sized, writable locals.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(last_os_error("getsockopt(SO_PEERCRED)"));
    }
    Ok(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Resolve a user name to its uid (NSS, like `id -u name`).
pub fn uid_of(name: &str) -> Result<u32> {
    let cname = CString::new(name).map_err(|_| Error::msg("user name contains NUL"))?;
    let mut pwd: libc::passwd = {
        // SAFETY: passwd is a plain C struct; all-zero is a valid (empty) value.
        unsafe { std::mem::zeroed() }
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; buf outlives the call and
    // `pwd` only borrows from it while we read pw_uid below.
    let r = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if r != 0 {
        bail!(
            "getpwnam_r({name}): {}",
            std::io::Error::from_raw_os_error(r)
        );
    }
    if result.is_null() {
        bail!("no such user: {name}");
    }
    Ok(pwd.pw_uid)
}

pub fn getuid() -> u32 {
    // SAFETY: getuid never fails.
    unsafe { libc::getuid() }
}

pub fn getpid() -> u32 {
    std::process::id()
}

pub fn isatty(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// Set the umask, returning the previous one.
pub fn umask(mask: u32) -> u32 {
    // SAFETY: umask never fails.
    unsafe { libc::umask(mask) }
}

/// SIGKILL a whole process group (best effort).
pub fn kill_group(pgid: u32) {
    if let Ok(p) = i32::try_from(pgid) {
        if p > 0 {
            if let Some(neg) = p.checked_neg() {
                // SAFETY: kill takes no pointers; a stale pgid just fails.
                unsafe {
                    libc::kill(neg, libc::SIGKILL);
                }
            }
        }
    }
}

pub fn page_size() -> usize {
    // SAFETY: sysconf takes no pointers.
    let r = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(r).ok().filter(|p| *p > 0).unwrap_or(4096)
}

/// Format a unix timestamp in local time, e.g. "2026-11-22 06:54:00 EST".
pub fn local_time(unix: i64) -> String {
    let t: libc::time_t = unix;
    let mut tm: libc::tm = {
        // SAFETY: tm is a plain C struct; all-zero is valid.
        unsafe { std::mem::zeroed() }
    };
    // SAFETY: both pointers are valid locals.
    let r = unsafe { libc::localtime_r(&t, &mut tm) };
    if r.is_null() {
        return format!("@{unix}");
    }
    let zone = if tm.tm_zone.is_null() {
        String::new()
    } else {
        // SAFETY: tm_zone points to a static NUL-terminated string set by libc.
        unsafe { CStr::from_ptr(tm.tm_zone) }
            .to_string_lossy()
            .into_owned()
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}",
        tm.tm_year.saturating_add(1900),
        tm.tm_mon.saturating_add(1),
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        zone
    )
}

/// Home directory of a uid from the passwd database (not $HOME, which the
/// caller controls).
pub fn home_of(uid: u32) -> Result<std::path::PathBuf> {
    let mut pwd: libc::passwd = {
        // SAFETY: passwd is a plain C struct; all-zero is a valid (empty) value.
        unsafe { std::mem::zeroed() }
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; buf outlives the call and
    // `pwd` only borrows from it while we copy pw_dir below.
    let r = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if r != 0 {
        bail!(
            "getpwuid_r({uid}): {}",
            std::io::Error::from_raw_os_error(r)
        );
    }
    if result.is_null() || pwd.pw_dir.is_null() {
        bail!("no passwd entry for uid {uid}");
    }
    // SAFETY: pw_dir points into `buf`, NUL-terminated by libc.
    let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
    use std::os::unix::ffi::OsStrExt;
    Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        dir.to_bytes(),
    )))
}

/// pipe2(O_CLOEXEC): (read end, write end).
pub fn pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: fds is a valid 2-element array.
    let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if r != 0 {
        return Err(last_os_error("pipe2"));
    }
    let [rd, wr] = fds;
    // SAFETY: pipe2 succeeded, so both are fresh descriptors we now own.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(rd),
            std::os::fd::OwnedFd::from_raw_fd(wr),
        )
    })
}

/// Clear FD_CLOEXEC so `fd` survives exec. Async-signal-safe (used in pre_exec).
pub fn clear_cloexec(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl on an integer descriptor takes no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let r = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set FD_CLOEXEC so `fd` doesn't leak into commands we start.
pub fn set_cloexec(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl on an fd we own; no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let r = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Close every fd >= `from` (close_range(2)).
pub fn close_from(from: u32) {
    // SAFETY: close_range takes integers only; we own no fds >= from that
    // are still in use at this point.
    unsafe {
        libc::syscall(libc::SYS_close_range, from, u32::MAX, 0);
    }
}

/// Whether a pid exists in our pid namespace.
pub fn pid_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 only checks for existence/permission.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Fill `buf` from the kernel CSPRNG (getrandom(2), blocking until seeded).
pub fn random(buf: &mut [u8]) -> Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        let rest = buf.get_mut(off..).unwrap_or(&mut []);
        // SAFETY: `rest` is a valid writable buffer of rest.len() bytes.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::from(e).context("getrandom"));
        }
        off = off.saturating_add(usize::try_from(n).unwrap_or(0));
    }
    Ok(())
}

/// Login name of a uid from the passwd database.
pub fn name_of(uid: u32) -> Result<String> {
    let mut pwd: libc::passwd = {
        // SAFETY: passwd is a plain C struct; all-zero is a valid (empty) value.
        unsafe { std::mem::zeroed() }
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; buf outlives the call.
    let r = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if r != 0 || result.is_null() || pwd.pw_name.is_null() {
        bail!("no passwd entry for uid {uid}");
    }
    // SAFETY: pw_name points into `buf`, NUL-terminated by libc.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) };
    Ok(name.to_string_lossy().into_owned())
}

/// Restores the terminal mode saved by [`no_echo`] when dropped.
pub struct EchoGuard {
    fd: RawFd,
    saved: libc::termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: fd is the terminal we read the settings from; saved is valid.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
    }
}

/// Turn off echo on terminal `fd` (keeps canonical line editing).
pub fn no_echo(fd: RawFd) -> Result<EchoGuard> {
    let mut t: libc::termios = {
        // SAFETY: termios is a plain C struct; zeroed is a valid value to fill.
        unsafe { std::mem::zeroed() }
    };
    // SAFETY: t is a valid termios out-pointer.
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(last_os_error("tcgetattr"));
    }
    let saved = t;
    t.c_lflag &= !(libc::ECHO | libc::ECHONL);
    t.c_lflag |= libc::ICANON;
    // SAFETY: as above.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &t) } != 0 {
        return Err(last_os_error("tcsetattr"));
    }
    Ok(EchoGuard { fd, saved })
}

pub fn now_unix_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Linux 6.5+: a pidfd for the peer of a unix socket.
const SO_PEERPIDFD: libc::c_int = 77;

/// A pidfd pinning the process that connected (None on older kernels).
pub fn peer_pidfd(fd: RawFd) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let mut pidfd: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: pidfd/len point to properly sized, writable locals.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut pidfd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if r != 0 || pidfd < 0 {
        return None;
    }
    // SAFETY: the kernel just gave us this new fd; we own it.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) };
    // Don't leak it into a command another thread is starting.
    let _ = set_cloexec(pidfd);
    Some(fd)
}

/// Whether the process behind a pidfd still runs (a pidfd never refers to a
/// reused pid).
pub fn pidfd_alive(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: pidfd_send_signal(fd, 0, NULL, 0) only checks the target.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drop every capability of this thread (call before spawning threads):
/// clear the ambient set, then empty effective/permitted/inheritable.
pub fn drop_all_caps() -> Result<()> {
    // SAFETY: prctl with integer arguments only.
    let r = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if r != 0 {
        return Err(last_os_error("prctl(PR_CAP_AMBIENT_CLEAR_ALL)"));
    }
    let mut hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: hdr and data are valid capset arguments for version 3 (two
    // CapData entries) and live across the call.
    let r = unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) };
    if r != 0 {
        return Err(last_os_error("capset"));
    }
    Ok(())
}

/// Effective capability mask of this process (from /proc/self/status).
pub fn effective_caps() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/self/status").ok()?;
    let v = t.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    u64::from_str_radix(v.trim(), 16).ok()
}

/// RFC 3339 UTC with milliseconds, e.g. "2026-11-22T16:54:03.123Z".
pub fn utc_time_ms(unix_ms: u64) -> String {
    let secs = unix_ms.checked_div(1000).unwrap_or(0);
    let ms = unix_ms.checked_rem(1000).unwrap_or(0);
    let t: libc::time_t = i64::try_from(secs).unwrap_or(0);
    let mut tm: libc::tm = {
        // SAFETY: tm is a plain C struct; all-zero is valid.
        unsafe { std::mem::zeroed() }
    };
    // SAFETY: both pointers are valid locals.
    let r = unsafe { libc::gmtime_r(&t, &mut tm) };
    if r.is_null() {
        return format!("@{secs}");
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        tm.tm_year.saturating_add(1900),
        tm.tm_mon.saturating_add(1),
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    )
}

/// Local wall-clock time -> unix seconds (mktime).
pub fn local_to_unix(year: i32, month: i32, day: i32, hour: i32, min: i32, sec: i32) -> Option<i64> {
    let mut tm: libc::tm = {
        // SAFETY: tm is a plain C struct; all-zero is valid.
        unsafe { std::mem::zeroed() }
    };
    tm.tm_year = year.checked_sub(1900)?;
    tm.tm_mon = month.checked_sub(1)?;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    tm.tm_isdst = -1;
    // SAFETY: tm is a valid, initialised struct.
    let t = unsafe { libc::mktime(&mut tm) };
    (t != -1).then_some(t)
}
