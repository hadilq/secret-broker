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
#[cfg(target_os = "linux")]
pub fn set_non_dumpable() -> Result<()> {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers.
    let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if r != 0 {
        return Err(last_os_error("prctl(PR_SET_DUMPABLE)"));
    }
    Ok(())
}

/// macOS: ptrace(PT_DENY_ATTACH), so debuggers can't attach. Weaker than
/// Linux: it does not stop task_for_pid (root, or a debugger the user
/// authorizes), so on macOS the real boundary is the broker's separate user.
/// No-op if this process is already being traced (PT_DENY_ATTACH would make
/// it exit).
#[cfg(target_os = "macos")]
pub fn set_non_dumpable() -> Result<()> {
    // SAFETY: PT_DENY_ATTACH takes no address/data; it only flags this process.
    let r = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if r != 0 {
        return Err(last_os_error("ptrace(PT_DENY_ATTACH)"));
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

/// SO_PEERCRED of a connected unix socket (the peer's credentials when it
/// connected, from the kernel).
#[cfg(target_os = "linux")]
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

/// macOS: getpeereid(3) (effective uid/gid at connect time, from the kernel)
/// plus LOCAL_PEERPID.
#[cfg(target_os = "macos")]
pub fn peer_cred(fd: RawFd) -> Result<PeerCred> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: uid/gid point to writable locals.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(last_os_error("getpeereid"));
    }
    let mut pid: libc::pid_t = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>())
        .map_err(|_| Error::msg("pid_t size"))?;
    // SAFETY: pid/len point to properly sized, writable locals.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(last_os_error("getsockopt(LOCAL_PEERPID)"));
    }
    Ok(PeerCred { pid, uid, gid })
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
#[cfg(target_os = "linux")]
pub fn umask(mask: u32) -> u32 {
    // SAFETY: umask never fails.
    unsafe { libc::umask(mask) }
}

/// Set the umask, returning the previous one (mode_t is 16-bit on macOS).
#[cfg(target_os = "macos")]
pub fn umask(mask: u32) -> u32 {
    let m = libc::mode_t::try_from(mask & 0o777).unwrap_or(0o077);
    // SAFETY: umask never fails.
    u32::from(unsafe { libc::umask(m) })
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
#[cfg(target_os = "linux")]
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

/// macOS has no pipe2: pipe(2), then FD_CLOEXEC on both ends. (A fork in
/// another thread between the two calls could inherit them; the broker
/// spawns commands with std, which closes nothing extra, so keep pipes
/// created before or outside concurrent spawns where it matters.)
#[cfg(target_os = "macos")]
pub fn pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: fds is a valid 2-element array.
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if r != 0 {
        return Err(last_os_error("pipe"));
    }
    let [rd, wr] = fds;
    // SAFETY: pipe succeeded, so both are fresh descriptors we now own.
    let (rd, wr) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(rd),
            std::os::fd::OwnedFd::from_raw_fd(wr),
        )
    };
    set_cloexec(rd.as_raw_fd())?;
    set_cloexec(wr.as_raw_fd())?;
    Ok((rd, wr))
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
#[cfg(target_os = "linux")]
pub fn close_from(from: u32) {
    // SAFETY: close_range takes integers only; we own no fds >= from that
    // are still in use at this point.
    unsafe {
        libc::syscall(libc::SYS_close_range, from, u32::MAX, 0);
    }
}

/// Close every fd >= `from` (macOS has no close_range: walk up to the
/// descriptor table size, capped).
#[cfg(target_os = "macos")]
pub fn close_from(from: u32) {
    // SAFETY: getdtablesize takes no arguments.
    let max = unsafe { libc::getdtablesize() }.clamp(0, 65_536);
    let mut fd = libc::c_int::try_from(from).unwrap_or(libc::c_int::MAX);
    while fd < max {
        // SAFETY: closing an integer descriptor; unused ones just fail (EBADF).
        unsafe {
            libc::close(fd);
        }
        fd = fd.saturating_add(1);
    }
}

/// Whether a pid exists in our pid namespace.
pub fn pid_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 only checks for existence/permission.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Fill `buf` from the kernel CSPRNG (getrandom(2), blocking until seeded).
#[cfg(target_os = "linux")]
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

/// Fill `buf` from the kernel CSPRNG (getentropy(2), at most 256 bytes a call).
#[cfg(target_os = "macos")]
pub fn random(buf: &mut [u8]) -> Result<()> {
    for chunk in buf.chunks_mut(256) {
        // SAFETY: `chunk` is a valid writable buffer of chunk.len() <= 256 bytes.
        let r = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        if r != 0 {
            return Err(last_os_error("getentropy"));
        }
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
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: libc::c_int = 77;

/// Pins the process that connected, so we can tell afterwards whether the
/// pid we read details for still is that process.
/// - Linux: a pidfd from SO_PEERPIDFD (6.5+), which never refers to a
///   reused pid.
/// - macOS: the process's 64-bit unique id (never reused until reboot) read
///   right after accept; a pid reused between connect and accept is not
///   caught (narrow: the peer must exit and its pid be reused in between).
pub struct PeerPin {
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
    #[cfg(target_os = "macos")]
    pid: i32,
    #[cfg(target_os = "macos")]
    uniqueid: u64,
}

/// Why `peer_pin` may give None here (shown as a note on the caller).
#[cfg(target_os = "linux")]
pub const NO_PEER_PIN: &str = "no SO_PEERPIDFD (kernel < 6.5): details are best effort";
#[cfg(target_os = "macos")]
pub const NO_PEER_PIN: &str = "the caller's unique id was unreadable: details are best effort";

#[cfg(target_os = "linux")]
pub fn peer_pin(fd: RawFd, _pid: i32) -> Option<PeerPin> {
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
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) };
    // Don't leak it into a command another thread is starting.
    let _ = set_cloexec(pidfd);
    Some(PeerPin { pidfd: owned })
}

#[cfg(target_os = "macos")]
pub fn peer_pin(_fd: RawFd, pid: i32) -> Option<PeerPin> {
    Some(PeerPin {
        pid,
        uniqueid: proc_uniqueid(pid)?,
    })
}

impl PeerPin {
    /// Whether the pinned process still runs (so details read by pid were
    /// that process's).
    #[cfg(target_os = "linux")]
    pub fn alive(&self) -> bool {
        use std::os::fd::AsRawFd;
        // SAFETY: pidfd_send_signal(fd, 0, NULL, 0) only checks the target.
        let r = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(target_os = "macos")]
    pub fn alive(&self) -> bool {
        proc_uniqueid(self.pid) == Some(self.uniqueid)
    }
}

/// struct proc_uniqidentifierinfo starts with p_uuid[16] and p_uniqueid;
/// the rest (parent id, pid version, reserved words) varies across SDKs, so
/// the buffer is generously sized and only the stable prefix is read.
#[cfg(target_os = "macos")]
#[repr(C)]
struct UniqIdInfo {
    uuid: [u8; 16],
    uniqueid: u64,
    rest: [u64; 12],
}

/// PROC_PIDUNIQIDENTIFIERINFO (libproc): a per-boot unique process id.
#[cfg(target_os = "macos")]
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

/// The 64-bit unique id of a live process (macOS; never reused until reboot).
#[cfg(target_os = "macos")]
pub fn proc_uniqueid(pid: i32) -> Option<u64> {
    let mut info = UniqIdInfo {
        uuid: [0; 16],
        uniqueid: 0,
        rest: [0; 12],
    };
    let size = libc::c_int::try_from(std::mem::size_of::<UniqIdInfo>()).ok()?;
    // SAFETY: info is a writable buffer of `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&mut info as *mut UniqIdInfo).cast(),
            size,
        )
    };
    // The kernel writes at least uuid + uniqueid (24 bytes) on success.
    (n >= 24 && info.uniqueid != 0).then_some(info.uniqueid)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drop every capability of this thread (call before spawning threads):
/// clear the ambient set, then empty effective/permitted/inheritable.
#[cfg(target_os = "linux")]
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

/// macOS has no capabilities: nothing to drop.
#[cfg(target_os = "macos")]
pub fn drop_all_caps() -> Result<()> {
    Ok(())
}

/// Effective capability mask of this process (from /proc/self/status).
#[cfg(target_os = "linux")]
pub fn effective_caps() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/self/status").ok()?;
    let v = t.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    u64::from_str_radix(v.trim(), 16).ok()
}

#[cfg(target_os = "macos")]
pub fn effective_caps() -> Option<u64> {
    Some(0)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn peer_cred_of_socketpair_is_us() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        for s in [&a, &b] {
            let c = peer_cred(s.as_raw_fd()).unwrap();
            assert_eq!(u32::try_from(c.pid).unwrap(), getpid());
            assert_eq!(c.uid, getuid());
            // SAFETY: getgid never fails.
            assert_eq!(c.gid, unsafe { libc::getgid() });
        }
    }

    #[test]
    fn peer_cred_fails_on_non_socket() {
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(peer_cred(f.as_raw_fd()).is_err());
    }

    #[test]
    fn peer_pin_tracks_liveness() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = i32::try_from(getpid()).unwrap();
        // Linux < 6.5 has no SO_PEERPIDFD; everywhere else this must work.
        match peer_pin(a.as_raw_fd(), me) {
            Some(pin) => assert!(pin.alive()),
            #[cfg(target_os = "linux")]
            None => eprintln!("skip: {NO_PEER_PIN}"),
            #[cfg(not(target_os = "linux"))]
            None => panic!("{NO_PEER_PIN}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn uniqueid_changes_with_the_process() {
        let me = i32::try_from(getpid()).unwrap();
        let id = proc_uniqueid(me).unwrap();
        assert_eq!(proc_uniqueid(me), Some(id));
        let mut child = std::process::Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let cpid = i32::try_from(child.id()).unwrap();
        let cid = proc_uniqueid(cpid).unwrap();
        assert_ne!(cid, id);
        let pin = PeerPin { pid: cpid, uniqueid: cid };
        assert!(pin.alive());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!pin.alive());
    }

    #[test]
    fn random_fills() {
        let mut a = [0u8; 600];
        let mut b = [0u8; 600];
        random(&mut a).unwrap();
        random(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(a.iter().skip(300).any(|x| *x != 0));
    }

    #[test]
    fn pipe_is_cloexec() {
        let (r, w) = pipe().unwrap();
        for fd in [r.as_raw_fd(), w.as_raw_fd()] {
            // SAFETY: fcntl on fds we own.
            let fl = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(fl & libc::FD_CLOEXEC != 0);
        }
    }
}
