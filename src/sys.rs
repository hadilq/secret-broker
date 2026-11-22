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
