//! Thin, checked wrappers around the few libc calls we need.

use crate::bail;
use crate::error::{Error, Result};
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use zeroize::Zeroizing;

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

/// Resolve a user name to uid and primary gid.
pub fn ids_of(name: &str) -> Result<(u32, u32)> {
    let cname = CString::new(name).map_err(|_| Error::msg("user name contains NUL"))?;
    let mut pwd: libc::passwd = {
        // SAFETY: passwd is a plain C struct; all-zero is a valid (empty) value.
        unsafe { std::mem::zeroed() }
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: same as uid_of.
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
    Ok((pwd.pw_uid, pwd.pw_gid))
}

pub fn chown(path: &std::path::Path, uid: u32, gid: u32) -> Result<()> {
    let c =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::msg("path contains NUL"))?;
    // SAFETY: c is a valid C string for the duration of the call.
    let r = unsafe { libc::chown(c.as_ptr(), uid, gid) };
    if r != 0 {
        return Err(last_os_error(&format!("chown {}", path.display())));
    }
    Ok(())
}

pub fn chmod(path: &std::path::Path, mode: u32) -> Result<()> {
    let c =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::msg("path contains NUL"))?;
    // SAFETY: c is a valid C string for the duration of the call.
    let r = unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
    if r != 0 {
        return Err(last_os_error(&format!("chmod {}", path.display())));
    }
    Ok(())
}

pub fn close_fd(fd: i32) {
    // SAFETY: closing an integer descriptor; EBADF is ignored.
    unsafe {
        libc::close(fd);
    }
}

const MAX_FDS: usize = 8;

/// Protocol cap for a helper frame. A `SOCK_SEQPACKET` send still cannot
/// exceed `SO_SNDBUF` (about 208 KiB by default; we raise it toward this).
/// Darwin `socketpair` has no `SOCK_SEQPACKET`; we fall back to `SOCK_STREAM`
/// with a 4-byte length prefix so messages still do not coalesce.
pub const HELPER_MAX_FRAME: usize = 1 << 20;

fn interrupted(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Interrupted || err.raw_os_error() == Some(libc::EINTR)
}

fn set_sock_buf(fd: RawFd, bytes: usize) {
    let max = usize::try_from(libc::c_int::MAX).unwrap_or(bytes);
    let v = libc::c_int::try_from(bytes.min(max)).unwrap_or(libc::c_int::MAX);
    let len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(0);
    // SAFETY: v is a c_int that lives across both calls.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::from_ref(&v).cast(),
            len,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::from_ref(&v).cast(),
            len,
        );
    }
}

/// Bytes a `SOCK_SEQPACKET` `sendmsg` can carry on `fd` (`SO_SNDBUF` minus
/// the unix skb overhead the kernel applies).
pub fn seqpacket_payload_limit(fd: RawFd) -> Result<usize> {
    let mut v: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .map_err(|_| Error::msg("socklen"))?;
    // SAFETY: v/len are writable locals of the right size.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::from_mut(&mut v).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(last_os_error("getsockopt(SO_SNDBUF)"));
    }
    let n = usize::try_from(v).unwrap_or(0);
    Ok(n.saturating_sub(32))
}

pub fn frame_too_large(got: usize, limit: usize) -> Error {
    Error::msg(format!(
        "SOCK_SEQPACKET message is {got} bytes; SO_SNDBUF allows {limit} bytes (kernel default is about 208 KiB). Shrink the secret environment or raise net.core.wmem_max"
    ))
}

fn socketpair_unix(ty: libc::c_int) -> std::io::Result<[RawFd; 2]> {
    let mut fds = [-1, -1];
    // SAFETY: fds is a valid 2-int array for socketpair.
    let r = unsafe { libc::socketpair(libc::AF_UNIX, ty, 0, fds.as_mut_ptr()) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fds)
}

fn sock_type(fd: RawFd) -> Option<libc::c_int> {
    let mut ty: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: ty/len are writable locals of the right size.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::from_mut(&mut ty).cast(),
            &mut len,
        )
    };
    (r == 0).then_some(ty)
}

fn is_seqpacket(fd: RawFd) -> bool {
    sock_type(fd) == Some(libc::SOCK_SEQPACKET)
}

/// Connected unix pair. Prefers `SOCK_SEQPACKET` (one sendmsg is one recvmsg).
/// Darwin `socketpair` rejects SEQPACKET (`EPROTONOSUPPORT`); we use STREAM
/// there and length-prefix in [`send_fds`] / [`recv_fds`].
pub fn seqpacket_pair() -> Result<(
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
)> {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    let seq_ty = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let seq_ty = libc::SOCK_SEQPACKET;
    let fds = match socketpair_unix(seq_ty) {
        Ok(fds) => fds,
        Err(err)
            if err.raw_os_error() == Some(libc::EPROTONOSUPPORT)
                || err.raw_os_error() == Some(libc::EPROTOTYPE) =>
        {
            #[cfg(target_os = "linux")]
            let stream_ty = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
            #[cfg(target_os = "macos")]
            let stream_ty = libc::SOCK_STREAM;
            socketpair_unix(stream_ty)
                .map_err(|e| Error::msg(format!("socketpair(STREAM): {e}")))?
        }
        Err(err) => {
            return Err(Error::msg(format!("socketpair(SEQPACKET): {err}")));
        }
    };
    let [a, b] = fds;
    #[cfg(target_os = "macos")]
    {
        set_cloexec(a)?;
        set_cloexec(b)?;
    }
    set_sock_buf(a, HELPER_MAX_FRAME);
    set_sock_buf(b, HELPER_MAX_FRAME);
    // SAFETY: socketpair succeeded; we own both descriptors.
    Ok(unsafe { (UnixStream::from_raw_fd(a), UnixStream::from_raw_fd(b)) })
}

fn sendmsg_once(sock: RawFd, payload: &[u8], fds: &[RawFd]) -> Result<usize> {
    let fd_bytes = std::mem::size_of::<RawFd>().saturating_mul(fds.len());
    loop {
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: payload.len(),
        };
        // SAFETY: CMSG_* macros only do size arithmetic; sendmsg on a socket we own
        // with iov pointing at `payload` and cbuf holding the SCM_RIGHTS header.
        let n = unsafe {
            let cap = usize::try_from(libc::CMSG_SPACE(fd_bytes as libc::c_uint)).unwrap_or(0);
            let mut cbuf = vec![0u8; cap.max(1)];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = std::ptr::from_mut(&mut iov);
            msg.msg_iovlen = 1 as _;
            if !fds.is_empty() {
                msg.msg_control = cbuf.as_mut_ptr().cast();
                msg.msg_controllen = cbuf.len() as _;
                let hdr = libc::CMSG_FIRSTHDR(&msg);
                if hdr.is_null() {
                    return Err(Error::msg("sendmsg: CMSG_FIRSTHDR"));
                }
                (*hdr).cmsg_level = libc::SOL_SOCKET;
                (*hdr).cmsg_type = libc::SCM_RIGHTS;
                (*hdr).cmsg_len = libc::CMSG_LEN(fd_bytes as libc::c_uint) as _;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(hdr).cast(), fds.len());
            }
            libc::sendmsg(sock, &msg, 0)
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if interrupted(&err) {
                continue;
            }
            if err.raw_os_error() == Some(libc::EMSGSIZE) {
                let limit = seqpacket_payload_limit(sock).unwrap_or(0);
                return Err(frame_too_large(payload.len(), limit));
            }
            return Err(last_os_error("sendmsg"));
        }
        return Ok(usize::try_from(n).unwrap_or(0));
    }
}

/// Send `payload` and `fds` (SCM_RIGHTS). A `u32be` length prefix keeps STREAM
/// sockets from coalescing two helper frames into one `recv`.
pub fn send_fds(sock: RawFd, payload: &[u8], fds: &[RawFd]) -> Result<()> {
    if fds.len() > MAX_FDS {
        bail!("too many fds");
    }
    if payload.len() > HELPER_MAX_FRAME {
        return Err(frame_too_large(
            payload.len(),
            seqpacket_payload_limit(sock).unwrap_or(HELPER_MAX_FRAME),
        ));
    }
    let plen = u32::try_from(payload.len()).map_err(|_| Error::msg("payload too large"))?;
    let mut framed = Zeroizing::new(Vec::new());
    framed.extend_from_slice(&plen.to_be_bytes());
    framed.extend_from_slice(payload);
    if is_seqpacket(sock) {
        if let Ok(limit) = seqpacket_payload_limit(sock) {
            if framed.len() > limit {
                return Err(frame_too_large(payload.len(), limit));
            }
        }
        let n = sendmsg_once(sock, &framed, fds)?;
        if n != framed.len() {
            return Err(last_os_error("sendmsg"));
        }
        return Ok(());
    }
    let mut off = 0usize;
    let mut first = true;
    while off < framed.len() {
        let rest = framed.get(off..).unwrap_or(&[]);
        let pass = if first { fds } else { &[][..] };
        let n = sendmsg_once(sock, rest, pass)?;
        if n == 0 {
            return Err(Error::msg("sendmsg: eof"));
        }
        first = false;
        off = off.saturating_add(n);
    }
    Ok(())
}

fn poll_in(fd: RawFd) -> Result<libc::c_short> {
    loop {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: p is a single pollfd we own.
        let r = unsafe { libc::poll(&mut p, 1, -1) };
        if r < 0 {
            let err = std::io::Error::last_os_error();
            if interrupted(&err) {
                continue;
            }
            return Err(last_os_error("poll"));
        }
        if r == 0 {
            continue;
        }
        return Ok(p.revents);
    }
}

fn fionread(fd: RawFd) -> Option<usize> {
    let mut n: libc::c_int = 0;
    // SAFETY: n is a writable c_int.
    let r = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) };
    if r != 0 || n < 0 {
        return None;
    }
    usize::try_from(n).ok()
}

struct Recvd {
    n: usize,
    fds: Vec<RawFd>,
    flags: libc::c_int,
}

fn recvmsg_into(sock: RawFd, buf: &mut [u8]) -> Result<Recvd> {
    if buf.is_empty() {
        return Ok(Recvd {
            n: 0,
            fds: Vec::new(),
            flags: 0,
        });
    }
    let fd_bytes = std::mem::size_of::<RawFd>().saturating_mul(MAX_FDS);
    loop {
        let mut fds = Vec::new();
        let flags: libc::c_int;
        // SAFETY: recvmsg into `buf`/`cbuf` we own; CMSG_* walk the kernel's
        // control message; copied fds are new descriptors we take ownership of.
        let n = unsafe {
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let cap = usize::try_from(libc::CMSG_SPACE(fd_bytes as libc::c_uint)).unwrap_or(1);
            let mut cbuf = vec![0u8; cap.max(1)];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = std::ptr::from_mut(&mut iov);
            msg.msg_iovlen = 1 as _;
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = cbuf.len() as _;
            let n = libc::recvmsg(sock, &mut msg, 0);
            flags = msg.msg_flags;
            if n >= 0 {
                let mut hdr = libc::CMSG_FIRSTHDR(&msg);
                while !hdr.is_null() {
                    if (*hdr).cmsg_level == libc::SOL_SOCKET && (*hdr).cmsg_type == libc::SCM_RIGHTS
                    {
                        let data = libc::CMSG_DATA(hdr);
                        // cmsg_len is size_t on Linux and socklen_t (u32) on Darwin.
                        let header = libc::CMSG_LEN(0) as u64;
                        let clen = (*hdr).cmsg_len as u64;
                        let bytes = usize::try_from(clen.saturating_sub(header)).unwrap_or(0);
                        let fd_sz = std::mem::size_of::<RawFd>();
                        let count = bytes.checked_div(fd_sz).unwrap_or(0).min(MAX_FDS);
                        for i in 0..count {
                            let mut fd: RawFd = -1;
                            std::ptr::copy_nonoverlapping(
                                data.add(i.saturating_mul(fd_sz)),
                                std::ptr::from_mut(&mut fd).cast(),
                                fd_sz,
                            );
                            if fd >= 0 {
                                fds.push(fd);
                            }
                        }
                    }
                    hdr = libc::CMSG_NXTHDR(&msg, hdr);
                }
            }
            n
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if interrupted(&err) {
                continue;
            }
            return Err(last_os_error("recvmsg"));
        }
        return Ok(Recvd {
            n: usize::try_from(n).unwrap_or(0),
            fds,
            flags,
        });
    }
}

fn recv_exact(sock: RawFd, buf: &mut [u8], fds: &mut Vec<RawFd>) -> Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        let rest = buf.get_mut(off..).unwrap_or(&mut []);
        let got = recvmsg_into(sock, rest)?;
        if got.n == 0 {
            return Err(Error::msg("recvmsg: eof"));
        }
        fds.extend(got.fds);
        off = off.saturating_add(got.n);
    }
    Ok(())
}

fn split_frame(buf: &[u8], max_payload: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hdr = buf
        .get(..4)
        .ok_or_else(|| Error::msg("truncated helper frame"))?;
    let arr: [u8; 4] = hdr
        .try_into()
        .map_err(|_| Error::msg("truncated helper frame"))?;
    let n = usize::try_from(u32::from_be_bytes(arr)).unwrap_or(0);
    if n > max_payload {
        bail!("helper frame is {n} bytes; max is {max_payload}. Shrink the secret environment");
    }
    let body = buf
        .get(4..4usize.saturating_add(n))
        .ok_or_else(|| Error::msg("truncated helper frame"))?;
    Ok(Zeroizing::new(body.to_vec()))
}

/// Receive one `send_fds` message. `max_payload` caps the body after the
/// length prefix. STREAM sockets read exactly that many bytes so a later
/// frame is not consumed.
pub fn recv_fds(sock: RawFd, max_payload: usize) -> Result<(Zeroizing<Vec<u8>>, Vec<RawFd>)> {
    if is_seqpacket(sock) {
        let revents = poll_in(sock)?;
        if revents & libc::POLLIN == 0 && revents & libc::POLLHUP != 0 {
            return Err(Error::msg("recvmsg: eof"));
        }
        let cap = max_payload.saturating_add(4);
        let avail = fionread(sock);
        let hint = match avail {
            Some(n) if n > 0 => n.min(cap.max(1)),
            _ => cap.max(1),
        };
        let mut buf = Zeroizing::new(vec![0u8; hint]);
        let got = recvmsg_into(sock, &mut buf)?;
        if got.n == 0 {
            return Err(Error::msg("recvmsg: eof"));
        }
        if got.flags & libc::MSG_TRUNC != 0 {
            for fd in &got.fds {
                close_fd(*fd);
            }
            return Err(Error::msg(format!(
                "SOCK_SEQPACKET message larger than {} bytes; shrink the secret environment",
                buf.len()
            )));
        }
        buf.truncate(got.n);
        let payload = split_frame(&buf, max_payload)?;
        Ok((payload, got.fds))
    } else {
        let mut fds = Vec::new();
        let mut hdr = [0u8; 4];
        recv_exact(sock, &mut hdr, &mut fds)?;
        let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(0);
        if n > max_payload {
            for fd in &fds {
                close_fd(*fd);
            }
            bail!("helper frame is {n} bytes; max is {max_payload}. Shrink the secret environment");
        }
        let mut payload = Zeroizing::new(vec![0u8; n]);
        if n > 0 {
            recv_exact(sock, &mut payload, &mut fds)?;
        }
        Ok((payload, fds))
    }
}

pub fn getuid() -> u32 {
    // SAFETY: getuid never fails.
    unsafe { libc::getuid() }
}

pub fn getgid() -> u32 {
    // SAFETY: getgid never fails.
    unsafe { libc::getgid() }
}

pub fn chdir(path: &std::ffi::CStr) -> std::io::Result<()> {
    // SAFETY: path is a valid C string.
    if unsafe { libc::chdir(path.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Drop supplementary groups and set real/effective/saved uid and gid to the
/// profile user. Always a full setuid (`ruid = euid = suid = uid`): leaving
/// ruid as the helper (`agent-secrets`) would keep dumpable=0 after exec of a
/// static binary, but the child could then `seteuid` back to `agent-secrets`.
/// Interpreters (bash) also reset euid to ruid when they differ.
///
/// Static binaries ignore `LD_PRELOAD`, so dumpable is reset by execve; the
/// remaining boundary is the dedicated `sb-*` uid and `ProtectProc=invisible`.
/// The parent then needs `CAP_KILL` to signal the child.
pub fn apply_profile_creds(uid: u32, gid: u32) -> std::io::Result<()> {
    // SAFETY: setgroups(0) clears the list.
    let sg = unsafe { libc::setgroups(0, std::ptr::null()) };
    if sg != 0 {
        let err = std::io::Error::last_os_error();
        let already = getuid() == uid && getgid() == gid;
        if !(already && err.raw_os_error() == Some(libc::EPERM)) {
            return Err(err);
        }
    }
    // SAFETY: integer ids; caller has CAP_SETUID/CAP_SETGID, or already is uid/gid.
    let r = unsafe { apply_ids(uid, gid) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn apply_ids(uid: u32, gid: u32) -> i32 {
    // SAFETY: integer ids; caller still has CAP_SETUID/CAP_SETGID.
    if unsafe { libc::setresgid(gid, gid, gid) != 0 || libc::setresuid(uid, uid, uid) != 0 } {
        -1
    } else {
        0
    }
}

#[cfg(target_os = "macos")]
unsafe fn apply_ids(uid: u32, gid: u32) -> i32 {
    // SAFETY: integer ids. Darwin has no setresuid; privileged setuid sets
    // real, effective, and saved.
    unsafe {
        if libc::setgid(gid) != 0 {
            return -1;
        }
        if libc::setuid(uid) != 0 {
            -1
        } else {
            0
        }
    }
}

/// NUL-terminated copies of secret env pairs for [`setenv_c`] in `pre_exec`.
/// Using this instead of `Command::env` avoids extra unwiped copies inside std.
pub type SecretEnvC = Vec<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>;

pub fn secret_env_c(secrets: &[(String, Zeroizing<Vec<u8>>)]) -> std::io::Result<SecretEnvC> {
    let mut o = Vec::new();
    for (k, v) in secrets {
        o.push((c_env_bytes(k.as_bytes())?, c_env_bytes(v.as_slice())?));
    }
    Ok(o)
}

fn c_env_bytes(bytes: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
    if bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "environment value contains NUL",
        ));
    }
    let mut v = Zeroizing::new(Vec::new());
    v.extend_from_slice(bytes);
    v.push(0);
    Ok(v)
}

/// `setenv` from NUL-terminated buffers. Used in `pre_exec` so secret values
/// never go through `Command::env`.
pub fn setenv_c(key: &[u8], val: &[u8]) -> std::io::Result<()> {
    if key.last() != Some(&0) || val.last() != Some(&0) || key.len() <= 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setenv: need a non-empty NUL-terminated key and value",
        ));
    }
    // SAFETY: both pointers are NUL-terminated; setenv copies them.
    let r = unsafe { libc::setenv(key.as_ptr().cast(), val.as_ptr().cast(), 1) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn install_secret_env(pairs: &SecretEnvC) -> std::io::Result<()> {
    for (k, v) in pairs {
        setenv_c(k, v)?;
    }
    Ok(())
}

pub fn str_env_c(pairs: &[(String, String)]) -> std::io::Result<Vec<(CString, CString)>> {
    let mut o = Vec::new();
    for (k, v) in pairs {
        let kc = CString::new(k.as_str()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "env key contains NUL")
        })?;
        let vc = CString::new(v.as_str()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "env value contains NUL")
        })?;
        o.push((kc, vc));
    }
    Ok(o)
}

pub fn setenv_cstr(key: &CStr, val: &CStr) -> std::io::Result<()> {
    // SAFETY: both are valid C strings; setenv copies them.
    let r = unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Empty this process's environment. Used in `pre_exec` so we can `setenv`
/// extra + secrets and then `execv`, which inherits `environ`. `Command`'s
/// `env_clear`/`env` build a separate envp for `execve` and ignore `setenv`.
pub fn clear_environ() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: clearenv frees libc's environment array.
        unsafe {
            libc::clearenv();
        }
    }
    #[cfg(target_os = "macos")]
    {
        loop {
            let first = {
                // SAFETY: _NSGetEnviron is the Darwin environ pointer.
                let p = unsafe { libc::_NSGetEnviron() };
                if p.is_null() {
                    return;
                }
                // SAFETY: p points at environ.
                let env = unsafe { *p };
                if env.is_null() {
                    return;
                }
                // SAFETY: first slot is a C string or null.
                let s = unsafe { *env };
                if s.is_null() {
                    return;
                }
                s
            };
            // SAFETY: first is a NUL-terminated NAME=value from environ.
            let bytes = unsafe { CStr::from_ptr(first) }.to_bytes();
            let name_len = bytes.iter().position(|b| *b == b'=').unwrap_or(bytes.len());
            let Some(nameb) = bytes.get(..name_len) else {
                return;
            };
            let Ok(name) = CString::new(nameb) else {
                return;
            };
            // SAFETY: name is a valid C string we just copied.
            unsafe {
                libc::unsetenv(name.as_ptr());
            }
        }
    }
}

/// Replace the environment with `extra` then `secrets`. Caller must not have
/// used `Command::env_clear`/`env`: those make `execve` ignore `environ`.
pub fn apply_child_env(extra: &[(CString, CString)], secrets: &SecretEnvC) -> std::io::Result<()> {
    clear_environ();
    for (k, v) in extra {
        setenv_cstr(k, v)?;
    }
    install_secret_env(secrets)
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

/// Block until `pid` has exited, but do not reap it. The pid stays a zombie so
/// it cannot be reused until a later `waitpid`. Callers remove the pid from any
/// kill-allow set in between.
#[cfg(target_os = "linux")]
pub fn waitid_exited_nowait(pid: u32) -> std::io::Result<()> {
    let id = libc::id_t::from(pid);
    loop {
        let mut info: libc::siginfo_t = {
            // SAFETY: siginfo_t is a plain C struct; zeroed is a valid out-value.
            unsafe { std::mem::zeroed() }
        };
        // SAFETY: waitid writes into `info`; WNOWAIT leaves the zombie in place.
        let r = unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if r == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if interrupted(&err) {
            continue;
        }
        return Err(err);
    }
}

/// Darwin: `kqueue` `EVFILT_PROC`/`NOTE_EXIT` does not reap. `waitid(WNOWAIT)`
/// is POSIX but has been unreliable for this on macOS.
#[cfg(target_os = "macos")]
pub fn waitid_exited_nowait(pid: u32) -> std::io::Result<()> {
    let ident = usize::try_from(pid)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "pid"))?;
    // SAFETY: kqueue takes no arguments.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let change = libc::kevent {
        ident,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: register one EVFILT_PROC watch; change lives across the call.
    let add = unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    if add < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: we own kq.
        unsafe {
            libc::close(kq);
        }
        return Err(err);
    }
    loop {
        let mut event = libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: wait for the one-shot NOTE_EXIT; event is an out-parameter.
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, std::ptr::null()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if interrupted(&err) {
                continue;
            }
            // SAFETY: we own kq.
            unsafe {
                libc::close(kq);
            }
            return Err(err);
        }
        if n > 0 {
            break;
        }
    }
    // SAFETY: we own kq.
    unsafe {
        libc::close(kq);
    }
    Ok(())
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
    drop_caps_keep(0)
}

/// Like `drop_all_caps`, but keep the bits in `keep` (Linux capability numbers
/// as a mask, e.g. `(1 << CAP_SETUID) | (1 << CAP_SETGID)`).
#[cfg(target_os = "linux")]
pub fn drop_caps_keep(keep: u64) -> Result<()> {
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
    let lo = keep as u32;
    let hi = (keep >> 32) as u32;
    let data = [
        CapData {
            effective: lo,
            permitted: lo,
            inheritable: 0,
        },
        CapData {
            effective: hi,
            permitted: hi,
            inheritable: 0,
        },
    ];
    // SAFETY: hdr and data are valid capset arguments for version 3 (two
    // CapData entries) and live across the call.
    let r = unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) };
    if r != 0 {
        return Err(last_os_error("capset"));
    }
    Ok(())
}

pub const CAP_KILL: u64 = 5;
pub const CAP_SETGID: u64 = 6;
pub const CAP_SETUID: u64 = 7;
pub const CAP_SYS_PTRACE: u64 = 19;

/// macOS has no capabilities: nothing to drop.
#[cfg(target_os = "macos")]
pub fn drop_all_caps() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn drop_caps_keep(_keep: u64) -> Result<()> {
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
pub fn local_to_unix(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    min: i32,
    sec: i32,
) -> Option<i64> {
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
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::sync::Mutex;

    fn find_bin(name: &str) -> PathBuf {
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        dirs.push(PathBuf::from("/usr/bin"));
        dirs.push(PathBuf::from("/bin"));
        dirs.into_iter()
            .map(|d| d.join(name))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("{name} not found on PATH"))
    }

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
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let cpid = i32::try_from(child.id()).unwrap();
        let cid = proc_uniqueid(cpid).unwrap();
        assert_ne!(cid, id);
        let pin = PeerPin {
            pid: cpid,
            uniqueid: cid,
        };
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

    #[test]
    fn send_recv_fds_roundtrip() {
        use std::io::{Read, Write};
        let (a, b) = seqpacket_pair().unwrap();
        let (pr, pw) = pipe().unwrap();
        send_fds(a.as_raw_fd(), b"hello", &[pw.as_raw_fd()]).unwrap();
        drop(pw);
        let (payload, fds) = recv_fds(b.as_raw_fd(), 64).unwrap();
        assert_eq!(&payload[..], b"hello");
        let fd = *fds.first().unwrap();
        // SAFETY: recv_fds transferred ownership of this descriptor.
        let mut w = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        w.write_all(b"xy").unwrap();
        drop(w);
        let mut buf = [0u8; 2];
        std::fs::File::from(pr).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"xy");
    }

    #[test]
    fn seqpacket_does_not_coalesce_messages() {
        let (a, b) = seqpacket_pair().unwrap();
        send_fds(a.as_raw_fd(), b"one", &[]).unwrap();
        send_fds(a.as_raw_fd(), b"two", &[]).unwrap();
        let (p1, f1) = recv_fds(b.as_raw_fd(), 64).unwrap();
        assert_eq!(&p1[..], b"one");
        assert!(f1.is_empty());
        let (p2, f2) = recv_fds(b.as_raw_fd(), 64).unwrap();
        assert_eq!(&p2[..], b"two");
        assert!(f2.is_empty());
    }

    #[test]
    fn stream_pair_does_not_coalesce_messages() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        send_fds(a.as_raw_fd(), b"one", &[]).unwrap();
        send_fds(a.as_raw_fd(), b"two", &[]).unwrap();
        let (p1, f1) = recv_fds(b.as_raw_fd(), 64).unwrap();
        assert_eq!(&p1[..], b"one");
        assert!(f1.is_empty());
        let (p2, f2) = recv_fds(b.as_raw_fd(), 64).unwrap();
        assert_eq!(&p2[..], b"two");
        assert!(f2.is_empty());
    }

    #[test]
    fn send_fds_names_sndbuf_when_message_too_big() {
        let (a, b) = seqpacket_pair().unwrap();
        drop(b);
        let n: libc::c_int = 2048;
        let len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
        // SAFETY: n is a c_int for SO_SNDBUF.
        let r = unsafe {
            libc::setsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&n).cast(),
                len,
            )
        };
        if r != 0 {
            // Darwin AF_UNIX socketpair often rejects SO_SNDBUF (errno 1/22).
            let err = std::io::Error::last_os_error();
            if cfg!(target_os = "linux") {
                panic!("setsockopt SO_SNDBUF: {err}");
            }
            return;
        }
        let payload = vec![0u8; 64 * 1024];
        match send_fds(a.as_raw_fd(), &payload, &[]) {
            Err(e) => {
                let err = e.to_string();
                assert!(err.contains("SO_SNDBUF"), "{err}");
                assert!(err.contains("65536"), "{err}");
                assert!(err.contains("secret environment"), "{err}");
                let limit = seqpacket_payload_limit(a.as_raw_fd()).unwrap();
                assert!(err.contains(&limit.to_string()), "{err}");
            }
            Ok(()) => {
                // Darwin unix SEQPACKET often ignores SO_SNDBUF as a message cap.
                #[cfg(target_os = "linux")]
                panic!("expected sendmsg to fail with EMSGSIZE");
            }
        }
    }

    extern "C" fn recv_eintr_nop(_: libc::c_int) {}

    #[test]
    #[allow(clippy::fn_to_numeric_cast)]
    fn recv_fds_retries_eintr() {
        static SIGNAL_LOCK: Mutex<()> = Mutex::new(());
        let _guard = SIGNAL_LOCK.lock().unwrap();
        let (a, b) = seqpacket_pair().unwrap();
        // SAFETY: nop handler so SIGUSR1 is not fatal; we restore SIG_DFL after.
        let prev = unsafe {
            libc::signal(
                libc::SIGUSR1,
                recv_eintr_nop as *const () as libc::sighandler_t,
            )
        };
        // SAFETY: pthread_self returns this thread's id.
        let tid = unsafe { libc::pthread_self() };
        let killer = std::thread::spawn(move || {
            for _ in 0..40 {
                // SAFETY: SIGUSR1 has a no-op handler in this process.
                unsafe {
                    libc::pthread_kill(tid, libc::SIGUSR1);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        send_fds(a.as_raw_fd(), b"after-intr", &[]).unwrap();
        let (p, f) = recv_fds(b.as_raw_fd(), 64).unwrap();
        assert_eq!(&p[..], b"after-intr");
        assert!(f.is_empty());
        let _ = killer.join();
        // SAFETY: restore the previous handler.
        unsafe {
            libc::signal(libc::SIGUSR1, prev);
        }
    }

    #[test]
    fn waitid_nowait_holds_zombie_until_reap() {
        let mut child = std::process::Command::new(find_bin("true"))
            .spawn()
            .unwrap();
        let pid = child.id();
        waitid_exited_nowait(pid).unwrap();
        let raw = i32::try_from(pid).unwrap();
        assert!(pid_alive(raw), "WNOWAIT must keep the pid as a zombie");
        #[cfg(target_os = "linux")]
        {
            let st = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            assert!(
                st.contains(" Z ") || st.contains(" Z\n"),
                "expected zombie, got {st}"
            );
        }
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_profile_creds_does_not_split_ruid() {
        let u = getuid();
        let g = getgid();
        if apply_profile_creds(u, g).is_err() {
            return;
        }
        let mut r = 0u32;
        let mut e = 0u32;
        let mut s = 0u32;
        // SAFETY: three writable uid_t outs.
        unsafe {
            libc::getresuid(&mut r, &mut e, &mut s);
        }
        assert_eq!((r, e, s), (u, u, u));
    }

    #[test]
    fn secret_env_c_rejects_nul_and_setenv_copies() {
        let bad = Zeroizing::new(vec![1, 0, 2]);
        assert!(secret_env_c(&[("A".into(), bad)]).is_err());
        let ok = Zeroizing::new(b"v".to_vec());
        let pairs = secret_env_c(&[("SB_TEST_ENV".into(), ok)]).unwrap();
        install_secret_env(&pairs).unwrap();
        assert_eq!(std::env::var("SB_TEST_ENV").unwrap(), "v");
        std::env::remove_var("SB_TEST_ENV");
    }

    #[test]
    fn pre_exec_setenv_reaches_child_when_command_does_not_set_envp() {
        let extra = str_env_c(&[("LANG".into(), "C".into())]).unwrap();
        let secrets =
            secret_env_c(&[("TOK".into(), Zeroizing::new(b"\xffsecret-bytes".to_vec()))]).unwrap();
        let mut cmd = std::process::Command::new(find_bin("printenv"));
        cmd.arg("TOK");
        // SAFETY: clearenv/setenv in the child; buffers live until spawn returns.
        unsafe {
            cmd.pre_exec(move || {
                apply_child_env(&extra, &secrets)?;
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        assert_eq!(
            out.stdout,
            b"\xffsecret-bytes\n",
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn command_env_clear_discards_pre_exec_setenv() {
        let secrets = secret_env_c(&[("TOK".into(), Zeroizing::new(b"secret".to_vec()))]).unwrap();
        let mut cmd = std::process::Command::new(find_bin("printenv"));
        cmd.arg("TOK")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default());
        // SAFETY: setenv in the child; this is the pattern spawn must not use.
        unsafe {
            cmd.pre_exec(move || {
                install_secret_env(&secrets)?;
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        assert!(
            out.stdout.is_empty(),
            "std execve uses Command's envp; env_clear must not be used on profile spawn, got {:?}",
            out.stdout
        );
    }
}
