//! Privileged exec helper. Spawned before the daemon drops CAP_SETUID/CAP_SETGID
//! (the daemon keeps none). It is the only process that changes uid, and only
//! to a configured profile user.

use crate::bail;
use crate::error::{Error, Result};
use crate::sys;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

const MAX: usize = 1 << 20;

#[derive(Serialize, Deserialize, Clone)]
pub struct SpawnReq {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
enum Msg {
    #[serde(rename = "spawn")]
    Spawn(SpawnReq),
    #[serde(rename = "kill")]
    Kill { pid: u32 },
}

#[derive(Serialize, Deserialize)]
struct SpawnRep {
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    error: String,
}

#[derive(Serialize, Deserialize)]
struct WaitRep {
    code: i32,
}

pub struct Helper {
    sock: Mutex<UnixStream>,
    child: Child,
}

impl Helper {
    pub fn spawn(exe: &Path) -> Result<Self> {
        let (local, remote) = UnixStream::pair().map_err(Error::from)?;
        sys::clear_cloexec(remote.as_raw_fd())?;
        let mut cmd = Command::new(exe);
        cmd.arg("exec-helper")
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(remote)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let child = cmd
            .spawn()
            .map_err(|e| Error::msg(format!("spawn exec-helper: {e}")))?;
        Ok(Helper {
            sock: Mutex::new(local),
            child,
        })
    }

    /// `stdio` is stdin, stdout, stderr, status-write (helper writes one JSON line).
    pub fn start(&self, req: &SpawnReq, stdio: [RawFd; 4]) -> Result<u32> {
        let buf = serde_json::to_vec(&Msg::Spawn(req.clone())).map_err(Error::from)?;
        let sock = self.sock.lock().unwrap_or_else(|p| p.into_inner());
        sys::send_fds(sock.as_raw_fd(), &buf, &stdio)?;
        let (rep, _) = sys::recv_fds(sock.as_raw_fd(), MAX)?;
        let r: SpawnRep = serde_json::from_slice(&rep).map_err(Error::from)?;
        if !r.error.is_empty() {
            return Err(Error::msg(r.error));
        }
        if r.pid == 0 {
            return Err(Error::msg("exec-helper returned pid 0"));
        }
        Ok(r.pid)
    }

    pub fn kill(&self, pid: u32) -> Result<()> {
        let buf = serde_json::to_vec(&Msg::Kill { pid }).map_err(Error::from)?;
        let sock = self.sock.lock().unwrap_or_else(|p| p.into_inner());
        sys::send_fds(sock.as_raw_fd(), &buf, &[])?;
        let (rep, _) = sys::recv_fds(sock.as_raw_fd(), MAX)?;
        let r: SpawnRep = serde_json::from_slice(&rep).map_err(Error::from)?;
        if !r.error.is_empty() {
            return Err(Error::msg(r.error));
        }
        Ok(())
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if let Ok(s) = self.sock.lock() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `secret-broker exec-helper`: read spawn requests from stdin (a unix socket).
pub fn helper_main() -> Result<()> {
    let _ = sys::set_non_dumpable();
    let have = sys::effective_caps().unwrap_or(0);
    let keep = (1u64 << sys::CAP_SETUID) | (1u64 << sys::CAP_SETGID) | (1u64 << sys::CAP_KILL);
    let _ = sys::drop_caps_keep(have & keep);
    sys::close_from(3);
    // SAFETY: the daemon passed the control socket as fd 0.
    let sock = unsafe { UnixStream::from_raw_fd(0) };
    loop {
        let (buf, fds) = match sys::recv_fds(sock.as_raw_fd(), MAX) {
            Ok(x) => x,
            Err(_) => return Ok(()),
        };
        let msg: Msg = match serde_json::from_slice(&buf) {
            Ok(m) => m,
            Err(e) => {
                let _ = reply(&sock, 0, &e.to_string());
                close_all(&fds);
                continue;
            }
        };
        match msg {
            Msg::Kill { pid } => {
                sys::kill_group(pid);
                reply(&sock, pid, "")?;
            }
            Msg::Spawn(req) => {
                if fds.len() != 4 {
                    let _ = reply(&sock, 0, "exec-helper: need 4 fds");
                    close_all(&fds);
                    continue;
                }
                match spawn_one(&req, &fds) {
                    Ok(pid) => reply(&sock, pid, "")?,
                    Err(e) => {
                        let _ = reply(&sock, 0, &e.to_string());
                        close_all(&fds);
                    }
                }
            }
        }
    }
}

fn reply(sock: &UnixStream, pid: u32, error: &str) -> Result<()> {
    let buf = serde_json::to_vec(&SpawnRep {
        pid,
        error: error.into(),
    })
    .map_err(Error::from)?;
    sys::send_fds(sock.as_raw_fd(), &buf, &[])
}

fn close_all(fds: &[RawFd]) {
    for fd in fds {
        sys::close_fd(*fd);
    }
}

fn spawn_one(req: &SpawnReq, fds: &[RawFd]) -> Result<u32> {
    let stdin = fd(*fds.first().ok_or_else(|| Error::msg("fds"))?)?;
    let stdout = fd(*fds.get(1).ok_or_else(|| Error::msg("fds"))?)?;
    let stderr = fd(*fds.get(2).ok_or_else(|| Error::msg("fds"))?)?;
    let status_w = fd(*fds.get(3).ok_or_else(|| Error::msg("fds"))?)?;
    let home_c = std::ffi::CString::new(req.cwd.as_str())
        .map_err(|_| Error::msg("cwd contains NUL"))?;
    let uid = req.uid;
    let gid = req.gid;
    let mut cmd = Command::new(&req.command);
    cmd.args(&req.args)
        .env_clear()
        .envs(req.env.iter().cloned())
        .process_group(0)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: setgroups/setresuid/chdir/caps; CString lives until spawn returns.
    unsafe {
        cmd.pre_exec(move || {
            sys::apply_profile_creds(uid, gid)?;
            sys::chdir(&home_c)?;
            let _ = sys::set_non_dumpable();
            let _ = sys::drop_all_caps();
            sys::close_from(3);
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::msg(format!("exec-helper spawn: {e}")))?;
    let pid = child.id();
    let mut status_w_file = std::fs::File::from(status_w);
    std::thread::spawn(move || {
        let code = match child.wait() {
            Ok(s) => match (s.code(), s.signal()) {
                (Some(c), _) => c,
                (None, Some(sig)) => sig.saturating_add(128),
                (None, None) => 1,
            },
            Err(_) => 1,
        };
        if let Ok(buf) = serde_json::to_vec(&WaitRep { code }) {
            let _ = status_w_file.write_all(&buf);
            let _ = status_w_file.write_all(b"\n");
        }
    });
    Ok(pid)
}

fn fd(raw: RawFd) -> Result<OwnedFd> {
    if raw < 0 {
        bail!("bad fd");
    }
    // SAFETY: recvmsg transferred ownership of this descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
