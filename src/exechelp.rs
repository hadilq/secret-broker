//! Privileged exec helper. Spawned before the daemon drops CAP_SETUID/CAP_SETGID
//! (the daemon keeps none). It changes uid only to a `(uid, gid)` pair it was
//! given at start (the configured profile users), and kills only pids it spawned.
//!
//! Command, argv, and cwd still come from the daemon and are not re-checked:
//! after the uid change the process is a configured `sb-*` user that owns only
//! its home, so those strings cannot reach the broker's files.

use crate::bail;
use crate::error::{Error, Result};
use crate::sys;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone)]
pub struct SpawnReq {
    pub command: String,
    pub args: Vec<String>,
    pub extra_env: Vec<(String, String)>,
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
    pub fn spawn(exe: &Path, allowed: &[(u32, u32)]) -> Result<Self> {
        let (local, remote) = sys::seqpacket_pair()?;
        sys::clear_cloexec(remote.as_raw_fd())?;
        let mut cmd = Command::new(exe);
        cmd.arg("exec-helper");
        for (u, g) in allowed {
            cmd.arg(format!("{u}:{g}"));
        }
        cmd.env_clear()
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
    pub fn start(
        &self,
        req: &SpawnReq,
        secrets: &[(String, Zeroizing<Vec<u8>>)],
        stdio: [RawFd; 4],
    ) -> Result<u32> {
        let json = serde_json::to_vec(&Msg::Spawn(req.clone())).map_err(Error::from)?;
        let secs: Vec<(&str, &[u8])> = secrets
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        let buf = encode(&json, &secs)?;
        let sock = self.sock.lock().unwrap_or_else(|p| p.into_inner());
        sys::send_fds(sock.as_raw_fd(), &buf, &stdio)?;
        let (rep, _) = sys::recv_fds(sock.as_raw_fd(), sys::HELPER_MAX_FRAME)?;
        drop(buf);
        parse_rep(&rep)
    }

    pub fn kill(&self, pid: u32) -> Result<()> {
        let json = serde_json::to_vec(&Msg::Kill { pid }).map_err(Error::from)?;
        let buf = encode(&json, &[])?;
        let sock = self.sock.lock().unwrap_or_else(|p| p.into_inner());
        sys::send_fds(sock.as_raw_fd(), &buf, &[])?;
        let (rep, _) = sys::recv_fds(sock.as_raw_fd(), sys::HELPER_MAX_FRAME)?;
        parse_rep(&rep).map(|_| ())
    }
}

fn parse_rep(rep: &[u8]) -> Result<u32> {
    let (json, secrets) = decode(rep)?;
    drop(secrets);
    let r: SpawnRep = serde_json::from_slice(&json).map_err(Error::from)?;
    if !r.error.is_empty() {
        return Err(Error::msg(r.error));
    }
    if r.pid == 0 {
        return Err(Error::msg("exec-helper returned pid 0"));
    }
    Ok(r.pid)
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

/// `uid:gid` tokens from argv. Empty list refuses every spawn.
pub fn parse_allowed(args: &[String]) -> Result<HashSet<(u32, u32)>> {
    let mut s = HashSet::new();
    for a in args {
        let Some((u, g)) = a.split_once(':') else {
            bail!("exec-helper: bad allow {a:?} (want uid:gid)");
        };
        let uid: u32 = u
            .parse()
            .map_err(|_| Error::msg(format!("exec-helper: bad uid in {a:?}")))?;
        let gid: u32 = g
            .parse()
            .map_err(|_| Error::msg(format!("exec-helper: bad gid in {a:?}")))?;
        s.insert((uid, gid));
    }
    Ok(s)
}

pub fn uid_allowed(uid: u32, gid: u32, allowed: &HashSet<(u32, u32)>) -> bool {
    allowed.contains(&(uid, gid))
}

/// `secret-broker exec-helper [uid:gid ...]`: stdin is the SEQPACKET socket.
pub fn helper_main() -> Result<()> {
    let _ = sys::set_non_dumpable();
    let have = sys::effective_caps().unwrap_or(0);
    let keep = (1u64 << sys::CAP_SETUID) | (1u64 << sys::CAP_SETGID) | (1u64 << sys::CAP_KILL);
    let _ = sys::drop_caps_keep(have & keep);
    sys::close_from(3);
    let allowed = parse_allowed(&std::env::args().skip(2).collect::<Vec<_>>())?;
    let live: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    // SAFETY: the daemon passed the control socket as fd 0.
    let sock = unsafe { UnixStream::from_raw_fd(0) };
    loop {
        let (buf, fds) = match sys::recv_fds(sock.as_raw_fd(), sys::HELPER_MAX_FRAME) {
            Ok(x) => x,
            Err(_) => return Ok(()),
        };
        let decoded = decode(&buf);
        drop(buf);
        let (json, secrets) = match decoded {
            Ok(x) => x,
            Err(e) => {
                let _ = reply(&sock, 0, &e.to_string());
                close_all(&fds);
                continue;
            }
        };
        let msg: Msg = match serde_json::from_slice(&json) {
            Ok(m) => m,
            Err(e) => {
                let _ = reply(&sock, 0, &e.to_string());
                close_all(&fds);
                continue;
            }
        };
        match msg {
            Msg::Kill { pid } => {
                let ok = live
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .contains(&pid);
                if ok {
                    sys::kill_group(pid);
                    reply(&sock, pid, "")?;
                } else {
                    reply(&sock, 0, "exec-helper: pid is not a child we spawned")?;
                }
            }
            Msg::Spawn(req) => {
                if !uid_allowed(req.uid, req.gid, &allowed) {
                    let _ = reply(
                        &sock,
                        0,
                        &format!(
                            "exec-helper: uid {}:{} is not a configured profile user",
                            req.uid, req.gid
                        ),
                    );
                    close_all(&fds);
                    continue;
                }
                if fds.len() != 4 {
                    let _ = reply(&sock, 0, "exec-helper: need 4 fds");
                    close_all(&fds);
                    continue;
                }
                match spawn_one(&req, &secrets, &fds, &live) {
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
    let json = serde_json::to_vec(&SpawnRep {
        pid,
        error: error.into(),
    })
    .map_err(Error::from)?;
    let buf = encode(&json, &[])?;
    sys::send_fds(sock.as_raw_fd(), &buf, &[])
}

fn close_all(fds: &[RawFd]) {
    for fd in fds {
        sys::close_fd(*fd);
    }
}

fn spawn_one(
    req: &SpawnReq,
    secrets: &[(String, Zeroizing<Vec<u8>>)],
    fds: &[RawFd],
    live: &Arc<Mutex<HashSet<u32>>>,
) -> Result<u32> {
    let stdin = fd(*fds.first().ok_or_else(|| Error::msg("fds"))?)?;
    let stdout = fd(*fds.get(1).ok_or_else(|| Error::msg("fds"))?)?;
    let stderr = fd(*fds.get(2).ok_or_else(|| Error::msg("fds"))?)?;
    let status_w = fd(*fds.get(3).ok_or_else(|| Error::msg("fds"))?)?;
    let home_c =
        std::ffi::CString::new(req.cwd.as_str()).map_err(|_| Error::msg("cwd contains NUL"))?;
    let uid = req.uid;
    let gid = req.gid;
    let extra_c = sys::str_env_c(&req.extra_env).map_err(Error::from)?;
    let secret_env = sys::secret_env_c(secrets).map_err(Error::from)?;
    let mut cmd = Command::new(&req.command);
    // Do not env_clear/env: std then calls execve with its own envp and
    // drops everything `setenv` wrote in pre_exec.
    cmd.args(&req.args)
        .process_group(0)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: setgroups/setresuid/chdir/caps/setenv; buffers live until spawn returns.
    unsafe {
        cmd.pre_exec(move || {
            sys::apply_profile_creds(uid, gid)?;
            sys::chdir(&home_c)?;
            sys::apply_child_env(&extra_c, &secret_env)?;
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
    live.lock().unwrap_or_else(|p| p.into_inner()).insert(pid);
    let live = Arc::clone(live);
    let mut status_w_file = std::fs::File::from(status_w);
    std::thread::spawn(move || {
        // WNOWAIT first: pid stays a zombie, so a kill cannot hit a reused
        // pid. Then drop it from `live` (kills are refused), then reap.
        let _ = sys::waitid_exited_nowait(pid);
        live.lock().unwrap_or_else(|p| p.into_inner()).remove(&pid);
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

/// Frame: `u32be json_len | json | u32be nsecrets | (u16be klen | key | u32be vlen | val)*`.
pub fn encode(json: &[u8], secrets: &[(&str, &[u8])]) -> Result<Zeroizing<Vec<u8>>> {
    let mut o = Zeroizing::new(Vec::new());
    let jl = u32::try_from(json.len()).map_err(|_| Error::msg("json too large"))?;
    o.extend_from_slice(&jl.to_be_bytes());
    o.extend_from_slice(json);
    let n = u32::try_from(secrets.len()).map_err(|_| Error::msg("too many secrets"))?;
    o.extend_from_slice(&n.to_be_bytes());
    for (k, v) in secrets {
        let kl = u16::try_from(k.len()).map_err(|_| Error::msg("secret name too long"))?;
        o.extend_from_slice(&kl.to_be_bytes());
        o.extend_from_slice(k.as_bytes());
        let vl = u32::try_from(v.len()).map_err(|_| Error::msg("secret too large"))?;
        o.extend_from_slice(&vl.to_be_bytes());
        o.extend_from_slice(v);
    }
    if o.len() > sys::HELPER_MAX_FRAME {
        bail!(
            "SOCK_SEQPACKET message is {} bytes; max is {} (SO_SNDBUF is typically about 208 KiB). Shrink the secret environment or raise net.core.wmem_max",
            o.len(),
            sys::HELPER_MAX_FRAME
        );
    }
    Ok(o)
}

type SecretEnv = Vec<(String, Zeroizing<Vec<u8>>)>;

pub fn decode(buf: &[u8]) -> Result<(Vec<u8>, SecretEnv)> {
    let mut i = 0usize;
    let take = |i: &mut usize, n: usize| -> Result<&[u8]> {
        let e = i.saturating_add(n);
        let s = buf
            .get(*i..e)
            .ok_or_else(|| Error::msg("truncated helper frame"))?;
        *i = e;
        Ok(s)
    };
    fn be4(s: &[u8]) -> Result<u32> {
        let a: [u8; 4] = s
            .try_into()
            .map_err(|_| Error::msg("truncated helper frame"))?;
        Ok(u32::from_be_bytes(a))
    }
    fn be2(s: &[u8]) -> Result<u16> {
        let a: [u8; 2] = s
            .try_into()
            .map_err(|_| Error::msg("truncated helper frame"))?;
        Ok(u16::from_be_bytes(a))
    }
    let jl = be4(take(&mut i, 4)?)?;
    let json = take(&mut i, usize::try_from(jl).unwrap_or(0))?.to_vec();
    let ns = be4(take(&mut i, 4)?)?;
    let mut secrets = Vec::new();
    for _ in 0..ns {
        let kl = be2(take(&mut i, 2)?)?;
        let k = take(&mut i, usize::from(kl))?;
        let name =
            String::from_utf8(k.to_vec()).map_err(|_| Error::msg("secret name is not utf-8"))?;
        let vl = be4(take(&mut i, 4)?)?;
        let v = take(&mut i, usize::try_from(vl).unwrap_or(0))?;
        secrets.push((name, Zeroizing::new(v.to_vec())));
    }
    if i != buf.len() {
        bail!("helper frame has trailing bytes");
    }
    Ok((json, secrets))
}

/// True for an ELF/Mach-O binary with no dynamic linker (PT_INTERP / LC_LOAD_DYLINKER).
/// Scripts (`#!`) and missing files are not static.
///
/// Not used for credential policy: a split ruid/euid (to keep dumpable=0 after
/// exec of a static binary) lets the child `seteuid` back to the helper.
pub fn is_statically_linked(path: &Path) -> bool {
    let Ok(buf) = std::fs::read(path) else {
        return false;
    };
    if buf.starts_with(b"#!") {
        return false;
    }
    if buf.len() >= 4 && buf.starts_with(b"\x7fELF") {
        return elf_has_no_interp(&buf);
    }
    if buf.len() >= 4
        && (buf.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
            || buf.starts_with(&[0xce, 0xfa, 0xed, 0xfe]))
    {
        return macho_has_no_dylinker(&buf);
    }
    false
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(o..o.saturating_add(2))?.try_into().ok()?,
    ))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(o..o.saturating_add(4))?.try_into().ok()?,
    ))
}
fn u64le(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(o..o.saturating_add(8))?.try_into().ok()?,
    ))
}

fn elf_has_no_interp(b: &[u8]) -> bool {
    let Some(class) = b.get(4).copied() else {
        return false;
    };
    const PT_INTERP: u32 = 3;
    let (phoff, phentsize, phnum): (u64, u16, u16) = if class == 2 {
        (
            match u64le(b, 32) {
                Some(v) => v,
                None => return false,
            },
            match u16le(b, 54) {
                Some(v) => v,
                None => return false,
            },
            match u16le(b, 56) {
                Some(v) => v,
                None => return false,
            },
        )
    } else if class == 1 {
        (
            u64::from(match u32le(b, 28) {
                Some(v) => v,
                None => return false,
            }),
            match u16le(b, 42) {
                Some(v) => v,
                None => return false,
            },
            match u16le(b, 44) {
                Some(v) => v,
                None => return false,
            },
        )
    } else {
        return false;
    };
    let ent = usize::from(phentsize);
    for i in 0..usize::from(phnum) {
        let off = match usize::try_from(phoff) {
            Ok(o) => o.saturating_add(i.saturating_mul(ent)),
            Err(_) => return false,
        };
        if u32le(b, off) == Some(PT_INTERP) {
            return false;
        }
    }
    phnum > 0
}

fn macho_has_no_dylinker(b: &[u8]) -> bool {
    const LC_LOAD_DYLINKER: u32 = 0xe;
    let ncmds = match u32le(b, 16) {
        Some(n) => n,
        None => return false,
    };
    let mut off = 32usize;
    if b.starts_with(&[0xce, 0xfa, 0xed, 0xfe]) {
        off = 28;
    }
    for _ in 0..ncmds {
        let cmd = match u32le(b, off) {
            Some(c) => c,
            None => return false,
        };
        let sz = match u32le(b, off.saturating_add(4)) {
            Some(s) => s,
            None => return false,
        };
        if cmd == LC_LOAD_DYLINKER {
            return false;
        }
        off = off.saturating_add(usize::try_from(sz).unwrap_or(0));
    }
    ncmds > 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parse_allowed_and_uid_check() {
        let s = parse_allowed(&["1001:1001".into(), "1002:1003".into()]).unwrap();
        assert!(uid_allowed(1001, 1001, &s));
        assert!(!uid_allowed(1001, 1002, &s));
        assert!(!uid_allowed(0, 0, &s));
        assert!(parse_allowed(&["nope".into()]).is_err());
        assert!(parse_allowed(&[]).unwrap().is_empty());
        assert!(!uid_allowed(1, 1, &HashSet::new()));
    }

    #[test]
    fn secret_frame_roundtrip_keeps_binary() {
        let json = br#"{"op":"spawn"}"#;
        let raw = [0xffu8, 0x00, 0xfe, b'x'];
        let buf = encode(json, &[("TOK", &raw)]).unwrap();
        let (j, secs) = decode(&buf).unwrap();
        assert_eq!(j, json);
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].0, "TOK");
        assert_eq!(&secs[0].1[..], &raw);
        assert!(decode(b"short").is_err());
        let mut extra = buf.to_vec();
        extra.push(1);
        assert!(decode(&extra).is_err());
    }

    #[test]
    fn encode_rejects_frame_over_seqpacket_cap() {
        let big = vec![0u8; sys::HELPER_MAX_FRAME];
        let err = encode(br#"{}"#, &[("K", &big)]).unwrap_err().to_string();
        assert!(err.contains("SOCK_SEQPACKET"), "{err}");
        assert!(err.contains("secret environment"), "{err}");
        assert!(
            err.contains(&sys::HELPER_MAX_FRAME.to_string()) || err.contains("208"),
            "{err}"
        );
    }

    #[test]
    fn static_elf_without_pt_interp() {
        let dir = std::env::temp_dir().join(format!("sb-elf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut elf = vec![0u8; 128];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // LE
        elf[16] = 2; // ET_EXEC
        elf[32] = 64; // e_phoff
        elf[52] = 64; // e_ehsize
        elf[54] = 56; // e_phentsize
        elf[56] = 1; // e_phnum
        elf[64] = 1; // PT_LOAD
        let p = dir.join("static");
        std::fs::write(&p, &elf).unwrap();
        assert!(is_statically_linked(&p));
        elf[64] = 3; // PT_INTERP
        std::fs::write(&p, &elf).unwrap();
        assert!(!is_statically_linked(&p));
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        assert!(!is_statically_linked(&p));
        assert!(!is_statically_linked(&dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
