//! The framed wire protocol over the broker's unix socket. Every frame is
//! 1 byte type, 4 byte big-endian length, payload.
//!
//! There is deliberately no frame or operation that returns a secret value.

use crate::bail;
use crate::error::{Error, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};

pub const T_JSON: u8 = b'J'; // control message (request or response)
pub const T_KEY: u8 = b'K'; // unlock: raw sops data key (client -> broker)
pub const T_STDIN: u8 = b'I'; // stdin chunk (client -> broker)
pub const T_STDIN_EOF: u8 = b'i'; // stdin closed (client -> broker)
pub const T_STDOUT: u8 = b'O'; // child stdout (broker -> client)
pub const T_STDERR: u8 = b'E'; // child stderr (broker -> client)
pub const T_EXIT: u8 = b'X'; // child finished, JSON ExitInfo
pub const T_PIN: u8 = b'P'; // quick-approval PIN (client/prompter -> broker)

pub const MAX_FRAME: usize = 1 << 20;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Request {
    /// status | lock | unlock | exec | approve | set_pin | prompter | report
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default)]
    pub stdin: bool,
    /// lock: wipe the secrets from memory instead of sealing them.
    /// set_pin: remove the PIN.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forget: bool,
    /// set_pin: anti-phishing phrase shown in every genuine dialog.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phrase: String,
    /// report: an event the client did itself (fido2_enroll), for the audit log.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ProfileInfo {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub command: String,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    #[serde(default)]
    pub env_vars: Vec<String>,
    #[serde(default)]
    pub allow: Vec<Vec<String>>,
    #[serde(default)]
    pub deny: Vec<Vec<String>>,
    #[serde(default)]
    pub deny_tokens: Vec<String>,
    /// env vars whose sops key is missing (only when unlocked)
    #[serde(default)]
    pub unresolved: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy)]
pub struct GpgCacheLimits {
    pub default_cache_ttl: u64,
    pub max_cache_ttl: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Status {
    pub unlocked: bool,
    #[serde(default)]
    pub expires_at_unix: i64,
    #[serde(default)]
    pub remaining_seconds: u64,
    pub secrets_file: String,
    #[serde(default)]
    pub secret_count: usize,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub gpg_cache_limits: GpgCacheLimits,
    #[serde(default)]
    pub profiles: Vec<ProfileInfo>,
    /// cold (nothing in memory: needs gpg) | sealed (in memory, needs a
    /// quick approval) | open
    #[serde(default)]
    pub state: String,
    /// Configured quick-approval methods ("pin", "fido2", PAM method names).
    #[serde(default)]
    pub methods: Vec<String>,
    /// An approval dialog (prompter) is connected.
    #[serde(default)]
    pub prompter: bool,
    #[serde(default)]
    pub pin_set: bool,
    #[serde(default)]
    pub pin_locked_out: bool,
    #[serde(default)]
    pub pin_attempts_left: u32,
    /// This connection came through the restricted (sandbox) socket.
    #[serde(default)]
    pub restricted: bool,
    #[serde(default)]
    pub approval_timeout_seconds: u64,
    /// Who unlocked / last opened the session (absent when cold).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

impl Response {
    pub fn err(e: impl Into<String>) -> Self {
        Response {
            ok: false,
            error: e.into(),
            status: None,
        }
    }
}

/// Who asked for the session (filled by the broker from SO_PEERCRED and the
/// socket the request came in on; the dialog may add /proc details itself).
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Requester {
    pub pid: i32,
    pub uid: u32,
    #[serde(default)]
    pub user: String,
    /// Came through the restricted socket (from inside ai-run).
    #[serde(default)]
    pub sandboxed: bool,
}

/// One process in a caller's parent chain.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comm: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exe: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
}

/// Everything the broker knows about the process on the other end of a
/// connection, snapshotted when the request arrived. Kernel facts
/// (SO_PEERCRED uid/pid, the socket) are reliable; the /proc details are as
/// reliable as a pid is: `verified` says the caller was still alive (pidfd)
/// after the snapshot, so the pid wasn't reused under us. Parents are not
/// pinned and may have exited.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Caller {
    pub pid: i32,
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default)]
    pub user: String,
    /// broker.sock | agent.sock
    #[serde(default)]
    pub socket: String,
    /// Came through the restricted (sandbox) socket.
    #[serde(default)]
    pub sandboxed: bool,
    /// ai-run profile, from the enclosing bwrap's command line.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ai_run_profile: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comm: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exe: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// cgroup v2 path, e.g. /user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-foot-1234.scope
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cgroup: String,
    /// Innermost systemd unit (scope/service).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unit: String,
    /// Application id from an app-*.scope/service unit ("foot").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    /// Who launched that app ("Hyprland").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub launcher: String,
    /// logind session id (from the cgroup, else the user's display session).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_session: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seat: String,
    /// Controlling terminal of the caller (/dev/pts/3), else the session's.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tty: String,
    /// logind session type/class (wayland/tty, user).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_session: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loginuid: Option<u32>,
    /// Process start time (clock ticks since boot), to spot pid reuse.
    #[serde(default)]
    pub start_time: u64,
    /// Nearest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<ProcInfo>,
    #[serde(default)]
    pub snapshot_unix: i64,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Caller {
    /// "secret-run gh pr list" (argv, or comm when /proc was unreadable).
    pub fn command(&self) -> String {
        if self.argv.is_empty() {
            return self.comm.clone();
        }
        let mut parts = self.argv.clone();
        if let Some(first) = parts.first_mut() {
            if first.starts_with("/nix/store/") {
                if let Some(name) = std::path::Path::new(first.as_str()).file_name() {
                    *first = name.to_string_lossy().into_owned();
                }
            }
        }
        parts.join(" ")
    }

    /// "foot (via Hyprland)" or the unit name.
    pub fn app_label(&self) -> String {
        match (self.app.is_empty(), self.launcher.is_empty()) {
            (false, false) => format!("{} (via {})", self.app, self.launcher),
            (false, true) => self.app.clone(),
            _ => self.unit.clone(),
        }
    }
}

/// Who opened the session, and how.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Owner {
    pub user: String,
    pub uid: u32,
    pub pid: i32,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub exe: String,
    /// "foot (via Hyprland)" / unit
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub socket: String,
    #[serde(default)]
    pub sandboxed: bool,
    /// gpg | pin | fido2 | <pam method>
    pub method: String,
    /// gpg | dialog | terminal
    #[serde(default)]
    pub via: String,
    pub at_unix: i64,
}

impl Owner {
    pub fn from_caller(c: &Caller, method: &str, via: &str, at_unix: i64) -> Self {
        Owner {
            user: c.user.clone(),
            uid: c.uid,
            pid: c.pid,
            command: c.command(),
            exe: c.exe.clone(),
            app: c.app_label(),
            socket: c.socket.clone(),
            sandboxed: c.sandboxed,
            method: method.into(),
            via: via.into(),
            at_unix,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SessionInfo {
    /// cold | sealed | open
    pub state: String,
    #[serde(default)]
    pub expires_at_unix: i64,
    /// The gpg unlock that put the secrets in memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocked: Option<Owner>,
    /// The latest opening (gpg or a quick approval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened: Option<Owner>,
}

/// Broker -> approval dialog (prompter) or `secret-broker unlock`.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Prompt {
    /// request | update | done
    pub kind: String,
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<Requester>,
    /// What will run, e.g. "secret-run gh pr list".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purpose: String,
    #[serde(default)]
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Human labels for hardware methods ("Touch your security key", ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
    /// Anti-phishing phrase chosen with `secret-broker set-pin`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phrase: String,
    #[serde(default)]
    pub attempts_left: u32,
    #[serde(default)]
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default)]
    pub ok: bool,
    /// Full details of the requester (snapshot at request time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<Caller>,
    /// The session being reopened: who unlocked it, when, how.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
}

/// Approval dialog -> broker. kind "pin" is followed by a T_PIN frame.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Answer {
    /// pin | deny
    pub kind: String,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ExitInfo {
    pub code: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

pub fn write_frame<W: Write>(w: &mut W, t: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        bail!("frame too large");
    }
    let len = u32::try_from(payload.len()).map_err(|_| Error::msg("frame too large"))?;
    let mut hdr = Vec::with_capacity(5);
    hdr.push(t);
    hdr.extend_from_slice(&len.to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

pub fn write_json<W: Write, T: Serialize>(w: &mut W, t: u8, v: &T) -> Result<()> {
    let b = serde_json::to_vec(v)?;
    write_frame(w, t, &b)
}

pub fn read_frame<R: Read>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let [t, a, b, c, d] = hdr;
    let n = usize::try_from(u32::from_be_bytes([a, b, c, d]))
        .map_err(|_| Error::msg("frame length"))?;
    if n > MAX_FRAME {
        bail!("frame too large");
    }
    let mut p = vec![0u8; n];
    r.read_exact(&mut p)?;
    Ok((t, p))
}

pub fn read_json<R: Read, T: DeserializeOwned>(r: &mut R, want: u8) -> Result<T> {
    let (t, p) = read_frame(r)?;
    if t != want {
        bail!(
            "protocol: expected frame {:?}, got {:?}",
            char::from(want),
            char::from(t)
        );
    }
    Ok(serde_json::from_slice(&p)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_json(
            &mut buf,
            T_JSON,
            &Request {
                op: "status".into(),
                ..Default::default()
            },
        )
        .unwrap();
        write_frame(&mut buf, T_STDOUT, b"hi").unwrap();
        let mut r = buf.as_slice();
        let req: Request = read_json(&mut r, T_JSON).unwrap();
        assert_eq!(req.op, "status");
        assert_eq!(read_frame(&mut r).unwrap(), (T_STDOUT, b"hi".to_vec()));
        assert!(read_frame(&mut r).is_err());
    }
}
