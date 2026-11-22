//! The framed wire protocol over the broker's unix socket. Every frame is
//! 1 byte type, 4 byte big-endian length, payload.
//!
//! There is deliberately no frame or operation that returns a secret value.

use crate::bail;
use crate::error::{Error, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};

pub const T_JSON: u8 = b'J'; // control message (request or response)
pub const T_KEY: u8 = b'K'; // unlock: raw sops data key (client -> broker)
pub const T_STDIN: u8 = b'I'; // stdin chunk (client -> broker)
pub const T_STDIN_EOF: u8 = b'i'; // stdin closed (client -> broker)
pub const T_STDOUT: u8 = b'O'; // child stdout (broker -> client)
pub const T_STDERR: u8 = b'E'; // child stderr (broker -> client)
pub const T_EXIT: u8 = b'X'; // child finished, JSON ExitInfo

pub const MAX_FRAME: usize = 1 << 20;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Request {
    pub op: String, // status | lock | unlock | exec
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default)]
    pub stdin: bool,
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
