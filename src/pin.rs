//! Quick-approval PIN, verified inside the broker.
//!
//! The PIN is never stored. The file holds argon2id(pin, salt, secret=pepper)
//! where the pepper is HMAC-SHA256(sops data key, "secret-broker pin pepper v1").
//! The data key only exists in the broker's memory after a gpg unlock, so:
//!
//! - a copy of the PIN file is useless for offline guessing without the data
//!   key (and with the data key you already have every secret);
//! - a PIN only works while the secrets are in RAM (state "sealed"); after a
//!   reboot or `lock --forget` the first unlock always needs gpg;
//! - online guessing is limited by attempts + backoff, after which the broker
//!   forgets everything (back to gpg).

use crate::bail;
use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

const MAGIC: &str = "secret-broker-pin";
const VERSION: &str = "v1";
pub const MAX_PHRASE: usize = 48;
pub const MAX_PIN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Cost {
    fn default() -> Self {
        Cost {
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        for (dst, src) in k.iter_mut().zip(d.iter()) {
            *dst = *src;
        }
    } else {
        for (dst, src) in k.iter_mut().zip(key.iter()) {
            *dst = *src;
        }
    }
    let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
    for ((i, o), kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(k.iter()) {
        *i ^= *kb;
        *o ^= *kb;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad[..]);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad[..]);
    outer.update(ih);
    outer.finalize().into()
}

/// The PIN pepper derived from the sops data key.
pub fn pepper(data_key: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac_sha256(data_key, b"secret-broker pin pepper v1"))
}

fn derive(pin: &[u8], salt: &[u8], pepper: &[u8], cost: Cost) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.m_kib, cost.t, cost.p, Some(32))
        .map_err(|e| Error::msg(format!("argon2 params: {e}")))?;
    let a = Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|e| Error::msg(format!("argon2: {e}")))?;
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pin, salt, &mut out[..])
        .map_err(|e| Error::msg(format!("argon2: {e}")))?;
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub cost: Cost,
    pub salt: [u8; 16],
    pub hash: [u8; 32],
    /// Anti-phishing phrase shown in every genuine approval dialog.
    pub phrase: String,
}

/// Printable, single-line, bounded.
pub fn clean_phrase(s: &str) -> Result<String> {
    let t = s.trim();
    if t.chars().count() > MAX_PHRASE {
        bail!("phrase is longer than {MAX_PHRASE} characters");
    }
    if t.chars().any(char::is_control) {
        bail!("phrase must not contain control characters");
    }
    Ok(t.to_string())
}

impl Record {
    pub fn create(pin: &[u8], pepper: &[u8], cost: Cost, phrase: &str) -> Result<Self> {
        if pin.len() > MAX_PIN {
            bail!("PIN too long");
        }
        let mut salt = [0u8; 16];
        crate::sys::random(&mut salt)?;
        let hash = derive(pin, &salt, pepper, cost)?;
        Ok(Record {
            cost,
            salt,
            hash: *hash,
            phrase: clean_phrase(phrase)?,
        })
    }

    pub fn verify(&self, pin: &[u8], pepper: &[u8]) -> Result<bool> {
        if pin.len() > MAX_PIN {
            return Ok(false);
        }
        let h = derive(pin, &self.salt, pepper, self.cost)?;
        Ok(crate::sops::ct_eq(&h[..], &self.hash))
    }

    pub fn encode(&self) -> String {
        format!(
            "{MAGIC} {VERSION} argon2id m={} t={} p={} salt={} hash={} phrase={}\n",
            self.cost.m_kib,
            self.cost.t,
            self.cost.p,
            B64.encode(self.salt),
            B64.encode(self.hash),
            B64.encode(self.phrase.as_bytes()),
        )
    }

    pub fn decode(s: &str) -> Result<Self> {
        let mut it = s.split_ascii_whitespace();
        if it.next() != Some(MAGIC) || it.next() != Some(VERSION) || it.next() != Some("argon2id") {
            bail!("unrecognized PIN file");
        }
        let mut cost = Cost::default();
        let mut salt = None;
        let mut hash = None;
        let mut phrase = String::new();
        for field in it {
            let Some((k, v)) = field.split_once('=') else {
                bail!("bad PIN file field");
            };
            let num = || {
                v.parse::<u32>()
                    .map_err(|_| Error::msg("bad PIN file number"))
            };
            match k {
                "m" => cost.m_kib = num()?,
                "t" => cost.t = num()?,
                "p" => cost.p = num()?,
                "salt" => {
                    let b = B64.decode(v).map_err(|_| Error::msg("bad PIN salt"))?;
                    salt = Some(
                        <[u8; 16]>::try_from(b.as_slice())
                            .map_err(|_| Error::msg("bad PIN salt"))?,
                    );
                }
                "hash" => {
                    let b = B64.decode(v).map_err(|_| Error::msg("bad PIN hash"))?;
                    hash = Some(
                        <[u8; 32]>::try_from(b.as_slice())
                            .map_err(|_| Error::msg("bad PIN hash"))?,
                    );
                }
                "phrase" => {
                    let b = B64.decode(v).map_err(|_| Error::msg("bad PIN phrase"))?;
                    phrase = clean_phrase(&String::from_utf8_lossy(&b))?;
                }
                _ => {}
            }
        }
        match (salt, hash) {
            (Some(salt), Some(hash)) => Ok(Record {
                cost,
                salt,
                hash,
                phrase,
            }),
            _ => bail!("incomplete PIN file"),
        }
    }
}

pub fn load(path: &Path) -> Result<Option<Record>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(Record::decode(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::from(e).context(path.display())),
    }
}

/// Atomically replace the PIN file (dir 0700, file 0600).
pub fn save(path: &Path, rec: &Record) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::msg("PIN file has no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let tmp = dir.join(".pin.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(rec.encode().as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Delay before the next attempt after `failures` consecutive wrong PINs:
/// 0, 1, 2, 4, 8 ... seconds, capped at 60.
pub fn backoff(failures: u32) -> Duration {
    if failures <= 1 {
        return Duration::from_secs(0);
    }
    let exp = failures.saturating_sub(2).min(6);
    Duration::from_secs(1u64.checked_shl(exp).unwrap_or(60).min(60))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const CHEAP: Cost = Cost {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    #[test]
    fn hmac_rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_long_key() {
        // RFC 4231 test case 6: 131-byte key.
        let key = [0xaau8; 131];
        let mac = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn verify_and_roundtrip() {
        let pep = pepper(&[7u8; 32]);
        let r = Record::create(b"123456", &pep[..], CHEAP, " my phrase ").unwrap();
        assert_eq!(r.phrase, "my phrase");
        assert!(r.verify(b"123456", &pep[..]).unwrap());
        assert!(!r.verify(b"123457", &pep[..]).unwrap());
        // Wrong pepper (different data key) never verifies.
        let other = pepper(&[8u8; 32]);
        assert!(!r.verify(b"123456", &other[..]).unwrap());
        let d = Record::decode(&r.encode()).unwrap();
        assert_eq!(d, r);
        assert!(Record::decode("garbage").is_err());
        assert!(Record::decode("secret-broker-pin v1 argon2id m=1").is_err());
    }

    #[test]
    fn phrase_rules() {
        assert!(clean_phrase("blue otter").is_ok());
        assert!(clean_phrase("a\nb").is_err());
        assert!(clean_phrase(&"x".repeat(MAX_PHRASE + 1)).is_err());
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1).as_secs(), 0);
        assert_eq!(backoff(2).as_secs(), 1);
        assert_eq!(backoff(3).as_secs(), 2);
        assert_eq!(backoff(5).as_secs(), 8);
        assert_eq!(backoff(50).as_secs(), 60);
    }

    #[test]
    fn save_load() {
        let dir = std::env::temp_dir().join(format!("sb-pin-{}", std::process::id()));
        let path = dir.join("auth").join("pin");
        let pep = pepper(&[1u8; 32]);
        let r = Record::create(b"0000", &pep[..], CHEAP, "").unwrap();
        save(&path, &r).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), r);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        remove(&path).unwrap();
        assert!(load(&path).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
