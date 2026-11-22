//! Decrypt a sops-encrypted JSON document with its data key and verify the
//! sops MAC.
//!
//! Why the broker does this itself instead of receiving plaintext: the
//! encrypted file is pinned by the system configuration (normally a
//! /nix/store path), and the caller only supplies the 32-byte data key it
//! unwrapped with gpg. A wrong or forged key fails AES-GCM authentication and
//! the MAC check, so a same-user process cannot feed the broker fake secrets.
//!
//! Supported: sops JSON files, AES256_GCM values of type str/int/float/bool/
//! bytes, unencrypted_suffix / encrypted_suffix / unencrypted_regex /
//! encrypted_regex, mac_only_encrypted. Not supported: key groups with
//! shamir_threshold > 1, YAML/dotenv/ini stores.

use crate::bail;
use crate::error::{Error, Result};
use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::fmt::Write as _;
use zeroize::Zeroizing;

pub const DATA_KEY_SIZE: usize = 32;

/// sops uses AES-256-GCM with a 32-byte nonce.
type Cipher = AesGcm<Aes256, U32>;

pub type Secrets = HashMap<String, Zeroizing<Vec<u8>>>;

#[derive(Deserialize, Debug, Default, Clone)]
pub struct PgpKey {
    #[serde(default)]
    pub fp: String,
    #[serde(default)]
    pub enc: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Metadata {
    #[serde(default)]
    pub pgp: Option<Vec<PgpKey>>,
    #[serde(default)]
    pub key_groups: Option<Vec<Value>>,
    #[serde(default)]
    pub shamir_threshold: Option<u64>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub lastmodified: Option<String>,
    #[serde(default)]
    pub unencrypted_suffix: Option<String>,
    #[serde(default)]
    pub encrypted_suffix: Option<String>,
    #[serde(default)]
    pub unencrypted_regex: Option<String>,
    #[serde(default)]
    pub encrypted_regex: Option<String>,
    #[serde(default)]
    pub mac_only_encrypted: Option<bool>,
}

impl Metadata {
    pub fn pgp_keys(&self) -> Vec<PgpKey> {
        self.pgp.clone().unwrap_or_default()
    }
}

/// The "sops" section, without decrypting anything.
pub fn read_metadata(doc: &[u8]) -> Result<Metadata> {
    let v: Value = serde_json::from_slice(doc)
        .map_err(|e| Error::msg(format!("sops file is not valid JSON: {e}")))?;
    match v.get("sops") {
        Some(m) => Ok(serde_json::from_value(m.clone())?),
        None => bail!("not a sops file: no top-level \"sops\" key"),
    }
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|x| !x.is_empty())
}

struct Rules {
    un_suffix: Option<String>,
    enc_suffix: Option<String>,
    un_re: Option<Regex>,
    enc_re: Option<Regex>,
}

impl Rules {
    // Mirrors sops' Tree.Decrypt decision for a leaf at `path`.
    fn encrypted(&self, path: &[String]) -> bool {
        let mut enc = true;
        if let Some(s) = &self.un_suffix {
            if path.iter().any(|p| p.ends_with(s.as_str())) {
                enc = false;
            }
        }
        if let Some(s) = &self.enc_suffix {
            enc = path.iter().any(|p| p.ends_with(s.as_str()));
        }
        if let Some(r) = &self.un_re {
            if path.iter().any(|p| r.is_match(p)) {
                enc = false;
            }
        }
        if let Some(r) = &self.enc_re {
            enc = path.iter().any(|p| r.is_match(p));
        }
        enc
    }
}

/// Parse `ENC[AES256_GCM,data:...,iv:...,tag:...,type:...]`.
fn parse_enc(value: &str) -> Option<(&str, &str, &str, &str)> {
    let inner = value
        .strip_prefix("ENC[AES256_GCM,data:")?
        .strip_suffix(']')?;
    let (data, rest) = inner.split_once(",iv:")?;
    let (iv, rest) = rest.split_once(",tag:")?;
    let (tag, typ) = rest.split_once(",type:")?;
    Some((data, iv, tag, typ))
}

/// Decrypt one value; returns plaintext and the sops type.
fn decrypt_value(cipher: &Cipher, value: &str, aad: &str) -> Result<(Zeroizing<Vec<u8>>, String)> {
    if value.is_empty() {
        return Ok((Zeroizing::new(Vec::new()), "str".into()));
    }
    let (data, iv, tag, typ) = parse_enc(value)
        .ok_or_else(|| Error::msg("value is not in sops ENC[AES256_GCM,...] format"))?;
    let bad = |_| Error::msg("bad base64 in ENC value");
    let mut ct = B64.decode(data).map_err(bad)?;
    let iv = B64.decode(iv).map_err(bad)?;
    let tag = B64.decode(tag).map_err(bad)?;
    let nonce = GenericArray::<u8, U32>::from_exact_iter(iv.iter().copied())
        .ok_or_else(|| Error::msg("unsupported nonce size (sops uses 32 bytes)"))?;
    ct.extend_from_slice(&tag);
    let pt = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::msg("authentication failed (wrong data key or tampered value)"))?;
    Ok((Zeroizing::new(pt), typ.to_string()))
}

/// Go's strconv.ParseBool.
fn parse_go_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn py_bool(b: bool) -> Vec<u8> {
    if b {
        b"True".to_vec()
    } else {
        b"False".to_vec()
    }
}

/// Mirrors sops' ToBytes() of the decrypted value; None for comments.
fn mac_bytes(pt: &[u8], typ: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let s = || std::str::from_utf8(pt).map_err(|_| Error::msg("non-UTF-8 numeric value"));
    let out = match typ {
        "str" | "bytes" => pt.to_vec(),
        "int" => s()?
            .parse::<i64>()
            .map_err(|e| Error::msg(format!("int: {e}")))?
            .to_string()
            .into_bytes(),
        "float" => format!(
            "{}",
            s()?.parse::<f64>()
                .map_err(|e| Error::msg(format!("float: {e}")))?
        )
        .into_bytes(),
        "bool" => py_bool(parse_go_bool(s()?).ok_or_else(|| Error::msg("bad bool"))?),
        "comment" => return Ok(None),
        other => bail!("unsupported sops value type {other:?}"),
    };
    Ok(Some(Zeroizing::new(out)))
}

fn plain_bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Number(n) => match n.as_f64() {
            Some(f) => format!("{f}").into_bytes(),
            None => n.to_string().into_bytes(),
        },
        Value::Bool(b) => py_bool(*b),
        Value::Null => Vec::new(),
        _ => bail!("not a leaf"),
    })
}

struct Walker<'a> {
    cipher: &'a Cipher,
    rules: Rules,
    mac_only_encrypted: bool,
    hash: Sha512,
    out: Secrets,
}

impl Walker<'_> {
    fn walk(&mut self, v: &Value, path: &mut Vec<String>, in_array: bool) -> Result<()> {
        match v {
            Value::Object(m) => {
                for (k, child) in m {
                    path.push(k.clone());
                    let r = self.walk(child, path, false);
                    path.pop();
                    r?;
                }
                Ok(())
            }
            Value::Array(a) => {
                for child in a {
                    self.walk(child, path, true)?;
                }
                Ok(())
            }
            leaf => self.leaf(leaf, path, in_array),
        }
    }

    fn leaf(&mut self, v: &Value, path: &[String], in_array: bool) -> Result<()> {
        let dotted = path.join(".");
        let enc = self.rules.encrypted(path);
        let val: Zeroizing<Vec<u8>> = if enc {
            let Value::String(s) = v else {
                bail!("{dotted}: expected an encrypted string");
            };
            let aad = format!("{}:", path.join(":"));
            let (pt, typ) = decrypt_value(self.cipher, s, &aad).map_err(|e| e.context(&dotted))?;
            if let Some(mb) = mac_bytes(&pt, &typ).map_err(|e| e.context(&dotted))? {
                self.hash.update(mb.as_slice());
            }
            pt
        } else {
            let b = Zeroizing::new(plain_bytes(v).map_err(|e| e.context(&dotted))?);
            if !self.mac_only_encrypted {
                self.hash.update(b.as_slice());
            }
            b
        };
        if !in_array {
            self.out.insert(dotted, val);
        }
        Ok(())
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Decrypt every value of `doc` with `data_key`, verify the MAC and return
/// leaves that sit directly in objects keyed by dotted path ("a.b.c").
/// Leaves inside arrays are authenticated but not returned.
pub fn decrypt(doc: &[u8], data_key: &[u8]) -> Result<Secrets> {
    if data_key.len() != DATA_KEY_SIZE {
        bail!("data key must be {DATA_KEY_SIZE} bytes");
    }
    let meta = read_metadata(doc)?;
    if meta.key_groups.as_ref().is_some_and(|g| !g.is_empty())
        && meta.shamir_threshold.unwrap_or(0) > 1
    {
        bail!("sops key groups with shamir_threshold > 1 are not supported");
    }
    let mac = non_empty(&meta.mac).ok_or_else(|| Error::msg("sops file has no MAC"))?;
    let compile = |s: &Option<String>| -> Result<Option<Regex>> {
        match non_empty(s) {
            Some(p) => Regex::new(p)
                .map(Some)
                .map_err(|e| Error::msg(format!("regex {p:?}: {e}"))),
            None => Ok(None),
        }
    };
    let rules = Rules {
        un_suffix: non_empty(&meta.unencrypted_suffix).map(str::to_string),
        enc_suffix: non_empty(&meta.encrypted_suffix).map(str::to_string),
        un_re: compile(&meta.unencrypted_regex)?,
        enc_re: compile(&meta.encrypted_regex)?,
    };
    let cipher = Cipher::new_from_slice(data_key).map_err(|_| Error::msg("invalid data key"))?;
    let root: Value = serde_json::from_slice(doc)?;
    let Value::Object(top) = &root else {
        bail!("top level of sops JSON must be an object");
    };
    let mut w = Walker {
        cipher: &cipher,
        rules,
        mac_only_encrypted: meta.mac_only_encrypted.unwrap_or(false),
        hash: Sha512::new(),
        out: HashMap::new(),
    };
    for (k, v) in top {
        if k == "sops" {
            continue;
        }
        let mut path = vec![k.clone()];
        w.walk(v, &mut path, false)?;
    }
    let digest = w.hash.finalize();
    let mut computed = String::with_capacity(128);
    for b in digest.iter() {
        let _ = write!(computed, "{b:02X}");
    }
    let lastmod = meta.lastmodified.clone().unwrap_or_default();
    let (stored, _) = decrypt_value(&cipher, mac, &lastmod).map_err(|e| e.context("MAC"))?;
    if !ct_eq(computed.as_bytes(), &stored) {
        bail!("MAC mismatch: the file was modified outside sops");
    }
    Ok(w.out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn load(name: &str, key: &str) -> (Vec<u8>, Vec<u8>) {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/");
        let doc = std::fs::read(format!("{dir}{name}")).unwrap();
        let kh = std::fs::read_to_string(format!("{dir}{key}")).unwrap();
        let kh = kh.trim();
        let key = (0..kh.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&kh[i..i + 2], 16).unwrap())
            .collect();
        (doc, key)
    }

    fn get<'a>(m: &'a Secrets, k: &str) -> &'a str {
        std::str::from_utf8(m.get(k).expect(k)).unwrap()
    }

    #[test]
    fn decrypts_real_sops_file() {
        let (doc, key) = load("secrets.sops.json", "datakey.hex");
        let m = decrypt(&doc, &key).unwrap();
        for (k, v) in [
            ("api.token", "tok-123456"),
            ("api.nested.deep", "d-val"),
            ("num", "42"),
            ("flt", "1.5"),
            ("flag", "True"),
            ("empty", ""),
            ("public_unencrypted", "visible"),
            ("pi_unencrypted", "3.14"),
        ] {
            assert_eq!(get(&m, k), v, "{k}");
        }
        assert!(!m.contains_key("list"));
    }

    #[test]
    fn encrypted_regex() {
        let (doc, key) = load("regex.sops.json", "regex.datakey.hex");
        let m = decrypt(&doc, &key).unwrap();
        assert_eq!(get(&m, "api.token"), "tok-123456");
        assert_eq!(get(&m, "num"), "42");
    }

    #[test]
    fn wrong_or_short_key() {
        let (doc, mut key) = load("secrets.sops.json", "datakey.hex");
        assert!(decrypt(&doc, &key[..16]).is_err());
        key[0] ^= 1;
        assert!(decrypt(&doc, &key).is_err());
    }

    #[test]
    fn tampered_unencrypted_value() {
        let (doc, key) = load("secrets.sops.json", "datakey.hex");
        let s = String::from_utf8(doc)
            .unwrap()
            .replacen("\"visible\"", "\"evil!!!\"", 1);
        let e = decrypt(s.as_bytes(), &key).unwrap_err().to_string();
        assert!(e.contains("MAC"), "{e}");
    }

    #[test]
    fn swapped_ciphertexts() {
        let (doc, key) = load("secrets.sops.json", "datakey.hex");
        let mut v: Value = serde_json::from_slice(&doc).unwrap();
        let tok = v["api"]["token"].clone();
        let deep = v["api"]["nested"]["deep"].clone();
        v["api"]["token"] = deep;
        v["api"]["nested"]["deep"] = tok;
        assert!(decrypt(&serde_json::to_vec(&v).unwrap(), &key).is_err());
    }

    #[test]
    fn not_sops() {
        assert!(read_metadata(b"{}").is_err());
        assert!(read_metadata(b"nope").is_err());
        assert!(decrypt(b"{\"a\":1}", &[0u8; 32]).is_err());
    }
}
