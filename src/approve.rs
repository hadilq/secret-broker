//! Hardware quick-approval verifiers, run by the broker while a dialog is
//! open. Each runs in its own thread and talks to the device through a
//! separate process (libfido2's command line tools, or our own `pam-check`
//! helper), so device and PAM-module code never runs inside the process that
//! holds the secrets. The broker itself checks every result:
//!
//! - FIDO2: the broker picks a fresh random challenge per request, asks the
//!   key for an assertion with user presence, checks the returned client data
//!   hash and relying party match, and verifies the signature against the
//!   public key configured in the (root-owned) NixOS config.
//! - PAM: success is the helper's exit status; the service file is root-owned.

use crate::config::{Fido2Config, Fido2Credential, PamMethod};
use crate::error::{Error, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwEvent {
    Approved(String),
    Info(String),
}

/// A set of running verifiers. Dropping it stops them and kills their
/// processes.
pub struct Hw {
    stop: Arc<AtomicBool>,
    pids: Arc<Mutex<Vec<u32>>>,
    tx: Sender<HwEvent>,
    rx: Receiver<HwEvent>,
}

impl Default for Hw {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hw {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let pids = self.pids.lock().unwrap_or_else(|p| p.into_inner());
        for pid in pids.iter() {
            crate::sys::kill_group(*pid);
        }
    }
}

/// Runs a command in its own process group, registered for killing, and
/// returns (success, stdout).
fn run(
    pids: &Mutex<Vec<u32>>,
    stop: &AtomicBool,
    cmd: &mut Command,
    input: &[u8],
) -> Result<(bool, Vec<u8>)> {
    if stop.load(Ordering::SeqCst) {
        return Err(Error::msg("stopped"));
    }
    cmd.process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| {
        eprintln!("approval helper {:?}: {e}", cmd.get_program());
        Error::from(e)
    })?;
    let pid = child.id();
    pids.lock().unwrap_or_else(|p| p.into_inner()).push(pid);
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(input);
    }
    let out = child.wait_with_output();
    pids.lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|p| *p != pid);
    let out = out?;
    if !out.status.success() && !stop.load(Ordering::SeqCst) {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        eprintln!(
            "approval helper {:?} exited {}: {}",
            cmd.get_program(),
            out.status,
            crate::server::sanitize(first, 200)
        );
    }
    Ok((out.status.success(), out.stdout))
}

/// Client data hash for one approval request.
pub fn challenge(request_id: u64, purpose: &str) -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    crate::sys::random(&mut nonce)?;
    let mut h = Sha256::new();
    h.update(b"secret-broker approval v1\0");
    h.update(nonce);
    h.update(request_id.to_be_bytes());
    h.update(purpose.as_bytes());
    Ok(h.finalize().into())
}

/// Device paths from `fido2-token -L` ("/dev/hidraw3: vendor=...").
pub fn parse_devices(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split_once(": ").map(|(d, _)| d.trim().to_string()))
        .filter(|d| d.starts_with("/dev/"))
        .collect()
}

/// Check `fido2-assert -G` output against what we asked for and return the
/// input for `fido2-assert -V`.
pub fn check_assertion(out: &str, cdh_b64: &str, rp: &str) -> Option<String> {
    let mut lines = out.lines().map(str::trim);
    let (c, r, authdata, sig) = (lines.next()?, lines.next()?, lines.next()?, lines.next()?);
    if c != cdh_b64 || r != rp || authdata.is_empty() || sig.is_empty() {
        return None;
    }
    Some(format!("{c}\n{r}\n{authdata}\n{sig}\n"))
}

struct Fido2Run {
    tools: PathBuf,
    rp: String,
    cdh_b64: String,
}

impl Fido2Run {
    fn assert_one(
        &self,
        pids: &Mutex<Vec<u32>>,
        stop: &AtomicBool,
        dev: &str,
        cred: &Fido2Credential,
    ) -> Result<bool> {
        let input = format!("{}\n{}\n{}\n", self.cdh_b64, self.rp, cred.id);
        let (ok, out) = run(
            pids,
            stop,
            Command::new(self.tools.join("fido2-assert"))
                .args(["-G", "-p", "-t", "up=true"])
                .arg(dev),
            input.as_bytes(),
        )?;
        if !ok {
            return Ok(false);
        }
        let Some(verify_input) =
            check_assertion(&String::from_utf8_lossy(&out), &self.cdh_b64, &self.rp)
        else {
            return Ok(false);
        };
        let (ok, _) = run(
            pids,
            stop,
            Command::new(self.tools.join("fido2-assert"))
                .args(["-V", "-p"])
                .arg(&cred.public_key_file)
                .arg(&cred.kind),
            verify_input.as_bytes(),
        )?;
        Ok(ok)
    }
}

impl Hw {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Hw {
            stop: Arc::new(AtomicBool::new(false)),
            pids: Arc::new(Mutex::new(Vec::new())),
            tx,
            rx,
        }
    }

    pub fn try_recv(&self) -> Option<HwEvent> {
        self.rx.try_recv().ok()
    }

    /// Wait for a touch on any plugged-in key that holds one of the
    /// configured credentials.
    pub fn start_fido2(&self, cfg: &Fido2Config, request_id: u64, purpose: &str) -> Result<()> {
        let cdh = challenge(request_id, purpose)?;
        let job = Arc::new(Fido2Run {
            tools: PathBuf::from(&cfg.tools_dir),
            rp: cfg.rp_id.clone(),
            cdh_b64: B64.encode(cdh),
        });
        let creds = Arc::new(cfg.credentials.clone());
        let (stop, pids, tx) = (
            Arc::clone(&self.stop),
            Arc::clone(&self.pids),
            self.tx.clone(),
        );
        std::thread::spawn(move || {
            let mut said_insert = false;
            while !stop.load(Ordering::SeqCst) {
                let devs = match run(
                    &pids,
                    &stop,
                    Command::new(job.tools.join("fido2-token")).arg("-L"),
                    b"",
                ) {
                    Ok((_, out)) => parse_devices(&String::from_utf8_lossy(&out)),
                    Err(_) => Vec::new(),
                };
                if devs.is_empty() {
                    if !said_insert {
                        said_insert = true;
                        let _ = tx.send(HwEvent::Info("Insert your security key".into()));
                    }
                    std::thread::sleep(Duration::from_millis(700));
                    continue;
                }
                let (rtx, rrx) = mpsc::channel::<bool>();
                let n = devs.len();
                for dev in devs {
                    let (job, creds, stop, pids, rtx) = (
                        Arc::clone(&job),
                        Arc::clone(&creds),
                        Arc::clone(&stop),
                        Arc::clone(&pids),
                        rtx.clone(),
                    );
                    std::thread::spawn(move || {
                        for cred in creds.iter() {
                            if matches!(job.assert_one(&pids, &stop, &dev, cred), Ok(true)) {
                                let _ = rtx.send(true);
                                return;
                            }
                        }
                        let _ = rtx.send(false);
                    });
                }
                drop(rtx);
                let approved = rrx.iter().take(n).any(|ok| ok);
                if approved && !stop.load(Ordering::SeqCst) {
                    let _ = tx.send(HwEvent::Approved("fido2".into()));
                    return;
                }
                std::thread::sleep(Duration::from_millis(700));
            }
        });
        Ok(())
    }

    /// Authenticate `user` against a PAM service through the `pam-check`
    /// helper (a separate process running our own binary).
    pub fn start_pam(&self, m: &PamMethod, helper: &Path, user: &str) {
        let (stop, pids, tx) = (
            Arc::clone(&self.stop),
            Arc::clone(&self.pids),
            self.tx.clone(),
        );
        let (m, helper, user) = (m.clone(), helper.to_path_buf(), user.to_string());
        std::thread::spawn(move || {
            for attempt in 1..=m.retries {
                let res = run(
                    &pids,
                    &stop,
                    Command::new(&helper)
                        .arg("pam-check")
                        .arg(&m.service)
                        .arg(&user)
                        .env_clear(),
                    b"",
                );
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if matches!(res, Ok((true, _))) {
                    let _ = tx.send(HwEvent::Approved(m.name.clone()));
                    return;
                }
                let msg = if attempt < m.retries {
                    format!("{}: not recognized, try again", m.name)
                } else {
                    format!("{}: giving up", m.name)
                };
                let _ = tx.send(HwEvent::Info(msg));
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn devices() {
        let out = "/dev/hidraw3: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\nioctl: x\n/dev/hidraw5: vendor=1\n";
        assert_eq!(parse_devices(out), vec!["/dev/hidraw3", "/dev/hidraw5"]);
        assert!(parse_devices("").is_empty());
    }

    #[test]
    fn assertion_checks() {
        let ok = "Q0RI\nsecret-broker\nQVVUSA==\nU0lH\n";
        assert_eq!(
            check_assertion(ok, "Q0RI", "secret-broker").unwrap(),
            "Q0RI\nsecret-broker\nQVVUSA==\nU0lH\n"
        );
        // Replayed assertion for another challenge or rp is refused.
        assert!(check_assertion(ok, "OTHER", "secret-broker").is_none());
        assert!(check_assertion(ok, "Q0RI", "evil").is_none());
        assert!(check_assertion("Q0RI\nsecret-broker\n", "Q0RI", "secret-broker").is_none());
    }

    #[test]
    fn challenges_differ() {
        assert_ne!(challenge(1, "x").unwrap(), challenge(1, "x").unwrap());
    }
}
