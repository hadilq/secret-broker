//! Details about the requesting process, read by the dialog (it runs as the
//! same user, so it can see /proc of processes inside ai-run sandboxes; the
//! broker itself can't, by design: it runs with ProtectProc=invisible).
//! Shown to help you decide; the pid can be reused, so treat it as a hint.

use std::path::Path;

fn clean(s: &str, max: usize) -> String {
    secret_broker::server::sanitize(s.trim(), max)
}

pub fn cmdline(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let parts: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let mut first = parts.first().cloned().unwrap_or_default();
    if first.starts_with("/nix/store/") {
        if let Some(name) = Path::new(&first).file_name() {
            first = name.to_string_lossy().into_owned();
        }
    }
    let rest = parts.get(1..).unwrap_or(&[]).join(" ");
    Some(clean(&format!("{first} {rest}"), 200))
}

fn status_field(pid: i32, field: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(field).map(|v| v.trim().to_string()))
}

pub fn comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| clean(&s, 32))
}

/// Parent chain, nearest first: "zsh ← grok ← ai-run ← bwrap ← …".
pub fn chain(pid: i32, depth: usize) -> String {
    let mut out = Vec::new();
    let mut cur = status_field(pid, "PPid:").and_then(|p| p.parse::<i32>().ok());
    while let Some(p) = cur {
        if p <= 1 || out.len() >= depth {
            break;
        }
        match comm(p) {
            Some(c) => {
                if c == "systemd" {
                    break;
                }
                out.push(c);
            }
            None => break,
        }
        cur = status_field(p, "PPid:").and_then(|v| v.parse::<i32>().ok());
    }
    out.join(" ← ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn own_process() {
        let me = i32::try_from(std::process::id()).unwrap();
        assert!(cmdline(me).unwrap().contains("secret_broker_dialog"));
        assert!(!comm(me).unwrap().is_empty());
        let _ = chain(me, 6);
        assert!(cmdline(-5).is_none());
    }
}
