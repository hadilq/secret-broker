//! Refuse to unlock while gpg-agent caches passphrases for a long time.
//!
//! While the passphrase sits in gpg-agent's cache, anything running as you
//! (the AI agent included) can silently run `sops -d` / `gpg -d` and read every
//! secret. `unlock` clears the cache for the sops key before and after, but
//! other uses (git signing, pass) re-warm it, and a 30-day TTL keeps it warm.
//!
//! The effective settings come from `gpgconf --list-options gpg-agent`, whose
//! colon-separated lines are
//! `name:flags:level:description:type:alt-type:argname:default:argdef:value`;
//! an empty `value` means gpg-agent's built-in default (field 8).

use crate::bail;
use crate::error::{Error, Result};
use crate::proto::GpgCacheLimits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSettings {
    pub default_cache_ttl: u64,
    pub max_cache_ttl: u64,
}

fn option_value(output: &str, name: &str) -> Result<u64> {
    for line in output.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() != Some(&name) {
            continue;
        }
        let value = fields.get(9).copied().unwrap_or("");
        let default = fields.get(7).copied().unwrap_or("");
        let raw = if value.is_empty() { default } else { value };
        let raw = raw.trim_start_matches('"');
        return raw
            .parse::<u64>()
            .map_err(|_| Error::msg(format!("gpgconf: cannot parse {name} value {raw:?}")));
    }
    bail!("gpgconf output has no {name} option")
}

/// Parse `gpgconf --list-options gpg-agent`.
pub fn parse_gpgconf(output: &str) -> Result<CacheSettings> {
    Ok(CacheSettings {
        default_cache_ttl: option_value(output, "default-cache-ttl")?,
        max_cache_ttl: option_value(output, "max-cache-ttl")?,
    })
}

/// Run gpgconf and return the effective settings.
pub fn query(gpgconf: &str) -> Result<CacheSettings> {
    let out = std::process::Command::new(gpgconf)
        .args(["--list-options", "gpg-agent"])
        .output()
        .map_err(|e| Error::msg(format!("cannot run {gpgconf}: {e}")))?;
    if !out.status.success() {
        bail!(
            "{gpgconf} --list-options gpg-agent failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    parse_gpgconf(&String::from_utf8_lossy(&out.stdout))
}

/// `Ok(())` if within limits, otherwise an explanation of how to fix it.
pub fn check(s: CacheSettings, limits: GpgCacheLimits) -> Result<()> {
    let bad_default = s.default_cache_ttl > limits.default_cache_ttl;
    let bad_max = s.max_cache_ttl > limits.max_cache_ttl;
    if !bad_default && !bad_max {
        return Ok(());
    }
    let mark = |bad: bool| if bad { "  <-- too long" } else { "" };
    Err(Error::msg(format!(
        "gpg-agent caches passphrases too long:\n\
         \x20 default-cache-ttl = {}s (limit {}s){}\n\
         \x20 max-cache-ttl     = {}s (limit {}s){}\n\
         While the passphrase is cached, anything running as you (including an AI\n\
         agent) can silently decrypt the secrets file with `sops -d`.\n\
         Fix it in Home Manager, either\n\
         \x20 programs.secret-broker.gpgAgent.recommended = true;   # 300s / 1800s + GUI pinentry\n\
         or\n\
         \x20 services.gpg-agent.defaultCacheTtl = 300;\n\
         \x20 services.gpg-agent.maxCacheTtl = 1800;\n\
         then run `home-manager switch` and `gpgconf --kill gpg-agent`.\n\
         (The limits come from services.secret-broker.gpgCacheLimits in the NixOS config.)",
        s.default_cache_ttl,
        limits.default_cache_ttl,
        mark(bad_default),
        s.max_cache_ttl,
        limits.max_cache_ttl,
        mark(bad_max),
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Real output from a machine with a 30-day cache (Home Manager config).
    const LONG: &str = "\
Monitor:1:0:Options controlling the diagnostic output:0:0::::
verbose:12:0:verbose:0:0::::
default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::2592000
default-cache-ttl-ssh:24:1:expire SSH keys after N seconds:3:3:N:1800::2592000
max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::2592000
max-cache-ttl-ssh:24:2:set maximum SSH key lifetime to N seconds:3:3:N:7200::2592000
";
    // gpg-agent defaults (no gpg-agent.conf).
    const DEFAULTS: &str = "\
default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::
max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::
";
    const LIMITS: GpgCacheLimits = GpgCacheLimits {
        default_cache_ttl: 900,
        max_cache_ttl: 7200,
    };

    #[test]
    fn parses_values_and_defaults() {
        assert_eq!(
            parse_gpgconf(LONG).unwrap(),
            CacheSettings {
                default_cache_ttl: 2_592_000,
                max_cache_ttl: 2_592_000
            }
        );
        assert_eq!(
            parse_gpgconf(DEFAULTS).unwrap(),
            CacheSettings {
                default_cache_ttl: 600,
                max_cache_ttl: 7200
            }
        );
    }

    #[test]
    fn thirty_days_is_refused() {
        let e = check(parse_gpgconf(LONG).unwrap(), LIMITS)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("too long")
                && e.contains("2592000")
                && e.contains("gpgconf --kill gpg-agent"),
            "{e}"
        );
    }

    #[test]
    fn defaults_and_recommended_pass() {
        assert!(check(parse_gpgconf(DEFAULTS).unwrap(), LIMITS).is_ok());
        assert!(check(
            CacheSettings {
                default_cache_ttl: 300,
                max_cache_ttl: 1800
            },
            LIMITS
        )
        .is_ok());
        assert!(check(
            CacheSettings {
                default_cache_ttl: 300,
                max_cache_ttl: 7201
            },
            LIMITS
        )
        .is_err());
    }

    #[test]
    fn malformed() {
        assert!(parse_gpgconf("").is_err());
        assert!(parse_gpgconf(
            "default-cache-ttl:24:0:x:3:3:N:600::abc\nmax-cache-ttl:24:2:x:3:3:N:7200::"
        )
        .is_err());
        assert!(parse_gpgconf("default-cache-ttl:24\nmax-cache-ttl").is_err());
    }
}
