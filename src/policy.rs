//! Argument allow/deny rules.
//!
//! A rule is a list of tokens matched position by position against the
//! caller's arguments (after the profile's fixed args):
//!
//! * `*` inside a token matches any run of characters (including `/`)
//! * `?` matches exactly one character
//! * `**` as a whole token matches all remaining arguments (zero or more);
//!   it is only meaningful as the last token
//!
//! Without a trailing `**` the argument count must equal the rule length.
//! Deny rules are checked first; then at least one allow rule must match.

/// Wildcard match (`*`, `?`) over bytes, iterative with backtracking.
pub fn glob(pattern: &str, s: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = s.as_bytes();
    let (mut p, mut i) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while i < txt.len() {
        let pc = pat.get(p).copied();
        let tc = txt.get(i).copied();
        if pc == Some(b'*') {
            star = Some(p);
            mark = i;
            p = p.saturating_add(1);
        } else if pc.is_some() && (pc == Some(b'?') || pc == tc) {
            p = p.saturating_add(1);
            i = i.saturating_add(1);
        } else if let Some(st) = star {
            p = st.saturating_add(1);
            mark = mark.saturating_add(1);
            i = mark;
        } else {
            return false;
        }
    }
    while pat.get(p) == Some(&b'*') {
        p = p.saturating_add(1);
    }
    p == pat.len()
}

pub fn matches(rule: &[String], args: &[String]) -> bool {
    for (i, tok) in rule.iter().enumerate() {
        if tok == "**" {
            return true;
        }
        match args.get(i) {
            Some(a) if glob(tok, a) => {}
            _ => return false,
        }
    }
    args.len() == rule.len()
}

/// Sent to the caller on any policy refusal. Must not quote arguments:
/// a redacted copy would confirm a guessed secret (`[REDACTED]` vs the guess).
pub const CLIENT_DENY: &str = "arguments not allowed";

/// Forms of `arg` that deny/allow flag globs are matched against.
/// Combined short flags (`-vh`) expand to `-v` and `-h`; `--foo=bar` also
/// yields `--foo`.
pub fn flag_forms(arg: &str) -> Vec<String> {
    let mut out = vec![arg.to_string()];
    if let Some(rest) = arg.strip_prefix("--") {
        if let Some((name, _)) = rest.split_once('=') {
            if !name.is_empty() {
                out.push(format!("--{name}"));
            }
        }
        return out;
    }
    let bytes = arg.as_bytes();
    if bytes.len() >= 3
        && bytes.first() == Some(&b'-')
        && bytes.get(1) != Some(&b'-')
        && bytes.iter().skip(1).all(u8::is_ascii_alphabetic)
    {
        for c in arg.chars().skip(1) {
            out.push(format!("-{c}"));
        }
    }
    out
}

fn is_flag(a: &str) -> bool {
    a.starts_with('-') && a != "-" && a != "--"
}

fn glob_any(pats: &[String], s: &str) -> bool {
    pats.iter().any(|p| glob(p, s))
}

/// `Ok(())` when `args` are allowed, otherwise a human-readable reason
/// (for logs). Callers must send [`CLIENT_DENY`] to the client, not this
/// string, so a guess cannot be confirmed by redaction.
///
/// `deny_tokens` are globs matched against every argument and against each
/// letter of a combined short flag, any position.
/// `allow_flags`, when non-empty, is an allowlist: every flag must match.
pub fn check(
    allow: &[Vec<String>],
    deny: &[Vec<String>],
    deny_tokens: &[String],
    allow_flags: &[String],
    args: &[String],
) -> Result<(), String> {
    if args.iter().any(|a| a.contains('\0')) {
        return Err("argument contains a NUL byte".into());
    }
    if let Some(r) = deny.iter().find(|r| matches(r, args)) {
        return Err(format!("arguments {args:?} match deny rule {r:?}"));
    }
    let mut after_end = false;
    for a in args {
        if a == "--" {
            after_end = true;
            continue;
        }
        if after_end {
            continue;
        }
        let forms = flag_forms(a);
        if let Some(tok) = forms.iter().find(|f| glob_any(deny_tokens, f)) {
            return Err(format!("argument {tok:?} is denied"));
        }
        if !allow_flags.is_empty() && is_flag(a) && !forms.iter().any(|f| glob_any(allow_flags, f))
        {
            return Err(format!("flag {a:?} is not on the allow list"));
        }
    }
    if allow.iter().any(|r| matches(r, args)) {
        Ok(())
    } else {
        Err(format!("arguments {args:?} match no allow rule"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn glob_cases() {
        let cases = [
            ("pr", "pr", true),
            ("pr", "prx", false),
            ("*", "", true),
            ("*", "a/b", true),
            ("repos/*", "repos/a/b", true),
            ("repos/*", "user", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*.json", "x.json", true),
            ("*.json", "x.jsonx", false),
            ("--limit=*", "--limit=5", true),
            ("a*b*c", "aXXbYYc", true),
            ("a*b*c", "aXXbYY", false),
        ];
        for (p, s, ok) in cases {
            assert_eq!(glob(p, s), ok, "glob({p:?},{s:?})");
        }
    }

    #[test]
    fn check_rules() {
        let allow = vec![
            v(&["pr", "list"]),
            v(&["pr", "view", "*"]),
            v(&["api", "repos/*", "**"]),
            v(&["run", "**"]),
        ];
        let deny = vec![v(&["auth", "**"]), v(&["run", "token"])];
        let none: &[String] = &[];
        for a in [
            v(&["pr", "list"]),
            v(&["pr", "view", "12"]),
            v(&["api", "repos/x/y"]),
            v(&["api", "repos/x", "--paginate"]),
            v(&["run", "list"]),
            v(&["run"]),
        ] {
            assert!(check(&allow, &deny, none, none, &a).is_ok(), "{a:?}");
        }
        for a in [
            v(&["pr"]),
            v(&["pr", "list", "--json"]),
            v(&["auth", "token"]),
            v(&["api", "user"]),
            v(&["run", "token"]),
            v(&[]),
            v(&["pr", "list\0"]),
        ] {
            assert!(check(&allow, &deny, none, none, &a).is_err(), "{a:?}");
        }
    }

    #[test]
    fn deny_tokens_block_leaky_flags() {
        let allow = vec![v(&["pr", "list", "**"]), v(&["api", "repos/*", "**"])];
        let deny: Vec<Vec<String>> = vec![];
        let toks = v(&[
            "--hostname",
            "--hostname=*",
            "--debug",
            "-v",
            "--verbose",
            "--config",
            "--config=*",
        ]);
        let none: &[String] = &[];
        assert!(check(&allow, &deny, &toks, none, &v(&["pr", "list"])).is_ok());
        assert!(check(&allow, &deny, &toks, none, &v(&["api", "repos/x"])).is_ok());
        assert!(check(&allow, &deny, &toks, none, &v(&["pr", "list", "--json"])).is_ok());
        for a in [
            v(&["pr", "list", "--hostname", "evil.com"]),
            v(&["pr", "list", "--hostname=evil.com"]),
            v(&["api", "repos/x", "--debug"]),
            v(&["api", "repos/x", "-v"]),
            v(&["pr", "list", "--verbose"]),
            v(&["api", "repos/x", "--config", "/tmp/gh.yml"]),
            v(&["pr", "list", "--config=/tmp/gh.yml"]),
        ] {
            let err = check(&allow, &deny, &toks, none, &a).err();
            assert!(
                err.as_ref().is_some_and(|e| e.contains("is denied")),
                "{a:?}: {err:?}"
            );
        }
        // Positional deny still wins; empty deny_tokens does not change allow.
        assert!(check(&allow, &deny, &[], none, &v(&["pr", "list", "--debug"])).is_ok());
        let deny_auth = vec![v(&["auth", "**"])];
        assert!(
            check(&allow, &deny_auth, &toks, none, &v(&["auth", "token"]))
                .err()
                .is_some_and(|e| e.contains("deny rule"))
        );
    }

    #[test]
    fn combined_short_flags_and_jq_are_denied() {
        let allow = vec![v(&["pr", "list", "**"])];
        let deny: Vec<Vec<String>> = vec![];
        let toks = v(&["-v", "--jq", "-q", "--quiet", "--jq=*"]);
        let none: &[String] = &[];
        assert!(check(&allow, &deny, &toks, none, &v(&["pr", "list"])).is_ok());
        for a in [
            v(&["pr", "list", "--jq"]),
            v(&["pr", "list", "-q"]),
            v(&["pr", "list", "--quiet"]),
            v(&["pr", "list", "-vq"]),
            v(&["pr", "list", "-qh"]),
            v(&["pr", "list", "--jq=body"]),
        ] {
            let err = check(&allow, &deny, &toks, none, &a).err();
            assert!(
                err.as_ref().is_some_and(|e| e.contains("is denied")),
                "{a:?}: {err:?}"
            );
        }
    }

    #[test]
    fn allow_flags_is_an_allowlist() {
        let allow = vec![v(&["pr", "list", "**"])];
        let deny: Vec<Vec<String>> = vec![];
        let none: &[String] = &[];
        let flags = v(&["--json", "--limit", "--limit=*"]);
        assert!(check(&allow, &deny, none, &flags, &v(&["pr", "list", "--json"])).is_ok());
        assert!(check(&allow, &deny, none, &flags, &v(&["pr", "list", "12"])).is_ok());
        let err = check(&allow, &deny, none, &flags, &v(&["pr", "list", "--jq"]))
            .err()
            .unwrap_or_default();
        assert!(err.contains("allow list"), "{err}");
        // Args after `--` are not flags.
        assert!(check(
            &allow,
            &deny,
            none,
            &flags,
            &v(&["pr", "list", "--", "--jq"])
        )
        .is_ok());
    }

    #[test]
    fn client_deny_does_not_quote_arguments() {
        assert_eq!(CLIENT_DENY, "arguments not allowed");
        assert!(!CLIENT_DENY.contains('['));
        let err = check(&[], &[], &[], &[], &v(&["s3cr3t-guess"]))
            .err()
            .unwrap_or_default();
        assert!(err.contains("s3cr3t-guess"));
        assert_ne!(err, CLIENT_DENY);
    }
}
