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

/// `Ok(())` when `args` are allowed, otherwise a human-readable reason.
///
/// `deny_tokens` are globs matched against every argument, any position.
/// They run after positional deny rules and before allow, so a trailing `**`
/// on an allow rule cannot sneak `--hostname` / `--debug` through.
pub fn check(
    allow: &[Vec<String>],
    deny: &[Vec<String>],
    deny_tokens: &[String],
    args: &[String],
) -> Result<(), String> {
    if args.iter().any(|a| a.contains('\0')) {
        return Err("argument contains a NUL byte".into());
    }
    if let Some(r) = deny.iter().find(|r| matches(r, args)) {
        return Err(format!("arguments {args:?} match deny rule {r:?}"));
    }
    if let Some(tok) = args
        .iter()
        .find(|a| deny_tokens.iter().any(|p| glob(p, a)))
    {
        return Err(format!("argument {tok:?} is denied"));
    }
    if allow.iter().any(|r| matches(r, args)) {
        Ok(())
    } else {
        Err(format!("arguments {args:?} match no allow rule"))
    }
}

#[cfg(test)]
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
            assert!(check(&allow, &deny, none, &a).is_ok(), "{a:?}");
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
            assert!(check(&allow, &deny, none, &a).is_err(), "{a:?}");
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
        assert!(check(&allow, &deny, &toks, &v(&["pr", "list"])).is_ok());
        assert!(check(&allow, &deny, &toks, &v(&["api", "repos/x"])).is_ok());
        assert!(check(&allow, &deny, &toks, &v(&["pr", "list", "--json"])).is_ok());
        for a in [
            v(&["pr", "list", "--hostname", "evil.com"]),
            v(&["pr", "list", "--hostname=evil.com"]),
            v(&["api", "repos/x", "--debug"]),
            v(&["api", "repos/x", "-v"]),
            v(&["pr", "list", "--verbose"]),
            v(&["api", "repos/x", "--config", "/tmp/gh.yml"]),
            v(&["pr", "list", "--config=/tmp/gh.yml"]),
        ] {
            let err = check(&allow, &deny, &toks, &a).err();
            assert!(
                err.as_ref().is_some_and(|e| e.contains("is denied")),
                "{a:?}: {err:?}"
            );
        }
    }
}
