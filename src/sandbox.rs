//! `ai-run`: run a program (an AI agent) in a bubblewrap sandbox under the
//! same uid, with credential paths masked, most of $HOME read-only and only
//! an explicit set of sockets reachable.
//!
//! This module only *plans* the sandbox (pure, unit-tested); `src/bin/ai-run.rs`
//! starts the optional D-Bus proxy and execs bwrap.

use crate::bail;
use crate::error::Result;
use crate::policy::glob;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Absolute path of `bwrap`.
    pub bwrap: String,
    /// Absolute path of `xdg-dbus-proxy` (needed by profiles with `dbus`).
    pub dbus_proxy: Option<String>,
    /// Paths hidden from every profile (relative paths are under $HOME).
    /// Directories become an empty tmpfs, files and sockets /dev/null.
    pub mask: Vec<String>,
    /// Paths that stay writable; everything else under / (and $HOME) is read-only.
    pub writable: Vec<String>,
    /// Paths re-mounted read-only (useful inside a writable path).
    pub read_only: Vec<String>,
    /// Environment variables always removed (globs allowed).
    pub env_unset: Vec<String>,
    /// Environment variables removed unless the profile keeps them (globs).
    pub env_deny: Vec<String>,
    /// Environment variables set in every profile (a profile's `env` wins).
    pub env: BTreeMap<String, String>,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub description: String,
    /// Global masks this profile may see (exact entries of `mask`).
    pub unmask: Vec<String>,
    pub extra_mask: Vec<String>,
    /// Extra writable paths; missing directories are created.
    pub writable: Vec<String>,
    pub read_only: Vec<String>,
    /// Environment variables naming extra writable directories (e.g.
    /// `GROK_HOME`, set by Omarchy's account switcher). Used only if set,
    /// absolute and existing.
    pub writable_from_env: Vec<String>,
    /// Wayland socket, PipeWire/PulseAudio sockets and /dev/dri.
    pub gui: bool,
    /// Filtered session bus through xdg-dbus-proxy; `None` = no session bus.
    pub dbus: Option<Dbus>,
    /// Expose $SSH_AUTH_SOCK (off by default: it can sign as you).
    pub ssh_agent: bool,
    /// Extra names inside $XDG_RUNTIME_DIR to expose read-only.
    pub runtime_files: Vec<String>,
    /// Variables to set inside the sandbox.
    pub env: BTreeMap<String, String>,
    /// Exceptions to `env_deny`.
    pub keep_env: Vec<String>,
    /// Directories prepended to PATH.
    pub path_prefix: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dbus {
    pub talk: Vec<String>,
    pub own: Vec<String>,
    pub call: Vec<String>,
    pub broadcast: Vec<String>,
}

impl Dbus {
    /// xdg-dbus-proxy filter arguments (after `--filter`).
    pub fn proxy_args(&self) -> Vec<String> {
        let mut v = vec!["--filter".to_string()];
        v.extend(self.talk.iter().map(|s| format!("--talk={s}")));
        v.extend(self.own.iter().map(|s| format!("--own={s}")));
        v.extend(self.call.iter().map(|s| format!("--call={s}")));
        v.extend(self.broadcast.iter().map(|s| format!("--broadcast={s}")));
        v
    }
}

impl Config {
    pub fn parse(json: &[u8]) -> Result<Config> {
        let c: Config = serde_json::from_slice(json)?;
        if !c.bwrap.starts_with('/') {
            bail!("config: bwrap must be an absolute path");
        }
        for (name, p) in &c.profiles {
            if p.dbus.is_some() && c.dbus_proxy.is_none() {
                bail!("config: profile {name:?} uses dbus but dbus_proxy is not set");
            }
            for k in p.env.keys() {
                if k.is_empty() || k.contains('=') {
                    bail!("config: profile {name:?}: bad env name {k:?}");
                }
            }
        }
        Ok(c)
    }
}

/// What a path is on the (outer) filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Missing,
    Dir,
    /// File, socket, device...
    Other,
}

/// Filesystem facts the planner needs (faked in tests).
pub trait Probe {
    /// Follows symlinks; `None` if the path (or its target) doesn't exist.
    fn resolve(&self, p: &Path) -> Option<PathBuf>;
    fn kind(&self, p: &Path) -> Kind;
}

pub struct RealFs;

impl Probe for RealFs {
    fn resolve(&self, p: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(p).ok()
    }
    fn kind(&self, p: &Path) -> Kind {
        match std::fs::metadata(p) {
            Ok(m) if m.is_dir() => Kind::Dir,
            Ok(_) => Kind::Other,
            Err(_) => Kind::Missing,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ctx {
    pub home: PathBuf,
    pub runtime_dir: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    /// `dev.tty.legacy_tiocsti` is on, so the sandbox needs its own session.
    pub legacy_tiocsti: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// bwrap arguments, without the trailing `-- cmd...`.
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Directories ai-run creates (mode 0700) before starting bwrap.
    pub create_dirs: Vec<PathBuf>,
    /// D-Bus proxy to start: filter and the socket path it listens on.
    pub proxy: Option<(Dbus, PathBuf)>,
}

/// `~/x`, `x` (relative to home) or `/abs`; rejects empty and `..`.
pub fn expand(home: &Path, p: &str) -> Result<PathBuf> {
    let rest = if p == "~" {
        ""
    } else {
        p.strip_prefix("~/").unwrap_or(p)
    };
    let rest = rest.trim_end_matches('/');
    let path = if rest.starts_with('/') {
        PathBuf::from(rest)
    } else if rest.is_empty() {
        home.to_path_buf()
    } else {
        home.join(rest)
    };
    if p.trim().is_empty() || path.components().any(|c| c == Component::ParentDir) {
        bail!("invalid path {p:?}");
    }
    Ok(path)
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn in_store(p: &Path) -> bool {
    p.starts_with("/nix/store")
}

fn env_get<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
    env.iter()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

fn any_glob(pats: &[String], name: &str) -> bool {
    pats.iter().any(|p| glob(p, name))
}

/// Variables that would hand the sandbox a way out regardless of config.
const ALWAYS_UNSET: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
    "WAYLAND_DISPLAY",
    "TMPDIR",
];

/// Full (unlock/approve/PIN) socket. Sandboxes may only see agent.sock.
const BROKER_SOCK: &[&str] = &[
    "/run/secret-broker/broker.sock",
    "/var/run/secret-broker/broker.sock",
];
const AGENT_SOCK: &str = "/run/secret-broker/agent.sock";
const BROKER_DIR: &[&str] = &["/run/secret-broker", "/var/run/secret-broker"];
/// Host `/run` is parked here, then `/tmp` is replaced so the copy is gone
/// before the command starts. Binds of paths under `/run` must use this
/// source: after `--tmpfs /run` the original paths are not visible to bwrap.
const HOST_RUN: &str = "/tmp/.ai-run-host-run";

fn host_run_src(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("/run") {
        return Path::new(HOST_RUN).join(rest);
    }
    if let Ok(rest) = p.strip_prefix("/var/run") {
        return Path::new(HOST_RUN).join(rest);
    }
    p.to_path_buf()
}

fn is_broker_sock(p: &Path) -> bool {
    BROKER_SOCK.iter().any(|s| p == Path::new(s))
}

fn is_forbidden_writable(p: &Path) -> bool {
    const ROOTS: &[&str] = &[
        "/", "/run", "/var", "/var/run", "/etc", "/usr", "/dev", "/proc", "/sys",
    ];
    if ROOTS.iter().any(|s| p == Path::new(s)) {
        return true;
    }
    BROKER_DIR
        .iter()
        .any(|s| p == Path::new(s) || p.starts_with(s))
}

fn points_at_broker_sock(v: &str) -> bool {
    BROKER_SOCK.contains(&v)
}

pub fn plan(cfg: &Config, name: &str, ctx: &Ctx, fs: &dyn Probe) -> Result<Plan> {
    let Some(prof) = cfg.profiles.get(name) else {
        let known: Vec<&str> = cfg.profiles.keys().map(String::as_str).collect();
        bail!("unknown profile {name:?} (known: {})", known.join(", "));
    };
    let home = ctx.home.as_path();
    let mut a: Vec<String> = Vec::new();
    let mut push = |xs: &[&str]| a.extend(xs.iter().map(|x| (*x).to_string()));
    push(&[
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        // Also in the environment below; here so the broker can name the
        // profile from bwrap's command line (it never reads environments).
        "--setenv",
        "AI_RUN_PROFILE",
        name,
    ]);
    if prof.gui {
        push(&["--dev-bind-try", "/dev/dri", "/dev/dri"]);
    }
    if ctx.legacy_tiocsti {
        push(&["--new-session"]);
    }
    let mut p = Plan::default();

    // Hide /run (docker.sock, system bus, pcscd, libvirt, ...). A bind of
    // /dev/null over those sockets drops when the daemon restarts and creates
    // a new inode; a tmpfs on /run does not. `--ro-bind / /` makes /tmp
    // read-only, so park host /run on a fresh tmpfs, then tmpfs /run, then
    // bind only the paths we need from the copy. Overlaying /tmp later hides
    // that copy.
    push(&["--tmpfs", "/tmp"]);
    push(&["--ro-bind-try", "/run", HOST_RUN]);
    push(&["--tmpfs", "/run"]);
    if fs
        .resolve(Path::new("/var/run"))
        .is_some_and(|r| r != Path::new("/run"))
    {
        push(&["--tmpfs", "/var/run"]);
    }
    push(&[
        "--ro-bind-try",
        &format!("{HOST_RUN}/current-system"),
        "/run/current-system",
    ]);
    if prof.gui {
        push(&[
            "--ro-bind-try",
            &format!("{HOST_RUN}/opengl-driver"),
            "/run/opengl-driver",
        ]);
        push(&[
            "--ro-bind-try",
            &format!("{HOST_RUN}/opengl-driver-32"),
            "/run/opengl-driver-32",
        ]);
    }

    // Hide the full broker socket even if it appears after we start: a tmpfs
    // on the directory, /dev/null over broker.sock, then bind only agent.sock.
    let mut sock_dirs: Vec<PathBuf> = Vec::new();
    for (d, sock) in BROKER_DIR.iter().zip(BROKER_SOCK) {
        let path = PathBuf::from(d);
        let key = fs.resolve(&path).unwrap_or(path);
        if sock_dirs.iter().any(|x| x == &key) {
            continue;
        }
        sock_dirs.push(key);
        push(&["--tmpfs", d]);
        push(&["--ro-bind-try", "/dev/null", sock]);
    }
    let agent_src = s(&host_run_src(Path::new(AGENT_SOCK)));
    push(&["--bind-try", &agent_src, AGENT_SOCK]);

    // /tmp: per-profile, shared by that profile's instances (Electron's
    // single-instance socket lives there), never the host's.
    // $XDG_RUNTIME_DIR: an empty tmpfs plus the sockets the profile may use.
    // That hides the session bus, gpg-agent, gnome-keyring, Hyprland IPC,
    // systemd --user, docker/podman, tmux, terminals' IPC sockets...
    let rt = ctx.runtime_dir.clone();
    if let Some(rt) = &rt {
        let base = rt.join("ai-run").join(name);
        let tmp = base.join("tmp");
        p.create_dirs.push(tmp.clone());
        a.extend(["--bind".into(), s(&tmp), "/tmp".into()]);
        a.extend(["--perms".into(), "0700".into(), "--tmpfs".into(), s(rt)]);
        let mut expose: Vec<PathBuf> = Vec::new();
        if prof.gui {
            if let Some(w) = env_get(&ctx.env, "WAYLAND_DISPLAY") {
                expose.push(if w.starts_with('/') {
                    PathBuf::from(w)
                } else {
                    rt.join(w)
                });
            }
            expose.push(rt.join("pipewire-0"));
            expose.push(rt.join("pulse").join("native"));
        }
        for f in &prof.runtime_files {
            if f.contains("..") || f.starts_with('/') {
                bail!("runtime_files entry {f:?} must be a plain name under XDG_RUNTIME_DIR");
            }
            expose.push(rt.join(f));
        }
        if prof.ssh_agent {
            if let Some(sock) = env_get(&ctx.env, "SSH_AUTH_SOCK") {
                expose.push(PathBuf::from(sock));
            }
        }
        for e in expose {
            a.extend(["--ro-bind-try".into(), s(&host_run_src(&e)), s(&e)]);
        }
        if let Some(d) = &prof.dbus {
            let dir = base.join(format!("proxy-{}", std::process::id()));
            let sock = dir.join("bus");
            p.create_dirs.push(dir);
            let inner = rt.join("bus");
            a.extend(["--ro-bind".into(), s(&host_run_src(&sock)), s(&inner)]);
            p.env.push((
                "DBUS_SESSION_BUS_ADDRESS".into(),
                format!("unix:path={}", s(&inner)),
            ));
            p.proxy = Some((d.clone(), sock));
        }
    } else {
        push(&["--tmpfs", "/tmp"]);
        if prof.dbus.is_some() || prof.gui {
            bail!("profile {name:?} needs XDG_RUNTIME_DIR (gui/dbus)");
        }
    }

    // Writable paths. Global ones only if they exist; the profile's own
    // state directories are created.
    for w in &cfg.writable {
        let path = expand(home, w)?;
        if let Some(r) = fs.resolve(&path).filter(|r| !in_store(r)) {
            if is_forbidden_writable(&r) {
                bail!(
                    "writable {w:?} resolves to {}, which would expose the host",
                    r.display()
                );
            }
            a.extend(["--bind".into(), s(&r), s(&r)]);
        }
    }
    for w in &prof.writable {
        let path = expand(home, w)?;
        let r = match fs.resolve(&path) {
            Some(r) => r,
            None => {
                p.create_dirs.push(path.clone());
                path
            }
        };
        if is_forbidden_writable(&r) {
            bail!(
                "writable {w:?} resolves to {}, which would expose the host",
                r.display()
            );
        }
        if !in_store(&r) {
            a.extend(["--bind".into(), s(&r), s(&r)]);
        }
    }
    for var in &prof.writable_from_env {
        let Some(v) = env_get(&ctx.env, var) else {
            continue;
        };
        let path = PathBuf::from(v);
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            continue;
        }
        if let Some(r) = fs
            .resolve(&path)
            .filter(|r| !in_store(r) && fs.kind(r) == Kind::Dir)
        {
            if is_forbidden_writable(&r) {
                bail!(
                    "writable_from_env {var}={v:?} resolves to {}, which would expose the host",
                    r.display()
                );
            }
            a.extend(["--bind".into(), s(&r), s(&r)]);
        }
    }
    for ro in cfg.read_only.iter().chain(&prof.read_only) {
        let path = expand(home, ro)?;
        if let Some(r) = fs.resolve(&path).filter(|r| !in_store(r)) {
            a.extend(["--ro-bind".into(), s(&r), s(&r)]);
        }
    }

    // Masks last, so they win over the binds above.
    let unmask: Vec<PathBuf> = prof
        .unmask
        .iter()
        .map(|u| expand(home, u))
        .collect::<Result<_>>()?;
    for u in &unmask {
        if is_broker_sock(u) {
            bail!("unmask of the full broker socket is not allowed");
        }
    }
    for m in cfg.mask.iter().chain(&prof.extra_mask) {
        let path = expand(home, m)?;
        if unmask.contains(&path) {
            continue;
        }
        let Some(r) = fs.resolve(&path) else { continue };
        if in_store(&r) {
            continue;
        }
        if r.starts_with("/run") || r.starts_with("/var/run") {
            continue;
        }
        match fs.kind(&r) {
            Kind::Missing => {}
            Kind::Dir => a.extend(["--tmpfs".into(), s(&r)]),
            Kind::Other => a.extend(["--ro-bind".into(), "/dev/null".into(), s(&r)]),
        }
    }
    p.args = a;

    // Environment.
    let mut env: Vec<(String, String)> = ctx
        .env
        .iter()
        .filter(|(k, _)| {
            let always = ALWAYS_UNSET.contains(&k.as_str())
                && !(k == "WAYLAND_DISPLAY" && prof.gui)
                && !(k == "SSH_AUTH_SOCK" && prof.ssh_agent);
            !always
                && !any_glob(&cfg.env_unset, k)
                && !(any_glob(&cfg.env_deny, k) && !any_glob(&prof.keep_env, k))
        })
        .cloned()
        .collect();
    env.retain(|(k, _)| {
        !prof.env.contains_key(k)
            && !cfg.env.contains_key(k)
            && k != "AI_RUN_PROFILE"
            && k != "AI_RUN_CONFIG"
    });
    env.append(&mut p.env);
    env.extend(
        cfg.env
            .iter()
            .filter(|(k, _)| !prof.env.contains_key(*k))
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    env.extend(prof.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env.push(("AI_RUN_PROFILE".into(), name.to_string()));
    if let Some((_, v)) = env.iter().find(|(k, _)| k == "SECRET_BROKER_SOCKET") {
        if points_at_broker_sock(v) {
            bail!("SECRET_BROKER_SOCKET must not point at the full broker socket");
        }
    }
    if !prof.path_prefix.is_empty() {
        let old = env_get(&env, "PATH")
            .unwrap_or("/run/current-system/sw/bin")
            .to_string();
        env.retain(|(k, _)| k != "PATH");
        let mut parts = prof.path_prefix.clone();
        parts.push(old);
        env.push(("PATH".into(), parts.join(":")));
    }
    p.env = env;
    Ok(p)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake(HashMap<PathBuf, (Kind, PathBuf)>);
    impl Fake {
        fn new(entries: &[(&str, Kind)]) -> Self {
            Fake(
                entries
                    .iter()
                    .map(|(p, k)| (PathBuf::from(p), (*k, PathBuf::from(p))))
                    .collect(),
            )
        }
        fn link(mut self, from: &str, to: &str, k: Kind) -> Self {
            self.0.insert(PathBuf::from(from), (k, PathBuf::from(to)));
            self.0.insert(PathBuf::from(to), (k, PathBuf::from(to)));
            self
        }
    }
    impl Probe for Fake {
        fn resolve(&self, p: &Path) -> Option<PathBuf> {
            self.0.get(p).map(|(_, t)| t.clone())
        }
        fn kind(&self, p: &Path) -> Kind {
            self.0.get(p).map(|(k, _)| *k).unwrap_or(Kind::Missing)
        }
    }

    fn cfg() -> Config {
        Config::parse(
            br#"{
            "bwrap": "/nix/store/x-bwrap/bin/bwrap",
            "dbus_proxy": "/nix/store/x-proxy/bin/xdg-dbus-proxy",
            "mask": [".gnupg", "~/.config/Grok Bot", ".netrc", ".missing", "/run/docker.sock", ".hm-link"],
            "writable": ["dev", ".cache", "Absent"],
            "read_only": ["dev/hm/.git/hooks"],
            "env_unset": ["DISPLAY"],
            "env_deny": ["*TOKEN*", "AWS_*", "*SECRET*"],
            "env": {"SECRET_BROKER_SOCKET": "/run/secret-broker/agent.sock", "SHELL": "/global"},
            "profiles": {
              "default": {},
              "bot": {
                "unmask": [".config/Grok Bot"],
                "writable": [".config/Grok Bot", ".grokbot"],
                "gui": true,
                "dbus": {"talk": ["org.freedesktop.Notifications"]},
                "env": {"SHELL": "/nix/store/w/zsh"},
                "keep_env": ["GROK_TOKEN"],
                "writable_from_env": ["GROK_HOME", "NOPE"],
                "path_prefix": ["/nix/store/shim/bin"]
              }
            }}"#,
        )
        .unwrap()
    }

    fn ctx() -> Ctx {
        Ctx {
            home: "/home/u".into(),
            runtime_dir: Some("/run/user/1000".into()),
            env: [
                ("PATH", "/bin"),
                ("HOME", "/home/u"),
                ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
                ("WAYLAND_DISPLAY", "wayland-1"),
                ("SSH_AUTH_SOCK", "/run/user/1000/gnupg/S.gpg-agent.ssh"),
                ("DISPLAY", ":0"),
                ("GH_TOKEN", "x"),
                ("GROK_TOKEN", "y"),
                ("AWS_SECRET_ACCESS_KEY", "z"),
                ("TERM", "xterm"),
                ("GROK_HOME", "/home/u/.local/share/acct"),
            ]
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
            legacy_tiocsti: false,
        }
    }

    fn fs() -> Fake {
        Fake::new(&[
            ("/home/u/.gnupg", Kind::Dir),
            ("/home/u/.config/Grok Bot", Kind::Dir),
            ("/home/u/.netrc", Kind::Other),
            ("/run/docker.sock", Kind::Other),
            ("/home/u/dev", Kind::Dir),
            ("/home/u/.cache", Kind::Dir),
            ("/home/u/dev/hm/.git/hooks", Kind::Dir),
            ("/home/u/.local/share/acct", Kind::Dir),
        ])
        .link("/home/u/.hm-link", "/nix/store/abc-file", Kind::Other)
    }

    fn has(args: &[String], seq: &[&str]) -> bool {
        args.windows(seq.len())
            .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
    }

    fn pos(args: &[String], seq: &[&str]) -> usize {
        args.windows(seq.len())
            .position(|w| w.iter().zip(seq).all(|(a, b)| a == b))
            .unwrap()
    }

    #[test]
    fn default_profile_masks_and_isolates() {
        let p = plan(&cfg(), "default", &ctx(), &fs()).unwrap();
        let a = &p.args;
        assert!(has(a, &["--ro-bind", "/", "/"]));
        assert!(has(a, &["--tmpfs", "/tmp"]));
        assert!(has(a, &["--ro-bind-try", "/run", "/tmp/.ai-run-host-run"]));
        assert!(
            pos(a, &["--ro-bind-try", "/run", "/tmp/.ai-run-host-run"])
                > pos(a, &["--tmpfs", "/tmp"])
        );
        assert!(has(a, &["--tmpfs", "/run"]));
        assert!(
            pos(a, &["--tmpfs", "/run"])
                > pos(a, &["--ro-bind-try", "/run", "/tmp/.ai-run-host-run"])
        );
        assert!(has(a, &["--tmpfs", "/run/secret-broker"]));
        assert!(has(
            a,
            &[
                "--bind-try",
                "/tmp/.ai-run-host-run/secret-broker/agent.sock",
                "/run/secret-broker/agent.sock"
            ]
        ));
        assert!(
            pos(
                a,
                &[
                    "--bind",
                    "/run/user/1000/ai-run/default/tmp",
                    "/tmp"
                ]
            ) > pos(a, &["--tmpfs", "/run"])
        );
        assert!(has(
            a,
            &[
                "--ro-bind-try",
                "/dev/null",
                "/run/secret-broker/broker.sock"
            ]
        ));
        assert!(has(a, &["--unshare-pid"]));
        assert!(!a.iter().any(|x| x == "--new-session"));
        assert!(has(a, &["--perms", "0700", "--tmpfs", "/run/user/1000"]));
        assert!(has(
            a,
            &["--bind", "/run/user/1000/ai-run/default/tmp", "/tmp"]
        ));
        assert!(has(a, &["--tmpfs", "/home/u/.gnupg"]));
        assert!(has(a, &["--tmpfs", "/home/u/.config/Grok Bot"]));
        assert!(has(a, &["--ro-bind", "/dev/null", "/home/u/.netrc"]));
        // docker.sock lives under /run: the tmpfs hides it, including a
        // socket recreated when dockerd restarts. Do not bind the host path.
        assert!(!has(a, &["--ro-bind", "/dev/null", "/run/docker.sock"]));
        assert!(!a.iter().any(|x| x == "/run/docker.sock"));
        assert!(has(
            a,
            &[
                "--ro-bind-try",
                "/tmp/.ai-run-host-run/current-system",
                "/run/current-system"
            ]
        ));
        assert!(has(a, &["--bind", "/home/u/dev", "/home/u/dev"]));
        assert!(has(
            a,
            &[
                "--ro-bind",
                "/home/u/dev/hm/.git/hooks",
                "/home/u/dev/hm/.git/hooks"
            ]
        ));
        // missing paths and store symlinks are skipped
        assert!(!a.iter().any(|x| x.contains(".missing")
            || x.contains("Absent")
            || x.contains("/nix/store/abc")));
        // no gui / bus / agent
        assert!(!a
            .iter()
            .any(|x| x.contains("wayland") || x.contains("/dev/dri") || x.ends_with("/bus")));
        assert!(p.proxy.is_none());
        // masks come after the writable binds
        assert!(
            pos(a, &["--tmpfs", "/home/u/.gnupg"])
                > pos(a, &["--bind", "/home/u/dev", "/home/u/dev"])
        );
        let names: Vec<&str> = p.env.iter().map(|(k, _)| k.as_str()).collect();
        for gone in [
            "DBUS_SESSION_BUS_ADDRESS",
            "WAYLAND_DISPLAY",
            "SSH_AUTH_SOCK",
            "DISPLAY",
            "GH_TOKEN",
            "GROK_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert!(!names.contains(&gone), "{gone} leaked");
        }
        assert!(names.contains(&"TERM") && names.contains(&"PATH"));
        assert!(p.env.contains(&("AI_RUN_PROFILE".into(), "default".into())));
        // global env is set even though it matches env_deny
        assert!(p.env.contains(&(
            "SECRET_BROKER_SOCKET".into(),
            "/run/secret-broker/agent.sock".into()
        )));
        assert_eq!(names.iter().filter(|n| **n == "SHELL").count(), 1);
        assert!(p.env.contains(&("SHELL".into(), "/global".into())));
    }

    #[test]
    fn run_tmpfs_hides_docker_and_system_bus() {
        let host = Fake::new(&[
            ("/home/u/.gnupg", Kind::Dir),
            ("/home/u/.config/Grok Bot", Kind::Dir),
            ("/home/u/.netrc", Kind::Other),
            ("/run/docker.sock", Kind::Other),
            ("/run/dbus/system_bus_socket", Kind::Other),
            ("/home/u/dev", Kind::Dir),
            ("/home/u/.cache", Kind::Dir),
            ("/home/u/dev/hm/.git/hooks", Kind::Dir),
            ("/var/run", Kind::Dir),
            ("/var/run/docker.sock", Kind::Other),
        ]);
        let p = plan(&cfg(), "default", &ctx(), &host).unwrap();
        let a = &p.args;
        assert!(has(a, &["--tmpfs", "/run"]));
        assert!(has(a, &["--tmpfs", "/var/run"]));
        assert!(!a.iter().any(|x| x == "/run/docker.sock"));
        assert!(!a.iter().any(|x| x == "/run/dbus/system_bus_socket"));
        assert!(!a.iter().any(|x| x == "/var/run/docker.sock"));
        assert!(has(a, &["--ro-bind-try", "/run", "/tmp/.ai-run-host-run"]));
        assert!(has(
            a,
            &[
                "--bind-try",
                "/tmp/.ai-run-host-run/secret-broker/agent.sock",
                "/run/secret-broker/agent.sock"
            ]
        ));
    }

    #[test]
    fn gui_profile_gets_wayland_proxy_and_own_state() {
        let p = plan(&cfg(), "bot", &ctx(), &fs()).unwrap();
        let a = &p.args;
        assert!(!has(a, &["--tmpfs", "/home/u/.config/Grok Bot"]));
        assert!(has(
            a,
            &[
                "--bind",
                "/home/u/.config/Grok Bot",
                "/home/u/.config/Grok Bot"
            ]
        ));
        assert!(has(a, &["--bind", "/home/u/.grokbot", "/home/u/.grokbot"]));
        assert!(p.create_dirs.contains(&PathBuf::from("/home/u/.grokbot")));
        assert!(has(a, &["--tmpfs", "/home/u/.gnupg"]));
        assert!(has(
            a,
            &[
                "--ro-bind-try",
                "/tmp/.ai-run-host-run/user/1000/wayland-1",
                "/run/user/1000/wayland-1"
            ]
        ));
        assert!(has(a, &["--tmpfs", "/run"]));
        assert!(has(a, &["--dev-bind-try", "/dev/dri", "/dev/dri"]));
        assert!(has(
            a,
            &[
                "--ro-bind-try",
                "/tmp/.ai-run-host-run/opengl-driver",
                "/run/opengl-driver"
            ]
        ));
        assert!(!a.iter().any(|x| x.contains("S.gpg-agent")));
        let (d, sock) = p.proxy.clone().unwrap();
        assert_eq!(
            d.proxy_args(),
            vec!["--filter", "--talk=org.freedesktop.Notifications"]
        );
        assert!(has(
            a,
            &[
                "--ro-bind",
                &host_run_src(&sock).to_string_lossy(),
                "/run/user/1000/bus"
            ]
        ));
        let get = |k: &str| p.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        // a profile's env wins over the global env
        assert_eq!(get("SHELL").as_deref(), Some("/nix/store/w/zsh"));
        assert_eq!(p.env.iter().filter(|(n, _)| n == "SHELL").count(), 1);
        assert_eq!(
            get("DBUS_SESSION_BUS_ADDRESS").unwrap(),
            "unix:path=/run/user/1000/bus"
        );
        assert_eq!(get("WAYLAND_DISPLAY").unwrap(), "wayland-1");
        assert_eq!(get("SHELL").unwrap(), "/nix/store/w/zsh");
        assert_eq!(get("GROK_TOKEN").unwrap(), "y");
        assert!(get("GH_TOKEN").is_none());
        assert_eq!(get("PATH").unwrap(), "/nix/store/shim/bin:/bin");
        assert!(has(
            a,
            &[
                "--bind",
                "/home/u/.local/share/acct",
                "/home/u/.local/share/acct"
            ]
        ));
        let d = plan(&cfg(), "default", &ctx(), &fs()).unwrap();
        assert!(!d.args.iter().any(|x| x.contains("acct")));
    }

    #[test]
    fn tiocsti_and_errors() {
        let mut c = ctx();
        c.legacy_tiocsti = true;
        assert!(plan(&cfg(), "default", &c, &fs())
            .unwrap()
            .args
            .iter()
            .any(|x| x == "--new-session"));
        assert!(plan(&cfg(), "nope", &ctx(), &fs()).is_err());
        c.runtime_dir = None;
        assert!(plan(&cfg(), "bot", &c, &fs()).is_err());
        let p = plan(&cfg(), "default", &c, &fs()).unwrap();
        assert!(has(&p.args, &["--tmpfs", "/tmp"]));
        assert!(expand(Path::new("/h"), "../etc").is_err());
        assert!(expand(Path::new("/h"), "").is_err());
        assert_eq!(
            expand(Path::new("/h"), "~/.ssh/").unwrap(),
            PathBuf::from("/h/.ssh")
        );
        assert_eq!(
            expand(Path::new("/h"), "/run/x").unwrap(),
            PathBuf::from("/run/x")
        );
        assert!(Config::parse(br#"{"bwrap":"bwrap"}"#).is_err());
        assert!(Config::parse(br#"{"bwrap":"/b","profiles":{"x":{"dbus":{}}}}"#).is_err());
        assert!(Config::parse(br#"{"bwrap":"/b","bogus":1}"#).is_err());
    }

    #[test]
    fn sandbox_cannot_reach_full_broker_socket() {
        let mut c = cfg();
        c.profiles
            .get_mut("bot")
            .unwrap()
            .unmask
            .push("/run/secret-broker/broker.sock".into());
        let e = plan(&c, "bot", &ctx(), &fs()).unwrap_err().to_string();
        assert!(e.contains("unmask of the full broker socket"), "{e}");

        let mut grok_ctx = ctx();
        grok_ctx.env.retain(|(k, _)| k != "GROK_HOME");
        grok_ctx.env.push(("GROK_HOME".into(), "/run".into()));
        let host = Fake::new(&[
            ("/home/u/.gnupg", Kind::Dir),
            ("/home/u/.config/Grok Bot", Kind::Dir),
            ("/home/u/.netrc", Kind::Other),
            ("/run/docker.sock", Kind::Other),
            ("/home/u/dev", Kind::Dir),
            ("/home/u/.cache", Kind::Dir),
            ("/home/u/dev/hm/.git/hooks", Kind::Dir),
            ("/run", Kind::Dir),
        ]);
        let e = plan(&cfg(), "bot", &grok_ctx, &host)
            .unwrap_err()
            .to_string();
        assert!(e.contains("would expose the host"), "{e}");

        let mut c = cfg();
        c.env.insert(
            "SECRET_BROKER_SOCKET".into(),
            "/run/secret-broker/broker.sock".into(),
        );
        let e = plan(&c, "default", &ctx(), &fs()).unwrap_err().to_string();
        assert!(e.contains("full broker socket"), "{e}");

        let mut c = cfg();
        c.profiles
            .get_mut("bot")
            .unwrap()
            .unmask
            .push("/var/run/secret-broker/broker.sock".into());
        let e = plan(&c, "bot", &ctx(), &fs()).unwrap_err().to_string();
        assert!(e.contains("unmask of the full broker socket"), "{e}");

        let mut c = cfg();
        c.writable.push("/etc".into());
        let host = Fake::new(&[
            ("/home/u/.gnupg", Kind::Dir),
            ("/home/u/.config/Grok Bot", Kind::Dir),
            ("/home/u/.netrc", Kind::Other),
            ("/run/docker.sock", Kind::Other),
            ("/home/u/dev", Kind::Dir),
            ("/home/u/.cache", Kind::Dir),
            ("/home/u/dev/hm/.git/hooks", Kind::Dir),
            ("/etc", Kind::Dir),
        ]);
        let e = plan(&c, "default", &ctx(), &host).unwrap_err().to_string();
        assert!(e.contains("would expose the host"), "{e}");

        let mut c = cfg();
        c.writable.push("/run/secret-broker".into());
        let host = Fake::new(&[
            ("/home/u/.gnupg", Kind::Dir),
            ("/home/u/.config/Grok Bot", Kind::Dir),
            ("/home/u/.netrc", Kind::Other),
            ("/run/docker.sock", Kind::Other),
            ("/home/u/dev", Kind::Dir),
            ("/home/u/.cache", Kind::Dir),
            ("/home/u/dev/hm/.git/hooks", Kind::Dir),
            ("/run/secret-broker", Kind::Dir),
        ]);
        let e = plan(&c, "default", &ctx(), &host).unwrap_err().to_string();
        assert!(e.contains("would expose the host"), "{e}");

        let mut c = cfg();
        c.profiles.get_mut("default").unwrap().env.insert(
            "SECRET_BROKER_SOCKET".into(),
            "/var/run/secret-broker/broker.sock".into(),
        );
        let e = plan(&c, "default", &ctx(), &fs()).unwrap_err().to_string();
        assert!(e.contains("full broker socket"), "{e}");
    }
}
