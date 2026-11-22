# secret-broker

Let an AI agent (or any process running as you) **use** secrets through
allowlisted commands, without being able to **read** them.

```
you (once per session)       agent (as many times as it likes)
──────────────────────       ─────────────────────────────────
secret-broker unlock         secret-run gh pr list
  └ gpg + pinentry: approve    └ broker checks the allowlist, runs gh as
                                 user agent-secrets with GH_TOKEN set,
                                 streams back stdout/stderr/exit code only
```

* Secrets live in a **sops JSON file encrypted to your gpg key**.
* A NixOS service runs as a dedicated system user `agent-secrets`. While
  unlocked it keeps the decrypted values **only in memory** (mlock'ed,
  excluded from core dumps, process marked non-dumpable) and wipes them on
  `lock`, when the TTL expires, or when the service stops.
* There is **no operation that returns a secret value**. The socket offers
  `status`, `lock`, `unlock` and `exec <profile>` and nothing else.
* Commands run as `agent-secrets`, a different uid, so you (and the agent)
  cannot read `/proc/<pid>/environ` or `/proc/<pid>/mem` or ptrace them.

## Why it's built this way

Every `xxx run -- cmd` wrapper that starts the child as **your** uid (sops
exec-env, fnox, secretspec, envchain, `op run`, psst...) cannot stop a
same-user caller: it can read `/proc/<child>/environ`, ptrace the child, ask
the same keyring over D-Bus, or simply run `wrapper -- env`. The only real
boundaries on Linux are a **different uid** and **not handing the value out at
all**. secret-broker provides both.

### Unlock: the caller can't feed in fake secrets
`secret-broker unlock` (run by you) reads the encrypted file, asks **gpg** to
unwrap the 32-byte sops *data key* (your pinentry prompt is the approval) and
sends **only that key** to the broker. The broker decrypts the file itself and
verifies every AES-GCM tag plus the sops MAC. The file path comes from the
system configuration (normally a `/nix/store` path; a mutable path must be
owned by root and not group/world-writable). So a same-user process that
connects to the socket cannot load fake secrets: a wrong key fails
authentication. Before and after decrypting, the client clears gpg-agent's
cached passphrase for that key (`CLEAR_PASSPHRASE`), so the prompt really
appears and the cache isn't left warm for anyone else to reuse.

### Unlock refuses a long gpg-agent cache
Clearing the cache only helps if gpg-agent doesn't re-cache the passphrase
for days the next time you sign a commit. So before asking for approval,
`unlock` runs `gpgconf --list-options gpg-agent` and **refuses** if
`default-cache-ttl` or `max-cache-ttl` is above the limits in the system
config (`services.secret-broker.gpgCacheLimits`, default **900 s / 7200 s**,
so gpg's own defaults of 600/7200 pass and a 30-day `2592000` fails):

```
secret-broker: refusing to unlock: gpg-agent caches passphrases too long:
  default-cache-ttl = 2592000s (limit 900s)  <-- too long
  max-cache-ttl     = 2592000s (limit 7200s)  <-- too long
...
Fix it in Home Manager, either
  programs.secret-broker.gpgAgent.recommended = true;   # 300s / 1800s + GUI pinentry
or
  services.gpg-agent.defaultCacheTtl = 300;
  services.gpg-agent.maxCacheTtl = 1800;
then run `home-manager switch` and `gpgconf --kill gpg-agent`.
```

There is deliberately **no override flag**: the limits live in root-owned
config, so an agent can't relax them. If `gpgconf` can't be run or parsed,
unlock is refused too (fail closed). `secret-broker status` prints the same
text as a `WARNING:` so you see it before you need to unlock. `gpgconf`
reports what's in `gpg-agent.conf`, so restart a running agent
(`gpgconf --kill gpg-agent`) after changing it.

### Exec: allowlisted shapes only
Profiles are declared in Nix: program (absolute path), fixed args, env var →
sops key mapping, and allow/deny rules for the caller's arguments:

```nix
allow = [ [ "pr" "list" ] [ "pr" "view" "*" ] [ "api" "repos/*" "**" ] ];
deny  = [ [ "auth" "**" ] ];
```

Rules are matched position by position. In a token, `*` matches anything and
`?` matches one character. A whole `**` token matches the rest of the
arguments. Without `**` the argument count must match exactly. Deny rules are
checked first. (`**` only works as the last token: a rule that starts
with `**` matches everything.) The child runs with a clean environment (`PATH` from the
profile, `HOME` = `/var/lib/secret-broker/home/<profile>`, `LANG`, the
secrets), inside the service's systemd sandbox (ProtectHome,
ProtectSystem=strict, no capabilities, ...). Output is scrubbed for the
injected values (`[REDACTED]`). That's only defence in depth: see below.

## Threat model

Protects against a process running **as you** (an AI agent, its tools, a
malicious dependency) that wants to read a secret value:

| Attack by a same-uid process | Result |
|---|---|
| read the secrets via the socket | no such operation |
| `secret-run p env`, `secret-run p sh -c 'echo $T'` | refused unless the profile allows it |
| `cat /proc/<child>/environ`, `/proc/<pid>/mem`, `strace -p` | EACCES/EPERM (different uid; broker is also non-dumpable) |
| connect and unlock with a forged key / fake file | rejected (GCM + MAC, file pinned by root) |
| `lock` | allowed on purpose (fail safe) |
| trigger `unlock` itself | you see a pinentry prompt (see residual risks) |

### Residual risks (be honest with yourself)
1. **Your gpg key decrypts everything.** Anything running as you can run
   `sops -d` / `gpg -d` on the file **if gpg-agent has the passphrase
   cached**. `unlock` clears that key's cache before and after, but other uses
   (git signing, `pass`) re-warm it, which is why `unlock` refuses a long
   cache (see above). Within the limits, a window of minutes remains. Use a
   GUI pinentry too; the HM option `programs.secret-broker.gpgAgent.recommended`
   sets both. A YubiKey or smartcard with touch-to-decrypt is the strongest
   version.
2. **Never approve a pinentry you didn't start.** (Inside `ai-run` there is no
   gpg-agent or `~/.gnupg`, so a sandboxed agent can't even ask.) If the agent runs `unlock`
   and you approve it, the agent's descendant `gpg` holds the data key and the
   agent can ptrace it (`kernel.yama.ptrace_scope=1` allows ptracing
   descendants) to read every secret. The client marks itself non-dumpable,
   but `gpg` is a separate process. Run `unlock` yourself, in a terminal the
   agent didn't spawn.
3. **The allowed program can leak.** `gh auth token`, `gh auth status -t`,
   `curl -v`, `--debug` flags, writing a config file, `gh alias`/`extension`
   (arbitrary code)... Allow narrow shapes and deny token-printing ones.
   Redaction misses transformed output (base64, split strings).
4. **Use isn't the same as read.** While unlocked, the agent can do whatever
   the allowed commands can do with the token. Use scoped, short-lived tokens.
5. **Root beats everything.** If the agent can become root (cached sudo in its
   terminal, permissive polkit rules), no user-level design holds.
6. **Shared uid between profiles.** All children run as `agent-secrets`. An
   allowed program that executes arbitrary code could read files under
   `/var/lib/secret-broker` (no secrets are stored there) but **not** the
   broker's memory (non-dumpable) or other profiles' secrets.
7. **Short-lived copies.** Values are kept in mlock'ed, `MADV_DONTDUMP`
   pages that are zeroed before unmapping. Temporary copies (decryption,
   building the child's environment, the redactor) are `Zeroizing` buffers
   wiped on drop, but the kernel copies the environment in `execve`, and
   heap copies can't be mlock'ed. The process is non-dumpable with
   `RLIMIT_CORE=0`, so only root can read them.
8. **Running children survive `lock`.** Locking stops new runs; a child that
   is already running keeps its environment until it exits (profile
   `timeout`, default 600 s).

## Setup

### NixOS (system flake)

```nix
# flake.nix
inputs.secret-broker = {
  url = "github:hadilq/secret-broker";      # or path:/home/you/dev/secret-broker
  inputs.nixpkgs.follows = "nixpkgs";
};
# modules = [ secret-broker.nixosModules.default ... ];

# configuration.nix
services.secret-broker = {
  enable = true;
  users = [ "you" ];                        # also added to group secret-broker
  secretsFile = ./secrets/agent.sops.json;  # copied to the store (it's encrypted)
  defaultTtl = 8 * 3600;
  profiles.gh = {
    description = "GitHub CLI, read-mostly";
    command = "${pkgs.gh}/bin/gh";
    env.GH_TOKEN = "github.token";
    path = [ pkgs.git pkgs.coreutils ];
    allow = [ [ "pr" "list" "**" ] [ "pr" "view" "**" ] [ "issue" "list" "**" ] [ "api" "repos/*" ] ];
    deny = [ [ "auth" "**" ] [ "alias" "**" ] [ "extension" "**" ] [ "config" "**" ] ];
  };
};
```

The child runs as `agent-secrets` with `ProtectHome=true`, so it can't see
your working directory. Pass data through arguments or stdin
(`secret-run --stdin p ...`; stdin is forwarded automatically when it isn't a
terminal). If a profile runs a JIT runtime (node, java), set
`services.secret-broker.memoryDenyWriteExecute = false`.

### Home Manager

```nix
inputs.secret-broker.url = "...";
# modules = [ secret-broker.homeManagerModules.default ];
programs.secret-broker.enable = true;
# optional: short gpg cache + the secret-broker dialog as pinentry
# programs.secret-broker.gpgAgent.recommended = true;
# programs.secret-broker.dialog.enable = true;   # default; approval dialog user service
```

### The secrets file

```sh
gpg --list-keys --with-colons you@example.org | awk -F: '/^fpr/{print $10; exit}'
cp examples/sops.yaml .sops.yaml      # put the fingerprint in
sops edit agent.sops.json             # write JSON: {"github": {"token": "..."}}
```

Only **JSON** sops files are supported (the broker decrypts them itself with
RustCrypto's AES-GCM and SHA-512; no YAML parser). Nested keys are addressed with dots
(`github.token`). Values inside arrays aren't exposed. Key groups with a
Shamir threshold > 1 aren't supported.

## Usage

```sh
secret-broker unlock --ttl 8h   # pinentry once; session lasts 8h (capped by maxTtl)
secret-broker status            # state, expiry, profiles, allow rules (never values)
secret-run gh pr list           # agent-facing; exit code is the child's
secret-broker lock              # seal (PIN/key to reopen); --forget wipes
secret-broker set-pin           # quick approval PIN (see below)
```

Exit codes: the child's own, `126` refused (locked / not allowlisted /
unknown profile), `125` broker unreachable or protocol error.

## Sessions: gpg once, then a PIN / security key / fingerprint

```
cold ──gpg unlock──▶ open ──ttl / lock──▶ sealed ──quick approval──▶ open
  ▲                                        │
  └──── lock --forget / restart / lockout / sealedTimeout ────┘
```

* **cold**: nothing in RAM. Only `secret-broker unlock` (gpg, via pinentry) helps.
* **open**: `secret-run` works until the TTL.
* **sealed**: the decrypted values stay in the broker's mlocked memory, but
  `secret-run` needs a quick approval first. If no quick method is configured,
  TTL expiry and `lock` go straight to cold (the old behaviour).
  `lock --forget` always wipes. `approval.sealedTimeout` (NixOS) wipes a sealed
  session after N seconds (0 = never).

Quick methods, all **checked by the broker**. The dialog only collects input
and shows the request.

| method | how it's verified | default |
|---|---|---|
| PIN | argon2id(pin, salt, secret = HMAC(data key)) in `/var/lib/secret-broker/auth/pin`; backoff 1,2,4…60 s; after `maxAttempts` (5) wrong PINs the secrets are wiped and gpg is needed again | on (once you `set-pin`) |
| FIDO2 key (YubiKey) | broker runs `fido2-assert` with a fresh challenge bound to the request id and purpose, then verifies the signature against the enrolled public key (user presence = touch) | off until a credential is configured |
| fingerprint | PAM service `secret-broker-fingerprint` (fprintd) run in a helper process | off |
| any PAM | `approval.pam.<name>` | none |

The PIN file is useless without the data key (it's peppered with a key derived
from it), so offline brute force needs the sops data key anyway. The PIN only
works while the session is **sealed**, never from cold.

### Setting a PIN / enrolling a security key

```sh
secret-broker unlock                 # gpg once after boot
secret-broker set-pin                # PIN twice + an anti-phishing phrase, then gpg again
secret-broker set-pin --remove
secret-broker fido2-enroll --name yubikey      # touch; prints a NixOS snippet:
#   services.secret-broker.approval.fido2.credentials = [{ name = "yubikey"; id = "…"; publicKey = ./yubikey.pub; }];
```

`set-pin` and `fido2-enroll` are refused on the sandbox socket.

### The dialog (`secret-broker-dialog`)

A ~1.2 MB Wayland layer-shell client (smithay-client-toolkit + fontdue,
software rendering into wl_shm, links only libxkbcommon and libc). It works on
any compositor with `wlr-layer-shell` (Hyprland, sway, river, niri, KDE…):
an overlay layer surface with **exclusive keyboard**, centred, and no pointer
input, so a click can't approve. It shows who asked (command, pid, parent chain,
whether it runs inside ai-run), what will run, how long it opens for, your
phrase, a PIN field, and hints for a key touch or fingerprint. It's themed from
`~/.local/state/omarchy/current/theme/colors.toml`.

Why not iced/GTK/Qt: on this nixpkgs, pinentry-qt's closure is ~753 MiB and
pinentry-gnome3's ~365 MiB. iced needs wgpu/tiny-skia + winit, so it's a few
MB of binary and still has no layer-shell or exclusive-keyboard support
without forks. The dialog has three modes:

* `prompter` (systemd user service): registers with the broker, shows approvals.
* `pinentry`: an Assuan pinentry, so the gpg unlock uses the same window
  (`pinentry-secret-broker`, which falls back to pinentry-curses without Wayland).
* `demo [--window]`: renders a sample.

Without a running dialog, `secret-broker unlock` on a terminal asks for the PIN
there (or the key touch). Inside ai-run the socket is restricted: no
unlock/approve/set-pin/prompter.

### Sandbox socket

The broker listens on two sockets: `broker.sock` (full) and `agent.sock`
(restricted). ai-run masks `broker.sock` and sets
`SECRET_BROKER_SOCKET=/run/secret-broker/agent.sock`, so a sandboxed agent
can run `secret-run` (which then waits for your approval) but can't register
a fake dialog, answer approvals, or change the PIN.

### Residual risks of the quick path

* The PIN is typed into a process running as you. Anything unsandboxed as you
  could draw a fake overlay or register its own prompter (the last registration
  wins). The phrase you chose at `set-pin` is the tell: no phrase, no PIN.
  The FIDO2 touch doesn't have this problem (the key signs the broker's challenge).
* Unsandboxed code as you can also edit the user service / environment of the
  dialog. Keep agents in ai-run.
* Requester info comes from `/proc` and can be stale if a pid is reused. It's
  advisory, and you can still approve blind.
* `agent-secrets` children can read the PIN file. It's peppered with the data
  key, so this is only an offline attack for someone who already has the key.
* Hyprland (optional): `ecosystem:enforce_permissions` with a screencopy deny
  for agents, and `layerrule = noscreenshare, secret-broker`, keep the dialog
  out of screenshots. This isn't enabled; check it against your Hyprland version.

## ai-run: sandbox the agent, not just the secrets

secret-broker keeps *its* secrets away from an agent, but an agent running
as you can still read everything else in `$HOME`: browser profiles, `gh`'s
`hosts.yml`, Proton Pass data, shell history, the keyring over D-Bus.
`ai-run` runs the agent in a [bubblewrap](https://github.com/containers/bubblewrap)
sandbox under the same uid:

| | inside `ai-run` |
|---|---|
| `/` | read-only, `/nix/store` and the nix daemon reachable (`nix build` works) |
| `$HOME` | **read-only**; writable: `~/dev`, `~/Documents`, `~/Downloads`, `~/Projects`, `~/Work`, media dirs, `~/.cache`, cargo/npm caches, plus the profile's own state (e.g. `~/.grok`) |
| credential paths | **masked** (empty tmpfs or `/dev/null`): `~/.gnupg`, `~/.ssh`, `~/.password-store`, keyrings, `gh`/`hub`/copilot, git-credentials, netrc, npm/pypi/cargo/docker/aws/gcloud/kube/rclone credentials, all browser profiles, Proton, Signal and other messengers, **other agents' logins** (`~/.config/Grok Bot`, `~/.grokbot`, `~/.grok`, `~/.claude`...), shell histories, `~/.cache/nix` (fresh, can't be poisoned) |
| `$XDG_RUNTIME_DIR` | empty tmpfs: no session bus, gpg-agent (so no `secret-broker unlock` from inside), gnome-keyring, Hyprland IPC, `systemd --user`, docker/podman, tmux, terminal IPC sockets |
| `/run` | system bus, `/run/docker.sock`, `/run/podman`, `/run/libvirt` masked (root-equivalent for your groups); `/run/secret-broker` **reachable**, so `secret-run` works |
| `/tmp` | per profile, not the host's |
| processes | own pid namespace (can't see or `/proc/<pid>/environ` your other processes), `no_new_privs` (sudo/setuid don't work) |
| env | `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*_KEY`, `AWS_*`, `GH_*`... removed; `DISPLAY`, `SSH_AUTH_SOCK`, `DBUS_SESSION_BUS_ADDRESS` removed |
| network | allowed (agents need their API) |

Why read-only `$HOME`: with a writable home, a sandboxed agent could write
`~/.config/zsh/.zshenv`, `~/.config/hypr/*`, `~/.config/autostart/*`, a
`systemd --user` unit, `~/.local/bin/grok` (Omarchy prefers it!) or replace an
HM symlink, and that code would run **outside** the sandbox the next time you
open a terminal or log in.

No SSH agent by default: the socket lets the sandbox authenticate and push as
you to every host your key opens (`sshAgent = true` per profile if you want it).
On this machine `SSH_AUTH_SOCK` is gpg-agent's, which is also hidden.

Profiles (Home Manager, `programs.ai-run.profiles.<name>`): `default`;
`grok-build` (sees and writes `~/.grok`, `$GROK_HOME`); `grok-bot` (GUI:
Wayland, PipeWire, `/dev/dri`; D-Bus through `xdg-dbus-proxy` with only
notifications, the tray and the OpenURI/FileChooser/Settings portal calls,
**not** `org.freedesktop.secrets`; its own `~/.config/Grok Bot` and
`~/.grokbot`; an `xdg-open` that sends http(s) links to your browser via the
portal); `grok-bot-tools` (Grok Bot's `$SHELL` points at a zsh that nests this
stricter sandbox, so the commands the bot runs can't read the bot's own login
or see its processes).

### Forcing agents through it
```nix
programs.ai-run = {
  enable = true;
  wrap = [ pkgs.grok-build { package = grok-bot; profile = "grok-bot"; } ];
};
```
`wrap` installs, at higher priority than the package, the same `bin/` names
and `.desktop` files pointing at `ai-run`. So `grok`, Omarchy's agent
launcher (`SUPER+SHIFT+CTRL+A` → `omarchy-agent` → agent-dispatch →
`omarchy-agent-account-exec`, which resolves `grok` on PATH outside the
dispatch dir) and the app menu / `grokbot://` links all start the sandbox.
This is best effort against *your* launch paths: anything that execs the
store path directly, or an agent that is already running unsandboxed, isn't
affected. Restart running agents after `home-manager switch`.

```sh
ai-run --list                 # profiles
ai-run                        # sandboxed $SHELL (default profile)
ai-run -p grok-build -- grok  # what the grok wrapper does
ai-run --print -p grok-bot -- grok-bot   # show the bwrap command line
```

### What it can't protect
* **Anything not started through ai-run** is unconstrained (an agent you start
  from an unwrapped path, a cron job, ...).
* **Same uid from outside**: your unsandboxed processes can still ptrace or read
  the sandbox (Yama allows descendants), so an unsandboxed agent gains nothing
  from it.
* **The app's own login**: Grok Bot must read `~/.config/Grok Bot`; the
  sandboxed app process (and its built-in file tools) can. Only the shell
  commands it runs are nested away from it. Electron's safeStorage has no
  keyring in the sandbox, so expect to sign in to Grok Bot once; the token is
  then stored with Electron's fixed fallback key, readable by the app only
  because nothing else can see that directory.
* **GUI profiles get the Wayland socket**: a Wayland client can read the
  screen and, on Hyprland, create virtual keyboards/pointers and type into
  your (unsandboxed) terminal. Use Hyprland's `ecosystem:enforce_permissions`
  rules for the app if you don't need computer use. Terminal agents get no
  Wayland socket (and no clipboard).
* **Writable code you later run**: `~/dev` is writable, so an agent can edit
  a repo's `flake.nix`, `.envrc`, Makefile or `.git/hooks` and that runs when
  you use it outside. Review diffs; put repos you don't want touched in
  `programs.ai-run.readOnly`.
* **Network**: allowed. A sandboxed agent can exfiltrate whatever it *can*
  read (your code) and use whatever `secret-run` allows.
* The terminal it runs in is outside: escape sequences (e.g. OSC 52 clipboard
  writes) still reach it. `TIOCSTI` injection is blocked by the kernel
  (`dev.tty.legacy_tiocsti = 0`; ai-run adds `--new-session` otherwise).

## Implementation (Rust, no panics)

Dependencies, kept small on purpose:

| crate | why |
|---|---|
| `aes-gcm` (no default features; `aes`, `zeroize`) | sops values are AES-256-GCM with a 32-byte nonce; RustCrypto, constant-time, zeroizes key schedules |
| `sha2` | the sops MAC is SHA-512 over the plaintext values |
| `base64` | sops encodes data/iv/tag in base64 |
| `serde`, `serde_json` (`preserve_order`) | protocol, config and the sops file; document order is needed to recompute the MAC |
| `regex` (`std` only) | sops `encrypted_regex` / `unencrypted_regex` rules |
| `zeroize` | wipe keys and temporary secret copies on drop |
| `libc` | `mlock`, `madvise(MADV_DONTDUMP)`, `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`, `SO_PEERCRED`, `getpwnam_r`, `killpg` |

`ai-run` (`src/sandbox.rs` plans the bwrap command line and is unit tested,
`src/bin/ai-run.rs` starts `xdg-dbus-proxy` with a sync pipe and execs bwrap)
uses no extra crates.

No async runtime, CLI parser or error crate: a thread per connection, a
hand-written argument parser and one `Error` enum (`src/error.rs`).

**No panics at runtime.** `Cargo.toml` denies, for all non-test code,
`clippy::{unwrap_used, expect_used, panic, panic_in_result_fn,
unwrap_in_result, get_unwrap, indexing_slicing, string_slice,
arithmetic_side_effects, unreachable, todo, unimplemented, exit,
undocumented_unsafe_blocks}`. Every fallible operation returns `Result`.
Test modules opt back in with `#[allow(...)]`. `checks.clippy` runs
`cargo clippy --all-targets -- -D warnings`, so a violation fails
`nix flake check`.

The release profile sets `panic = "abort"`: if a panic still happened (in a
dependency, or an allocation failure), the process dies at once instead of
unwinding. That means no half-unwound state with secrets in it, and no
chance that a caught panic leaves the broker serving while locks are
poisoned. systemd restarts it, and a restart is a lock (memory is gone).

## Development

```sh
nix develop
cargo clippy --all-targets -- -D warnings && cargo test
nix flake check -L                         # package + tests, clippy, NixOS VM test (needs KVM)
scripts/gen-testdata.sh                    # regenerate sops fixtures (throwaway age key)
```
