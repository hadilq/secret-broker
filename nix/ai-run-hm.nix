# programs.ai-run: run AI agents in a bubblewrap sandbox (same uid) that
# masks credential paths, keeps most of $HOME read-only and exposes no
# session bus / gpg-agent / keyring / compositor IPC. See README.md.
{ config, lib, pkgs, ... }:
let
  cfg = config.programs.ai-run;
  inherit (lib) mkOption mkEnableOption mkIf types literalExpression;

  dbusType = types.submodule {
    options = {
      talk = mkOption { type = types.listOf types.str; default = [ ]; };
      own = mkOption { type = types.listOf types.str; default = [ ]; };
      call = mkOption { type = types.listOf types.str; default = [ ]; };
      broadcast = mkOption { type = types.listOf types.str; default = [ ]; };
    };
  };

  profileType = types.submodule {
    options = {
      description = mkOption { type = types.str; default = ""; };
      unmask = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Entries of `mask` this profile may see (exact strings).";
      };
      extraMask = mkOption { type = types.listOf types.str; default = [ ]; };
      writable = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra writable paths (relative to $HOME); missing directories are created.";
      };
      readOnly = mkOption { type = types.listOf types.str; default = [ ]; };
      writableFromEnv = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Variables naming extra writable directories (e.g. GROK_HOME).";
      };
      gui = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Wayland, PipeWire/PulseAudio and /dev/dri. A Wayland client can read
          the screen and, on Hyprland, create virtual keyboards: see README.
        '';
      };
      dbus = mkOption {
        type = types.nullOr dbusType;
        default = null;
        description = "Filtered session bus (xdg-dbus-proxy). null = no session bus.";
      };
      sshAgent = mkOption {
        type = types.bool;
        default = false;
        description = "Expose $SSH_AUTH_SOCK (lets the sandbox sign/authenticate as you).";
      };
      runtimeFiles = mkOption { type = types.listOf types.str; default = [ ]; };
      env = mkOption { type = types.attrsOf types.str; default = { }; };
      keepEnv = mkOption { type = types.listOf types.str; default = [ ]; };
      pathPrefix = mkOption { type = types.listOf types.str; default = [ ]; };
    };
  };

  toJsonProfile = p: {
    inherit (p) description unmask writable env;
    extra_mask = p.extraMask;
    read_only = p.readOnly;
    writable_from_env = p.writableFromEnv;
    inherit (p) gui dbus;
    ssh_agent = p.sshAgent;
    runtime_files = p.runtimeFiles;
    keep_env = p.keepEnv;
    path_prefix = p.pathPrefix;
  };

  configFile = pkgs.writeText "ai-run.json" (builtins.toJSON {
    bwrap = "${cfg.bubblewrap}/bin/bwrap";
    dbus_proxy = "${pkgs.xdg-dbus-proxy}/bin/xdg-dbus-proxy";
    mask = cfg.mask ++ cfg.extraMask;
    writable = cfg.writable ++ cfg.extraWritable;
    read_only = cfg.readOnly;
    env_unset = cfg.envUnset;
    env_deny = cfg.envDeny;
    inherit (cfg) env;
    profiles = lib.mapAttrs (_: toJsonProfile) cfg.profiles;
  });

  # `ai-run` with the store config baked in: the sandboxed side can't edit
  # it (a config under ~/.config could be swapped by a sandboxed agent).
  aiRun = lib.setPrio (-20) (pkgs.writeShellScriptBin "ai-run" ''
    exec ${cfg.package}/bin/ai-run --config ${configFile} "$@"
  '');

  # Grok Bot runs tool commands with $SHELL (it keeps the path if it
  # contains "zsh"). Point it at a zsh that nests a stricter sandbox, so
  # those commands can't read the app's own login.
  # (ai-run exports AI_RUN_CONFIG, the store path of this config; referring
  # to configFile here directly would be a cycle. Inside the sandbox a
  # changed value can only nest a *different* sandbox inside this one.)
  toolsShell = pkgs.writeShellScriptBin "zsh" ''
    exec ${cfg.package}/bin/ai-run --config "''${AI_RUN_CONFIG:?}" --profile grok-bot-tools -- ${cfg.toolsShell} "$@"
  '';

  # Inside a sandbox, open links with the host browser via the portal.
  xdgOpenShim = pkgs.writeShellScriptBin "xdg-open" ''
    case "''${1:-}" in
      http://*|https://*|mailto:*) ;;
      *) echo "ai-run xdg-open: only http(s)/mailto links are forwarded" >&2; exit 1 ;;
    esac
    exec ${pkgs.glib.bin}/bin/gdbus call --session \
      --dest org.freedesktop.portal.Desktop \
      --object-path /org/freedesktop/portal/desktop \
      --method org.freedesktop.portal.OpenURI.OpenURI "" "$1" "{}" >/dev/null
  '';

  wrapType = types.coercedTo types.package (package: { inherit package; }) (types.submodule {
    options = {
      package = mkOption { type = types.package; };
      profile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Profile to use; default: the package name if such a profile exists, else `default`.";
      };
    };
  });

  profileFor = w:
    if w.profile != null then w.profile
    else if cfg.profiles ? ${lib.getName w.package} then lib.getName w.package
    else "default";

  # Same bin/ names and .desktop files as the package, but every entry
  # point goes through ai-run. Higher priority than the package itself.
  mkWrapped = w:
    let
      pkg = w.package;
      profile = profileFor w;
    in
    lib.setPrio (-20) (pkgs.runCommand "ai-run-${lib.getName pkg}" { } ''
      mkdir -p $out/bin
      for f in ${pkg}/bin/*; do
        n=$(basename "$f")
        {
          echo '#!${pkgs.runtimeShell}'
          echo "exec ${aiRun}/bin/ai-run --profile ${lib.escapeShellArg profile} -- $f \"\$@\""
        } > "$out/bin/$n"
        chmod 755 "$out/bin/$n"
      done
      if [ -d ${pkg}/share/applications ]; then
        mkdir -p $out/share/applications
        for d in ${pkg}/share/applications/*.desktop; do
          sed -e "s|${pkg}/bin/|$out/bin/|g" "$d" > "$out/share/applications/$(basename "$d")"
        done
      fi
    '');
in
{
  options.programs.ai-run = {
    enable = mkEnableOption "ai-run, a bubblewrap sandbox for AI agents";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
    };

    bubblewrap = mkOption {
      type = types.package;
      default = pkgs.bubblewrap;
    };

    toolsShell = mkOption {
      type = types.str;
      default = "${pkgs.zsh}/bin/zsh";
      defaultText = literalExpression ''"''${pkgs.zsh}/bin/zsh"'';
      description = "Real shell behind the grok-bot-tools $SHELL wrapper.";
    };

    wrap = mkOption {
      type = types.listOf wrapType;
      default = [ ];
      example = literalExpression "[ pkgs.grok-build { package = grok-bot; profile = \"grok-bot\"; } ]";
      description = ''
        Packages whose binaries and .desktop entries are replaced (higher
        priority on PATH and in share/applications) by wrappers that start
        them through ai-run.
      '';
    };

    mask = mkOption {
      type = types.listOf types.str;
      description = ''
        Hidden from every profile unless the profile unmasks the exact entry.
        Relative paths are under $HOME. Directories become an empty tmpfs,
        files and sockets /dev/null. Missing paths are skipped.
      '';
      default = [
        # keys, password stores, keyrings
        ".gnupg" ".ssh" ".password-store" ".local/share/password-store"
        ".local/share/keyrings" ".local/share/kwalletd" ".pki"
        ".config/sops" ".config/age"
        # CLI credentials
        ".config/gh" ".config/hub" ".config/github-copilot"
        ".git-credentials" ".config/git/credentials" ".netrc" ".npmrc" ".pypirc"
        ".cargo/credentials" ".cargo/credentials.toml"
        ".docker/config.json" ".config/containers/auth.json"
        ".aws" ".azure" ".config/gcloud" ".kube" ".config/rclone" ".vault-token"
        ".config/op" ".config/1Password" ".config/Bitwarden"
        # browsers
        ".mozilla" ".librewolf" ".zen" ".config/zen" ".config/chromium"
        ".config/google-chrome" ".config/google-chrome-beta" ".config/google-chrome-unstable"
        ".config/BraveSoftware" ".config/vivaldi" ".config/microsoft-edge" ".var/app"
        # Proton, messengers
        ".config/Proton Pass" ".config/Proton Mail" ".config/protonmail" ".config/Proton"
        ".config/Signal" ".local/share/TelegramDesktop" ".config/discord" ".config/Slack" ".config/Element"
        # other AI agents' logins (each agent's own profile unmasks its own)
        ".config/Grok Bot" ".grokbot" ".grok" ".claude" ".claude.json" ".codex" ".gemini" ".hermes" ".pi"
        # shell histories (pasted tokens), X auth
        ".zsh_history" ".config/zsh/.zsh_history" ".bash_history" ".python_history"
        ".node_repl_history" ".psql_history" ".mysql_history" ".Xauthority" ".ICEauthority"
        # nix's eval/fetch cache: fresh per sandbox, so it can't be poisoned
        ".cache/nix"
        # root-equivalent or session-wide sockets outside $XDG_RUNTIME_DIR
        "/run/docker.sock" "/run/podman" "/run/libvirt" "/run/dbus/system_bus_socket" "/run/pcscd"
        # secret-broker's full socket (unlock, approve, PIN, dialog); sandboxes
        # use the restricted socket instead (see `env`). Both spellings: on
        # some systems /var/run is not a symlink to /run.
        "/run/secret-broker/broker.sock"
        "/var/run/secret-broker/broker.sock"
        # the broker's audit log (who unlocked/ran what): yours to read, not the agent's
        "/var/log/secret-broker"
      ];
    };
    extraMask = mkOption { type = types.listOf types.str; default = [ ]; };

    writable = mkOption {
      type = types.listOf types.str;
      description = ''
        The only writable parts of $HOME (if they exist). Everything else,
        including ~/.config, dotfiles, ~/.local/share and ~/.local/bin, is
        read-only, so a sandboxed agent can't plant code that you later run
        outside (shell rc files, autostart, systemd units, hypr config...).
      '';
      default = [
        "dev" "Documents" "Downloads" "Projects" "Work" "Pictures" "Videos" "Music"
        "go" ".cache" ".cargo/registry" ".cargo/git" ".npm" "agent-tools"
      ];
    };
    extraWritable = mkOption { type = types.listOf types.str; default = [ ]; };
    readOnly = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Paths kept read-only inside writable ones (e.g. a repo's .git/hooks).";
    };

    envUnset = mkOption {
      type = types.listOf types.str;
      default = [
        "DISPLAY" "XAUTHORITY" "GPG_AGENT_INFO" "GNOME_KEYRING_CONTROL" "SSH_AGENT_PID"
        "HYPRLAND_INSTANCE_SIGNATURE" "SWAYSOCK" "NIRI_SOCKET" "TMUX" "TMUX_PANE"
        "ALACRITTY_SOCKET" "KITTY_LISTEN_ON" "DOCKER_HOST" "CONTAINER_HOST"
      ];
    };
    env = mkOption {
      type = types.attrsOf types.str;
      default = {
        SECRET_BROKER_SOCKET = "/run/secret-broker/agent.sock";
      };
      description = ''
        Variables set in every profile (a profile's own `env` wins). The
        default points secret-run at the broker's restricted socket, which
        can run profiles (popping up the approval dialog when the session is
        sealed) but can't unlock, approve or set the PIN.
      '';
    };
    envDeny = mkOption {
      type = types.listOf types.str;
      default = [
        "*TOKEN*" "*SECRET*" "*PASSWORD*" "*PASSWD*" "*API_KEY*" "*APIKEY*" "*_KEY"
        "*CREDENTIAL*" "AWS_*" "GITHUB_*" "GH_*"
      ];
      description = "Variables removed unless a profile lists them in keepEnv (globs).";
    };

    profiles = mkOption {
      type = types.attrsOf profileType;
      default = { };
      description = "Sandbox profiles; `default`, `grok-build`, `grok-bot` and `grok-bot-tools` are predefined.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "programs.ai-run: the sandbox uses bubblewrap (Linux only); a macOS sandbox-exec backend is not implemented yet.";
      }
    ];
    programs.ai-run.profiles = {
      default.description = lib.mkDefault "generic: credentials masked, no bus, no GUI";
      grok-build = {
        description = lib.mkDefault "Grok Build (terminal agent): sees its own ~/.grok";
        unmask = [ ".grok" ];
        writable = [ ".grok" ];
        writableFromEnv = [ "GROK_HOME" ];
      };
      grok-bot = {
        description = lib.mkDefault "Grok Bot desktop app: GUI, filtered D-Bus, its own login";
        unmask = [ ".config/Grok Bot" ".grokbot" ];
        # .local/share/pki: Chromium's NSS certificate DB.
        # terminals: the app's shell tool writes each command's output to
        # ~/terminals/<id>.txt (EROFS = commands fail to start). Command
        # output only; the nested grok-bot-tools sandbox sees it read-only.
        writable = [ ".config/Grok Bot" ".grokbot" ".local/share/pki" "terminals" ];
        gui = lib.mkDefault true;
        dbus = lib.mkDefault {
          talk = [ "org.freedesktop.Notifications" "org.kde.StatusNotifierWatcher" ];
          own = [ "org.kde.*" ];
          call = [
            "org.freedesktop.portal.Desktop=org.freedesktop.portal.OpenURI.OpenURI@/org/freedesktop/portal/desktop"
            "org.freedesktop.portal.Desktop=org.freedesktop.portal.FileChooser.*@/org/freedesktop/portal/desktop"
            "org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.*@/org/freedesktop/portal/desktop"
            "org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.*@/org/freedesktop/portal/desktop"
            "org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*@/org/freedesktop/portal/desktop/request/*"
          ];
          broadcast = [ "org.freedesktop.portal.Desktop=*@/org/freedesktop/portal/*" ];
        };
        env.SHELL = "${toolsShell}/bin/zsh";
        pathPrefix = [ "${xdgOpenShim}/bin" ];
      };
      grok-bot-tools.description = lib.mkDefault "commands Grok Bot runs: like default, nested inside grok-bot";
    };

    home.packages = [ aiRun ] ++ map mkWrapped cfg.wrap;
  };
}
