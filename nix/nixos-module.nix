{ config, lib, pkgs, ... }:
let
  cfg = config.services.secret-broker;
  inherit (lib) mkOption mkEnableOption mkIf types literalExpression;

  profileModule = { name, ... }: {
    options = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether this profile is offered by the broker.";
      };
      description = mkOption {
        type = types.str;
        default = "";
      };
      command = mkOption {
        type = types.str;
        example = literalExpression ''"''${pkgs.gh}/bin/gh"'';
        description = "Absolute path of the program to run.";
      };
      fixedArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Arguments always prepended (not matched by allow/deny).";
      };
      env = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = { GH_TOKEN = "github.token"; };
        description = "Environment variable -> dotted key path in the sops JSON file.";
      };
      extraEnv = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "Extra non-secret environment for the child.";
      };
      path = mkOption {
        type = types.listOf types.package;
        default = [ pkgs.coreutils ];
        description = "Packages whose bin/ form the child's PATH.";
      };
      allow = mkOption {
        type = types.listOf (types.listOf types.str);
        example = [ [ "pr" "list" ] [ "pr" "view" "*" ] [ "api" "repos/*" "**" ] ];
        description = ''
          Allowed argument shapes, matched position by position. In a token,
          `*` matches anything (including `/`) and `?` one character; a whole
          `**` token matches all remaining arguments. Without `**` the number of
          arguments must match exactly. Use `[ [ "**" ] ]` to allow anything.
        '';
      };
      deny = mkOption {
        type = types.listOf (types.listOf types.str);
        default = [ ];
        example = [ [ "auth" "**" ] ];
        description = "Argument shapes refused even if an allow rule matches.";
      };
      timeout = mkOption {
        type = types.int;
        default = 600;
        description = "Seconds before the child is killed (0 = no limit).";
      };
    };
  };

  enabledProfiles = lib.filterAttrs (_: p: p.enable) cfg.profiles;

  configFile = pkgs.writeText "secret-broker.json" (builtins.toJSON {
    secrets_file = if builtins.isPath cfg.secretsFile then "${cfg.secretsFile}" else cfg.secretsFile;
    state_dir = "/var/lib/secret-broker";
    allowed_users = cfg.users;
    default_ttl_seconds = cfg.defaultTtl;
    max_ttl_seconds = cfg.maxTtl;
    redact_output = cfg.redactOutput;
    gpg_cache_limits = {
      default_cache_ttl = cfg.gpgCacheLimits.defaultCacheTtl;
      max_cache_ttl = cfg.gpgCacheLimits.maxCacheTtl;
    };
    profiles = lib.mapAttrs (_: p: {
      inherit (p) description command env allow deny;
      fixed_args = p.fixedArgs;
      extra_env = p.extraEnv;
      path = lib.makeBinPath p.path;
      timeout_seconds = p.timeout;
    }) enabledProfiles;
  });
in
{
  options.services.secret-broker = {
    enable = mkEnableOption "secret-broker, a daemon that lets AI agents use secrets without reading them";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = literalExpression "secret-broker";
    };

    secretsFile = mkOption {
      type = types.either types.path types.str;
      example = literalExpression "./secrets/agent.sops.json";
      description = ''
        sops-encrypted JSON file (encrypt with `sops --pgp <your fingerprint>`).
        Prefer a Nix path: it is copied to the store, so nothing running as a
        normal user can swap it. A string path must be owned by root and not
        group/world writable (checked at every unlock).
      '';
    };

    users = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Users allowed to talk to the broker (added to `group`, also checked by uid).";
    };

    group = mkOption {
      type = types.str;
      default = "secret-broker";
      description = "Group that may connect to the socket.";
    };

    defaultTtl = mkOption {
      type = types.int;
      default = 8 * 3600;
      description = "Seconds an unlock lasts when `--ttl` is not given.";
    };

    maxTtl = mkOption {
      type = types.int;
      default = 24 * 3600;
      description = "Upper bound for `--ttl`.";
    };

    redactOutput = mkOption {
      type = types.bool;
      default = true;
      description = "Replace injected secret values in child output with [REDACTED] (defence in depth only).";
    };

    gpgCacheLimits = {
      defaultCacheTtl = mkOption {
        type = types.ints.unsigned;
        default = 900;
        description = ''
          `secret-broker unlock` refuses to run while the caller's gpg-agent
          `default-cache-ttl` is above this many seconds: a cached passphrase
          would let anything running as the user decrypt the secrets file with
          `sops -d`, bypassing the broker. There is deliberately no client-side
          override; the limit lives here, in root-owned config.
        '';
      };
      maxCacheTtl = mkOption {
        type = types.ints.unsigned;
        default = 7200;
        description = "Same as `defaultCacheTtl`, for gpg-agent's `max-cache-ttl`.";
      };
    };

    profiles = mkOption {
      type = types.attrsOf (types.submodule profileModule);
      default = { };
      description = "Allowlisted commands the broker will run with secrets.";
    };

    memoryDenyWriteExecute = mkOption {
      type = types.bool;
      default = true;
      description = ''
        systemd MemoryDenyWriteExecute for the broker. Children inherit it, so
        turn it off if a profile runs a JIT runtime (node, java, luajit...).
      '';
    };

    serviceConfig = mkOption {
      type = types.attrs;
      default = { };
      description = "Extra/overriding systemd serviceConfig (children inherit the sandbox).";
    };
  };

  config = mkIf cfg.enable {
    users.users.agent-secrets = {
      isSystemUser = true;
      group = "agent-secrets";
      home = "/var/lib/secret-broker";
      description = "secret-broker daemon";
    };
    users.groups.agent-secrets = { };
    users.groups.${cfg.group}.members = cfg.users;

    environment.systemPackages = [ cfg.package ];

    systemd.sockets.secret-broker = {
      description = "secret-broker socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/secret-broker/broker.sock" ];
      socketConfig = {
        SocketUser = "root";
        SocketGroup = cfg.group;
        SocketMode = "0660";
        DirectoryMode = "0755";
        RemoveOnStop = true;
      };
    };

    systemd.services.secret-broker = {
      description = "secret-broker: run allowlisted commands with secrets";
      requires = [ "secret-broker.socket" ];
      after = [ "secret-broker.socket" ];
      restartTriggers = [ configFile ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/secret-broker daemon --config ${configFile}";
        User = "agent-secrets";
        Group = "agent-secrets";
        StateDirectory = "secret-broker";
        StateDirectoryMode = "0700";
        UMask = "0077";
        KillMode = "control-group";
        Restart = "on-failure";

        # Secrets live only in this process' memory.
        LimitCORE = 0;
        LimitMEMLOCK = "64M";
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectProc = "invisible";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = cfg.memoryDenyWriteExecute;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        KeyringMode = "private";
        RemoveIPC = true;
      } // cfg.serviceConfig;
    };
  };
}
