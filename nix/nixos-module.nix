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
        example = [ [ "pr" "list" ] [ "pr" "view" "*" ] [ "api" "repos/*" ] ];
        description = ''
          Allowed argument shapes, matched position by position. In a token,
          `*` matches anything (including `/`) and `?` one character; a whole
          `**` token matches all remaining arguments. Without `**` the number of
          arguments must match exactly. Use `[ [ "**" ] ]` to allow anything.
          A trailing `**` lets callers pass flags such as `--hostname` or
          `--debug`; pair it with `denyTokens` if you use it.
        '';
      };
      deny = mkOption {
        type = types.listOf (types.listOf types.str);
        default = [ ];
        example = [ [ "auth" "**" ] ];
        description = "Argument shapes refused even if an allow rule matches.";
      };
      denyTokens = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "--hostname" "--hostname=*" "--debug" "-v" "--verbose" ];
        description = ''
          Globs matched against every argument, any position. Use this for
          flags that print or redirect credentials (`--debug`, `--hostname`)
          even when an allow rule ends in `**`.
        '';
      };
      timeout = mkOption {
        type = types.int;
        default = 600;
        description = "Seconds before the child is killed (0 = no limit).";
      };
    };
  };

  enabledProfiles = lib.filterAttrs (_: p: p.enable) cfg.profiles;

  acfg = cfg.approval;

  fido2CredModule = { ... }: {
    options = {
      name = mkOption {
        type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]*";
        description = "A label for this key.";
      };
      id = mkOption {
        type = types.str;
        description = "Base64 credential id printed by `secret-broker fido2-enroll`.";
      };
      publicKey = mkOption {
        type = types.str;
        description = "PEM public key printed by `secret-broker fido2-enroll` (public data).";
      };
      type = mkOption {
        type = types.enum [ "es256" "rs256" "eddsa" ];
        default = "es256";
      };
    };
  };

  pamMethodModule = { name, ... }: {
    options = {
      service = mkOption {
        type = types.str;
        default = "secret-broker-${name}";
        description = "PAM service (/etc/pam.d/<service>) to authenticate the approving user against.";
      };
      label = mkOption {
        type = types.str;
        default = "Authenticate with ${name}";
        description = "Hint shown in the approval dialog.";
      };
      retries = mkOption {
        type = types.ints.positive;
        default = 3;
      };
      text = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = ''
          If set, the PAM service file content. Only non-interactive modules
          work: the helper refuses every prompt, so a password module can
          never be used here.
        '';
      };
    };
  };

  fingerprintMethod = {
    service = "secret-broker-fingerprint";
    label = acfg.fingerprint.label;
    retries = acfg.fingerprint.retries;
    text = ''
      auth    required ${acfg.fingerprint.package}/lib/security/pam_fprintd.so max-tries=1 timeout=${toString acfg.fingerprint.timeout}
      account required pam_permit.so
    '';
  };

  pamMethods = acfg.pam // lib.optionalAttrs acfg.fingerprint.enable { fingerprint = fingerprintMethod; };

  fido2Enabled = acfg.fido2.credentials != [ ];

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
    profiles = lib.mapAttrs (name: p: {
      inherit (p) description command env allow deny;
      deny_tokens = p.denyTokens;
      fixed_args = p.fixedArgs;
      extra_env = p.extraEnv;
      path = lib.makeBinPath p.path;
      timeout_seconds = p.timeout;
      user = "sb-${name}";
    }) enabledProfiles;
    approval = {
      timeout_seconds = acfg.timeout;
      sealed_max_seconds = acfg.sealedTimeout;
      prompter_exe = if acfg.prompterExe == null then "" else acfg.prompterExe;
      client_exe = if acfg.clientExe == null then "" else acfg.clientExe;
      pin = {
        inherit (acfg.pin) enable;
        min_length = acfg.pin.minLength;
        max_attempts = acfg.pin.maxAttempts;
        argon2_memory_kib = acfg.pin.argon2.memoryKiB;
        argon2_iterations = acfg.pin.argon2.iterations;
        argon2_parallelism = acfg.pin.argon2.parallelism;
      };
      fido2 = {
        rp_id = acfg.fido2.rpId;
        tools_dir = "${acfg.fido2.package}/bin";
        credentials = map (c: {
          inherit (c) name id type;
          public_key_file = "${pkgs.writeText "secret-broker-fido2-${c.name}.pem" c.publicKey}";
        }) acfg.fido2.credentials;
      };
      pam = lib.mapAttrsToList (name: m: {
        inherit name;
        inherit (m) service label retries;
      }) pamMethods;
    };
    audit = {
      inherit (cfg.audit) enable directory journal;
      max_file_bytes = cfg.audit.maxFileSize;
      keep_files = cfg.audit.keepFiles;
    };
  });
  auditCfg = cfg.audit;
in
{
  options.services.secret-broker = {
    enable = mkEnableOption "secret-broker, a daemon that lets AI agents use secrets without reading them";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = literalExpression "secret-broker";
    };

    dialogPackage = mkOption {
      type = types.package;
      default = pkgs.callPackage ./dialog.nix { };
      defaultText = literalExpression "secret-broker-dialog";
      description = "Approval dialog binary; used as the default `approval.prompterExe`.";
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

    callerDetails = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Show and log full details of whoever asks (exe, cwd, argv, parents,
        systemd unit, login session). The broker can't see your processes
        (ProtectProc=invisible), so a small helper it starts keeps
        CAP_SYS_PTRACE to read /proc/<pid>/{exe,cwd,cmdline,stat,cgroup}; the
        daemon drops every capability right after starting it, and neither
        the daemon nor the commands it runs keep any. ptrace and
        process_vm_* stay blocked by the syscall filter. Without this, only
        the uid/pid (SO_PEERCRED) and the socket are known.
      '';
    };

    audit = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Log every session event (unlock, lock, seal/expiry, approvals,
          refusals, every secret-run with argv/exit code/duration, PIN and
          dialog changes) with the caller's details, to journald
          (SYSLOG_IDENTIFIER=secret-broker) and to a hash-chained JSON-lines
          file. Never secret or environment values. Read it with
          `secret-broker log`, check it with `secret-broker log verify`.
        '';
      };
      directory = mkOption {
        type = types.str;
        default = "/var/log/secret-broker";
        description = ''
          Where audit.jsonl lives: owned by agent-secrets, group `group`
          (read-only for its members), mode 2750. ai-run hides it from sandboxes.
        '';
      };
      maxFileSize = mkOption {
        type = types.ints.positive;
        default = 10 * 1024 * 1024;
        description = "Rotate audit.jsonl when it would grow past this many bytes.";
      };
      keepFiles = mkOption {
        type = types.ints.unsigned;
        default = 9;
        description = ''
          Rotated files to keep (audit.jsonl.1 .. .N); older are deleted. The
          log uses at most maxFileSize * (keepFiles + 1). The hash chain
          continues across files.
        '';
      };
      journal = mkOption {
        type = types.bool;
        default = true;
        description = "Also send each entry (with its hash) to journald.";
      };
    };

    memoryDenyWriteExecute = mkOption {
      type = types.bool;
      default = true;
      description = ''
        systemd MemoryDenyWriteExecute for the broker. Children inherit it, so
        turn it off if a profile runs a JIT runtime (node, java, luajit...).
      '';
    };

    approval = {
      timeout = mkOption {
        type = types.ints.positive;
        default = 120;
        description = "Seconds an approval dialog waits before refusing.";
      };
      prompterExe = mkOption {
        type = types.nullOr types.str;
        default = "${cfg.dialogPackage}/bin/secret-broker-dialog";
        defaultText = literalExpression ''"''${config.services.secret-broker.dialogPackage}/bin/secret-broker-dialog"'';
        description = ''
          Absolute path of the only binary allowed to register as the approval
          dialog. That process is the only client sent the anti-phishing phrase.
          `null` disables the check (protocol-level tests).
        '';
      };
      clientExe = mkOption {
        type = types.nullOr types.str;
        default = "${cfg.package}/bin/secret-broker";
        defaultText = literalExpression ''"''${config.services.secret-broker.package}/bin/secret-broker"'';
        description = ''
          Absolute path of `secret-broker`. Terminal approve/unlock is sent the
          anti-phishing phrase only when the caller is this binary. `null`
          disables the check.
        '';
      };
      sealedTimeout = mkOption {
        type = types.ints.unsigned;
        default = 0;
        description = ''
          After the session TTL expires (or `secret-broker lock`), the secrets
          stay in the broker's locked memory, "sealed": a quick approval (PIN,
          security key, fingerprint) reopens the session without gpg. Wipe them
          after this many seconds sealed; 0 keeps them until reboot or
          `secret-broker lock --forget`. Without any quick method configured,
          expiry always wipes.
        '';
      };
      pin = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Allow a PIN (set with `secret-broker set-pin`, which asks gpg once)
            to reopen a sealed session. The broker verifies it: argon2id with a
            pepper derived from the sops data key, so the stored hash is useless
            without the secrets themselves. Wrong PINs back off; after
            `maxAttempts` the secrets are wiped and gpg is needed again.
          '';
        };
        minLength = mkOption {
          type = types.ints.positive;
          default = 6;
        };
        maxAttempts = mkOption {
          type = types.ints.positive;
          default = 5;
        };
        argon2 = {
          memoryKiB = mkOption {
            type = types.ints.positive;
            default = 65536;
          };
          iterations = mkOption {
            type = types.ints.positive;
            default = 3;
          };
          parallelism = mkOption {
            type = types.ints.positive;
            default = 1;
          };
        };
      };
      fido2 = {
        credentials = mkOption {
          type = types.listOf (types.submodule fido2CredModule);
          default = [ ];
          description = ''
            Security keys (YubiKey, SoloKey...) whose touch reopens a sealed
            session. Create one with `secret-broker fido2-enroll` and paste the
            printed snippet. The broker sends a fresh challenge per request and
            verifies the signature against these public keys; the key must be
            touched (user presence).
          '';
        };
        rpId = mkOption {
          type = types.str;
          default = "secret-broker";
        };
        package = mkOption {
          type = types.package;
          default = pkgs.libfido2;
          defaultText = literalExpression "pkgs.libfido2";
          description = "Provides fido2-token and fido2-assert (run by the broker as separate processes).";
        };
      };
      fingerprint = {
        enable = mkEnableOption "fingerprint (fprintd) approval of a sealed session";
        package = mkOption {
          type = types.package;
          default = pkgs.fprintd;
          defaultText = literalExpression "pkgs.fprintd";
        };
        label = mkOption {
          type = types.str;
          default = "Touch the fingerprint sensor";
        };
        retries = mkOption {
          type = types.ints.positive;
          default = 3;
        };
        timeout = mkOption {
          type = types.ints.positive;
          default = 30;
        };
      };
      pam = mkOption {
        type = types.attrsOf (types.submodule pamMethodModule);
        default = { };
        description = ''
          Extra PAM-based approval methods, run in a helper process
          (`secret-broker pam-check`) as the broker user, never in the daemon.
        '';
      };
    };

    serviceConfig = mkOption {
      type = types.attrs;
      default = { };
      description = "Extra/overriding systemd serviceConfig (children inherit the sandbox).";
    };
  };

  config = mkIf cfg.enable {
    users.users = {
      agent-secrets = {
        isSystemUser = true;
        group = "agent-secrets";
        home = "/var/lib/secret-broker";
        description = "secret-broker daemon";
      };
    }
    // lib.mapAttrs' (
      name: _:
      lib.nameValuePair "sb-${name}" {
        isSystemUser = true;
        group = "sb-${name}";
        home = "/var/lib/secret-broker/home/${name}";
        createHome = false;
        description = "secret-broker profile ${name}";
      }
    ) enabledProfiles;
    users.groups = {
      agent-secrets = { };
      ${cfg.group}.members = cfg.users;
    }
    // lib.mapAttrs' (name: _: lib.nameValuePair "sb-${name}" { }) enabledProfiles;

    environment.systemPackages = [ cfg.package ];
    # `secret-broker log` reads the file directly (group read).
    environment.variables.SECRET_BROKER_AUDIT_DIR = lib.mkIf auditCfg.enable auditCfg.directory;

    systemd.tmpfiles.rules = lib.optionals auditCfg.enable [
      "d ${auditCfg.directory} 2750 agent-secrets ${cfg.group} - -"
      "z ${auditCfg.directory}/audit.jsonl 0640 agent-secrets ${cfg.group} - -"
    ];

    systemd.sockets.secret-broker = {
      description = "secret-broker socket";
      wantedBy = [ "sockets.target" ];
      # fd 3: full socket. fd 4: restricted socket for ai-run sandboxes (run
      # profiles, status, lock; never unlock/approve/set-pin/dialog).
      listenStreams = [
        "/run/secret-broker/broker.sock"
        "/run/secret-broker/agent.sock"
      ];
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
        # Only for the /proc helper (see callerDetails); the daemon drops it
        # at start, before it serves anything.
        # SETUID/SETGID: drop to sb-<profile> before exec. SYS_PTRACE is
        # dropped in the daemon after the /proc helper is spawned.
        CapabilityBoundingSet = lib.concatStringsSep " " (
          [
            "CAP_SETUID"
            "CAP_SETGID"
          ]
          ++ lib.optionals cfg.callerDetails [ "CAP_SYS_PTRACE" ]
        );
        AmbientCapabilities = lib.concatStringsSep " " (
          [
            "CAP_SETUID"
            "CAP_SETGID"
          ]
          ++ lib.optionals cfg.callerDetails [ "CAP_SYS_PTRACE" ]
        );
        PrivateTmp = true;
        # FIDO2 keys are /dev/hidraw*: only those, through the device cgroup.
        PrivateDevices = !fido2Enabled;
        DevicePolicy = "closed";
        DeviceAllow = lib.optionals fido2Enabled [ "char-hidraw rw" ];
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
        SystemCallFilter = [ "@system-service" "~ptrace process_vm_readv process_vm_writev" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        KeyringMode = "private";
        RemoveIPC = true;
        ReadWritePaths = lib.optionals auditCfg.enable [ "-${auditCfg.directory}" ];
      } // cfg.serviceConfig;
    };

    assertions = [
      {
        assertion = lib.all (m: m.service != "" && !(lib.hasInfix "/" m.service)) (lib.attrValues pamMethods);
        message = "services.secret-broker.approval.pam: invalid service name";
      }
    ];

    # Security keys: give the broker's group access next to systemd's uaccess
    # ACL (your desktop session keeps access through the ACL).
    services.udev.extraRules = lib.mkIf fido2Enabled ''
      ACTION=="add|change", SUBSYSTEM=="hidraw", ENV{ID_FIDO_TOKEN}=="1", GROUP="agent-secrets", MODE="0660"
    '';

    security.pam.services = lib.mapAttrs' (_: m: lib.nameValuePair m.service { inherit (m) text; })
      (lib.filterAttrs (_: m: m.text != null) pamMethods);

    services.fprintd.enable = lib.mkIf acfg.fingerprint.enable (lib.mkDefault true);

    # pam_fprintd in the broker's helper verifies *your* finger on behalf of
    # agent-secrets.
    security.polkit.extraConfig = lib.mkIf acfg.fingerprint.enable ''
      polkit.addRule(function(action, subject) {
        if ((action.id == "net.reactivated.fprint.device.verify" ||
             action.id == "net.reactivated.fprint.device.setusername") &&
            subject.user == "agent-secrets") {
          return polkit.Result.YES;
        }
      });
    '';
  };
}
