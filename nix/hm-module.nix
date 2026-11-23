{ config, lib, pkgs, ... }:
let
  cfg = config.programs.secret-broker;
  inherit (lib) mkOption mkEnableOption mkIf types;
  defaultSocket = "/run/secret-broker/broker.sock";
  dcfg = cfg.dialog;

  fontArgs = lib.escapeShellArgs (
    [ "--font" "${dcfg.font}" ]
    ++ lib.optionals (dcfg.fontBold != null) [ "--font-bold" "${dcfg.fontBold}" ]
    ++ lib.optionals (dcfg.theme != null) [ "--theme" "${dcfg.theme}" ]
    ++ [ "--size" (toString dcfg.size) ]
  );

  # gpg-agent's pinentry: the same dialog; pinentry-curses when there is no
  # Wayland display (tty login, ssh).
  dialogPinentry = pkgs.writeShellScriptBin "pinentry-secret-broker" ''
    exec ${dcfg.package}/bin/secret-broker-dialog pinentry \
      --fallback ${pkgs.pinentry-curses}/bin/pinentry-curses ${fontArgs} "$@"
  '';

  jbm = "${pkgs.nerd-fonts.jetbrains-mono}/share/fonts/truetype/NerdFonts/JetBrainsMono";
in
{
  imports = [ ./ai-run-hm.nix ];

  options.programs.secret-broker = {
    enable = mkEnableOption "the secret-broker client (`secret-broker`, `secret-run`)";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
    };

    socket = mkOption {
      type = types.str;
      default = defaultSocket;
      description = "Broker socket (the NixOS module listens on ${defaultSocket}).";
    };

    gpgAgent = {
      recommended = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Opinionated gpg-agent settings for using secret-broker with an AI
          agent: a short passphrase cache (so a same-user process cannot
          silently decrypt with a warm cache) and a GUI pinentry (so the
          approval prompt is visible). Applied with mkOverride 90, i.e. they
          win over plain definitions elsewhere.
        '';
      };
      cacheTtl = mkOption {
        type = types.int;
        default = 300;
        description = "default-cache-ttl when `recommended` is on.";
      };
      maxCacheTtl = mkOption {
        type = types.int;
        default = 1800;
        description = "max-cache-ttl when `recommended` is on.";
      };
      pinentryPackage = mkOption {
        type = types.package;
        default = if dcfg.enable && dcfg.pinentry then dialogPinentry else pkgs.pinentry-qt;
        defaultText = lib.literalExpression "the secret-broker dialog's pinentry if dialog.pinentry, else pkgs.pinentry-qt";
        description = "pinentry used when `recommended` is on.";
      };
    };

    dialog = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Run the approval dialog (`secret-broker-dialog prompter`) as a
          systemd user service in the graphical session. When the session is
          sealed and an agent runs `secret-run`, it shows a Wayland overlay
          (layer-shell, exclusive keyboard) with who is asking and what will
          run; you approve with your PIN, a security-key touch or a finger.
          It only collects input: the broker verifies everything. It runs from
          systemd, never inside ai-run, and the broker refuses dialogs from
          sandboxes.
        '';
      };
      package = mkOption {
        type = types.package;
        default = pkgs.callPackage ./dialog.nix { };
      };
      pinentry = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Use the same dialog as gpg-agent's pinentry (with `gpgAgent.recommended`),
          i.e. for the one gpg passphrase prompt after boot.
        '';
      };
      font = mkOption {
        type = types.path;
        default = "${jbm}/JetBrainsMonoNerdFont-Regular.ttf";
        defaultText = lib.literalExpression "JetBrainsMono Nerd Font Regular (Omarchy's UI font)";
      };
      fontBold = mkOption {
        type = types.nullOr types.path;
        default = "${jbm}/JetBrainsMonoNerdFont-Bold.ttf";
      };
      theme = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "colors.toml to use; null follows the current Omarchy theme.";
      };
      size = mkOption {
        type = types.numbers.between 0.5 2.0;
        default = 0.75;
        example = 1.0;
        description = ''
          Size of the dialog (fonts and box together), relative to the
          original layout. 0.75 is the default; 1.0 is the larger, older look.
          Also settable per run with `--size` or SECRET_BROKER_DIALOG_SIZE.
        '';
      };
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [
    {
      home.packages = [ cfg.package ];
      home.sessionVariables = mkIf (cfg.socket != defaultSocket) { SECRET_BROKER_SOCKET = cfg.socket; };
    }
    (mkIf dcfg.enable {
      home.packages = [ dcfg.package ];
      systemd.user.services.secret-broker-dialog = {
        Unit = {
          Description = "secret-broker approval dialog";
          PartOf = [ "graphical-session.target" ];
          After = [ "graphical-session.target" ];
        };
        Service = {
          ExecStart = "${dcfg.package}/bin/secret-broker-dialog prompter ${fontArgs}";
          Restart = "always";
          RestartSec = 3;
          LimitCORE = 0;
          NoNewPrivileges = true;
          Environment = lib.optional (cfg.socket != defaultSocket) "SECRET_BROKER_SOCKET=${cfg.socket}";
        };
        Install.WantedBy = [ "graphical-session.target" ];
      };
    })
    (mkIf cfg.gpgAgent.recommended {
      services.gpg-agent = {
        defaultCacheTtl = lib.mkOverride 90 cfg.gpgAgent.cacheTtl;
        maxCacheTtl = lib.mkOverride 90 cfg.gpgAgent.maxCacheTtl;
        pinentry.package = lib.mkOverride 90 cfg.gpgAgent.pinentryPackage;
      };
    })
  ]);
}
