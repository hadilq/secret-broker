{ config, lib, pkgs, ... }:
let
  cfg = config.programs.secret-broker;
  inherit (lib) mkOption mkEnableOption mkIf types;
  defaultSocket = "/run/secret-broker/broker.sock";
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
        default = pkgs.pinentry-qt;
        description = "pinentry used when `recommended` is on.";
      };
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [
    {
      home.packages = [ cfg.package ];
      home.sessionVariables = mkIf (cfg.socket != defaultSocket) { SECRET_BROKER_SOCKET = cfg.socket; };
    }
    (mkIf cfg.gpgAgent.recommended {
      services.gpg-agent = {
        defaultCacheTtl = lib.mkOverride 90 cfg.gpgAgent.cacheTtl;
        maxCacheTtl = lib.mkOverride 90 cfg.gpgAgent.maxCacheTtl;
        pinentry.package = lib.mkOverride 90 cfg.gpgAgent.pinentryPackage;
      };
    })
  ]);
}
