{
  description = "secret-broker: let AI agents use secrets through allowlisted commands without reading them";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # macOS: the broker, secret-run and their tests/clippy (no dialog, no
      # ai-run sandbox, no NixOS module yet; see "macOS" in README.md).
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      linuxOnly = pkgs: attrs: nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux attrs;
    in
    {
      packages = forAll (
        pkgs:
        rec {
          secret-broker = pkgs.callPackage ./nix/package.nix { };
          default = secret-broker;
        }
        // linuxOnly pkgs {
          secret-broker-dialog = pkgs.callPackage ./nix/dialog.nix { };
        }
      );

      overlays.default = final: _prev: {
        secret-broker = final.callPackage ./nix/package.nix { };
        secret-broker-dialog = final.callPackage ./nix/dialog.nix { };
      };

      nixosModules.default = ./nix/nixos-module.nix;
      nixosModules.secret-broker = ./nix/nixos-module.nix;
      homeManagerModules.default = ./nix/hm-module.nix;
      homeManagerModules.secret-broker = ./nix/hm-module.nix;

      checks = forAll (
        pkgs:
        {
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          clippy = pkgs.callPackage ./nix/clippy.nix {
            secret-broker = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
        }
        // linuxOnly pkgs {
          dialog = self.packages.${pkgs.stdenv.hostPlatform.system}.secret-broker-dialog;
          vm = pkgs.testers.runNixOSTest (import ./nix/vm-test.nix { inherit self; });
        }
      );

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages =
            with pkgs;
            [ cargo rustc clippy rustfmt rust-analyzer sops gnupg age jq pkg-config libfido2 ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [ libxkbcommon linux-pam ];
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-tree);
    };
}
