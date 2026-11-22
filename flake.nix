{
  description = "secret-broker: let AI agents use secrets through allowlisted commands without reading them";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        secret-broker = pkgs.callPackage ./nix/package.nix { };
        default = secret-broker;
      });

      overlays.default = final: _prev: { secret-broker = final.callPackage ./nix/package.nix { }; };

      nixosModules.default = ./nix/nixos-module.nix;
      nixosModules.secret-broker = ./nix/nixos-module.nix;
      homeManagerModules.default = ./nix/hm-module.nix;
      homeManagerModules.secret-broker = ./nix/hm-module.nix;

      checks = forAll (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        clippy = pkgs.callPackage ./nix/clippy.nix {
          secret-broker = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
        vm = pkgs.testers.runNixOSTest (import ./nix/vm-test.nix { inherit self; });
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer sops gnupg age jq ];
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-tree);
    };
}
