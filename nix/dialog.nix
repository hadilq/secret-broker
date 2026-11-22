# The approval dialog / pinentry. Separate from the broker package so the
# system service never pulls in Wayland or font code.
{
  lib,
  rustPlatform,
  pkg-config,
  libxkbcommon,
}:
let
  cargo = lib.importTOML ../dialog/Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "secret-broker-dialog";
  inherit (cargo.package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
      ../tests
      ../dialog
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "-p" "secret-broker-dialog" ];
  cargoTestFlags = [ "-p" "secret-broker-dialog" ];

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ libxkbcommon ];

  meta = {
    description = "Wayland layer-shell approval dialog and pinentry for secret-broker";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "secret-broker-dialog";
  };
}
