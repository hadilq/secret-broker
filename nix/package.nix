{
  lib,
  rustPlatform,
  gnupg,
}:
let
  cargo = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "secret-broker";
  inherit (cargo.package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
      ../tests
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # Absolute gpg/gpgconf/gpg-connect-agent fallback when they are not on PATH.
  env.SECRET_BROKER_GNUPG_BIN = "${gnupg}/bin";

  postInstall = ''
    ln -s secret-broker $out/bin/secret-run
  '';

  meta = {
    description = "Let AI agents use secrets through allowlisted commands without reading them";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "secret-broker";
  };
}
