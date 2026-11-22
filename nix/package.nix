{
  lib,
  rustPlatform,
  gnupg,
  linux-pam,
  libfido2,
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
      # workspace member manifest (cargo needs it even when building -p secret-broker)
      ../dialog
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "-p" "secret-broker" ];
  cargoTestFlags = [ "-p" "secret-broker" ];

  # libpam for the `pam-check` helper (fingerprint & other PAM approval
  # methods run in that separate process, never in the daemon).
  buildInputs = [ linux-pam ];

  # Absolute gpg/gpgconf/gpg-connect-agent fallback when they are not on PATH.
  env.SECRET_BROKER_GNUPG_BIN = "${gnupg}/bin";
  # fido2-token / fido2-cred for `secret-broker fido2-enroll`.
  env.SECRET_BROKER_FIDO2_DIR = "${libfido2}/bin";

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
