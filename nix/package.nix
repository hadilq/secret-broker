{
  lib,
  stdenv,
  rustPlatform,
  gnupg,
  linux-pam,
  openpam,
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
  # Linux-PAM on Linux; OpenPAM on Darwin (the Apple SDK's libpam is not
  # on rustc's link path in a Nix build).
  buildInputs = [
    (if stdenv.hostPlatform.isLinux then linux-pam else openpam)
  ];

  # Absolute gpg/gpgconf/gpg-connect-agent fallback when they are not on PATH.
  env.SECRET_BROKER_GNUPG_BIN = "${gnupg}/bin";
  # fido2-token / fido2-cred for `secret-broker fido2-enroll`.
  env.SECRET_BROKER_FIDO2_DIR = "${libfido2}/bin";

  postInstall = ''
    ln -s secret-broker $out/bin/secret-run
  ''
  + lib.optionalString stdenv.hostPlatform.isLinux ''
    mkdir -p $out/lib
    $CC -shared -fPIC -o $out/lib/libsb_nondump.so ${./nondump.c}
  '';

  meta = {
    description = "Let AI agents use secrets through allowlisted commands without reading them";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
    mainProgram = "secret-broker";
  };
}
