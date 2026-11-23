# `cargo clippy --all-targets -- -D warnings` as a derivation, so any lint
# (including the no-panic lints in Cargo.toml) fails `nix flake check`.
{
  lib,
  stdenv,
  secret-broker,
  clippy,
  pkg-config,
  libxkbcommon,
}:
secret-broker.overrideAttrs (old: {
  pname = "secret-broker-clippy";
  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
    clippy
    pkg-config
  ];
  # The dialog's Wayland deps are Linux-only (Cargo.toml target table).
  buildInputs = (old.buildInputs or [ ]) ++ lib.optionals stdenv.hostPlatform.isLinux [ libxkbcommon ];
  buildPhase = ''
    runHook preBuild
    cargo clippy --offline --workspace --all-targets -- -D warnings
    runHook postBuild
  '';
  doCheck = false;
  installPhase = ''
    touch $out
  '';
  postInstall = "";
  dontFixup = true;
})
