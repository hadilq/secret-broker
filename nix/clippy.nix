# `cargo clippy --all-targets -- -D warnings` as a derivation, so any lint
# (including the no-panic lints in Cargo.toml) fails `nix flake check`.
{ secret-broker, clippy }:
secret-broker.overrideAttrs (old: {
  pname = "secret-broker-clippy";
  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ clippy ];
  buildPhase = ''
    runHook preBuild
    cargo clippy --offline --all-targets -- -D warnings
    runHook postBuild
  '';
  doCheck = false;
  installPhase = ''
    touch $out
  '';
  postInstall = "";
  dontFixup = true;
})
