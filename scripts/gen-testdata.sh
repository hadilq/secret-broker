#!/usr/bin/env bash
# Regenerates tests/testdata with a throwaway age key.
# The fixture's data key is written next to it ON PURPOSE: it is test data.
# Run: nix shell nixpkgs#sops nixpkgs#age nixpkgs#jq -c scripts/gen-testdata.sh
set -euo pipefail
cd "$(dirname "$0")/../tests/testdata"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
age-keygen -o "$tmp/key.txt" 2>/dev/null
recip=$(age-keygen -y "$tmp/key.txt")
cat > "$tmp/plain.json" <<'JSON'
{
  "api": { "token": "tok-123456", "nested": { "deep": "d-val" } },
  "list": ["a", "b"],
  "num": 42,
  "flt": 1.5,
  "flag": true,
  "empty": "",
  "public_unencrypted": "visible",
  "pi_unencrypted": 3.14
}
JSON
SOPS_AGE_RECIPIENTS=$recip sops encrypt --input-type json --output-type json "$tmp/plain.json" > secrets.sops.json
jq -r '.sops.age[0].enc' secrets.sops.json | age -d -i "$tmp/key.txt" | od -An -tx1 | tr -d ' \n' > datakey.hex
# encrypted_regex variant
SOPS_AGE_RECIPIENTS=$recip sops encrypt --encrypted-regex '^(token|deep)$' --input-type json --output-type json "$tmp/plain.json" > regex.sops.json
jq -r '.sops.age[0].enc' regex.sops.json | age -d -i "$tmp/key.txt" | od -An -tx1 | tr -d ' \n' > regex.datakey.hex
echo "ok: $(wc -c < datakey.hex) hex chars"
