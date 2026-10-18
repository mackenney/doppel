#!/usr/bin/env bash
# Mutation check for step-02: if encryption is skipped (ciphertext field holds
# the plaintext secret), entries_no_leak must catch it through the decoded
# serialized form. Reverts the source on exit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
f=doppel/src/crypto.rs
git diff --quiet -- "$f" || { echo "refusing: $f has uncommitted changes"; exit 2; }
trap 'git checkout -- "$f"' EXIT
sed -i '/encrypt_in_place(&nonce, &fake, &mut buffer)/s/&mut buffer)/\&mut Vec::<u8>::new())/' "$f"
grep -qF 'encrypt_in_place(&nonce, &fake, &mut Vec::<u8>::new())' "$f" || { echo "mutation not applied"; exit 2; }
cargo nextest run -p doppel --all-features --test property --no-run
set +e
out=$(PROPTEST_CASES=256 PROPTEST_MAX_SHRINK_ITERS=64 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
  cargo nextest run -p doppel --all-features --test property --no-fail-fast entries_no_leak:: 2>&1)
status=$?
set -e
echo "$out" | tail -n 40
if [ "$status" -eq 0 ]; then echo "MUTANT SURVIVED"; exit 1; fi
echo "$out" | grep -Eq 'FAIL .*entries_no_leak::prop_entries_expose_no_secret_bytes' \
  || { echo "expected property did not fail"; exit 1; }
echo "MUTANT KILLED"
