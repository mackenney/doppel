#!/usr/bin/env bash
# Mutation check for step-02: if the nonce field carries session key bytes,
# entries_no_leak must catch the embedded key. Reverts the source on exit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
f=doppel/src/crypto.rs
git diff --quiet -- "$f" || { echo "refusing: $f has uncommitted changes"; exit 2; }
trap 'git checkout -- "$f"' EXIT
sed -i 's/nonce: nonce_bytes.to_vec(),/nonce: session_key.as_bytes()[..24].to_vec(),/' "$f"
grep -qF 'nonce: session_key.as_bytes()[..24].to_vec(),' "$f" || { echo "mutation not applied"; exit 2; }
cargo nextest run -p doppel --all-features --test property --no-run
set +e
out=$(PROPTEST_CASES=256 PROPTEST_MAX_SHRINK_ITERS=64 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
  cargo nextest run -p doppel --all-features --test property --no-fail-fast entries_no_leak:: 2>&1)
status=$?
set -e
echo "$out" | tail -n 40
if [ "$status" -eq 0 ]; then echo "MUTANT SURVIVED"; exit 1; fi
echo "$out" | grep -Eq 'FAIL .*entries_no_leak::prop_entries_do_not_embed_session_key' \
  || { echo "expected property did not fail"; exit 1; }
echo "MUTANT KILLED"
