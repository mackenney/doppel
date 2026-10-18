#!/usr/bin/env bash
# Mutation check for step-01: a restore that holds one byte more than
# max_hold must be caught by restore_holdback. Reverts the source on exit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
f=doppel/src/restore.rs
git diff --quiet -- "$f" || { echo "refusing: $f has uncommitted changes"; exit 2; }
trap 'git checkout -- "$f"' EXIT
sed -i '/let max_hold: usize =/s/unwrap_or(0);/unwrap_or(0) + 1;/' "$f"
grep -qF 'max().unwrap_or(0) + 1;' "$f" || { echo "mutation not applied"; exit 2; }
cargo nextest run -p doppel --all-features --test property --no-run
set +e
out=$(PROPTEST_CASES=256 PROPTEST_MAX_SHRINK_ITERS=64 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
  cargo nextest run -p doppel --all-features --test property --no-fail-fast restore_holdback:: 2>&1)
status=$?
set -e
echo "$out" | tail -n 40
if [ "$status" -eq 0 ]; then echo "MUTANT SURVIVED"; exit 1; fi
echo "$out" | grep -Eq 'FAIL .*restore_holdback::prop_restore_holdback_bound_after_every_chunk' \
  || { echo "expected property did not fail"; exit 1; }
echo "MUTANT KILLED"
