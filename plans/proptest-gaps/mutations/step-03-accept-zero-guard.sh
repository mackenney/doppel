#!/usr/bin/env bash
# Mutation check for step-03: registration that accepts a zero threshold
# (INV-49 / VC-23) must be caught. Reverts the source on exit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
f=doppel/src/secrets.rs
git diff --quiet -- "$f" || { echo "refusing: $f has uncommitted changes"; exit 2; }
trap 'git checkout -- "$f"' EXIT
sed -i 's/if opts.trailing_run_guard == Some(0) {/if false \&\& opts.trailing_run_guard == Some(0) {/' "$f"
grep -qF 'if false && opts.trailing_run_guard == Some(0) {' "$f" || { echo "mutation not applied"; exit 2; }
cargo nextest run -p doppel --all-features --test property --no-run
set +e
out=$(PROPTEST_CASES=256 PROPTEST_MAX_SHRINK_ITERS=64 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
  cargo nextest run -p doppel --all-features --test property --no-fail-fast registration_guard:: 2>&1)
status=$?
set -e
echo "$out" | tail -n 40
if [ "$status" -eq 0 ]; then echo "MUTANT SURVIVED"; exit 1; fi
echo "$out" | grep -Eq 'FAIL .*registration_guard::prop_registration_guard_option_errors' \
  || { echo "expected property did not fail"; exit 1; }
echo "MUTANT KILLED"
