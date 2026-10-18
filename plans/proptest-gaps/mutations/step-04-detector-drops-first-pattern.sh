#!/usr/bin/env bash
# Mutation check for step-04: a Detector whose swap diverges from the free
# swap (here: it ignores its first pattern) must be caught by detector_reuse.
# Reverts the source on exit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
f=doppel/src/detector.rs
git diff --quiet -- "$f" || { echo "refusing: $f has uncommitted changes"; exit 2; }
trap 'git checkout -- "$f"' EXIT
sed -i 's/swap_with_ac(payload, &self.patterns, &self.ac)/swap_with_ac(payload, \&self.patterns[self.patterns.len().min(1)..], \&self.ac)/' "$f"
grep -qF 'swap_with_ac(payload, &self.patterns[self.patterns.len().min(1)..], &self.ac)' "$f" || { echo "mutation not applied"; exit 2; }
cargo nextest run -p doppel --all-features --test property --no-run
set +e
out=$(PROPTEST_CASES=256 PROPTEST_MAX_SHRINK_ITERS=64 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
  cargo nextest run -p doppel --all-features --test property --no-fail-fast detector_reuse:: 2>&1)
status=$?
set -e
echo "$out" | tail -n 40
if [ "$status" -eq 0 ]; then echo "MUTANT SURVIVED"; exit 1; fi
echo "$out" | grep -Eq 'FAIL .*detector_reuse::prop_detector_(reused_sequentially|shared_across_threads)_matches_free_swap' \
  || { echo "expected property did not fail"; exit 1; }
echo "MUTANT KILLED"
