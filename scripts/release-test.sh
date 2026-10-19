#!/usr/bin/env bash
# Release-grade test run: many more property cases than the default and zero
# tolerated skips or ignored tests. A skipped test is unverified behavior.
set -euo pipefail
cd "$(dirname "$0")/.."

log=$(mktemp)
trap 'rm -f "$log"' EXIT

PROPTEST_CASES="${PROPTEST_CASES:-10000}" \
  cargo nextest run --workspace --all-features --locked --no-tests=fail 2>&1 | tee "$log"

if grep -qE 'Summary.*[1-9][0-9]* skipped' "$log"; then
  echo "release-test: tests were skipped; a release requires all tests to run" >&2
  exit 1
fi
