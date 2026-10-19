#!/usr/bin/env bash
# Release gate: CHANGELOG.md must have been updated since the last tag and its
# [Unreleased] section must carry entries. Prints the first-parent history since
# the tag so the reviewer can confirm every change is accounted for.
set -euo pipefail
cd "$(dirname "$0")/.."

last_tag=$(git describe --tags --abbrev=0 --match 'v*')
fail=0
note() { echo "changelog-check: $*" >&2; fail=1; }

git diff --quiet "$last_tag"..HEAD -- CHANGELOG.md && note "CHANGELOG.md is unchanged since $last_tag"

unreleased=$(awk '/^## \[Unreleased\]/{on=1; next} /^## \[/{on=0} on' CHANGELOG.md)
grep -qE '^- ' <<<"$unreleased" || note "[Unreleased] has no entries"

grep -q '^<!-- next-header -->' CHANGELOG.md || note "missing <!-- next-header --> marker (cargo-release needs it)"
grep -q '^<!-- next-url -->' CHANGELOG.md || note "missing <!-- next-url --> marker (cargo-release needs it)"

echo "changes since $last_tag (compare against [Unreleased]):"
git log --first-parent --oneline "$last_tag"..HEAD

if [[ -n $(git diff --name-only "$last_tag"..HEAD -- doppel/src doppel-cli/src) ]] && ! grep -qE '^### (Added|Changed|Fixed)' <<<"$unreleased"; then
  note "source changed since $last_tag but [Unreleased] has no Added/Changed/Fixed section"
fi
exit $fail
