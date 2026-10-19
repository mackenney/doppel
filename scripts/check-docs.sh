#!/usr/bin/env bash
# Fails when README.md's CLI reference and the binary's --help output disagree.
# Both directions are checked: every flag the CLI exposes must be documented in
# its command's README section, and every flag the README mentions must exist.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -q -p doppel-cli --locked
doppel() { cargo run -q -p doppel-cli --locked -- "$@"; }

# Flags the README mentions on purpose even though the CLI must not have them.
ignored_in_readme=(--key)

fail=0
note() { echo "docs-check: $*" >&2; fail=1; }

section() {
  awk -v cmd="### \`$1\`" 'index($0, cmd) == 1 {on=1; next} /^##+ /{on=0} on' README.md
}

commands=$(doppel --help | awk '/^Commands:/{on=1; next} /^$/{on=0} on {print $1}' | grep -vx help)
[[ -n $commands ]] || { echo "docs-check: no commands parsed from --help" >&2; exit 1; }

for cmd in $commands; do
  text=$(section "$cmd")
  [[ -n $text ]] || { note "README has no '### \`$cmd\`' section"; continue; }
  help_flags=$(doppel "$cmd" --help | grep -oE '^ +(-[A-Za-z], )?--[a-z][a-z0-9-]*' \
    | grep -oE -- '--[a-z][a-z0-9-]*' | grep -vx -- --help | sort -u)
  for f in $help_flags; do
    grep -qF -- "$f" <<<"$text" || note "$cmd: $f is in --help but not documented in README"
  done
  for f in $(grep -oE -- '--[a-z][a-z0-9-]*' <<<"$text" | sort -u); do
    [[ $f == --help ]] && continue
    printf '%s\n' "${ignored_in_readme[@]}" | grep -qx -- "$f" && continue
    grep -qx -- "$f" <<<"$help_flags" || note "$cmd: README mentions $f but --help does not list it"
  done
done

charsets=$(doppel define --help | grep -m1 '^Charsets:' | sed 's/^Charsets: *//; s/,/ /g')
[[ -n $charsets ]] || note "could not parse charset list from 'define --help'"
# Every "Valid charset names" list in the README (two lines each) must be complete.
lists=$(grep -A1 'Valid charset names' README.md | grep -v '^--$')
for c in $charsets; do
  while IFS= read -r block; do
    grep -qF -- "\`$c\`" <<<"$block" || note "README charset list is missing $c: ${block:0:60}"
  done < <(awk '/Valid charset names/{if (b) print b; b=$0; next} b {b=b" "$0; print b; b=""}' <<<"$lists")
done

exit $fail
