#!/usr/bin/env bash
# Tag policy: every version published to crates.io has a `v<version>` tag whose
# commit is on main's first-parent chain (a merge or release commit, never a
# feature-branch commit) and whose Cargo.toml versions match the tag.
# Usage: check-tags.sh [--after-release <version>]
#   default            checks every published version (run before a release)
#   --after-release V  also requires V to be tagged, published and pushed
set -euo pipefail
cd "$(dirname "$0")/.."

# Published before tags became mandatory; never tagged.
grandfathered=(0.0.1)

crates=(doppel doppel-cli)
fail=0
note() { echo "tag-check: $*" >&2; fail=1; }

expect=""
if [[ ${1:-} == --after-release ]]; then expect=${2:?version required}; fi

main_chain=$(git rev-list --first-parent main)

published() {
  curl -fsS -A "doppel-tag-check" "https://crates.io/api/v1/crates/$1" \
    | jq -r '.versions[] | select(.yanked | not) | .num'
}

versions=$(for c in "${crates[@]}"; do published "$c"; done | sort -u)
[[ -n $versions ]] || { echo "tag-check: no versions fetched from crates.io" >&2; exit 1; }
[[ -z $expect ]] || versions=$(printf '%s\n%s\n' "$versions" "$expect" | sort -u)

for v in $versions; do
  if printf '%s\n' "${grandfathered[@]}" | grep -qx -- "$v"; then continue; fi
  tag="v$v"
  commit=$(git rev-parse -q --verify "refs/tags/$tag^{commit}") || { note "$tag does not exist"; continue; }
  grep -qx "$commit" <<<"$main_chain" || note "$tag ($commit) is not on main's first-parent chain"
  for c in "${crates[@]}"; do
    tv=$(git show "$tag:$c/Cargo.toml" | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1)
    [[ $tv == "$v" ]] || note "$tag: $c/Cargo.toml says '$tv'"
  done
done

if [[ -n $expect ]]; then
  for c in "${crates[@]}"; do
    published "$c" | grep -qx -- "$expect" || note "$c $expect is not on crates.io"
  done
  # origin fetches from one host and pushes to several; check every destination.
  for url in $( (git remote get-url origin; git remote get-url --all --push origin) | sort -u); do
    git ls-remote --exit-code --tags "$url" "refs/tags/v$expect" >/dev/null 2>&1 \
      || note "v$expect is not on $url"
  done
fi
exit $fail
