# Canonical development entrypoints. Hooks and release checks reuse these.

default:
    @just --list

# Install local hooks; safe to repeat.
setup:
    prek install

# Apply formatting.
fmt:
    cargo fmt --all

# Non-mutating formatting and lint checks.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-features --all-targets --locked -- -D warnings

# Fast deterministic tests: spec invariants, integration, inline unit tests.
test:
    cargo nextest run --workspace --all-features --locked

# Property tests; scale with PROPTEST_CASES=N.
test-property:
    cargo nextest run -p doppel --all-features --locked --test property

# CLI process-boundary tests.
test-e2e:
    cargo nextest run -p doppel-cli --features test-e2e --locked --test e2e

# RustSec advisory check against Cargo.lock. Fails if cargo-audit is missing.
audit:
    cargo audit --deny warnings

# Verify both crates package cleanly.
package:
    cargo package --workspace --locked

# Full integration gate; run before merging to main and before a release.
verify: check test test-e2e audit package

# Fail when README's CLI reference and `doppel --help` disagree.
docs-check:
    scripts/check-docs.sh

# Fail when CHANGELOG.md was not updated since the last tag.
changelog-check:
    scripts/check-changelog.sh

# Fail unless every published version has a tag on main's first-parent chain.
tag-check:
    scripts/check-tags.sh

# Release-scale tests (PROPTEST_CASES=10000) with no skipped tests.
release-test:
    scripts/release-test.sh

# Stricter gate run before a release.
release-verify: check audit package docs-check changelog-check tag-check release-test
