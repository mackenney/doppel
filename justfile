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
