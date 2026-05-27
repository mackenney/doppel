# Step 07: Remove Redundant `bytes` from `[dev-dependencies]`

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 3 — cleanup. No file conflict with any other step. Can run in parallel with steps 05
and 06. `Cargo.toml` is not touched by any other step in this plan.

### This Step
`Cargo.toml` currently has:

```toml
[dev-dependencies]
zeroize = { version = "1", features = ["derive"] }
rand = { version = "0.8", features = ["std", "std_rng"] }
tempfile = "3"
futures = "0.3"
bytes = "1"
```

`bytes` is also a main dependency gated on the `async` feature:
`bytes = { version = "1", optional = true }`.

Tests that use `bytes::Bytes` are inside `src/unscrub_stream.rs`, which is only compiled
under `#[cfg(feature = "async")]`. When the `async` feature is enabled, `bytes` is already
a main dep and is available. When the feature is disabled, no code in `[dev-dependencies]`
requires `bytes`. The `bytes = "1"` dev-dep is therefore redundant in both cases.

## Prerequisites
None. This step has no file conflicts with any other step.

## Files to Read Before Starting
- `Cargo.toml` — the `[dev-dependencies]` section (last five lines)

## Implementation

### Task 1: Remove `bytes = "1"` from `[dev-dependencies]`

Open `Cargo.toml`. Locate the `[dev-dependencies]` block. Delete the `bytes = "1"` line.

**Before:**
```toml
[dev-dependencies]
zeroize = { version = "1", features = ["derive"] }
rand = { version = "0.8", features = ["std", "std_rng"] }
tempfile = "3"
futures = "0.3"
bytes = "1"
```

**After:**
```toml
[dev-dependencies]
zeroize = { version = "1", features = ["derive"] }
rand = { version = "0.8", features = ["std", "std_rng"] }
tempfile = "3"
futures = "0.3"
```

No other changes to `Cargo.toml`.

## Acceptance Criteria

- [ ] `grep 'bytes' Cargo.toml` prints exactly one match (the `bytes = { version = "1", optional = true }` main dep line) and zero matches in `[dev-dependencies]`
- [ ] `cargo test --features async 2>&1 | tail -5` exits 0
- [ ] `cargo test 2>&1 | tail -5` exits 0
- [ ] `cargo clippy --features async 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm only the `bytes = "1"` dev-dep line was removed — no other lines changed.
2. Confirm `bytes = { version = "1", optional = true }` in `[dependencies]` is untouched.
3. Confirm both `cargo test` and `cargo test --features async` still compile and pass.

## Rollback

Add `bytes = "1"` back to the `[dev-dependencies]` block.
