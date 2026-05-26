# step-03: Flatten ScrubError — no internal type leakage

## Context

**Overall Objective:** Clean up library public API. Internal error types should not leak through `ScrubError`.

**Phase Context:** Wave 2 (parallel with step-02). Workspace split is complete.

**This Step:** Add `#[non_exhaustive]` to `ScrubError`, replace `#[from]` variants with
`{msg: String}` fields, add manual `From` impls, and restrict visibility of `FakeError` and
`crypto::Error` to `pub(crate)`.

## Prerequisites

- step-01 complete and committed.
- `cargo nextest run` reports 79 passed.

## Files to Read Before Starting

| File | Why |
|------|-----|
| `src/types.rs` | `ScrubError` enum (lines 57–63) — the target of this change |
| `src/fake.rs` | `pub enum FakeError` (line 6) — must change to `pub(crate)` |
| `src/crypto.rs` | `pub enum Error` (line 78) — must change to `pub(crate)` |
| `src/scrub.rs` | Uses `?` on crypto/fake errors (lines 97–98) — From impls must work |
| `src/tier2.rs` | `From<FakeError> for RegistrationError` (line 72) — must still compile |

## Implementation

### Task 1: Replace `ScrubError` variants and add `#[non_exhaustive]`

**File:** `src/types.rs`, lines 57–63

Replace:
```rust
#[derive(Debug, thiserror::Error)]
pub enum ScrubError {
    #[error("encryption failed: {0}")]
    Crypto(#[from] crate::crypto::Error),
    #[error("fake generation failed: {0}")]
    Fake(#[from] crate::fake::FakeError),
}
```

With:
```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScrubError {
    #[error("encryption failed: {msg}")]
    Crypto { msg: String },
    #[error("fake generation failed: {msg}")]
    Fake { msg: String },
}

impl From<crate::crypto::Error> for ScrubError {
    fn from(e: crate::crypto::Error) -> Self {
        ScrubError::Crypto { msg: e.to_string() }
    }
}

impl From<crate::fake::FakeError> for ScrubError {
    fn from(e: crate::fake::FakeError) -> Self {
        ScrubError::Fake { msg: e.to_string() }
    }
}
```

**Why this works:** `scrub.rs` line 97 does `generate_fake_for_match(&m, &secret)?` which
returns `Result<Vec<u8>, FakeError>`. The `?` operator calls `From<FakeError> for ScrubError`.
Line 98 does `encrypt_secret(&session_key, fake.clone(), &secret)?` which returns
`Result<Entry, crypto::Error>`. The `?` calls `From<crypto::Error> for ScrubError`. Both
manual `From` impls handle these conversions identically to the previous `#[from]` attributes.

### Task 2: Change `FakeError` to `pub(crate)`

**File:** `src/fake.rs`, line 6

Change:
```rust
pub enum FakeError {
```

To:
```rust
pub(crate) enum FakeError {
```

**Impact:** `FakeError` is used in:
- `src/fake.rs` (same module — fine)
- `src/scrub.rs` line 5: `use crate::fake::FakeError;` (same crate — fine with `pub(crate)`)
- `src/tier2.rs` line 5: `use crate::fake::{FakeError, charsets, generate_fake_tier2};` (same crate — fine)
- `src/types.rs`: `From<crate::fake::FakeError> for ScrubError` (same crate — fine)

No external code references `FakeError` directly. The type was only reachable through
`ScrubError::Fake(FakeError)` which no longer exists.

### Task 3: Change `crypto::Error` to `pub(crate)`

**File:** `src/crypto.rs`, line 78

Change:
```rust
pub enum Error {
```

To:
```rust
pub(crate) enum Error {
```

**Impact:** `crypto::Error` is used in:
- `src/crypto.rs` (same module — fine)
- `src/types.rs`: `From<crate::crypto::Error> for ScrubError` (same crate — fine)

No external code references `crypto::Error` directly. The type was only reachable through
`ScrubError::Crypto(crypto::Error)` which no longer exists.

### Task 4: Verify compilation

Run:
```sh
cargo build --workspace
```

If `scrub.rs` fails to compile, check that:
- The `From<FakeError> for ScrubError` impl is in `types.rs` (not gated behind `#[cfg(test)]`)
- The `From<crypto::Error> for ScrubError` impl is in `types.rs`
- Both use `.to_string()` which requires `Display` — both error types derive `thiserror::Error`
  which implements `Display`

### Task 5: Commit

```sh
cargo fmt --all
git add -A
git commit -m "step-03: flatten ScrubError — no internal type leakage"
```

## Acceptance Criteria

1. `cargo nextest run` exits 0, reports exactly 79 tests passed.
2. `cargo build --workspace` exits 0.
3. `cargo clippy --workspace` exits 0 with no warnings.
4. `cargo fmt --all --check` exits 0.
5. Verify `FakeError` is `pub(crate)`:
   ```sh
   grep 'pub(crate) enum FakeError' src/fake.rs
   # Expected: 1 match
   ```
6. Verify `crypto::Error` is `pub(crate)`:
   ```sh
   grep 'pub(crate) enum Error' src/crypto.rs
   # Expected: 1 match
   ```
7. Verify `ScrubError` has `#[non_exhaustive]`:
   ```sh
   grep -A1 'non_exhaustive' src/types.rs | grep 'pub enum ScrubError'
   # Expected: "pub enum ScrubError {"
   ```
8. Verify no `#[from]` attributes remain in `ScrubError`:
   ```sh
   grep '#\[from\]' src/types.rs
   # Expected: no output
   ```

## Reviewer Instructions

Run these commands in order. All must pass.

```sh
cargo nextest run 2>&1 | tail -3
# Expected: "79 tests run: 79 passed, 0 skipped"

grep 'pub(crate) enum FakeError' src/fake.rs
# Expected: 1 match

grep 'pub(crate) enum Error' src/crypto.rs
# Expected: 1 match

grep '#\[non_exhaustive\]' src/types.rs
# Expected: 1 match

grep '#\[from\]' src/types.rs; echo "exit: $?"
# Expected: no output, exit 1

cargo clippy --workspace 2>&1 | grep -c warning
# Expected: 0
```

## Rollback

```sh
git reset --hard HEAD~1
cargo nextest run   # verify step-01 state restored
```
