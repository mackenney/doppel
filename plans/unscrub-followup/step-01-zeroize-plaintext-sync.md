# Step 01: Zeroize decrypted plaintext in sync unscrub

## Context

### Overall Objective
Close five post-review findings on unscrub correctness, safety, and test coverage.

### Phase Context
Wave 0. Isolated to `src/unscrub.rs`. Runs in parallel with step-02.

### This Step
`unscrub_stream.rs` wraps the decrypted plaintext in `Zeroizing::new(plaintext)` before
`copy_from_slice`. `unscrub.rs` does not — it holds a bare `Vec<u8>` that is written to
output and dropped unzeroed. Apply the same treatment to the sync path.

## Prerequisites
None.

## Files to Read Before Starting
- `src/unscrub.rs` — full file; the plaintext site is around line 127-134
- `src/unscrub_stream.rs` — lines 155-165, to copy the exact pattern already used

## Implementation

### Task 1: Add Zeroizing import

At the top of `src/unscrub.rs`, after the existing `use` statements, add:

```rust
use zeroize::Zeroizing;
```

`zeroize` is already a workspace dependency (it is in `[dependencies]` via the `zeroize`
crate used by `SessionKey`); no Cargo.toml change is needed.

### Task 2: Wrap plaintext in the Some(m) match arm

Find the block in the inner loop that currently reads:

```rust
let plaintext =
    decrypt_entry(session_key, &entries[entry_idx]).map_err(|e| {
        log::debug!("AEAD decryption failed for entry {entry_idx}: {e}");
        UnscrubError::AeadTagFailure {
            entry_index: entry_idx,
        }
    })?;
// INV-5: emit plaintext ONLY after successful decryption
output.write_all(&plaintext)?;
cursor = m.end();
```

Change to:

```rust
let plaintext = Zeroizing::new(
    decrypt_entry(session_key, &entries[entry_idx]).map_err(|e| {
        log::debug!("AEAD decryption failed for entry {entry_idx}: {e}");
        UnscrubError::AeadTagFailure {
            entry_index: entry_idx,
        }
    })?,
);
// INV-5: emit plaintext ONLY after successful decryption
output.write_all(&plaintext)?;
cursor = m.end();
```

`Zeroizing<Vec<u8>>` implements `Deref<Target = Vec<u8>>` so `&plaintext` passes as
`&[u8]` to `write_all` without any other changes. The wrapper zeroes the heap allocation
when `plaintext` drops at the end of the `Some(m)` arm.

## Acceptance Criteria

- [ ] `grep -n 'use zeroize::Zeroizing' src/unscrub.rs` finds exactly one match
- [ ] `grep -n 'Zeroizing::new' src/unscrub.rs` finds exactly one match
- [ ] `grep -n 'Bytes::from\|let plaintext =' src/unscrub.rs | grep -v Zeroizing` finds zero plaintext-assignment lines without Zeroizing (i.e., no bare Vec<u8> assignment for decrypted plaintext)
- [ ] `cargo test` exits 0 (all existing tests pass)
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 01. Verify:

1. `grep -n 'use zeroize::Zeroizing' src/unscrub.rs` — must find exactly one match
2. `grep -n 'Zeroizing::new' src/unscrub.rs` — must find exactly one match, wrapping the `decrypt_entry` call
3. `cargo test` — must exit 0
4. `cargo clippy -- -D warnings` — must exit 0
5. Confirm `write_all(&plaintext)` still compiles (Zeroizing derefs to Vec<u8> which derefs to [u8])

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
`git revert` the single commit for this step.
