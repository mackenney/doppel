# Step 01: Comment fixes

## Context
Two small documentation consistency fixes identified by code review:
1. The async `process_buffer` Zeroizing site is missing the `INV-5` reference that the sync path has.
2. The async spec test `test_inv_empty_fake_async_rejected` has no `output.is_empty()` check — add a comment explaining why (constructor failure prevents stream creation, so no I/O can occur).

## Files to Read Before Starting
- `src/unscrub_stream.rs` — Zeroizing comment around line 159
- `tests/spec/inv.rs` — `test_inv_empty_fake_async_rejected` around line 911

## Implementation

### Task 1: Add INV-5 reference in unscrub_stream.rs

Find:
```rust
let plaintext = Zeroizing::new(plaintext);
// copy_from_slice produces an unzeroized Bytes; Zeroizing zeroes the decrypt buffer only.
self.pending
    .push_back(Ok(Bytes::copy_from_slice(&plaintext)));
```

Change to:
```rust
let plaintext = Zeroizing::new(plaintext);
// INV-5: emit plaintext ONLY after successful decryption.
// copy_from_slice produces an unzeroized Bytes; Zeroizing zeroes the decrypt buffer only.
self.pending
    .push_back(Ok(Bytes::copy_from_slice(&plaintext)));
```

### Task 2: Add explanatory comment to async spec test

In `tests/spec/inv.rs`, inside `test_inv_empty_fake_async_rejected`, after the final `assert!`, add a comment before the closing `}`:

```rust
    assert!(
        matches!(result, Err(UnscrubError::Build { .. })),
        "empty fake MUST return Err(Build) from constructor"
    );
    // No output check: constructor failure prevents stream creation,
    // so zero bytes can ever be emitted (no stream object → no I/O).
}
```

## Acceptance Criteria

- [ ] `grep -n 'INV-5' src/unscrub_stream.rs` finds at least one match in process_buffer
- [ ] `grep -n 'constructor failure' tests/spec/inv.rs` finds one match
- [ ] `cargo test --features async` exits 0
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Reviewer Instructions

1. `grep -n 'INV-5' src/unscrub_stream.rs` → must find match in process_buffer
2. `grep -n 'constructor failure\|no stream object' tests/spec/inv.rs` → must find one match
3. `cargo test --features async` → exits 0
4. `cargo clippy --workspace --all-targets -- -D warnings` → exits 0

Report: "PASS" or "FAIL: <criterion> — <what's wrong>"

## Rollback
`git revert` this step's commit.
