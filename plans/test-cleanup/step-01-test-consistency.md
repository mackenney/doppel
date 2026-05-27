# Step 01: Test consistency fixes

## Context

### Overall Objective
Align inline unit tests with the spec test suite on nonce size and assertion completeness,
and add an explicit `break` to the None branch of `process_buffer` for control-flow symmetry.

### This Step
Three mechanical changes across two files:

1. `src/unscrub_stream.rs` — `test_empty_fake_rejected_stream`: change `nonce: vec![0u8; 12]`
   to `nonce: vec![0u8; 24]` to match the XChaCha20-Poly1305 requirement and the spec tests.

2. `src/unscrub.rs` — `test_empty_fake_rejected_sync`: add
   `assert!(output.is_empty(), "guard must fire before any bytes are written");`
   after the existing `assert!(matches!(result, Err(...)))` check.

3. `src/unscrub_stream.rs` — `process_buffer` None arm: add `break;` after `cursor = safe_end`
   so the None arm has explicit control flow like the two non-match `Some(ac)` arms.
   The behaviour is equivalent (next iteration would hit `remaining == 0 → break` anyway),
   but the intent is now explicit. Update the comment accordingly.

## Prerequisites
None.

## Files to Read Before Starting
- `src/unscrub_stream.rs` — `test_empty_fake_rejected_stream` (around line 462) and
  `process_buffer` None arm (around line 125)
- `src/unscrub.rs` — `test_empty_fake_rejected_sync` (around line 282)

## Implementation

### Task 1: Fix nonce in test_empty_fake_rejected_stream

In `src/unscrub_stream.rs`, find:
```rust
fn test_empty_fake_rejected_stream() {
    ...
    let bad_entry = Entry {
        fake: vec![],
        ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],   // ← change this
    };
```
Change to `nonce: vec![0u8; 24]`.

### Task 2: Add output.is_empty() assertion to test_empty_fake_rejected_sync

In `src/unscrub.rs`, find `test_empty_fake_rejected_sync`. After the `assert!(matches!(...))` block, add:
```rust
assert!(output.is_empty(), "guard must fire before any bytes are written");
```

### Task 3: Add break to None branch in process_buffer

In `src/unscrub_stream.rs`, find the `None =>` arm of `process_buffer`:
```rust
None => {
    // No entries: forward all safe bytes as one chunk.
    // Advance cursor so the post-loop epilogue drains uniformly.
    let chunk = Bytes::copy_from_slice(&self.buffer[cursor..safe_end]);
    self.pending.push_back(Ok(chunk));
    cursor = safe_end;
    // Loop: with max_hold == 0, cursor == buffer.len() after draining,
    // then remaining == 0 → break.
}
```

Change to:
```rust
None => {
    // No entries: forward all safe bytes as one chunk.
    // Advance cursor so the post-loop epilogue drains uniformly.
    let chunk = Bytes::copy_from_slice(&self.buffer[cursor..safe_end]);
    self.pending.push_back(Ok(chunk));
    cursor = safe_end;
    break;
}
```

(Remove the stale "then remaining == 0 → break" comment — the `break` is now explicit.)

## Acceptance Criteria

- [ ] `grep -n 'vec!\[0u8; 12\]' src/unscrub_stream.rs src/unscrub.rs` finds zero matches
- [ ] `grep -n 'output.is_empty' src/unscrub.rs` finds exactly one match
- [ ] `grep -n 'cursor = safe_end' src/unscrub_stream.rs` is followed by `break` in the None arm (check with context)
- [ ] `cargo test --features async` exits 0
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Reviewer Instructions

Verify:
1. `grep -n 'vec!\[0u8; 12\]' src/unscrub_stream.rs src/unscrub.rs` → zero matches
2. `grep -n 'output.is_empty' src/unscrub.rs` → one match in the test
3. `grep -A2 'cursor = safe_end' src/unscrub_stream.rs | grep break` → finds break in None arm context
4. `cargo test --features async` → exits 0
5. `cargo clippy --workspace --all-targets -- -D warnings` → exits 0

Report: "PASS" or "FAIL: <criterion> — <what's wrong>"

## Rollback
`git revert` the single commit.
