# Step 02: Fix None-branch cursor + add Zeroizing comment in unscrub_stream.rs

## Context

### Overall Objective
Close five post-review findings on unscrub correctness, safety, and test coverage.

### Phase Context
Wave 0. Isolated to `src/unscrub_stream.rs`. Runs in parallel with step-01.

### This Step
Two small fixes in `process_buffer`:

1. **None-branch cursor inconsistency**: the `ac = None` arm drains inline and leaves
   `cursor = 0`. The post-loop epilogue `if cursor > 0 { self.buffer.drain(..cursor) }`
   therefore never fires for that path. The two paths mix drain strategies. Fix: advance
   `cursor` in the None arm instead of draining inline, so the epilogue handles all drains
   uniformly.

2. **Zeroizing comment gap**: `Bytes::copy_from_slice(&plaintext)` produces a separate heap
   allocation that is NOT zeroized by the `Zeroizing` drop. This is correct and intentional
   defense-in-depth, but a future reader could misread it as end-to-end zeroing. Add a
   one-line comment.

## Prerequisites
None.

## Files to Read Before Starting
- `src/unscrub_stream.rs` — the `process_buffer` function (roughly lines 106-190)

## Implementation

### Task 1: Fix the None-branch to use cursor

Find the `None =>` arm in `process_buffer` that currently reads:

```rust
None => {
    // No entries: forward all safe bytes as one chunk.
    // cursor stays 0 in this branch; drain inline as before.
    let chunk = Bytes::copy_from_slice(&self.buffer[..safe_end]);
    self.buffer.drain(..safe_end);
    self.pending.push_back(Ok(chunk));
    // Loop: with max_hold == 0, safe_end == buffer.len() each
    // iteration until buffer is empty, then remaining == 0 → break.
}
```

Replace with:

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

The post-loop epilogue `if cursor > 0 { self.buffer.drain(..cursor); }` already
handles the drain. Remove the inline `self.buffer.drain(..safe_end)` call.

Note: with `max_hold = 0` (the invariant when `ac = None`), `safe_end = buffer.len()`
on every iteration, so `cursor = safe_end` drains everything in one pass and the next
iteration hits `remaining == 0` → `break`. Behaviour is identical to before.

### Task 2: Add Zeroizing comment

Find the `Ok(plaintext)` arm in `process_buffer` that reads:

```rust
Ok(plaintext) => {
    let plaintext = Zeroizing::new(plaintext);
    self.pending
        .push_back(Ok(Bytes::copy_from_slice(&plaintext)));
}
```

Add a one-line comment above `copy_from_slice`:

```rust
Ok(plaintext) => {
    let plaintext = Zeroizing::new(plaintext);
    // copy_from_slice produces an unzeroized Bytes; Zeroizing zeroes the decrypt buffer only.
    self.pending
        .push_back(Ok(Bytes::copy_from_slice(&plaintext)));
}
```

## Acceptance Criteria

- [ ] `grep -n 'self.buffer.drain' src/unscrub_stream.rs` — the None-branch drain must be gone; only the epilogue drain (`if cursor > 0`) remains in `process_buffer`
- [ ] `grep -n 'cursor stays 0\|drain inline' src/unscrub_stream.rs` — stale comments removed
- [ ] `grep -n 'unzeroized Bytes\|zeroes the decrypt buffer' src/unscrub_stream.rs` — new comment present
- [ ] `cargo test --features async` exits 0
- [ ] `cargo clippy --features async -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 02. Verify:

1. `grep -n 'self.buffer.drain' src/unscrub_stream.rs` — must NOT appear inside the None arm of `process_buffer`; only the post-loop epilogue drain should remain
2. `grep -n 'cursor = safe_end' src/unscrub_stream.rs` — must appear in the None arm
3. `grep -n 'unzeroized Bytes\|zeroes the decrypt buffer' src/unscrub_stream.rs` — must find one match
4. `cargo test --features async` — must exit 0
5. `cargo clippy --features async -- -D warnings` — must exit 0

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
`git revert` the single commit for this step.
