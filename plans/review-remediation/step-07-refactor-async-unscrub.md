# Step 07: Refactor Async unscrub_stream to Use Core

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 2 — Refactor `unscrub_stream.rs` to use the shared `process_safe_region` from `unscrub_core`. This is the final deduplication step; after this, both sync and async share identical sliding-window logic.

### This Step
Replace the `process_buffer` method's inline loop (lines ~109-186) with a call to `process_safe_region`, providing async-appropriate emit and error callbacks that push to `self.pending`.

## Prerequisites
- Step 05 complete (unscrub_core module exists)
- Step 06 complete (sync unscrub verified working with core)

## Files to Read Before Starting
- `src/unscrub_core.rs` — understand `process_safe_region` signature
- `src/unscrub_stream.rs` — locate `process_buffer` method and its inline loop
- `SPEC.md` — INV-5, INV-6, INV-8 constraints

## Implementation
### Task 1: Import unscrub_core
**File:** `src/unscrub_stream.rs`

Add import at top:
```rust
use crate::unscrub_core::process_safe_region;
```

### Task 2: Refactor process_buffer to use process_safe_region
**File:** `src/unscrub_stream.rs`
**Location:** `process_buffer` method (around line 109)

**Borrow conflict resolution:** The closure captures `&mut self.pending`, but we also need `&mut self.buffer`. Solution: pass references to individual fields rather than `&mut self` in closures.

Refactored code:
```rust
fn process_buffer(&mut self, eof: bool) {
    let pending = &mut self.pending;
    let result = process_safe_region(
        &mut self.buffer,
        &self.ac,
        &self.entries,
        &self.session_key,
        eof,
        self.max_hold,
        &mut |bytes| {
            pending.push_back(Ok(Bytes::copy_from_slice(bytes)));
            Ok::<(), UnscrubError>(())
        },
        &mut |entry_idx| UnscrubError::AeadTagFailure { entry_index: entry_idx },
    );

    if let Err(e) = result {
        pending.push_back(Err(e));
        self.error_emitted = true;
    }
}
```

### Task 3: Remove duplicated code
Delete the inline implementation from `process_buffer`:
- `safe_end` calculation
- AC match finding
- `decrypt_entry` calls
- Cursor management and buffer draining

All this is now handled by `process_safe_region`.

### Task 4: Verify error handling
When `process_safe_region` returns `Err(UnscrubError::AeadTagFailure { .. })`:
1. Push the error to `pending`
2. Set `self.error_emitted = true` to stop the stream (INV-6)

The existing `poll_next` logic should already check `error_emitted` before processing.

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo nextest run -p its-classified --test spec --features async` passes (includes new async INV tests)
- [ ] `cargo nextest run -p its-classified` passes (all tests)
- [ ] `grep "process_safe_region" src/unscrub_stream.rs` returns at least 1 match
- [ ] `grep "safe_end" src/unscrub_stream.rs` returns 0 matches (logic moved to core)
- [ ] `cargo clippy --workspace --all-features -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 07. Verify:
1. Run `cargo nextest run -p its-classified --test spec --features async` — all INV tests pass (sync + async)
2. Check `src/unscrub_stream.rs` imports and calls `process_safe_region`
3. Verify emit callback pushes `Ok(Bytes::copy_from_slice(bytes))` to pending
4. Verify error handling pushes error to pending and sets `error_emitted = true`
5. Check no duplicated `safe_end` calculation remains in `unscrub_stream.rs`
6. Run `cargo nextest run --workspace` — all 134+ tests pass

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/unscrub_stream.rs
```
