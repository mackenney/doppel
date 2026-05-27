# Step 06: Refactor Sync unscrub to Use Core

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 2 — Refactor `unscrub.rs` to use the shared `process_safe_region` from `unscrub_core`. This removes duplicated sliding-window logic while preserving all behavior.

### This Step
Replace the inline loop in `unscrub.rs` (lines ~95-146) with a call to `process_safe_region`, providing sync-appropriate emit and error callbacks.

## Prerequisites
- Step 05 complete (unscrub_core module exists)

## Files to Read Before Starting
- `src/unscrub_core.rs` — understand `process_safe_region` signature
- `src/unscrub.rs` — locate the inner loop to replace (lines ~95-146)
- `SPEC.md` — INV-5, INV-6, INV-8 constraints

## Implementation
### Task 1: Import unscrub_core
**File:** `src/unscrub.rs`

Add import at top:
```rust
use crate::unscrub_core::process_safe_region;
```

### Task 2: Replace inline loop with process_safe_region call
**File:** `src/unscrub.rs`
**Location:** Inside the main processing loop (around lines 95-146)

The current structure looks like:
```rust
loop {
    // read chunk into buffer
    // process safe region with inline logic
}
```

Replace the "process safe region" portion with:
```rust
process_safe_region(
    &mut buffer,
    &ac,
    entries,
    session_key,
    eof,
    max_hold,
    &mut |bytes| {
        output.write_all(bytes).map_err(UnscrubError::Io)
    },
    &mut |entry_idx| UnscrubError::AeadTagFailure { entry_index: entry_idx },
)?;
```

Preserve the outer loop structure that:
1. Reads chunks from input into buffer
2. Tracks `eof` flag
3. Calls `process_safe_region`
4. Breaks when input exhausted and buffer empty

### Task 3: Remove duplicated code
Delete the inline implementation that was replaced — the `safe_end` calculation, match finding, decrypt calls, and cursor management are now in `unscrub_core`.

### Task 4: Verify error types are compatible
The emit callback returns `Result<(), UnscrubError>` via `write_all().map_err(UnscrubError::Io)`.
The error callback returns `UnscrubError::AeadTagFailure { entry_index }`.

Both match the `E` type parameter.

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo nextest run -p its-classified --test spec` passes (all invariant tests)
- [ ] `cargo nextest run -p its-classified --test integration` passes
- [ ] `grep "process_safe_region" src/unscrub.rs` returns at least 1 match
- [ ] `grep "safe_end" src/unscrub.rs` returns 0 matches (logic moved to core)
- [ ] `cargo clippy -p its-classified -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 06. Verify:
1. Run `cargo nextest run -p its-classified --test spec` — all INV tests pass
2. Check `src/unscrub.rs` imports and calls `process_safe_region`
3. Verify the emit callback writes to output and maps errors to `UnscrubError::Io`
4. Verify the error callback produces `UnscrubError::AeadTagFailure { entry_index }`
5. Check no duplicated `safe_end` calculation remains in `unscrub.rs`
6. Run full test suite: `cargo nextest run -p its-classified` — all pass

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/unscrub.rs
```
