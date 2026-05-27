# Step 12: Optional — Unscrub Buffer Optimization

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 5 (Optional) — Lower priority optimization for unscrub streaming. Currently `buffer.drain(..cursor)` shifts remaining bytes on every process_safe_region call. For large responses with many fakes, this causes O(N²) byte copying.

### This Step
Replace `Vec::drain` with a cursor-based approach or ring buffer that avoids shifting. Only compact when necessary.

## Prerequisites
- Steps 05-07 complete (shared abstraction in unscrub_core)

## Files to Read Before Starting
- `src/unscrub_core.rs` — current `buffer.drain(..cursor)` at end of `process_safe_region`
- Understand the trade-off: complexity vs. performance gain

## Implementation
### Task 1: Analyze current pattern
**File:** `src/unscrub_core.rs`

Current:
```rust
// At end of process_safe_region
if cursor > 0 {
    buffer.drain(..cursor);
}
```

This is O(remaining_bytes) for each drain.

### Task 2: Option A — Cursor-based approach
Track a `buffer_start` offset instead of draining:
```rust
pub(crate) fn process_safe_region<F, G, E>(
    buffer: &mut Vec<u8>,
    buffer_start: &mut usize,  // New parameter
    // ... rest unchanged
) -> Result<(), E>
{
    let mut cursor = *buffer_start;
    
    // ... processing loop using buffer[cursor..] instead of buffer[..] ...
    
    *buffer_start = cursor;
    
    // Compact only when start > threshold (e.g., CHUNK_SIZE)
    if *buffer_start > CHUNK_SIZE {
        buffer.drain(..*buffer_start);
        *buffer_start = 0;
    }
    
    Ok(())
}
```

### Task 3: Option B — Ring buffer
Use a `VecDeque<u8>` or custom ring buffer. More complex but avoids all copying.

**Trade-off:** `VecDeque` has slightly worse cache locality than `Vec`. May not be worth it for typical payload sizes.

### Task 4: Update callers
If signature changes, update both `unscrub.rs` and `unscrub_stream.rs` to pass the new `buffer_start` parameter.

### Task 5: Benchmark before/after
Add a benchmark test:
```rust
#[bench]
fn bench_unscrub_large_response() {
    // Create response with many fakes
    // Measure time with current vs. cursor approach
}
```

Without clear benchmark showing improvement, this change may not be worth the added complexity.

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo nextest run -p its-classified --test spec --features async` passes (INV-8 bounded hold)
- [ ] Benchmark shows measurable improvement OR document why change was not made
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 12. Verify:
1. Run `cargo nextest run -p its-classified --test spec --features async` — INV-5, INV-6, INV-8 pass
2. If cursor approach implemented: verify compaction threshold is reasonable
3. If ring buffer: verify no regression in streaming behavior
4. If skipped: verify rationale is documented (e.g., benchmark showed no improvement)
5. Check INV-8 (bounded hold) is still enforced

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason> / SKIPPED: <rationale>"

## Rollback
```
git checkout src/unscrub_core.rs src/unscrub.rs src/unscrub_stream.rs
```
