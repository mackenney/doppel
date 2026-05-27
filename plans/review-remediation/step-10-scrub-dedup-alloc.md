# Step 10: Fix to_vec() Allocation Before Dedup Check

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 3 — Independent performance fix that can run in parallel with charset optimization. Currently `scrub` allocates `payload[m.start..m.end].to_vec()` before checking if the match is already in the dedup map.

### This Step
Reorder the dedup check to avoid allocation when the secret has already been seen. Check the HashMap using a slice reference first, only allocate if the entry is new.

## Prerequisites
- Wave 2 complete (no dependency on charset steps)

## Files to Read Before Starting
- `src/scrub.rs` — locate the dedup HashMap usage (around line 115)
- Understand the current flow: match found → to_vec() → check HashMap → process or skip

## Implementation
### Task 1: Identify the allocation pattern
**File:** `src/scrub.rs`
**Location:** Around line 115

Current pattern:
```rust
let matched_bytes = payload[m.start..m.end].to_vec();  // ALLOCATION
if let Some(&idx) = seen.get(&matched_bytes) {
    // Already seen — skip
} else {
    // New secret — process
    seen.insert(matched_bytes, idx);
}
```

### Task 2: Reorder to check before allocating
**File:** `src/scrub.rs`

Change to:
```rust
let matched_slice = &payload[m.start..m.end];

// Check if we've seen this secret before (using slice, no allocation)
if let Some(&idx) = seen.get(matched_slice) {
    // Already seen — reuse existing entry
    // ... existing logic to use existing fake
} else {
    // New secret — now we need to allocate for the HashMap key
    let matched_bytes = matched_slice.to_vec();
    // ... process new secret
    seen.insert(matched_bytes, new_idx);
}
```

### Task 3: Consider HashMap<&[u8], usize> if lifetime allows
If the payload lifetime extends through the entire scrub operation:
```rust
let mut seen: HashMap<&[u8], usize> = HashMap::new();
```

This avoids allocation entirely for dedup keys. The slice borrows from `payload` which outlives the scrub call.

**Constraint:** Verify `payload` is borrowed for the duration of scrub and not modified. If so, this is safe.

### Task 4: Verify no behavioral change
The dedup logic MUST still:
1. Produce the same fake for identical secrets (stability)
2. Track entry indices correctly
3. Not affect entry ordering or output

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo nextest run -p its-classified --test spec` passes (scrub correctness)
- [ ] `cargo nextest run -p its-classified --test integration` passes
- [ ] No allocation before dedup check for already-seen secrets
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 10. Verify:
1. Run `cargo nextest run -p its-classified` — all tests pass
2. Check `src/scrub.rs` checks HashMap before calling `to_vec()`
3. Verify the dedup logic still produces same fake for same secret
4. If using `HashMap<&[u8], usize>`, verify lifetime is sound (payload outlives map)
5. Check no behavioral change to scrub output

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/scrub.rs
```
