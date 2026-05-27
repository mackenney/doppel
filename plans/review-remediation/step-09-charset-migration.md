# Step 09: Migrate CharsetName::resolve to Static Reference

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 3 — Migrate all charset usage from allocating `Vec<u8>` to static `&'static Charset` references. This eliminates per-call allocations in the hot path.

### This Step
Three changes: (1) Change `CharsetName::resolve()` to return `&'static Charset`, (2) Update `match_segments` to use `charset.contains(b)`, (3) Update fake generation to use `charset.bytes()`, (4) Remove `resolve_charset_fn_to_name` materialization allocations.

## Prerequisites
- Step 08 complete (CharsetBitmap and static Charset instances exist)

## Files to Read Before Starting
- `src/segment.rs` — `CharsetName::resolve()` and its callers
- `src/tier1.rs` — `match_segments` usage of charset
- `src/fake.rs` — `derive_fake_core` and `derive_fake_tier1_segments` usage

## Implementation
### Task 1: Change CharsetName::resolve return type
**File:** `src/segment.rs`

Change:
```rust
impl CharsetName {
    pub fn resolve(&self) -> Vec<u8> {
        match self {
            CharsetName::Alphanumeric => charsets::alphanumeric(),
            CharsetName::UrlSafeBase64 => charsets::url_safe_base64(),
            // ...
        }
    }
}
```

To:
```rust
impl CharsetName {
    pub fn resolve(&self) -> &'static Charset {
        match self {
            CharsetName::Alphanumeric => charsets::alphanumeric_ref(),
            CharsetName::UrlSafeBase64 => charsets::url_safe_base64_ref(),
            CharsetName::UppercaseAlphanumeric => charsets::uppercase_alphanumeric_ref(),
            CharsetName::Digits => charsets::digits_ref(),
            CharsetName::HexLower => charsets::hex_lower_ref(),
        }
    }
}
```

### Task 2: Update match_segments to use Charset::contains
**File:** `src/tier1.rs` (or wherever `match_segments` is called)

Change:
```rust
let cs = charset.resolve();
if payload[cur..end].iter().all(|b| cs.contains(b)) {
```

To:
```rust
let cs = charset.resolve();
if payload[cur..end].iter().all(|&b| cs.contains(b)) {
```

Note: The `&b` dereference is needed because `Charset::contains` takes `u8`, not `&u8`.

### Task 3: Update fake generation to use Charset::bytes()
**File:** `src/fake.rs`

In `derive_fake_core` and `derive_fake_tier1_segments`, change:
```rust
let charset_bytes = charset.resolve();
let fake_byte = charset_bytes[index % charset_bytes.len()];
```

To:
```rust
let charset = charset.resolve();
let fake_byte = charset.bytes()[index % charset.len()];
```

### Task 4: Remove resolve_charset_fn_to_name materialization
**File:** `src/segment.rs`

The function `resolve_charset_fn_to_name` currently materializes all 5 charsets as `Vec<u8>` to compare bytes. Replace with direct enum comparison.

If the function takes a `fn() -> Vec<u8>` pointer:
```rust
// Option A: Store CharsetName directly in BuiltinSegment::Variable
// (best approach — avoids function pointer comparison)

// Option B: Use ptr comparison (if function pointers are stable)
fn resolve_charset_fn_to_name(charset_fn: fn() -> Vec<u8>) -> CharsetName {
    // Compare function pointers directly
    if charset_fn as usize == charsets::alphanumeric as usize {
        CharsetName::Alphanumeric
    } else if charset_fn as usize == charsets::url_safe_base64 as usize {
        CharsetName::UrlSafeBase64
    } // ... etc
}
```

**Preferred:** Store `CharsetName` enum directly in `BuiltinSegment::Variable` instead of function pointer. This avoids both allocation and pointer comparison.

### Task 5: Remove deprecated Vec-returning functions (if safe)
**File:** `src/fake.rs`

If all callers migrated, remove:
```rust
pub fn alphanumeric() -> Vec<u8> { ... }
pub fn url_safe_base64() -> Vec<u8> { ... }
// etc.
```

Or deprecate with `#[deprecated]` for a release cycle.

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo nextest run -p its-classified --test spec` passes (INV-29 charset tests)
- [ ] `grep "resolve.*-> Vec<u8>" src/segment.rs` returns 0 matches
- [ ] `grep "resolve.*&'static Charset" src/segment.rs` returns 1 match
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 09. Verify:
1. Run `cargo nextest run -p its-classified --test spec` — all pass, especially INV-29
2. Check `CharsetName::resolve()` returns `&'static Charset`, not `Vec<u8>`
3. Check `match_segments` uses `cs.contains(b)` with the new Charset type
4. Check fake generation uses `charset.bytes()[index]` for random selection
5. Verify no `Vec<u8>` allocation in the charset resolution path
6. Run `cargo nextest run --workspace` — all tests pass

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/segment.rs src/tier1.rs src/fake.rs
```
