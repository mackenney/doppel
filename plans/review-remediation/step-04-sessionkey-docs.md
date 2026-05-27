# Step 04: SessionKey Ownership Docs

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 1 — Document the intentional API asymmetry between sync `unscrub` (borrows `&SessionKey`) and async `unscrub_stream` (takes `SessionKey` owned). This is not a bug — the stream must own the key for its `'static` lifetime across poll cycles.

### This Step
Add doc comments to both functions explaining the ownership difference and why it exists.

## Prerequisites
- None — Wave 1 step, documentation only

## Files to Read Before Starting
- `src/unscrub.rs` — locate `unscrub()` function signature
- `src/unscrub_stream.rs` — locate `unscrub_stream()` function signature

## Implementation
### Task 1: Document `unscrub_stream` ownership
**File:** `src/unscrub_stream.rs`
**Location:** Doc comment block for `unscrub_stream()` function

Add to the existing doc comment (or create one):
```rust
/// # Ownership
///
/// Takes `SessionKey` by value (unlike sync [`unscrub`] which borrows).
/// The stream must own the key for its `'static` lifetime across poll cycles.
```

### Task 2: Document `unscrub` ownership
**File:** `src/unscrub.rs`
**Location:** Doc comment block for `unscrub()` function

Add to the existing doc comment (or create one):
```rust
/// # Ownership
///
/// Borrows `SessionKey` (unlike async [`unscrub_stream`] which takes ownership).
/// The function runs to completion synchronously, so borrowing is sufficient.
```

## Acceptance Criteria
- [ ] `cargo doc -p its-classified --no-deps` exits 0
- [ ] `grep -A2 "# Ownership" src/unscrub.rs` shows the borrowing explanation
- [ ] `grep -A2 "# Ownership" src/unscrub_stream.rs` shows the ownership explanation
- [ ] `cargo build -p its-classified` exits 0 (doc comments are valid)

## Reviewer Instructions
You are reviewing Step 04. Verify:
1. Run `cargo doc -p its-classified --no-deps` — must exit 0
2. Check `src/unscrub.rs` has `# Ownership` doc section explaining borrowing
3. Check `src/unscrub_stream.rs` has `# Ownership` doc section explaining owned key
4. Verify cross-references use correct `[`unscrub`]` / `[`unscrub_stream`]` syntax

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/unscrub.rs src/unscrub_stream.rs
```
