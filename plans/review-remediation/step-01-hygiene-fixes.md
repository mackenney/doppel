# Step 01: Hygiene Fixes

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 1 — Quick hygiene fixes that can run in parallel with security fixes. These are 1-2 line changes with no behavioral impact.

### This Step
Two tiny fixes: (1) Change `pub mod unscrub_stream` to `pub(crate) mod unscrub_stream` since the module's public items are already re-exported at crate root, and (2) use the existing `From<BuildError>` impl consistently in `unscrub_stream.rs` instead of inline mapping.

## Prerequisites
- None — Wave 1 step

## Files to Read Before Starting
- `src/lib.rs` — locate `pub mod unscrub_stream` declaration
- `src/unscrub_stream.rs` — locate inline `.map_err(|e| UnscrubError::Build { msg: e.to_string() })?`
- `src/unscrub.rs` — reference for existing `From<BuildError>` impl usage

## Implementation
### Task 1: Fix module visibility
**File:** `src/lib.rs`

Find line with `pub mod unscrub_stream;` and change to:
```rust
pub(crate) mod unscrub_stream;
```

This mirrors `pub(crate) mod unscrub` pattern. Public API (`UnscrubStream`, `unscrub_stream`) is already re-exported via `pub use` statements.

### Task 2: Fix AhoCorasick error mapping
**File:** `src/unscrub_stream.rs`

Find the AhoCorasick builder error handling (around line 82):
```rust
.map_err(|e| UnscrubError::Build { msg: e.to_string() })?
```

Change to:
```rust
.map_err(UnscrubError::from)?
```

This uses the existing `impl From<aho_corasick::BuildError> for UnscrubError` in `unscrub.rs`.

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `grep -n "pub mod unscrub_stream" src/lib.rs` returns empty (no match)
- [ ] `grep -n "pub(crate) mod unscrub_stream" src/lib.rs` returns exactly 1 match
- [ ] `grep "to_string()" src/unscrub_stream.rs | grep -c "Build"` returns 0
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 01. Verify:
1. Run `cargo build -p its-classified` — must exit 0
2. Check `src/lib.rs` contains `pub(crate) mod unscrub_stream;` (not `pub mod`)
3. Check `src/unscrub_stream.rs` uses `.map_err(UnscrubError::from)?` for AC builder
4. Run `cargo nextest run -p its-classified --test spec` — must pass

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git revert HEAD  # if committed
git checkout src/lib.rs src/unscrub_stream.rs  # if uncommitted
```
