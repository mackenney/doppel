# Step 02: Empty-Fake Guard in `unscrub()` Constructor

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 1 — BLOCKER fix. Runs in parallel with step 01 (different file). `unscrub.rs` has
never been touched by any prior step in this plan.

### This Step
The sync `unscrub()` function has the same empty-fake vulnerability as `unscrub_stream()`.
AhoCorasick matches a zero-length pattern at every position, so the inner `loop` at lines
87–128 will never make progress and spin forever.

The fix mirrors step 01: reject empty fakes before the AhoCorasick build.

## Prerequisites
- No prior step modifies `src/unscrub.rs`.
- Step 01 may run in parallel.

## Files to Read Before Starting
- `src/unscrub.rs` — full file (especially lines 53–75 for the early-return / build block)

## Implementation

### Task 1: Add the empty-fake guard before the AhoCorasick build

In `src/unscrub.rs`, after the early-return for empty entries (lines 53–63) and before the
AhoCorasick build (currently starting at line 65), insert the guard:

Current code at lines 64–71:

```rust
    // Build Aho-Corasick automaton from fake byte strings
    let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&fakes)
        .map_err(UnscrubError::from)?;
```

Replace with:

```rust
    for (idx, e) in entries.iter().enumerate() {
        if e.fake.is_empty() {
            return Err(UnscrubError::Build {
                msg: format!("empty fake in entry at index {idx}"),
            });
        }
    }
    // Build Aho-Corasick automaton from fake byte strings
    let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&fakes)
        .map_err(UnscrubError::from)?;
```

The guard must appear AFTER the `if entries.is_empty() { ... return Ok(()); }` block and
BEFORE the `let fakes: ...` line.

### Task 2: Add a unit test

Add the following test inside the existing `#[cfg(test)] mod tests { ... }` block at the
bottom of `src/unscrub.rs`, after the last existing test:

```rust
    #[test]
    fn test_empty_fake_rejected_sync() {
        use crate::types::{Entry, SessionKey};
        // An Entry with an empty fake must cause unscrub() to return Err(Build),
        // not succeed and produce an infinite loop.
        let bad_entry = Entry {
            fake: vec![],
            ciphertext: vec![0u8; 32],
            nonce: [0u8; 12],
        };
        let session_key = SessionKey::new([0u8; 32]);
        let mut input = b"some input".as_slice();
        let mut output = Vec::new();
        let result = unscrub(&mut input, &mut output, &[bad_entry], &session_key);
        assert!(
            matches!(result, Err(UnscrubError::Build { .. })),
            "empty fake must return Err(Build)"
        );
    }
```

Note: verify the exact field names of `Entry` and the `SessionKey::new` constructor
against `src/types.rs` before writing the test — adjust if they differ.

## Acceptance Criteria

- [ ] `cargo test test_empty_fake_rejected_sync 2>&1 | tail -5` exits 0 and reports 1 test passed
- [ ] `grep -n 'empty fake in entry at index' src/unscrub.rs` prints exactly one match
- [ ] `cargo test 2>&1 | tail -5` exits 0 (all existing tests still pass)
- [ ] `cargo clippy 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm the guard loop appears after `if entries.is_empty() { ... }` and before `let fakes:`.
2. Confirm the error message is `"empty fake in entry at index {idx}"` (matches the stream variant).
3. Confirm no `#[allow(clippy::*)]` was added.
4. Run `cargo test` (no `--features async` needed; unscrub.rs is always compiled).

## Rollback

Remove the `for (idx, e) in entries.iter().enumerate() { ... }` guard block and the
`test_empty_fake_rejected_sync` test. Code returns to its pre-step state.
