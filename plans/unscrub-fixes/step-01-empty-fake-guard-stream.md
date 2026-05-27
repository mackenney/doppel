# Step 01: Empty-Fake Guard + `#[must_use]` in `unscrub_stream()` Constructor

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 1 — BLOCKER fix. `unscrub_stream.rs` has never been touched by any prior step in this plan.

### This Step
AhoCorasick accepts zero-length patterns and returns `Match{0,0}` on every search.
If any `Entry` in `entries` has an empty `fake`, `process_buffer` will match at offset 0
on every loop iteration, consume nothing, and spin forever.

The fix: reject empty fakes at the constructor entry point, before the AhoCorasick build.
Use the existing `UnscrubError::Build` variant with a descriptive message — no new variant needed.

The `#[must_use]` attribute is added in the same edit because it touches the same three
lines (the doc comment line, the attribute line, and the `pub fn` line). Doing both here
avoids a second Wave-3 step on the same file.

## Prerequisites
- No prior step modifies `src/unscrub_stream.rs`.

## Files to Read Before Starting
- `src/unscrub_stream.rs` — full file
- `src/unscrub.rs` — for the `UnscrubError` definition (lines 8–22)

## Implementation

### Task 1: Add `#[must_use]` to the `unscrub_stream` function

In `src/unscrub_stream.rs`, the function begins at line 57:

```rust
pub fn unscrub_stream<S>(
```

Add the attribute on the line immediately before `pub fn unscrub_stream`:

```rust
#[must_use = "the stream must be polled to process data"]
pub fn unscrub_stream<S>(
```

### Task 2: Add the empty-fake guard inside the `else` branch of the AC constructor

The AC constructor block currently reads (lines 65–75):

```rust
    let ac = if entries.is_empty() {
        None
    } else {
        let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
        Some(
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&fakes)
                .map_err(|e| UnscrubError::Build { msg: e.to_string() })?,
        )
    };
```

Replace the `else` branch so it validates before building:

```rust
    let ac = if entries.is_empty() {
        None
    } else {
        for (idx, e) in entries.iter().enumerate() {
            if e.fake.is_empty() {
                return Err(UnscrubError::Build {
                    msg: format!("empty fake in entry at index {idx}"),
                });
            }
        }
        let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
        Some(
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&fakes)
                .map_err(|e| UnscrubError::Build { msg: e.to_string() })?,
        )
    };
```

### Task 3: Add a unit test

Add the following test inside the existing `#[cfg(test)] mod tests { ... }` block at the
bottom of `src/unscrub_stream.rs`, after the last existing test:

```rust
    #[test]
    fn test_empty_fake_rejected_stream() {
        use crate::types::{Entry, SessionKey};
        // An Entry with an empty fake must cause the constructor to return Err,
        // not succeed and produce an infinite loop.
        let bad_entry = Entry {
            fake: vec![],
            ciphertext: vec![0u8; 32],
            nonce: [0u8; 12],
        };
        let session_key = SessionKey::new([0u8; 32]);
        let inner = futures::stream::empty::<Result<Bytes, io::Error>>();
        let result = unscrub_stream(inner, vec![bad_entry], session_key);
        assert!(
            matches!(result, Err(UnscrubError::Build { .. })),
            "empty fake must return Err(Build)"
        );
    }
```

Note: check the exact field names of `Entry` and `SessionKey::new` against
`src/types.rs` before writing the test — adjust if the constructor or field
names differ.

## Acceptance Criteria

- [ ] `cargo test --features async test_empty_fake_rejected_stream 2>&1 | tail -5` exits 0 and reports 1 test passed
- [ ] `grep -n 'must_use' src/unscrub_stream.rs` prints the line with `#[must_use = "the stream must be polled to process data"]`
- [ ] `grep -n 'empty fake in entry at index' src/unscrub_stream.rs` prints exactly one match
- [ ] `cargo test --features async 2>&1 | tail -5` exits 0 (all existing tests still pass)
- [ ] `cargo clippy --features async 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm the guard loop appears **inside** the `else` branch, **before** `let fakes: Vec<...>`.
2. Confirm the error message contains `"empty fake in entry at index"`.
3. Confirm `#[must_use]` is the line immediately before `pub fn unscrub_stream<S>`.
4. Confirm no `#[allow(clippy::*)]` was added.
5. Run `cargo test --features async` and confirm no regressions.

## Rollback

Revert the three changes: remove the `for (idx, e) in ...` guard block from the `else`
branch, remove the `#[must_use]` attribute, and remove the `test_empty_fake_rejected_stream`
test. The code returns to the exact state before this step.
