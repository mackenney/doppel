# Step 03: Tests — spec invariant suite + multi-chunk None-branch coverage

## Context

### Overall Objective
Close five post-review findings on unscrub correctness, safety, and test coverage.

### Phase Context
Wave 1. Depends on steps 01 and 02 being committed. Touches two files:
`tests/spec/inv.rs` and the inline test module at the bottom of `src/unscrub_stream.rs`.

### This Step
Add three tests:

1. **`tests/spec/inv.rs`**: `test_inv_empty_fake_sync_rejected` — spec-level behavioral
   contract: `unscrub()` with an entry whose `fake` field is empty MUST return
   `UnscrubError::Build`, not loop forever.

2. **`tests/spec/inv.rs`**: `test_inv_empty_fake_async_rejected` — same contract for
   `unscrub_stream()` constructor.

3. **`src/unscrub_stream.rs` inline test module**: `test_async_empty_entries_multichunk`
   — the `ac = None` path exercised with a multi-chunk stream (chunked_stream with a
   small chunk size and empty entries), verifying all bytes pass through correctly after
   the None-branch cursor fix from step-02.

## Prerequisites
- Step 01 committed (adds `Zeroizing` to `unscrub.rs`)
- Step 02 committed (fixes None-branch cursor in `process_buffer`)

## Files to Read Before Starting
- `tests/spec/inv.rs` — see the last few tests for style; entries use `its_classified::` prefix
- `src/unscrub_stream.rs` — the inline test module (chunked_stream helper, existing tests)
- `src/types.rs` — for `Entry` and `SessionKey` field names

## Implementation

### Task 1: Add spec invariant test — sync empty-fake rejection

Append to `tests/spec/inv.rs`:

```rust
#[test]
fn test_inv_empty_fake_sync_rejected() {
    // The empty-fake guard MUST fire before AhoCorasick build to prevent
    // an infinite loop (Match{0,0} → drain(..0) no-op).
    use its_classified::types::{Entry, SessionKey};
    use its_classified::{UnscrubError, unscrub};

    let bad_entry = Entry {
        fake: vec![],
        ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
    };
    let key = SessionKey::from_bytes([1u8; 32]);
    let mut input = b"some payload".as_slice();
    let mut output = Vec::new();
    let result = unscrub(&mut input, &mut output, &[bad_entry], &key);
    assert!(
        matches!(result, Err(UnscrubError::Build { .. })),
        "empty fake MUST return Err(Build), not loop"
    );
}
```

### Task 2: Add spec invariant test — async empty-fake rejection

Append to `tests/spec/inv.rs` (immediately after the sync test):

```rust
#[test]
fn test_inv_empty_fake_async_rejected() {
    use its_classified::types::{Entry, SessionKey};
    use its_classified::{UnscrubError, unscrub_stream};
    use futures::stream;
    use bytes::Bytes;
    use std::io;

    let bad_entry = Entry {
        fake: vec![],
        ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
    };
    let key = SessionKey::from_bytes([1u8; 32]);
    let inner = stream::empty::<Result<Bytes, io::Error>>();
    let result = unscrub_stream(inner, vec![bad_entry], key);
    assert!(
        matches!(result, Err(UnscrubError::Build { .. })),
        "empty fake MUST return Err(Build) from constructor"
    );
}
```

`futures = "0.3"` is already in `[dev-dependencies]` in the root `Cargo.toml`.
`bytes` is NOT in `[dev-dependencies]` (only as an optional main dep). Add it:

```toml
# root Cargo.toml [dev-dependencies]
bytes = "1"
```

Note: there is no `tests/Cargo.toml` — integration tests are governed by the root `Cargo.toml`.

### Task 3: Add multi-chunk None-branch inline test

Append to the `#[cfg(test)] mod tests` block in `src/unscrub_stream.rs`:

```rust
#[test]
fn test_async_empty_entries_multichunk() {
    // ac = None path (no entries) exercised with many small chunks.
    // Verifies the cursor-based None branch drains correctly across multiple
    // process_buffer iterations rather than a single eof=true flush.
    let response = b"hello world this is a multi-chunk passthrough test";
    let sr = scrub(b"unrelated", &[]).unwrap();
    assert!(sr.entries.is_empty());

    let inner = chunked_stream(response.to_vec(), 4); // 4-byte chunks
    let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
    let result = futures::executor::block_on(collect_stream(stream)).unwrap();
    assert_eq!(result, response, "multi-chunk passthrough with no entries must be byte-identical");
}
```

## Acceptance Criteria

- [ ] `cargo test --features async 2>&1 | grep test_inv_empty_fake_sync_rejected` shows `ok`
- [ ] `cargo test --features async 2>&1 | grep test_inv_empty_fake_async_rejected` shows `ok`
- [ ] `cargo test --features async 2>&1 | grep test_async_empty_entries_multichunk` shows `ok`
- [ ] `cargo test --features async` exits 0 (all existing tests still pass)
- [ ] `cargo nextest run --test spec 2>&1 | grep empty_fake` shows both spec tests passing
- [ ] `cargo clippy --features async -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 03. Verify:

1. `grep -n 'test_inv_empty_fake' tests/spec/inv.rs` — must find exactly two test functions
2. `grep -n 'test_async_empty_entries_multichunk' src/unscrub_stream.rs` — must find one
3. `cargo test --features async` — must exit 0, three new test names in output
4. `cargo nextest run --test spec` — must exit 0, both inv tests appear
5. `cargo clippy --features async -- -D warnings` — must exit 0

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
`git revert` the single commit for this step.
