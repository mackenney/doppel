# Step 02: Sync unit test parity

## Context
The async test suite in `src/unscrub_stream.rs` has 14 tests; the sync suite in `src/unscrub.rs`
has 6. Three specific gaps have async equivalents and are meaningful regressions risks:

1. Empty input stream — if `input.read()` returns 0 on the first call, the function must
   return `Ok(())` with no output and no error.
2. Two distinct secrets — exercises multi-entry Aho-Corasick pattern indexing
   (`m.pattern().as_usize()`). A mis-indexed decryption would silently restore the wrong secret.
3. Tier 2 registered secret — a different fake-derivation path (HMAC-based) vs Tier 1 structural.

## Files to Read Before Starting
- `src/unscrub.rs` — existing test module at the bottom; imports and helpers in scope
- `src/unscrub_stream.rs` — `test_async_two_distinct_fakes` and `test_async_tier2_pattern_restoration`
  for reference on constructing the test payloads
- `src/tier1.rs` — for `patterns::openai_project()` API
- `src/tier2.rs` — for `register(secret)` API

## Implementation

Append the following three tests to the `#[cfg(test)] mod tests` block in `src/unscrub.rs`.
The existing imports (`use super::*`, `use crate::scrub::scrub`, `use crate::tier1::patterns`) are
already in scope.

### Task 1: test_unscrub_empty_input

```rust
#[test]
fn test_unscrub_empty_input() {
    // An empty input must produce empty output with no error.
    // Exercises the early-return fast path (entries.is_empty edge)
    // and the eof-on-first-read path with entries present.
    let sr = scrub(b"payload", &[patterns::anthropic()]).unwrap();
    let mut input = b"".as_slice();
    let mut output = Vec::new();
    unscrub(&mut input, &mut output, &sr.entries, &sr.session_key).unwrap();
    assert!(output.is_empty(), "empty input must produce empty output");
}
```

### Task 2: test_unscrub_two_distinct_secrets

```rust
#[test]
fn test_unscrub_two_distinct_secrets() {
    // Two different key types → two entries → validates multi-entry AC indexing.
    // sk-proj- (8) + 58×'A' + T3BlbkFJ (8) + 58×'B' = 132 chars total.
    let anthropic_key = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
    let openai_key: Vec<u8> = {
        let mut k = b"sk-proj-".to_vec();
        k.extend(std::iter::repeat(b'A').take(58));
        k.extend_from_slice(b"T3BlbkFJ");
        k.extend(std::iter::repeat(b'B').take(58));
        k
    };

    let payload = [
        b"anthropic: ".as_slice(),
        anthropic_key,
        b" openai: ",
        openai_key.as_slice(),
    ]
    .concat();

    let sr = scrub(
        &payload,
        &[patterns::anthropic(), patterns::openai_project()],
    )
    .unwrap();
    assert_eq!(sr.entries.len(), 2, "must detect two distinct secrets");

    let mut input = sr.payload.as_slice();
    let mut output = Vec::new();
    unscrub(&mut input, &mut output, &sr.entries, &sr.session_key).unwrap();
    assert_eq!(output, payload, "both distinct secrets must be restored");
}
```

### Task 3: test_unscrub_tier2_roundtrip

```rust
#[test]
fn test_unscrub_tier2_roundtrip() {
    // Tier 2 registered secret exercises the HMAC-based fake path.
    let secret = b"my-custom-tier2-api-token-that-is-long-enough-for-registration-abcd1234";
    let pattern = crate::register(secret).expect("register failed");
    let payload = [b"Bearer ".as_slice(), secret, b" end"].concat();

    let sr = scrub(&payload, &[pattern]).unwrap();
    assert_eq!(sr.entries.len(), 1, "Tier 2 scrub must produce one entry");

    let mut input = sr.payload.as_slice();
    let mut output = Vec::new();
    unscrub(&mut input, &mut output, &sr.entries, &sr.session_key).unwrap();
    assert_eq!(output, payload, "Tier 2 secret must be restored correctly");
}
```

## Acceptance Criteria

- [ ] `cargo test -p its-classified 2>&1 | grep -E 'test_unscrub_empty_input|test_unscrub_two_distinct|test_unscrub_tier2'` shows all three as `ok`
- [ ] `cargo test -p its-classified` exits 0 (all existing tests still pass)
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

1. `grep -n 'test_unscrub_empty_input\|test_unscrub_two_distinct\|test_unscrub_tier2' src/unscrub.rs` → must find all three
2. `cargo test -p its-classified` → exits 0, three new test names in output
3. `cargo clippy -- -D warnings` → exits 0

Report: "PASS" or "FAIL: <criterion> — <what's wrong>"

## Rollback
`git revert` this step's commit.
