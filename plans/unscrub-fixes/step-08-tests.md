# Step 08: Add Three Missing Async Tests

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 4 — test coverage. Depends on step 05. This is the last step.
`unscrub_stream.rs` was last touched by step 05 (Zeroizing + AEAD log). This step only
adds to the `mod tests` block at the bottom of the file.

### This Step
Three code paths in `UnscrubStream` have never been exercised by tests:

1. **Two distinct fakes** — all existing tests use a single `patterns::anthropic()`.
   `m.pattern().as_usize()` indexes into the entries slice; if it is off-by-one or
   reversed, single-fake tests never catch it.

2. **`Poll::Pending` from the inner stream** — existing tests use `futures::stream::iter`
   which always returns `Poll::Ready`. The `Poll::Pending` branch in `poll_next` (the
   `Poll::Pending => { return Poll::Pending; }` arm) is never exercised.

3. **Tier 2 pattern restoration** — all existing tests use Tier 1 built-in patterns.
   Tier 2 fakes are derived deterministically from an HMAC salt and have different byte
   structure. The Tier 2 decrypt path in `crypto::decrypt_entry` is exercised by the sync
   tests but not by the async stream.

## Prerequisites
- Step 05 is complete (`src/unscrub_stream.rs` has Zeroizing + AEAD log in `process_buffer`).

## Files to Read Before Starting
- `src/unscrub_stream.rs` — the `#[cfg(test)] mod tests` block (from the `mod tests {`
  opening to the final `}`) — to understand existing imports and helpers
- `src/tier1.rs` — the `pub mod patterns` block — to confirm `patterns::openai_project()` exists
- `src/lib.rs` — to confirm `register` is re-exported at the crate root

## Implementation

### Task 1: Add `PendingOnceStream` helper struct

Inside the `#[cfg(test)] mod tests { ... }` block, after the existing helpers
(`collect_stream`, `chunked_stream`, `single_chunk_stream`) and before the first `#[test]`,
add the following helper struct and its `Stream` impl.

The `use super::*;` already in scope brings `Bytes`, `io`, `Pin`, `Context`, `Poll`, and
`Stream` into the test module. No additional imports are needed for the struct itself.

```rust
    struct PendingOnceStream {
        state: u8,
        chunks: std::collections::VecDeque<Bytes>,
    }

    impl PendingOnceStream {
        fn new(data: Vec<u8>, chunk_size: usize) -> Self {
            let chunks = data
                .chunks(chunk_size)
                .map(Bytes::copy_from_slice)
                .collect();
            Self { state: 0, chunks }
        }
    }

    impl Stream for PendingOnceStream {
        type Item = Result<Bytes, io::Error>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match self.state {
                0 => {
                    self.state = 1;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                _ => {
                    if let Some(chunk) = self.chunks.pop_front() {
                        Poll::Ready(Some(Ok(chunk)))
                    } else {
                        Poll::Ready(None)
                    }
                }
            }
        }
    }

    impl Unpin for PendingOnceStream {}
```

**How it works:** `state 0` returns `Poll::Pending` and schedules a re-poll via
`wake_by_ref()`. On all subsequent polls (`state 1+`), it drains `chunks` and finally
returns `Poll::Ready(None)`.

### Task 2: Add test — two distinct fakes (different Tier 1 patterns)

The function `patterns::openai_project()` matches keys with structure:
`sk-proj-` + 58–74 url_safe_base64 chars + `T3BlbkFJ` + 58–74 url_safe_base64 chars
(132–164 chars total). `A` and `B` are both valid url_safe_base64 characters.

Add the following test after the last existing test in the `mod tests` block:

```rust
    #[test]
    fn test_async_two_distinct_fakes() {
        // Two different API key types → two entries → validates multi-entry AC indexing.
        // sk-proj- (8) + 58 'A' chars + T3BlbkFJ (8) + 58 'B' chars = 132 chars total.
        let openai_key: Vec<u8> = {
            let mut k = b"sk-proj-".to_vec();
            k.extend(std::iter::repeat(b'A').take(58));
            k.extend_from_slice(b"T3BlbkFJ");
            k.extend(std::iter::repeat(b'B').take(58));
            k
        };

        let payload = [
            b"anthropic: ".as_slice(),
            ANTHROPIC_SECRET,
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

        let inner = single_chunk_stream(sr.payload);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload, "both distinct fakes must restore correctly");
    }
```

### Task 3: Add test — `Poll::Pending` from inner stream

```rust
    #[test]
    fn test_async_pending_then_ready() {
        // Exercises the waker path: first poll of the inner stream returns Pending.
        let payload = [b"prefix ".as_slice(), ANTHROPIC_SECRET, b" suffix"].concat();
        let sr = scrub(&payload, &[patterns::anthropic()]).unwrap();
        let inner = PendingOnceStream::new(sr.payload.clone(), 32);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload, "Pending → Ready path must restore correctly");
    }
```

### Task 4: Add test — Tier 2 pattern restoration

`crate::register` takes `&[u8]` and returns `Result<Pattern, RegistrationError>`. It is
re-exported at the crate root in `src/lib.rs`.

```rust
    #[test]
    fn test_async_tier2_pattern_restoration() {
        // Tier 2: user-registered secret with deterministic fake derivation.
        // Must be long enough to meet the minimum length requirement of register().
        let secret =
            b"my-custom-tier2-api-token-that-is-long-enough-for-registration-abcd1234";
        let pattern = crate::register(secret).expect("register failed");
        let payload = [b"Bearer ".as_slice(), secret, b" end"].concat();

        let sr = scrub(&payload, &[pattern]).unwrap();
        assert_eq!(sr.entries.len(), 1, "Tier 2 scrub must produce one entry");

        let inner = single_chunk_stream(sr.payload);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload, "Tier 2 fake must restore correctly");
    }
```

If `crate::register` returns an error for this secret (e.g., minimum-length not met),
check `src/tier2.rs` for the minimum required length and adjust the `secret` bytes
accordingly, keeping the total length above that minimum.

## Acceptance Criteria

- [ ] `cargo test --features async test_async_two_distinct_fakes 2>&1 | tail -5` exits 0 and reports 1 test passed
- [ ] `cargo test --features async test_async_pending_then_ready 2>&1 | tail -5` exits 0 and reports 1 test passed
- [ ] `cargo test --features async test_async_tier2_pattern_restoration 2>&1 | tail -5` exits 0 and reports 1 test passed
- [ ] `cargo test --features async 2>&1 | tail -5` exits 0 (all tests pass, including all pre-existing ones)
- [ ] `grep -n 'PendingOnceStream' src/unscrub_stream.rs | wc -l` prints `7` or more (struct def, impl block, Stream impl, Unpin impl, usage in test)
- [ ] `cargo clippy --features async 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm `PendingOnceStream` is placed inside `#[cfg(test)] mod tests { ... }` — not
   in the public module.
2. Confirm `state 0` returns `Poll::Pending` and calls `wake_by_ref()` to reschedule.
3. Confirm the OpenAI key is exactly 132 bytes: 8 + 58 + 8 + 58. Run
   `assert_eq!(openai_key.len(), 132)` in the test or verify the construction.
4. Confirm `sr.entries.len() == 2` is asserted before calling `unscrub_stream`.
5. Confirm the Tier 2 test uses `crate::register`, not a Tier 1 pattern function.
6. Run all three new tests individually and confirm they pass.

## Rollback

Remove `PendingOnceStream` (struct + impls) and the three new test functions from the
`mod tests` block. The file returns to its state after step 05.
