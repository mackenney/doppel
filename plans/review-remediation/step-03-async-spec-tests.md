# Step 03: Async Spec Tests

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 1 — Add spec-level tests for async unscrub streaming invariants. Current async tests are inline unit tests which "carry no stability guarantee" per AGENTS.md. These spec tests protect INV-5, INV-6, INV-8 from silent regression during refactoring.

### This Step
Add three `#[cfg(feature = "async")]` tests in `tests/spec/inv.rs` that verify: (1) INV-5: no plaintext emitted before AEAD verification, (2) INV-6: AEAD failure produces error and stream stops, (3) INV-8: bounded hold window observed via input/output lag tracking.

## Prerequisites
- None — Wave 1 step, independent of CLI zeroization

## Files to Read Before Starting
- `tests/spec/inv.rs` — existing sync INV-5, INV-6, INV-8 tests for reference patterns
- `SPEC.md` — exact invariant wording for INV-5, INV-6, INV-8
- `src/unscrub_stream.rs` — understand `unscrub_stream` API and `UnscrubError` variants

## Implementation
### Task 1: Add async INV-5 test
**File:** `tests/spec/inv.rs`
**Location:** After `test_inv5_unscrub_does_not_emit_before_aead_verified`

```rust
#[cfg(feature = "async")]
#[test]
fn test_inv5_async_no_plaintext_before_aead_verified() {
    // INV-5: "unscrub MUST NOT emit restored plaintext before the AEAD tag has been verified."
    // Async variant: tamper tag, verify secret never appears in any emitted chunk.
    use bytes::Bytes;
    use futures::{StreamExt, stream};
    use its_classified::unscrub_stream;
    use std::io;

    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut sr = scrub(&payload, &[patterns::github_classic()]).expect("scrub failed");
    let last = sr.entries[0].ciphertext.len() - 1;
    sr.entries[0].ciphertext[last] ^= 0xFF; // tamper tag

    let chunks: Vec<Result<Bytes, io::Error>> = sr
        .payload
        .chunks(16)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let inner = stream::iter(chunks);
    let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();

    let result = futures::executor::block_on(async {
        let mut all: Vec<u8> = Vec::new();
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => all.extend_from_slice(&chunk),
                Err(e) => return Err((e, all)),
            }
        }
        Ok(all)
    });

    let (_, emitted) = result.expect_err("tampered tag must produce error");
    assert!(
        !emitted.windows(SYNTH_GITHUB_CLASSIC.len()).any(|w| w == SYNTH_GITHUB_CLASSIC),
        "INV-5: secret must not appear in output before tag failure (async)"
    );
}
```

### Task 2: Add async INV-6 test
**File:** `tests/spec/inv.rs`
**Location:** After `test_inv6_aead_tag_failure_produces_error`

```rust
#[cfg(feature = "async")]
#[test]
fn test_inv6_async_aead_tag_failure_produces_error() {
    // INV-6: "An AEAD tag failure MUST produce an error; the stream MUST NOT continue."
    use bytes::Bytes;
    use futures::{StreamExt, stream};
    use its_classified::{UnscrubError, unscrub_stream};
    use std::io;

    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut sr = scrub(&payload, &[patterns::github_classic()]).expect("scrub failed");
    let last = sr.entries[0].ciphertext.len() - 1;
    sr.entries[0].ciphertext[last] ^= 0xFF; // tamper tag

    let chunks: Vec<Result<Bytes, io::Error>> = sr
        .payload
        .chunks(16)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let inner = stream::iter(chunks);
    let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();

    let result = futures::executor::block_on(async {
        let mut items_after_err = 0usize;
        let mut saw_err = false;
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            if saw_err {
                items_after_err += 1;
            }
            if item.is_err() {
                assert!(
                    matches!(item, Err(UnscrubError::AeadTagFailure { .. })),
                    "INV-6: must yield AeadTagFailure"
                );
                saw_err = true;
            }
        }
        (saw_err, items_after_err)
    });

    assert!(result.0, "INV-6: must produce an error on tampered tag");
    assert_eq!(result.1, 0, "INV-6: stream must not yield items after error");
}
```

### Task 3: Add async INV-8 test
**File:** `tests/spec/inv.rs`
**Location:** After `test_inv8_unscrub_bounded_hold`

```rust
#[cfg(feature = "async")]
#[test]
fn test_inv8_async_hold_bound_observed() {
    // INV-8: "unscrub MUST NOT hold more than max{|fake_i|} bytes unemitted at any point."
    // Direct observation: feed bytes one at a time, verify output never lags input by more than max_hold.
    use bytes::Bytes;
    use futures::StreamExt;
    use its_classified::unscrub_stream;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let payload = [b"prefix ".as_slice(), SYNTH_ANTHROPIC, b" suffix"].concat();
    let sr = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
    let max_hold = sr.entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);

    let fed = Arc::new(AtomicUsize::new(0));
    let fed_clone = fed.clone();

    let chunks = sr.payload.iter().map(move |&b| {
        fed_clone.fetch_add(1, Ordering::SeqCst);
        Ok::<_, io::Error>(Bytes::from(vec![b]))
    });
    let inner = futures::stream::iter(chunks);
    let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();

    let mut max_lag = 0usize;
    let mut total_out = 0usize;

    futures::executor::block_on(async {
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let chunk = item.expect("no error expected");
            total_out += chunk.len();
            let current_fed = fed.load(Ordering::SeqCst);
            let lag = current_fed.saturating_sub(total_out);
            if lag > max_lag {
                max_lag = lag;
            }
        }
    });

    assert!(
        max_lag <= max_hold,
        "INV-8: max lag {} exceeds max_hold {}", max_lag, max_hold
    );
    assert_eq!(total_out, payload.len(), "round-trip length mismatch");
}
```

### Task 4: Verify async feature gate exists
Check `Cargo.toml` has an `async` feature. If not, add:
```toml
[features]
async = ["futures", "bytes"]
```

Ensure `futures` and `bytes` are dev-dependencies or gated properly.

## Acceptance Criteria
- [ ] `cargo nextest run -p its-classified --test spec --features async` passes
- [ ] `grep -c "test_inv5_async" tests/spec/inv.rs` returns 1
- [ ] `grep -c "test_inv6_async" tests/spec/inv.rs` returns 1
- [ ] `grep -c "test_inv8_async" tests/spec/inv.rs` returns 1
- [ ] All three tests follow `test_invN_<description>` naming convention
- [ ] `cargo clippy --workspace --all-features -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 03. Verify:
1. Run `cargo nextest run -p its-classified --test spec --features async -- async` — all 3 async tests pass
2. Check test names: `test_inv5_async_no_plaintext_before_aead_verified`, `test_inv6_async_aead_tag_failure_produces_error`, `test_inv8_async_hold_bound_observed`
3. Verify each test has spec comment citing the invariant
4. Verify `#[cfg(feature = "async")]` gate on all three tests
5. Run `cargo nextest run -p its-classified --test spec` (without async feature) — tests are not compiled

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout tests/spec/inv.rs Cargo.toml
```
