# Step 02: Extract `derive_fake_core` and Add `derive_fake_tier2_deterministic`

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 0. This step creates the shared derivation primitive that both Tier 1 and the new Tier 2 deterministic derivation will use. It has no dependencies and runs in parallel with step-01.

### This Step
Extract the HMAC→StdRng→rejection-sampling logic from `derive_fake_tier1` into a shared internal helper `derive_fake_core`. Rewrite `derive_fake_tier1` as a thin wrapper. Add `derive_fake_tier2_deterministic` as a second wrapper that supports both prefix and suffix preservation. Add unit tests for the new functions.

## Prerequisites
- None

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/fake.rs` — full file, 298 lines. Contains `derive_fake_tier1` (lines 78–127) and `generate_fake_tier2` (lines 139–184).

## Implementation

### Task 1: Add `derive_fake_core` function

In `src/fake.rs`, add a new private function **above** `derive_fake_tier1` (before line 72):

```rust
fn derive_fake_core(
    salt: &[u8; 32],
    original: &[u8],
    prefix: &[u8],
    suffix: &[u8],
    charset: &[u8],
    target_len: usize,
) -> Result<Vec<u8>, FakeError> {
    let fixed_len = prefix.len() + suffix.len();
    assert!(
        target_len >= fixed_len,
        "target_len must be >= prefix.len() + suffix.len()"
    );
    assert!(!charset.is_empty(), "charset must not be empty");

    let variable_len = target_len - fixed_len;
    const MAX_ATTEMPTS: u32 = 1_000;

    for attempt in 0u32..MAX_ATTEMPTS {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key size");
        mac.update(original);
        mac.update(&attempt.to_le_bytes());
        let seed_bytes: [u8; 32] = mac.finalize().into_bytes().into();

        let mut rng = StdRng::from_seed(seed_bytes);
        let mut fake = Vec::with_capacity(target_len);
        fake.extend_from_slice(prefix);

        let charset_len = charset.len() as u32;
        let threshold = u32::MAX - (u32::MAX % charset_len);
        for _ in 0..variable_len {
            let idx = loop {
                let r = rng.next_u32();
                if r < threshold {
                    break (r % charset_len) as usize;
                }
            };
            fake.push(charset[idx]);
        }

        fake.extend_from_slice(suffix);

        if fake != original {
            return Ok(fake);
        }
    }

    Err(FakeError::CollisionLimit {
        attempts: MAX_ATTEMPTS,
    })
}
```

### Task 2: Rewrite `derive_fake_tier1` as a wrapper

Replace the body of `derive_fake_tier1` (lines 78–127) with a single call to `derive_fake_core`:

```rust
pub(crate) fn derive_fake_tier1(
    salt: &[u8; 32],
    prefix: &[u8],
    charset: &[u8],
    target_len: usize,
    original: &[u8],
) -> Result<Vec<u8>, FakeError> {
    derive_fake_core(salt, original, prefix, &[], charset, target_len)
}
```

The function signature stays the same — only the body changes. This keeps all existing callers working.

### Task 3: Add `derive_fake_tier2_deterministic`

Add a new public(crate) function after `derive_fake_tier1`:

```rust
/// Derive a deterministic fake for a Tier 2 secret at match time.
///
/// Same HMAC→StdRng derivation as Tier 1 but supports both prefix and suffix preservation.
/// Called from `Tier2Pat::try_match` after HMAC verification confirms the candidate.
pub(crate) fn derive_fake_tier2_deterministic(
    salt: &[u8; 32],
    original: &[u8],
    preserved_prefix: &[u8],
    preserved_suffix: &[u8],
    charset: &[u8],
    target_len: usize,
) -> Result<Vec<u8>, FakeError> {
    derive_fake_core(salt, original, preserved_prefix, preserved_suffix, charset, target_len)
}
```

### Task 4: Add unit tests

Add the following tests to the `#[cfg(test)] mod tests` block in `src/fake.rs`:

```rust
#[test]
fn test_derive_fake_core_prefix_and_suffix() {
    let salt = [99u8; 32];
    let original = b"MY_ORG_secretbytes1234END";
    let prefix = b"MY_ORG_";
    let suffix = b"END";
    let charset = charsets::alphanumeric();
    let fake = derive_fake_core(&salt, original, prefix, suffix, &charset, original.len()).unwrap();
    assert!(fake.starts_with(prefix), "prefix must be preserved");
    assert!(fake.ends_with(suffix), "suffix must be preserved");
    assert_eq!(fake.len(), original.len());
    assert_ne!(fake.as_slice(), original.as_slice());
}

#[test]
fn test_derive_fake_tier2_deterministic_stability() {
    let salt = [7u8; 32];
    let original = b"my-custom-api-token-abc123xyz";
    let prefix = b"my-";
    let suffix = b"";
    let charset = charsets::wide();
    let fake1 = derive_fake_tier2_deterministic(&salt, original, prefix, suffix, &charset, original.len()).unwrap();
    let fake2 = derive_fake_tier2_deterministic(&salt, original, prefix, suffix, &charset, original.len()).unwrap();
    assert_eq!(fake1, fake2, "same inputs must produce same fake (INV-13)");
}

#[test]
fn test_derive_fake_tier1_unchanged_after_refactor() {
    // Verify that the refactored derive_fake_tier1 produces the same output
    // as the shared derive_fake_core when called with no suffix.
    let salt = [42u8; 32];
    let prefix = b"sk-ant-";
    let charset = charsets::alphanumeric();
    let original = b"sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let via_tier1 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original).unwrap();
    let via_core = derive_fake_core(&salt, original, prefix, &[], &charset, original.len()).unwrap();
    assert_eq!(via_tier1, via_core, "tier1 wrapper must produce identical output to core");
}
```

### Task 5: Verify existing tests still pass

Run the existing `fake.rs` unit tests to confirm no regression:

```sh
cargo nextest run --lib -p its-classified -- fake::tests
```

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run --lib -p its-classified -- fake::tests 2>&1 | tail -1` contains "test result: ok" or shows all tests passing (0 failures)
- [ ] `grep -c "fn derive_fake_core" /home/ignacio/pr/its-classified/src/fake.rs` outputs `1`
- [ ] `grep -c "fn derive_fake_tier2_deterministic" /home/ignacio/pr/its-classified/src/fake.rs` outputs `1`
- [ ] `grep -c "fn test_derive_fake_tier2_deterministic_stability" /home/ignacio/pr/its-classified/src/fake.rs` outputs `1`
- [ ] `grep -c "fn test_derive_fake_tier1_unchanged_after_refactor" /home/ignacio/pr/its-classified/src/fake.rs` outputs `1`
- [ ] `cargo nextest run --lib -p its-classified -- fake::tests::test_derive_fake_tier1_stability 2>&1 | grep -c "PASS"` outputs `1` (pre-existing test still passes)

## Reviewer Instructions

You are reviewing Step 02. Verify:
1. Run `cargo nextest run --lib -p its-classified -- fake::tests` — all tests must pass
2. Check `src/fake.rs` for:
   - `derive_fake_core` is a private `fn` (no `pub`)
   - `derive_fake_tier1` body is a single call to `derive_fake_core` with `suffix: &[]`
   - `derive_fake_tier2_deterministic` is `pub(crate)` and calls `derive_fake_core`
   - `generate_fake_tier2` (the RNG-based one) is UNCHANGED (still present, still used by registration)
3. Run `cargo clippy -p its-classified --lib 2>&1 | grep -c "warning"` — should be 0 new warnings
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/fake.rs
```
