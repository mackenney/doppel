# Step 05: Tier 2 Registration

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration.

### Phase Context
Wave 2 (parallel with step-04). Implements the `register()` function and the `Tier2Pat`
struct. Registration allows callers to detect arbitrary secrets (not covered by Tier 1
built-ins) by producing a Pattern from a secret value. The secret is consumed and
discarded immediately; only fragments and an HMAC token are retained (INV-16, INV-17).

### This Step
Implement `src/tier2.rs`: the `Tier2Pat` struct, the `register()` public function,
HMAC token construction with a unique random salt (INV-17), fake pre-generation
(using the Tier 2 CSPRNG path from step-03), and the structural detection helpers
used by the scrub engine in step-06.

## Prerequisites

- Step 01 complete
- Step 02 complete (Entry, SessionKey types)
- Step 03 complete (generate_fake_tier2, hmac_sha256, charsets)
- Step 04 complete or in parallel (Tier2Pat is referenced by the Pattern enum in tier1.rs)

## Files to Read Before Starting

- `src/tier2.rs` — current stub
- `src/fake.rs` — generate_fake_tier2, charsets::detect
- `src/crypto.rs` — hmac_sha256, verify_hmac
- `SPEC.md §Registration` — exact requirements
- `SPEC.md §Tier 2 — Registered Arbitrary Secrets` — detection mechanism
- `SPEC.md INV-16, INV-17` — HMAC bypass and salt uniqueness

## Implementation

### Task 1: Tier2Pat struct

```rust
/// Internal representation of a Tier 2 registered secret pattern.
/// Opaque to callers — they receive a `Pattern::Tier2(Arc<Tier2Pat>)`.
pub(crate) struct Tier2Pat {
    /// First N bytes of the original secret. Used to quickly identify candidates.
    pub start_fragment: Vec<u8>,
    /// Last M bytes of the original secret. Verified after start fragment matches.
    pub end_fragment: Vec<u8>,
    /// Exact byte length of the original secret.
    pub exact_length: usize,
    /// Observed character set from the original secret (for fake generation only;
    /// detection does not use charset — it uses exact fragment matching + HMAC).
    pub charset: Vec<u8>,
    /// Unique random salt for this registration (INV-17: must not reuse).
    pub hmac_salt: [u8; 32],
    /// HMAC-SHA256(hmac_salt, original_secret) — confirmation token.
    pub hmac_digest: [u8; 32],
    /// Pre-generated fake, produced at registration time.
    /// Returned on all subsequent detections of this secret (INV-13 for Tier 2).
    pub fake: Vec<u8>,
}

/// Fragment sizes: how many bytes to take from start and end of the secret.
/// Caller-controlled via the SPEC ("caller-controlled amount").
/// Library uses sensible defaults.
const START_FRAGMENT_LEN: usize = 8;
const END_FRAGMENT_LEN: usize = 8;
```

### Task 2: register() function

```rust
use rand::{RngCore, rngs::OsRng};
use crate::fake::{charsets, generate_fake_tier2};
use crate::crypto::hmac_sha256;
use crate::tier1::Pattern;
use std::sync::Arc;

/// Register an arbitrary secret and produce a Tier 2 Pattern.
///
/// The original secret is consumed and discarded; only fragments and an HMAC token
/// are retained. See SPEC.md §Registration.
///
/// # Panics
/// Panics if `secret` is shorter than 2 bytes (cannot extract meaningful fragments).
pub fn register(secret: impl AsRef<[u8]>) -> Pattern {
    register_with_rng(secret.as_ref(), &mut OsRng)
}

/// Testable variant — accepts any RNG (seeded for deterministic tests).
pub(crate) fn register_with_rng<R: RngCore>(secret: &[u8], rng: &mut R) -> Pattern {
    assert!(secret.len() >= 2, "secret must be at least 2 bytes for Tier 2 registration");

    // Unique salt per registration (INV-17)
    let mut hmac_salt = [0u8; 32];
    rng.fill_bytes(&mut hmac_salt);

    let hmac_digest = hmac_sha256(&hmac_salt, secret);

    let start_len = START_FRAGMENT_LEN.min(secret.len());
    let end_len = if secret.len() > start_len { END_FRAGMENT_LEN.min(secret.len() - start_len) } else { 0 };

    let start_fragment = secret[..start_len].to_vec();
    let end_fragment = if end_len > 0 {
        secret[secret.len() - end_len..].to_vec()
    } else {
        vec![]
    };

    let charset = charsets::detect(secret);
    // Ensure charset is non-empty (fallback to alphanumeric if secret is homogeneous)
    let charset = if charset.len() <= 1 { charsets::alphanumeric() } else { charset };

    // Use start_fragment as the "prefix" for fake generation
    let fake = generate_fake_tier2(&start_fragment, &charset, secret.len(), secret, rng);

    // Secret is dropped here — no reference to secret after this line
    Pattern::Tier2(Arc::new(Tier2Pat {
        start_fragment,
        end_fragment,
        exact_length: secret.len(),
        charset,
        hmac_salt,
        hmac_digest,
        fake,
    }))
}
```

### Task 3: Tier 2 detection helper (used by scrub engine in step-06)

```rust
impl Tier2Pat {
    /// Attempt to match this pattern at `payload[pos..]`.
    ///
    /// Returns `Some(end_pos)` if:
    /// 1. payload[pos..pos+start_fragment.len()] == start_fragment
    /// 2. payload[pos..pos+exact_length].ends_with(&end_fragment)
    /// 3. HMAC-SHA256(hmac_salt, payload[pos..pos+exact_length]) == hmac_digest
    ///
    /// Returns `None` on any structural mismatch (no HMAC computed).
    /// Returns `None` on HMAC failure (structural match but wrong content — INV-16).
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<usize> {
        use crate::crypto::verify_hmac;

        // 1. Start fragment
        if !payload[pos..].starts_with(&self.start_fragment) {
            return None;
        }

        // 2. Length check
        let end = pos + self.exact_length;
        if end > payload.len() {
            return None;
        }

        // 3. End fragment
        if !self.end_fragment.is_empty() {
            let ef_start = end - self.end_fragment.len();
            if &payload[ef_start..end] != self.end_fragment.as_slice() {
                return None;
            }
        }

        // 4. HMAC verification (INV-16: failure → None, caller passes through)
        let candidate = &payload[pos..end];
        if !verify_hmac(&self.hmac_salt, candidate, &self.hmac_digest) {
            return None;  // structural match but HMAC failed → pass through (INV-16)
        }

        Some(end)
    }
}
```

### Task 4: Unit tests

```rust
#[test]
fn test_register_unique_salts() {
    // INV-17: two registrations of the same secret must have different salts
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let secret = b"my-arbitrary-secret-value-12345";
    let pat1 = register_with_rng(secret, &mut StdRng::seed_from_u64(1));
    let pat2 = register_with_rng(secret, &mut StdRng::seed_from_u64(2));
    match (&pat1, &pat2) {
        (Pattern::Tier2(a), Pattern::Tier2(b)) => {
            assert_ne!(a.hmac_salt, b.hmac_salt, "salts must differ per registration (INV-17)");
        }
        _ => panic!("expected Tier2"),
    }
}

#[test]
fn test_register_hmac_digest_correct() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use crate::crypto::hmac_sha256;
    let secret = b"my-arbitrary-secret-value-12345";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(99));
    match &pat {
        Pattern::Tier2(p) => {
            let expected = hmac_sha256(&p.hmac_salt, secret);
            assert_eq!(p.hmac_digest, expected, "HMAC digest must match recomputed value");
        }
        _ => panic!("expected Tier2"),
    }
}

#[test]
fn test_tier2_try_match_correct_secret() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let secret = b"my-arbitrary-secret-value-12345";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(99));
    let payload = b"token: my-arbitrary-secret-value-12345 end";
    match &pat {
        Pattern::Tier2(p) => {
            let pos = 7;  // position of "my-arb..."
            let result = p.try_match(payload, pos);
            assert_eq!(result, Some(pos + secret.len()));
        }
        _ => panic!(),
    }
}

#[test]
fn test_tier2_try_match_hmac_failure_returns_none() {
    // INV-16: structural match + HMAC failure → None (pass through)
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let secret = b"my-arbitrary-secret-value-12345";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(99));
    // A different secret with same start/end fragments (crafted)
    // Use a payload that has the right start fragment but different middle bytes
    let mut fake_payload = secret.to_vec();
    fake_payload[8] ^= 0xFF;  // flip a byte in the middle
    let payload = fake_payload.clone();
    match &pat {
        Pattern::Tier2(p) => {
            let result = p.try_match(&payload, 0);
            assert!(result.is_none(), "HMAC failure must return None (INV-16)");
        }
        _ => panic!(),
    }
}

#[test]
fn test_register_discards_secret() {
    // The secret bytes must not appear in the pattern fields (other than fragments)
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let secret = b"super-secret-api-key-value-here!";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(7));
    match &pat {
        Pattern::Tier2(p) => {
            // Only the first 8 and last 8 bytes of secret are stored (fragments)
            // The middle 16 bytes must NOT appear verbatim in the pattern
            let middle = &secret[8..secret.len()-8];
            let all_fields: Vec<u8> = p.start_fragment.iter()
                .chain(&p.end_fragment)
                .chain(&p.fake)
                .chain(&p.hmac_salt)
                .chain(&p.hmac_digest)
                .copied().collect();
            // Middle of secret should NOT appear in all_fields
            // (This is a best-effort check; HMAC digest could theoretically match,
            //  but with 16+ bytes this is astronomically unlikely)
            assert!(
                !all_fields.windows(middle.len()).any(|w| w == middle),
                "middle bytes of secret must not appear verbatim in pattern fields"
            );
        }
        _ => panic!(),
    }
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --lib` exits 0
- [ ] `test_register_unique_salts` passes (INV-17 verified)
- [ ] `test_register_hmac_digest_correct` passes
- [ ] `test_tier2_try_match_correct_secret` passes (correct detection)
- [ ] `test_tier2_try_match_hmac_failure_returns_none` passes (INV-16 verified)
- [ ] `cargo clippy -- -D warnings` exits 0
- [ ] `register()` function signature is `pub fn register(secret: impl AsRef<[u8]>) -> Pattern`

## Reviewer Instructions

You are reviewing Step 05. Verify:

1. Run `cargo nextest run --lib` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Run `cargo nextest run --lib -E 'test(register|tier2)'` — must pass
4. Confirm `register()` is in `pub use` from `src/lib.rs`
5. Confirm `Tier2Pat` struct does NOT have a field storing the full secret (only fragments)

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-05 commit.
