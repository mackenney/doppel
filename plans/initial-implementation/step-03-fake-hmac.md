# Step 03: Fake Derivation and HMAC Helpers

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration. Full contract in SPEC.md.

### Phase Context
Wave 1 (parallel with step-02). Provides the fake generation algorithm used by both Tier 1
(keyed derivation for cross-call stability, INV-13) and Tier 2 (CSPRNG at registration time),
plus the HMAC construction helpers used by Tier 2 registration and verification (INV-16, INV-17).

### This Step
Implement `src/fake.rs`: keyed fake derivation from a stable salt + secret bytes, collision
avoidance loop (INV-15), charset sampling from a seeded CSPRNG. Implement `src/hmac_util.rs`
(or add to `src/crypto.rs`): HMAC-SHA256 computation and constant-time verification.

## Prerequisites

- Step 01 complete (deps in Cargo.toml: `hmac`, `sha2`, `rand`, `subtle`)
- Step 02 complete or in parallel (no direct dependency on types.rs for this step — can proceed concurrently)

## Files to Read Before Starting

- `src/fake.rs` — current stub
- `SPEC.md §Fake Generation` — all four constraints (prefix, length, charset, no collision)
- `SPEC.md INV-13, INV-15` — stability and collision avoidance
- `TESTING.md` — seeded RNG injection pattern

## Implementation

### Task 1: Charset representation

Define charset as a sorted `Vec<u8>` of valid byte values. Helper to detect charset from
a secret (used in Tier 2 `register()`):

```rust
/// A set of valid byte values for a character class.
pub(crate) type Charset = Vec<u8>;

/// Common charsets used by built-in Tier 1 patterns.
pub(crate) mod charsets {
    /// [A-Za-z0-9]
    pub fn alphanumeric() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9').collect();
        v.sort_unstable();
        v
    }

    /// [A-Z0-9] (uppercase only)
    pub fn uppercase_alphanumeric() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z').chain(b'0'..=b'9').collect();
        v.sort_unstable();
        v
    }

    /// [A-Za-z0-9_-]
    pub fn url_safe_base64() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain([b'-', b'_'])
            .collect();
        v.sort_unstable();
        v
    }

    /// [A-Za-z0-9+/=] (standard base64 including padding)
    pub fn base64_standard() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain([b'+', b'/', b'='])
            .collect();
        v.sort_unstable();
        v
    }

    /// Detect charset from observed bytes (for Tier 2 registration).
    pub fn detect(bytes: &[u8]) -> Vec<u8> {
        let mut present: std::collections::BTreeSet<u8> = bytes.iter().copied().collect();
        // Return the minimal observed set, sorted
        present.into_iter().collect()
    }
}
```

### Task 2: Keyed fake derivation for Tier 1 (INV-13)

The fake is deterministically derived from `(pattern_salt, secret_bytes)`:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::{SeedableRng, RngCore};
use rand::rngs::StdRng;

/// Derive a structurally-equivalent fake for a Tier 1 secret.
///
/// The same (salt, prefix, charset, original) inputs always produce the same fake (INV-13).
/// Resamples if fake == original (INV-15).
///
/// In tests, the derivation is still deterministic (no RNG injection needed here —
/// the "RNG" is driven by the HMAC-derived seed, which is deterministic).
pub(crate) fn derive_fake_tier1(
    salt: &[u8; 32],
    prefix: &[u8],
    charset: &[u8],
    target_len: usize,
    original: &[u8],
) -> Vec<u8> {
    assert!(target_len >= prefix.len(), "target_len must be >= prefix.len()");
    assert!(!charset.is_empty(), "charset must not be empty");

    const MAX_ATTEMPTS: u32 = 1_000;

    for attempt in 0u32..MAX_ATTEMPTS {
        // Seed = HMAC-SHA256(salt, secret || attempt_bytes)
        let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key size");
        mac.update(original);
        mac.update(&attempt.to_le_bytes());
        let seed_bytes: [u8; 32] = mac.finalize().into_bytes().into();

        let mut rng = StdRng::from_seed(seed_bytes);
        let payload_len = target_len - prefix.len();
        let mut fake = Vec::with_capacity(target_len);
        fake.extend_from_slice(prefix);
        for _ in 0..payload_len {
            let idx = (rng.next_u32() as usize) % charset.len();
            fake.push(charset[idx]);
        }

        if fake != original {
            return fake;
        }
        // Collision: try next attempt (INV-15)
    }

    // This path is unreachable for realistic charsets (probability ~charset_size^-payload_len per attempt)
    panic!("fake derivation: could not avoid collision after {MAX_ATTEMPTS} attempts — charset too small");
}
```

**Stability guarantee**: Same inputs → same HMAC seed → same StdRng stream → same fake.
Across calls: `pattern_salt` is fixed for the lifetime of the Pattern; `original` is the
same bytes; `attempt` starts at 0. Result is always identical.

### Task 3: Tier 2 fake generation (CSPRNG at registration time)

For Tier 2, the fake is generated once at registration using a live CSPRNG (OsRng in production,
injected RNG in tests):

```rust
/// Generate a Tier 2 fake using a CSPRNG. Called once at registration time.
/// The generated fake is stored in the Pattern and returned on all subsequent detections.
pub(crate) fn generate_fake_tier2<R: rand::RngCore>(
    prefix: &[u8],          // for Tier 2, this is the start_fragment
    charset: &[u8],
    target_len: usize,
    original: &[u8],
    rng: &mut R,
) -> Vec<u8> {
    assert!(target_len >= prefix.len());
    assert!(!charset.is_empty());

    const MAX_ATTEMPTS: u32 = 1_000;

    for _ in 0..MAX_ATTEMPTS {
        let payload_len = target_len - prefix.len();
        let mut fake = Vec::with_capacity(target_len);
        fake.extend_from_slice(prefix);
        for _ in 0..payload_len {
            let idx = (rng.next_u32() as usize) % charset.len();
            fake.push(charset[idx]);
        }
        if fake != original {
            return fake;
        }
    }

    panic!("fake generation: could not avoid collision after {MAX_ATTEMPTS} attempts");
}
```

### Task 4: HMAC helpers (src/crypto.rs or src/fake.rs)

Add to `src/crypto.rs`:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Compute HMAC-SHA256(salt, data). Returns 32-byte digest.
pub(crate) fn hmac_sha256(salt: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify HMAC-SHA256(salt, data) == expected in constant time.
/// Returns true if match, false if not. Never leaks timing information.
pub(crate) fn verify_hmac(salt: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = hmac_sha256(salt, data);
    computed.ct_eq(expected).into()
}
```

### Task 5: Unit tests

In `src/fake.rs` `#[cfg(test)]`:

```rust
#[test]
fn test_derive_fake_tier1_stability() {
    let salt = [42u8; 32];
    let prefix = b"sk-ant-";
    let charset = charsets::alphanumeric();
    let original = b"sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAA";

    let fake1 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original);
    let fake2 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original);
    assert_eq!(fake1, fake2, "same inputs must produce same fake (INV-13)");
}

#[test]
fn test_derive_fake_tier1_no_collision() {
    let salt = [0u8; 32];
    let prefix = b"gh";
    let charset = vec![b'a', b'b'];  // tiny charset to stress collision avoidance
    // original = "ghab..." — collision is possible; verify function still returns something != original
    let original = b"ghab".to_vec();
    let fake = derive_fake_tier1(&salt, prefix, &charset, original.len(), &original);
    assert_ne!(fake, original.as_slice(), "fake must not equal original (INV-15)");
    assert!(fake.starts_with(prefix), "fake must preserve prefix");
    assert_eq!(fake.len(), original.len(), "fake must preserve length");
}

#[test]
fn test_hmac_verify_correct() {
    let salt = [1u8; 32];
    let data = b"test-secret";
    let digest = hmac_sha256(&salt, data);
    assert!(verify_hmac(&salt, data, &digest));
}

#[test]
fn test_hmac_verify_wrong_data() {
    let salt = [1u8; 32];
    let data = b"test-secret";
    let digest = hmac_sha256(&salt, data);
    assert!(!verify_hmac(&salt, b"wrong-data", &digest));
}

#[test]
fn test_generate_fake_tier2_with_seeded_rng() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let mut rng = StdRng::seed_from_u64(12345);
    let charset = charsets::alphanumeric();
    let original = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let fake = generate_fake_tier2(b"ghp_", &charset, original.len(), original, &mut rng);
    assert_ne!(fake, original.as_slice());
    assert!(fake.starts_with(b"ghp_"));
    assert_eq!(fake.len(), original.len());
    // Deterministic: same seed → same fake
    let mut rng2 = StdRng::seed_from_u64(12345);
    let fake2 = generate_fake_tier2(b"ghp_", &charset, original.len(), original, &mut rng2);
    assert_eq!(fake, fake2);
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --lib` exits 0
- [ ] `test_derive_fake_tier1_stability` passes (same inputs → same fake)
- [ ] `test_derive_fake_tier1_no_collision` passes (fake != original, prefix preserved, length preserved)
- [ ] `test_hmac_verify_correct` passes
- [ ] `test_hmac_verify_wrong_data` passes
- [ ] `test_generate_fake_tier2_with_seeded_rng` passes (deterministic with seeded RNG)
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 03. Verify:

1. Run `cargo nextest run --lib` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Confirm `derive_fake_tier1` in `src/fake.rs` uses HMAC-SHA256 as the derivation key (not a plain hash)
4. Confirm `verify_hmac` in `src/crypto.rs` uses `subtle::ConstantTimeEq` (not `==` on raw bytes)
5. Run `cargo nextest run --lib -E 'test(stability)'` — must pass

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-03 commit.
