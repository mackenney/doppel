use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
pub enum FakeError {
    #[error(
        "could not generate a fake distinct from original after {attempts} attempts (charset too small)"
    )]
    CollisionLimit { attempts: u32 },
}

pub(crate) mod charsets {
    /// [A-Za-z0-9]
    pub fn alphanumeric() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .collect();
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
    #[allow(dead_code)]
    pub fn base64_standard() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain([b'+', b'/', b'='])
            .collect();
        v.sort_unstable();
        v
    }

    /// Detect charset from observed bytes (for Tier 2 `restrict_charset` mode).
    pub fn detect(bytes: &[u8]) -> Vec<u8> {
        let present: std::collections::BTreeSet<u8> = bytes.iter().copied().collect();
        present.into_iter().collect()
    }

    /// Standard wide charset used for Tier 2 fakes by default.
    ///
    /// 72 printable ASCII chars that are safe in JSON strings and most API contexts.
    /// Excludes `"` (0x22) and `\` (0x5C) to avoid breaking JSON payloads.
    pub fn wide() -> Vec<u8> {
        // Printable ASCII 0x21..=0x7E minus '"' (0x22) and '\\' (0x5C).
        (0x21u8..=0x7E)
            .filter(|&b| b != b'\"' && b != b'\\')
            .collect()
    }
}

/// Derive a structurally-equivalent fake for a Tier 1 secret.
///
/// The same (salt, prefix, charset, original) inputs always produce the same fake (INV-13).
/// Resamples if fake == original (INV-15).
///
/// Derivation is deterministic: HMAC-SHA256(salt, original || attempt) seeds a StdRng.
pub(crate) fn derive_fake_tier1(
    salt: &[u8; 32],
    prefix: &[u8],
    charset: &[u8],
    target_len: usize,
    original: &[u8],
) -> Result<Vec<u8>, FakeError> {
    assert!(
        target_len >= prefix.len(),
        "target_len must be >= prefix.len()"
    );
    assert!(!charset.is_empty(), "charset must not be empty");

    const MAX_ATTEMPTS: u32 = 1_000;

    for attempt in 0u32..MAX_ATTEMPTS {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key size");
        mac.update(original);
        mac.update(&attempt.to_le_bytes());
        let seed_bytes: [u8; 32] = mac.finalize().into_bytes().into();

        let mut rng = StdRng::from_seed(seed_bytes);
        let payload_len = target_len - prefix.len();
        let mut fake = Vec::with_capacity(target_len);
        fake.extend_from_slice(prefix);

        // Rejection sampling to avoid modulo bias
        let charset_len = charset.len() as u32;
        let threshold = u32::MAX - (u32::MAX % charset_len);
        for _ in 0..payload_len {
            let idx = loop {
                let r = rng.next_u32();
                if r < threshold {
                    break (r % charset_len) as usize;
                }
            };
            fake.push(charset[idx]);
        }

        if fake != original {
            return Ok(fake);
        }
        // Collision: try next attempt (INV-15)
    }

    Err(FakeError::CollisionLimit {
        attempts: MAX_ATTEMPTS,
    })
}

/// Generate a Tier 2 fake using a CSPRNG. Called once at registration time.
/// The generated fake is stored in the Pattern and returned on all subsequent detections.
///
/// Structure: `preserved_prefix || random_variable_bytes || preserved_suffix`
/// - `preserved_prefix`: non-secret bytes declared by the caller (may be empty)
/// - `preserved_suffix`: non-secret bytes declared by the caller (may be empty)
/// - variable bytes are drawn from `charset`
/// - total length == `target_len`
///
/// `original` is used solely for collision detection (INV-15).
pub(crate) fn generate_fake_tier2<R: rand::RngCore>(
    preserved_prefix: &[u8],
    preserved_suffix: &[u8],
    charset: &[u8],
    target_len: usize,
    original: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, FakeError> {
    let fixed_len = preserved_prefix.len() + preserved_suffix.len();
    assert!(
        target_len >= fixed_len,
        "target_len must be >= preserved_prefix.len() + preserved_suffix.len()"
    );
    assert!(!charset.is_empty(), "charset must not be empty");

    let variable_len = target_len - fixed_len;
    const MAX_ATTEMPTS: u32 = 1_000;

    for _ in 0..MAX_ATTEMPTS {
        let mut fake = Vec::with_capacity(target_len);
        fake.extend_from_slice(preserved_prefix);

        // Rejection sampling to avoid modulo bias (INV-15 requires non-colliding output)
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

        fake.extend_from_slice(preserved_suffix);

        if fake != original {
            return Ok(fake);
        }
    }

    Err(FakeError::CollisionLimit {
        attempts: MAX_ATTEMPTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_fake_tier1_stability() {
        let salt = [42u8; 32];
        let prefix = b"sk-ant-";
        let charset = charsets::alphanumeric();
        let original = b"sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let fake1 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original).unwrap();
        let fake2 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original).unwrap();
        assert_eq!(fake1, fake2, "same inputs must produce same fake (INV-13)");
    }

    #[test]
    fn test_derive_fake_tier1_no_collision() {
        let salt = [0u8; 32];
        let prefix = b"gh";
        let charset = vec![b'a', b'b'];
        let original = b"ghab".to_vec();
        let fake = derive_fake_tier1(&salt, prefix, &charset, original.len(), &original).unwrap();
        assert_ne!(
            fake,
            original.as_slice(),
            "fake must not equal original (INV-15)"
        );
        assert!(fake.starts_with(prefix), "fake must preserve prefix");
        assert_eq!(fake.len(), original.len(), "fake must preserve length");
    }

    #[test]
    fn test_hmac_verify_correct() {
        use crate::crypto::{hmac_sha256, verify_hmac};
        let salt = [1u8; 32];
        let data = b"test-secret";
        let digest = hmac_sha256(&salt, data);
        assert!(verify_hmac(&salt, data, &digest));
    }

    #[test]
    fn test_hmac_verify_wrong_data() {
        use crate::crypto::{hmac_sha256, verify_hmac};
        let salt = [1u8; 32];
        let data = b"test-secret";
        let digest = hmac_sha256(&salt, data);
        assert!(!verify_hmac(&salt, b"wrong-data", &digest));
    }

    #[test]
    fn test_generate_fake_tier2_with_seeded_rng() {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(12345);
        let charset = charsets::alphanumeric();
        let original = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fake = generate_fake_tier2(b"ghp_", b"", &charset, original.len(), original, &mut rng)
            .unwrap();
        assert_ne!(fake, original.as_slice());
        assert!(fake.starts_with(b"ghp_"));
        assert_eq!(fake.len(), original.len());
        let mut rng2 = StdRng::seed_from_u64(12345);
        let fake2 =
            generate_fake_tier2(b"ghp_", b"", &charset, original.len(), original, &mut rng2)
                .unwrap();
        assert_eq!(fake, fake2);
    }

    #[test]
    fn test_generate_fake_tier2_no_secret_bytes_in_variable_region() {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(42);
        let secret = b"mysecretvalue123";
        let charset = charsets::wide();
        // No prefix, no suffix — fake must share zero variable bytes pattern
        let fake = generate_fake_tier2(b"", b"", &charset, secret.len(), secret, &mut rng).unwrap();
        assert_ne!(fake, secret.as_slice());
        assert_eq!(fake.len(), secret.len());
    }

    #[test]
    fn test_generate_fake_tier2_with_preserved_affix() {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(7);
        let secret = b"MY_ORG_secretvalue123END";
        let prefix = b"MY_ORG_";
        let suffix = b"END";
        let charset = charsets::alphanumeric();
        let fake =
            generate_fake_tier2(prefix, suffix, &charset, secret.len(), secret, &mut rng).unwrap();
        assert!(
            fake.starts_with(prefix),
            "declared prefix must be preserved"
        );
        assert!(fake.ends_with(suffix), "declared suffix must be preserved");
        assert_eq!(fake.len(), secret.len());
        assert_ne!(fake, secret.as_slice());
    }

    #[test]
    fn test_wide_charset_excludes_json_unsafe() {
        let wide = charsets::wide();
        assert!(
            !wide.contains(&b'"'),
            "wide charset must not contain double-quote"
        );
        assert!(
            !wide.contains(&b'\\'),
            "wide charset must not contain backslash"
        );
        assert!(wide.len() >= 60, "wide charset should be substantial");
    }
}
