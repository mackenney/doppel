use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::Sha256;

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

    /// Detect charset from observed bytes (for Tier 2 registration).
    pub fn detect(bytes: &[u8]) -> Vec<u8> {
        let present: std::collections::BTreeSet<u8> = bytes.iter().copied().collect();
        present.into_iter().collect()
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
) -> Vec<u8> {
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
        for _ in 0..payload_len {
            let idx = (rng.next_u32() as usize) % charset.len();
            fake.push(charset[idx]);
        }

        if fake != original {
            return fake;
        }
        // Collision: try next attempt (INV-15)
    }

    panic!(
        "fake derivation: could not avoid collision after {MAX_ATTEMPTS} attempts — charset too small"
    );
}

/// Generate a Tier 2 fake using a CSPRNG. Called once at registration time.
/// The generated fake is stored in the Pattern and returned on all subsequent detections.
pub(crate) fn generate_fake_tier2<R: rand::RngCore>(
    prefix: &[u8],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_fake_tier1_stability() {
        let salt = [42u8; 32];
        let prefix = b"sk-ant-";
        let charset = charsets::alphanumeric();
        let original = b"sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let fake1 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original);
        let fake2 = derive_fake_tier1(&salt, prefix, &charset, original.len(), original);
        assert_eq!(fake1, fake2, "same inputs must produce same fake (INV-13)");
    }

    #[test]
    fn test_derive_fake_tier1_no_collision() {
        let salt = [0u8; 32];
        let prefix = b"gh";
        let charset = vec![b'a', b'b'];
        let original = b"ghab".to_vec();
        let fake = derive_fake_tier1(&salt, prefix, &charset, original.len(), &original);
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
        let fake = generate_fake_tier2(b"ghp_", &charset, original.len(), original, &mut rng);
        assert_ne!(fake, original.as_slice());
        assert!(fake.starts_with(b"ghp_"));
        assert_eq!(fake.len(), original.len());
        let mut rng2 = StdRng::seed_from_u64(12345);
        let fake2 = generate_fake_tier2(b"ghp_", &charset, original.len(), original, &mut rng2);
        assert_eq!(fake, fake2);
    }
}
