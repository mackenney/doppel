use rand::{RngCore, rngs::OsRng};
use std::sync::Arc;

use crate::crypto::hmac_sha256;
use crate::fake::{FakeError, charsets, derive_fake_tier2_deterministic};
use crate::patterns::Pattern;

/// Options for Tier 2 secret registration.
///
/// All fields default to the secure-by-default configuration: no prefix/suffix
/// preservation, wide charset for fake generation.
#[derive(Debug, Clone, Default)]
pub struct SecretOptions {
    /// Number of bytes at the start of the secret that are declared **non-secret**
    /// by the caller and will appear verbatim in the fake.
    ///
    /// Use this when the secret has a well-known structural prefix that must appear
    /// in the payload for detection to fire (e.g., `MY_ORG_`). Setting this to a
    /// non-zero value means those bytes are visible in the entries file; they are
    /// explicitly not part of the confidential value. Misuse — marking actual secret
    /// bytes as prefix — weakens protection for those bytes.
    ///
    /// Default: 0.
    pub preserve_prefix: usize,

    /// Number of bytes at the end of the secret that are declared **non-secret**
    /// by the caller and will appear verbatim in the fake. Same caveats as
    /// `preserve_prefix`.
    ///
    /// Default: 0.
    pub preserve_suffix: usize,

    /// When `true`, the variable portion of the fake is drawn exclusively from the
    /// distinct byte values observed in the registered secret (`charsets::detect`).
    ///
    /// When `false` (default), the wide standard charset is used. The wide charset
    /// has no connection to the secret's content; it reveals only the byte length of
    /// the detected secret. Use `restrict_charset: true` only when the target system
    /// requires a structurally plausible replacement — the trade-off is that an
    /// observer of the entries file can infer the secret's character class.
    ///
    /// Default: false.
    pub restrict_charset: bool,
}

/// Errors returned by Tier 2 registration.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// Secret is empty; there are no bytes to protect.
    #[error("secret is empty; Tier 2 registration requires at least 1 byte")]
    TooShort,

    /// `preserve_prefix + preserve_suffix` covers the entire secret, leaving no
    /// variable bytes. A fake with zero variable bytes cannot differ from the
    /// original, making replacement impossible.
    #[error(
        "preserve_prefix ({preserve_prefix}) + preserve_suffix ({preserve_suffix}) \
         >= secret length ({secret_len}); no variable bytes remain"
    )]
    NoVariableBytes {
        preserve_prefix: usize,
        preserve_suffix: usize,
        secret_len: usize,
    },

    /// Fake generation failed because the charset is too small relative to the
    /// variable portion length (all candidates collided with the original).
    #[error("fake generation exhausted {attempts} attempts; charset too small for variable length")]
    CollisionLimit { attempts: u32 },
}

impl From<FakeError> for SecretError {
    fn from(e: FakeError) -> Self {
        match e {
            FakeError::CollisionLimit { attempts } => SecretError::CollisionLimit { attempts },
        }
    }
}

/// Minimum variable-byte count below which a warning is emitted (INV-26).
const MIN_VARIABLE_BYTES_WARNING: usize = 14;

/// Internal representation of a Tier 2 registered secret pattern.
/// Opaque to callers — they receive a `Pattern::Tier2(Arc<Tier2Pat>)`.
pub struct Tier2Pat {
    /// First N bytes of the original secret. Used to quickly identify candidates.
    pub(crate) start_fragment: Vec<u8>,
    /// Last M bytes of the original secret. Verified after start fragment matches.
    pub(crate) end_fragment: Vec<u8>,
    /// Exact byte length of the original secret.
    pub(crate) exact_length: usize,
    /// Unique random salt for this registration (INV-17: must not reuse).
    pub(crate) hmac_salt: [u8; 32],
    /// HMAC-SHA256(hmac_salt, original_secret) — confirmation token.
    pub(crate) hmac_digest: [u8; 32],
    /// Number of prefix bytes declared non-secret, preserved verbatim in the fake.
    pub(crate) preserve_prefix: usize,
    /// Number of suffix bytes declared non-secret, preserved verbatim in the fake.
    pub(crate) preserve_suffix: usize,
    /// Resolved charset for fake variable bytes. Wide charset when restrict_charset is false;
    /// detected charset otherwise.
    pub(crate) charset: Vec<u8>,
}
const START_FRAGMENT_LEN: usize = 8;
const END_FRAGMENT_LEN: usize = 8;

/// Register an arbitrary secret with default options and produce a Tier 2 Pattern.
///
/// Returns `Err` instead of panicking on invalid input. See [`SecretError`]
/// for the error conditions. See [`register_with_options`] to customise prefix/suffix
/// preservation or charset restriction.
///
/// # Examples
///
/// ```
/// use doppel::{register, swap};
///
/// let secret = b"my-custom-api-token-that-is-long-enough-for-tier2";
/// let pattern = register(secret).unwrap();
/// let result = swap(secret, &[pattern]).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// ```
pub fn register(secret: impl AsRef<[u8]>) -> Result<Pattern, SecretError> {
    register_with_options(secret, &SecretOptions::default())
}

/// Register an arbitrary secret with explicit options.
///
/// See [`SecretOptions`] for the available knobs.
pub fn register_with_options(
    secret: impl AsRef<[u8]>,
    opts: &SecretOptions,
) -> Result<Pattern, SecretError> {
    register_with_options_rng(secret.as_ref(), opts, &mut OsRng)
}

/// Testable variant — accepts any RNG (seeded for deterministic tests).
#[cfg(test)]
pub(crate) fn register_with_rng<R: RngCore>(
    secret: &[u8],
    rng: &mut R,
) -> Result<Pattern, SecretError> {
    register_with_options_rng(secret, &SecretOptions::default(), rng)
}

/// Core registration logic. All public entry points funnel here.
pub(crate) fn register_with_options_rng<R: RngCore>(
    secret: &[u8],
    opts: &SecretOptions,
    rng: &mut R,
) -> Result<Pattern, SecretError> {
    // INV-25: return error, never panic.
    if secret.is_empty() {
        return Err(SecretError::TooShort);
    }

    let pp = opts.preserve_prefix;
    let ps = opts.preserve_suffix;

    if pp + ps >= secret.len() {
        return Err(SecretError::NoVariableBytes {
            preserve_prefix: pp,
            preserve_suffix: ps,
            secret_len: secret.len(),
        });
    }

    let variable_len = secret.len() - pp - ps;

    // INV-26: warn when variable portion is small.
    if variable_len < MIN_VARIABLE_BYTES_WARNING {
        log::warn!(
            "doppel: registered secret registration has only {} variable byte(s) (minimum recommended: {}). \
             Secrets with small variable portions offer weak protection.",
            variable_len,
            MIN_VARIABLE_BYTES_WARNING
        );
    }

    // INV-27: warn when secret looks alphanumeric but restrict_charset is off.
    if !opts.restrict_charset {
        let observed = charsets::detect(secret);
        let alnum = charsets::alphanumeric();
        if observed.iter().all(|b| alnum.contains(b)) {
            log::warn!(
                "doppel: registered secret appears alphanumeric ([A-Za-z0-9]) but \
                 restrict_charset is false. The fake will be drawn from the wide charset, \
                 which may look structurally different from the original. Set \
                 restrict_charset: true if the replacement must also be alphanumeric."
            );
        }
    }

    // Unique salt per registration (INV-17).
    let mut hmac_salt = [0u8; 32];
    rng.fill_bytes(&mut hmac_salt);

    let hmac_digest = hmac_sha256(&hmac_salt, secret);

    let start_len = START_FRAGMENT_LEN.min(secret.len());
    let end_len = if secret.len() > start_len {
        END_FRAGMENT_LEN.min(secret.len() - start_len)
    } else {
        0
    };

    let start_fragment = secret[..start_len].to_vec();
    let end_fragment = if end_len > 0 {
        secret[secret.len() - end_len..].to_vec()
    } else {
        vec![]
    };

    // Choose charset for variable bytes.
    let charset = if opts.restrict_charset {
        let detected = charsets::detect(secret);
        if detected.len() <= 1 {
            charsets::alphanumeric()
        } else {
            detected
        }
    } else {
        charsets::wide()
    };

    let pat = Tier2Pat {
        start_fragment,
        end_fragment,
        exact_length: secret.len(),
        hmac_salt,
        hmac_digest,
        preserve_prefix: pp,
        preserve_suffix: ps,
        charset,
    };

    // Trial derivation to detect CollisionLimit at registration time (INV-25).
    // The secret itself is the canonical candidate for this pattern.
    derive_fake_tier2_deterministic(
        &pat.hmac_salt,
        secret,
        &secret[..pp],
        &secret[secret.len() - ps..],
        &pat.charset,
        secret.len(),
    )
    .map_err(SecretError::from)?;

    Ok(Pattern::Tier2(Arc::new(pat)))
}

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
    #[rustfmt::skip]
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Result<Option<(usize, Vec<u8>)>, FakeError> {
        use crate::crypto::verify_hmac;
        use crate::fake::derive_fake_tier2_deterministic;

        // 1. Start fragment
        if !payload[pos..].starts_with(&self.start_fragment) {
            return Ok(None);
        }

        // 2. Length check
        let end = pos + self.exact_length;
        if end > payload.len() {
            return Ok(None);
        }

        // 3. End fragment
        if !self.end_fragment.is_empty() {
            let ef_start = end - self.end_fragment.len();
            if &payload[ef_start..end] != self.end_fragment.as_slice() {
                return Ok(None);
            }
        }

        // 4. HMAC verification (INV-16: failure → None, caller passes through)
        let candidate = &payload[pos..end];
        if !verify_hmac(&self.hmac_salt, candidate, &self.hmac_digest) {
            return Ok(None);
        }

        // 5. Derive fake from salt + candidate (deterministic, INV-13)
        let prefix_bytes = &candidate[..self.preserve_prefix];
        let suffix_bytes = if self.preserve_suffix > 0 {
            &candidate[candidate.len() - self.preserve_suffix..]
        } else {
            &[]
        };
        let fake = derive_fake_tier2_deterministic(
            &self.hmac_salt,
            candidate,
            prefix_bytes,
            suffix_bytes,
            &self.charset,
            self.exact_length,
        )?;

        Ok(Some((end, fake)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_register_unique_salts() {
        // INV-17: two registrations of the same secret must have different salts.
        let secret = b"my-arbitrary-secret-value-12345";
        let pat1 = register_with_rng(secret, &mut StdRng::seed_from_u64(1)).unwrap();
        let pat2 = register_with_rng(secret, &mut StdRng::seed_from_u64(2)).unwrap();
        match (&pat1, &pat2) {
            (Pattern::Tier2(a), Pattern::Tier2(b)) => {
                assert_ne!(
                    a.hmac_salt, b.hmac_salt,
                    "salts must differ per registration (INV-17)"
                );
            }
            _ => panic!("expected Tier2"),
        }
    }

    #[test]
    fn test_register_hmac_digest_correct() {
        use crate::crypto::hmac_sha256;
        let secret = b"my-arbitrary-secret-value-12345";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(99)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                let expected = hmac_sha256(&p.hmac_salt, secret);
                assert_eq!(
                    p.hmac_digest, expected,
                    "HMAC digest must match recomputed value"
                );
            }
            _ => panic!("expected Tier2"),
        }
    }

    #[test]
    fn test_tier2_try_match_correct_secret() {
        let secret = b"my-arbitrary-secret-value-12345";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(99)).unwrap();
        let payload = b"token: my-arbitrary-secret-value-12345 end";
        match &pat {
            Pattern::Tier2(p) => {
                let pos = 7;
                let result = p
                    .try_match(payload, pos)
                    .expect("try_match should not error");
                assert!(result.is_some(), "should match");
                let (end, fake) = result.unwrap();
                assert_eq!(end, pos + secret.len());
                assert_eq!(
                    fake.len(),
                    secret.len(),
                    "fake must have same length as secret"
                );
                assert_ne!(fake.as_slice(), secret, "fake must differ from original");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_tier2_try_match_hmac_failure_returns_none() {
        // INV-16: structural match + HMAC failure → None (pass through)
        let secret = b"my-arbitrary-secret-value-12345";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(99)).unwrap();
        let mut fake_payload = secret.to_vec();
        fake_payload[8] ^= 0xFF;
        let payload = fake_payload.clone();
        match &pat {
            Pattern::Tier2(p) => {
                let result = p
                    .try_match(&payload, 0)
                    .expect("try_match should not error");
                assert!(result.is_none(), "HMAC failure must return None (INV-16)");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_register_discards_secret() {
        let secret = b"super-secret-api-key-value-here!";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(7)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                let middle = &secret[8..secret.len() - 8];
                let all_fields: Vec<u8> = p
                    .start_fragment
                    .iter()
                    .chain(&p.end_fragment)
                    .chain(&p.hmac_salt)
                    .chain(&p.hmac_digest)
                    .copied()
                    .collect();
                assert!(
                    !all_fields.windows(middle.len()).any(|w| w == middle),
                    "middle bytes of secret must not appear verbatim in pattern fields"
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_register_fake_contains_no_secret_variable_bytes() {
        let secret = b"deadbeef12345678";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(123)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                let result = p
                    .try_match(secret, 0)
                    .expect("try_match error")
                    .expect("should match");
                let (_end, fake) = result;
                for window in secret.windows(4) {
                    assert!(
                        !fake.windows(4).any(|w| w == window),
                        "fake must not contain secret bytes (variable portion): {:?}",
                        std::str::from_utf8(window).unwrap_or("<binary>")
                    );
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_register_with_preserve_prefix_affix_in_fake() {
        let secret = b"MY_ORG_secretbytes1234END";
        let opts = SecretOptions {
            preserve_prefix: 7,
            preserve_suffix: 3,
            restrict_charset: false,
        };
        let pat = register_with_options_rng(secret, &opts, &mut StdRng::seed_from_u64(55)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                let result = p
                    .try_match(secret, 0)
                    .expect("try_match error")
                    .expect("should match");
                let (_end, fake) = result;
                assert!(
                    fake.starts_with(b"MY_ORG_"),
                    "declared prefix must appear in fake"
                );
                assert!(
                    fake.ends_with(b"END"),
                    "declared suffix must appear in fake"
                );
                assert_eq!(fake.len(), secret.len());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_register_wide_charset_by_default() {
        let secret = b"my-hex-secret-value-abcd1234";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(77)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                let result = p
                    .try_match(secret, 0)
                    .expect("try_match error")
                    .expect("should match");
                let (_end, fake) = result;
                let wide = charsets::wide();
                for &b in &fake {
                    assert!(wide.contains(&b), "fake byte 0x{b:02x} not in wide charset");
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_register_restrict_charset_uses_secret_charset() {
        let secret = b"abcdef1234567890abcdef";
        let opts = SecretOptions {
            preserve_prefix: 0,
            preserve_suffix: 0,
            restrict_charset: true,
        };
        let pat = register_with_options_rng(secret, &opts, &mut StdRng::seed_from_u64(88)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                let result = p
                    .try_match(secret, 0)
                    .expect("try_match error")
                    .expect("should match");
                let (_end, fake) = result;
                let allowed: std::collections::BTreeSet<u8> = secret.iter().copied().collect();
                for &b in &fake {
                    assert!(
                        allowed.contains(&b),
                        "fake byte 0x{b:02x} not in secret charset under restrict_charset"
                    );
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_registration_performs_trial_derivation() {
        // A normal secret should register without collision.
        // Verifies that trial derivation runs (INV-25) and does not false-positive.
        let secret = b"sk-test-abcdefghijklmnopqrstuvwxyz1234567890abcdef";
        let opts = SecretOptions {
            preserve_prefix: 0,
            preserve_suffix: 0,
            restrict_charset: false,
        };
        let pattern = register_with_options(secret, &opts).unwrap();
        match &pattern {
            Pattern::Tier2(_) => {}
            _ => panic!("expected Tier2"),
        }
    }
}

#[cfg(test)]
mod derivation_param_tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_register_stores_derivation_params() {
        let secret = b"MY_ORG_secretbytes1234END";
        let opts = SecretOptions {
            preserve_prefix: 7,
            preserve_suffix: 3,
            restrict_charset: true,
        };
        let pat = register_with_options_rng(secret, &opts, &mut StdRng::seed_from_u64(42)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                assert_eq!(p.preserve_prefix, 7);
                assert_eq!(p.preserve_suffix, 3);
                let detected = crate::fake::charsets::detect(secret);
                assert_eq!(p.charset, detected, "charset must match detected charset");
            }
            _ => panic!("expected Tier2"),
        }
    }

    #[test]
    fn test_register_default_uses_wide_charset() {
        let secret = b"my-arbitrary-secret-value-12345";
        let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(1)).unwrap();
        match &pat {
            Pattern::Tier2(p) => {
                assert_eq!(p.preserve_prefix, 0);
                assert_eq!(p.preserve_suffix, 0);
                assert_eq!(p.charset, crate::fake::charsets::wide());
            }
            _ => panic!("expected Tier2"),
        }
    }
}
