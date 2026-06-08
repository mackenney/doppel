use crate::patterns::Pattern;
use crate::segment::{CharsetName, Segment};
use rand::rngs::OsRng;
use std::sync::Arc;

const ENTROPY_HARD_FAIL_BITS: f64 = 83.0;
const ENTROPY_WARN_BITS: f64 = 131.0;

/// Calculate effective entropy for a variable portion.
///
/// entropy_bits = variable_len × log₂(charset_size)
fn calculate_entropy(variable_len: usize, charset_size: usize) -> f64 {
    if charset_size <= 1 {
        return 0.0;
    }
    variable_len as f64 * (charset_size as f64).log2()
}

/// Options for registered secret registration.
#[derive(Debug, Clone)]
pub struct SecretOptions {
    /// Number of leading secret bytes stored as the detection anchor.
    /// SPEC: default 3; longer values reduce false-positive AC hits.
    pub anchor_len: usize,

    /// Number of trailing secret bytes stored as secondary anchor.
    /// SPEC: default 0; non-zero adds trailing Opaque segment.
    pub tail_anchor_len: usize,

    /// When true, variable portion uses detected charset instead of wide.
    /// SPEC: default false; use only when target system requires.
    pub restrict_charset: bool,

    /// Suppress entropy hard failure (83-bit threshold).
    /// SPEC: entropy warning is still emitted; only hard fail is suppressed.
    pub force: bool,
}

impl Default for SecretOptions {
    fn default() -> Self {
        Self {
            anchor_len: 3,
            tail_anchor_len: 0,
            restrict_charset: false,
            force: false,
        }
    }
}

/// Errors returned by registration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// Secret is empty or shorter than `anchor_len`.
    #[error("secret too short for the given anchor_len")]
    TooShort,

    /// `anchor_len + tail_anchor_len` covers the entire secret, leaving no variable bytes.
    /// A fake with zero variable bytes cannot differ from the original.
    #[error(
        "anchor_len ({anchor_len}) + tail_anchor_len ({tail_anchor_len}) \
         >= secret length ({secret_len}); no variable bytes remain"
    )]
    NoVariableBytes {
        /// The `anchor_len` value passed to registration.
        anchor_len: usize,
        /// The effective `tail_anchor_len` value.
        tail_anchor_len: usize,
        /// Total byte length of the secret.
        secret_len: usize,
    },

    /// Fake generation failed because the charset is too small relative to the
    /// variable portion length (all candidates collided with the original).
    #[error("fake generation exhausted {attempts} attempts; charset too small for variable length")]
    CollisionLimit {
        /// Number of derivation attempts made before giving up.
        attempts: u32,
    },

    /// Registration rejected due to insufficient entropy in variable portion.
    /// Use `force: true` in `SecretOptions` to override.
    #[error(
        "insufficient entropy: {bits:.1} bits < {threshold:.1} bit minimum \
         (use --force to override)"
    )]
    InsufficientEntropy {
        /// Computed entropy in bits.
        bits: f64,
        /// Minimum threshold (83.0).
        threshold: f64,
    },
}

/// Register an arbitrary secret with default options and produce a registered-secret Pattern.
///
/// Returns `Err` instead of panicking on invalid input. See [`SecretError`] for error conditions.
/// See [`register_with_options`] to customise anchor lengths, charset restriction, or force.
///
/// # Examples
///
/// ```
/// use doppel::{register, swap};
///
/// let secret = b"my-custom-api-token-that-is-long-enough";
/// let pattern = register(secret).unwrap();
/// let result = swap(secret, &[pattern]).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// ```
///
/// # Errors
///
/// See [`register_with_options`] for the full error set.
pub fn register(secret: &[u8]) -> Result<Pattern, SecretError> {
    register_with_options_rng(secret, &SecretOptions::default(), &mut OsRng)
}

/// Register an arbitrary secret with explicit options.
///
/// See [`SecretOptions`] for the available knobs.
///
/// # Errors
///
/// - [`SecretError::TooShort`] if `secret` is empty or shorter than `anchor_len`.
/// - [`SecretError::NoVariableBytes`] if `anchor_len + tail_anchor_len >= secret.len()`.
/// - [`SecretError::InsufficientEntropy`] if entropy < 83 bits and `!opts.force`.
/// - [`SecretError::CollisionLimit`] if fake generation exhausts all attempts.
pub fn register_with_options(secret: &[u8], opts: &SecretOptions) -> Result<Pattern, SecretError> {
    register_with_options_rng(secret, opts, &mut OsRng)
}

/// Testable variant — accepts any RNG (seeded for deterministic tests).
#[cfg(test)]
pub(crate) fn register_with_rng<R: rand::RngCore>(
    secret: &[u8],
    rng: &mut R,
) -> Result<Pattern, SecretError> {
    register_with_options_rng(secret, &SecretOptions::default(), rng)
}

/// Core registration logic. All public entry points funnel here.
pub(crate) fn register_with_options_rng<R: rand::RngCore>(
    secret: &[u8],
    opts: &SecretOptions,
    rng: &mut R,
) -> Result<Pattern, SecretError> {
    if secret.is_empty() {
        return Err(SecretError::TooShort);
    }
    if secret.len() < opts.anchor_len {
        return Err(SecretError::TooShort);
    }

    let anchor_len = opts.anchor_len;
    // Clamp tail_anchor_len so it can't exceed the bytes after the head anchor.
    let tail_anchor_len = opts
        .tail_anchor_len
        .min(secret.len().saturating_sub(anchor_len));

    let middle_start = anchor_len;
    let middle_end = secret.len().saturating_sub(tail_anchor_len);
    let middle_len = middle_end.saturating_sub(middle_start);

    if middle_len == 0 {
        return Err(SecretError::NoVariableBytes {
            anchor_len,
            tail_anchor_len,
            secret_len: secret.len(),
        });
    }

    let middle_bytes = &secret[middle_start..middle_end];

    // Determine charset for variable portion and entropy calculation.
    let (charset, charset_size) = if opts.restrict_charset {
        let detected_name = crate::segment::detect_charset_name(middle_bytes);
        let size = detected_name.resolve().bytes.len();
        (detected_name, size)
    } else {
        (CharsetName::Wide, 92)
    };

    // Entropy enforcement.
    let entropy = calculate_entropy(middle_len, charset_size);
    if entropy < ENTROPY_HARD_FAIL_BITS && !opts.force {
        return Err(SecretError::InsufficientEntropy {
            bits: entropy,
            threshold: ENTROPY_HARD_FAIL_BITS,
        });
    }
    if entropy < ENTROPY_WARN_BITS {
        log::warn!(
            "doppel: effective entropy {:.1} bits < {:.1} bits recommended; \
             consider a longer secret or --force",
            entropy,
            ENTROPY_WARN_BITS
        );
    }

    // INV-26: warn when alphanumeric secret uses wide charset (unexpected wide fakes).
    if !opts.restrict_charset && middle_bytes.iter().all(|b| b.is_ascii_alphanumeric()) {
        log::warn!(
            "doppel: secret variable bytes are all alphanumeric but restrict-charset is false; \
             fake bytes will be drawn from the wide charset (92 chars) which may be structurally \
             implausible for the target system. Use --restrict-charset to match the secret's charset."
        );
    }
    let anchor_bytes = &secret[..anchor_len];
    let anchor_charset = crate::segment::detect_charset_name(anchor_bytes);

    let mut segments: Vec<Segment> = vec![
        Segment::Opaque {
            value: anchor_bytes.to_vec(),
            charset: anchor_charset,
        },
        Segment::Variable {
            charset,
            min: middle_len,
            max: middle_len, // INV-31: instance patterns have fixed-length variable segments
        },
    ];

    if tail_anchor_len > 0 {
        let tail_bytes = &secret[middle_end..];
        let tail_charset = crate::segment::detect_charset_name(tail_bytes);
        segments.push(Segment::Opaque {
            value: tail_bytes.to_vec(),
            charset: tail_charset,
        });
    }

    // INV-31 assertion: variable segments in instance patterns must have min == max.
    for seg in &segments {
        if let Segment::Variable { min, max, .. } = seg {
            debug_assert_eq!(
                min, max,
                "INV-31: instance pattern variable segment min must equal max"
            );
        }
    }

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let digest = crate::crypto::hmac_sha256(&salt, secret);

    let arc_segments: Arc<[Segment]> = segments.into();

    let pattern = Pattern {
        identifier: String::new(),
        segments: arc_segments.clone(),
        salt,
        digests: vec![digest],
    };

    // Sanity check: verify fake derivation succeeds at registration time.
    let variable_lengths = vec![middle_len];
    crate::fake::derive_fake_structural_segments(&salt, &arc_segments, &variable_lengths, secret)
        .map_err(|_| SecretError::CollisionLimit { attempts: 1_000 })?;

    Ok(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_register_with_rng_deterministic() {
        // register_with_rng exists for deterministic tests per AGENTS.md.
        // Same seed must produce the same salt and digest.
        let secret = b"deterministic-registration-test-secret-01";
        let mut rng_a = StdRng::seed_from_u64(42);
        let mut rng_b = StdRng::seed_from_u64(42);
        let pat_a = register_with_rng(secret, &mut rng_a).unwrap();
        let pat_b = register_with_rng(secret, &mut rng_b).unwrap();
        assert_eq!(pat_a.salt, pat_b.salt, "same seed must produce same salt");
        assert_eq!(
            pat_a.digests, pat_b.digests,
            "same seed must produce same digest"
        );
    }
}
