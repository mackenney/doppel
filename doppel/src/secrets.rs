use crate::patterns::Pattern;
use crate::segment::{CharsetName, Segment};
use rand::rngs::OsRng;
use std::sync::Arc;

const ENTROPY_HARD_FAIL_BITS: f64 = 83.0;
const ENTROPY_WARN_BITS: f64 = 131.0;
/// Advisory threshold above which a supplied trailing_run_guard warns (SPEC item 50).
/// Real-world encoded blobs run tens of KB to a few MB; a threshold well past that
/// range does not improve suppression and can reduce it near blob tails (see SPEC.md's
/// "A larger threshold is not uniformly better" limitation). Advisory only — never rejected.
const TRAILING_RUN_GUARD_WARN_THRESHOLD: usize = 20_000;

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
    /// Number of leading secret bytes stored as the detection anchor (default 3).
    ///
    /// Must be at least 2; values of 0 or 1 are rejected with [`SecretError::AnchorTooShort`].
    /// Values below 3 emit a warning — 3 (the default) is the recommended minimum.
    /// Longer anchors reduce false-positive Aho-Corasick hits at the cost of more
    /// plaintext bytes stored in the patterns file.
    pub anchor_len: usize,

    /// Number of trailing secret bytes stored as secondary anchor.
    /// SPEC: default 0; non-zero adds trailing Opaque segment.
    pub tail_anchor_len: usize,

    /// When true, variable portion uses detected charset instead of wide.
    /// SPEC: default false; use only when target system requires.
    pub restrict_charset: bool,

    /// Optional trailing run guard threshold in bytes (default `None` — no guard).
    ///
    /// When set, the produced Pattern declares a trailing run guard (SPEC
    /// §Trailing Run Guard): a winning match followed by at least this many
    /// consecutive guard-charset bytes is suppressed as a likely slice of an
    /// encoded blob. The guard charset is the Pattern's single `variable`
    /// segment charset — wide by default, or the detected charset when
    /// `restrict_charset` is true. Must be positive; zero is rejected with
    /// [`SecretError::ZeroTrailingRunGuard`]. Registered patterns are
    /// HMAC-gated, so the guard suppresses only genuine occurrences of the
    /// secret embedded directly in same-charset runs — leave `None` unless
    /// that trade-off is intended.
    pub trailing_run_guard: Option<usize>,

    /// Explicit trailing run guard charset name (default `None` — inferred).
    ///
    /// SPEC §Registration Options / item 51: when set, overrides the guard
    /// charset the Pattern would otherwise infer from `restrict_charset`
    /// (SPEC item 49's "unless the explicit guard-charset option is
    /// supplied"). Requires `trailing_run_guard` to also be set; string-typed
    /// because [`crate::segment::CharsetName`] is `pub(crate)`. Not exposed as
    /// a CLI flag. Unrecognised names are rejected with
    /// [`SecretError::UnknownGuardCharset`]; setting this without
    /// `trailing_run_guard` is rejected with
    /// [`SecretError::GuardCharsetWithoutGuard`].
    pub trailing_run_guard_charset: Option<String>,

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
            trailing_run_guard: None,
            trailing_run_guard_charset: None,
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

    /// `anchor_len` is 0 or 1 — too short to serve as a reliable Aho-Corasick anchor.
    /// Use at least 2; the default and recommended value is 3.
    #[error(
        "anchor_len {anchor_len} is too short (minimum 2, recommended 3+); a 0- or 1-byte anchor cannot pre-filter candidates reliably"
    )]
    AnchorTooShort {
        /// The `anchor_len` value that was rejected.
        anchor_len: usize,
    },

    /// `anchor_len + tail_anchor_len` covers the entire secret, leaving no variable bytes.
    /// A fake with zero variable bytes cannot differ from the original.
    #[error(
        "anchor_len ({anchor_len}) + tail_anchor_len ({tail_anchor_len}) >= secret length ({secret_len}); no variable bytes remain"
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

    /// `trailing_run_guard` is zero — the guard threshold must be a positive byte count.
    #[error("trailing_run_guard must be a positive integer (got 0)")]
    ZeroTrailingRunGuard,

    /// `trailing_run_guard_charset` was set without `trailing_run_guard`.
    #[error("trailing_run_guard_charset requires trailing_run_guard")]
    GuardCharsetWithoutGuard,

    /// `trailing_run_guard_charset` named a charset doppel does not recognise.
    #[error("unknown trailing_run_guard_charset \"{name}\"")]
    UnknownGuardCharset {
        /// The unrecognised charset name that was supplied.
        name: String,
    },

    /// Registration rejected due to insufficient entropy in variable portion.
    /// Use `force: true` in `SecretOptions` to override.
    #[error(
        "insufficient entropy: {bits:.1} bits < {threshold:.1} bit minimum (use --force to override)"
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
/// See [`register_with_options`] to customise anchor lengths, charset restriction, a trailing run guard, or force.
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
/// - [`SecretError::AnchorTooShort`] if `anchor_len` < 2.
/// - [`SecretError::TooShort`] if `secret` is empty or shorter than `anchor_len`.
/// - [`SecretError::NoVariableBytes`] if `anchor_len + tail_anchor_len >= secret.len()`.
/// - [`SecretError::InsufficientEntropy`] if entropy < 83 bits and `!opts.force`.
/// - [`SecretError::CollisionLimit`] if fake generation exhausts all attempts.
/// - [`SecretError::ZeroTrailingRunGuard`] if `trailing_run_guard` is `Some(0)`.
/// - [`SecretError::GuardCharsetWithoutGuard`] if `trailing_run_guard_charset` is set without `trailing_run_guard`.
/// - [`SecretError::UnknownGuardCharset`] if `trailing_run_guard_charset` names an unrecognised charset.
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
    if opts.anchor_len < 2 {
        return Err(SecretError::AnchorTooShort {
            anchor_len: opts.anchor_len,
        });
    }
    if secret.is_empty() {
        return Err(SecretError::TooShort);
    }
    if secret.len() < opts.anchor_len {
        return Err(SecretError::TooShort);
    }
    if opts.anchor_len < 3 {
        log::warn!(
            "doppel: anchor_len {} is below the recommended minimum of 3; short anchors generate more false Aho-Corasick candidates",
            opts.anchor_len
        );
    }
    if opts.trailing_run_guard == Some(0) {
        return Err(SecretError::ZeroTrailingRunGuard);
    }
    if opts.trailing_run_guard_charset.is_some() && opts.trailing_run_guard.is_none() {
        return Err(SecretError::GuardCharsetWithoutGuard);
    }
    let guard_charset = match &opts.trailing_run_guard_charset {
        Some(name) => Some(
            CharsetName::from_name(name)
                .ok_or_else(|| SecretError::UnknownGuardCharset { name: name.clone() })?,
        ),
        None => None,
    };
    if let Some(n) = opts.trailing_run_guard {
        if n > TRAILING_RUN_GUARD_WARN_THRESHOLD {
            log::warn!(
                "doppel: trailing_run_guard {} exceeds {}; real-world blob sizes are tens of KB to \
                 a few MB, so a threshold this large does not improve suppression and can reduce it \
                 near blob tails",
                n,
                TRAILING_RUN_GUARD_WARN_THRESHOLD
            );
        }
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
        trailing_run_guard: opts.trailing_run_guard,
        trailing_run_guard_charset: guard_charset,
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

    #[test]
    fn test_anchor_too_short_rejects_zero() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            anchor_len: 0,
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(1);
        assert!(matches!(
            register_with_options_rng(secret, &opts, &mut rng),
            Err(SecretError::AnchorTooShort { anchor_len: 0 })
        ));
    }

    #[test]
    fn test_anchor_too_short_rejects_one() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            anchor_len: 1,
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(2);
        assert!(matches!(
            register_with_options_rng(secret, &opts, &mut rng),
            Err(SecretError::AnchorTooShort { anchor_len: 1 })
        ));
    }

    #[test]
    fn test_anchor_len_two_succeeds() {
        // anchor_len=2 is above the hard-fail threshold; registration must succeed.
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            anchor_len: 2,
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(3);
        assert!(register_with_options_rng(secret, &opts, &mut rng).is_ok());
    }

    #[test]
    fn test_zero_trailing_run_guard_rejected() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            trailing_run_guard: Some(0),
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(4);
        assert!(matches!(
            register_with_options_rng(secret, &opts, &mut rng),
            Err(SecretError::ZeroTrailingRunGuard)
        ));
    }

    #[test]
    fn test_trailing_run_guard_wired_into_pattern() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            trailing_run_guard: Some(2048),
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(5);
        let pattern = register_with_options_rng(secret, &opts, &mut rng).unwrap();
        assert_eq!(pattern.trailing_run_guard, Some(2048));
    }

    #[test]
    fn test_default_options_have_no_trailing_run_guard() {
        let secret = b"my-long-enough-secret-value";
        let mut rng = StdRng::seed_from_u64(6);
        let pattern = register_with_rng(secret, &mut rng).unwrap();
        assert_eq!(pattern.trailing_run_guard, None);
    }

    #[test]
    fn test_restrict_charset_guard_uses_detected_charset() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            restrict_charset: true,
            trailing_run_guard: Some(2048),
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(7);
        let pattern = register_with_options_rng(secret, &opts, &mut rng).unwrap();
        let anchor_len = opts.anchor_len;
        let middle_bytes = &secret[anchor_len..secret.len() - opts.tail_anchor_len];
        let detected = crate::segment::detect_charset_name(middle_bytes);
        assert_eq!(pattern.last_variable_charset(), Some(detected));
    }

    #[test]
    fn test_guard_charset_without_guard_rejected() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            trailing_run_guard_charset: Some("base64_any".to_string()),
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(8);
        assert!(matches!(
            register_with_options_rng(secret, &opts, &mut rng),
            Err(SecretError::GuardCharsetWithoutGuard)
        ));
    }

    #[test]
    fn test_unknown_guard_charset_rejected() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            trailing_run_guard: Some(2048),
            trailing_run_guard_charset: Some("bogus".to_string()),
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(9);
        match register_with_options_rng(secret, &opts, &mut rng) {
            Err(SecretError::UnknownGuardCharset { name }) => assert_eq!(name, "bogus"),
            Err(other) => panic!("expected UnknownGuardCharset, got {other:?}"),
            Ok(_) => panic!("expected UnknownGuardCharset, got Ok"),
        }
    }

    #[test]
    fn test_explicit_guard_charset_wired_into_pattern() {
        let secret = b"my-long-enough-secret-value";
        let opts = SecretOptions {
            trailing_run_guard: Some(2048),
            trailing_run_guard_charset: Some("base64_any".to_string()),
            ..SecretOptions::default()
        };
        let mut rng = StdRng::seed_from_u64(10);
        let pattern = register_with_options_rng(secret, &opts, &mut rng).unwrap();
        assert_eq!(
            pattern.trailing_run_guard_charset,
            Some(CharsetName::Base64Any)
        );
    }
}
