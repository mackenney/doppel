use crate::patterns::Pattern;

/// Options for registered secret registration.
///
/// All fields default to the secure-by-default configuration: no prefix/suffix
/// preservation, wide charset for fake generation.
#[derive(Debug, Clone)]
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

    /// Number of bytes taken from the start of the secret as the detection anchor.
    /// Shorter values reduce false-positive eliminations before HMAC verification;
    /// longer values allow faster pre-filtering. Default: 2.
    pub start_fragment_len: usize,

    /// Number of bytes taken from the end of the secret as the detection anchor.
    /// Default: 2.
    pub end_fragment_len: usize,
}

impl Default for SecretOptions {
    fn default() -> Self {
        Self {
            preserve_prefix: 0,
            preserve_suffix: 0,
            restrict_charset: false,
            start_fragment_len: 2,
            end_fragment_len: 2,
        }
    }
}

/// Errors returned by registration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// Secret is empty; there are no bytes to protect.
    #[error("secret is empty; registration requires at least 1 byte")]
    TooShort,

    /// `preserve_prefix + preserve_suffix` covers the entire secret, leaving no
    /// variable bytes. A fake with zero variable bytes cannot differ from the
    /// original, making replacement impossible.
    #[error(
        "preserve_prefix ({preserve_prefix}) + preserve_suffix ({preserve_suffix}) \
         >= secret length ({secret_len}); no variable bytes remain"
    )]
    NoVariableBytes {
        /// The `preserve_prefix` value passed to registration.
        preserve_prefix: usize,
        /// The `preserve_suffix` value passed to registration.
        preserve_suffix: usize,
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
}

/// Register an arbitrary secret with default options and produce a registered-secret Pattern.
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
/// let secret = b"my-custom-api-token-that-is-long-enough";
/// let pattern = register(secret).unwrap();
/// let result = swap(secret, &[pattern]).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// ```
///
/// # Errors
///
/// See [`register_with_options`] for the full error set.
pub fn register(secret: impl AsRef<[u8]>) -> Result<Pattern, SecretError> {
    register_with_options(secret, &SecretOptions::default())
}

/// Register an arbitrary secret with explicit options.
///
/// See [`SecretOptions`] for the available knobs.
///
/// # Errors
///
/// - [`SecretError::TooShort`] if `secret` is empty.
/// - [`SecretError::NoVariableBytes`] if `preserve_prefix + preserve_suffix >= secret.len()`.
/// - [`SecretError::CollisionLimit`] if fake generation exhausts all attempts (charset too small).
pub fn register_with_options(
    _secret: impl AsRef<[u8]>,
    _opts: &SecretOptions,
) -> Result<Pattern, SecretError> {
    // Registration rework — step-04 will implement this with the unified Pattern model.
    todo!("Registration will be updated in step-04")
}

/// Testable variant — accepts any RNG (seeded for deterministic tests).
#[cfg(test)]
pub(crate) fn register_with_rng<R: rand::RngCore>(
    _secret: &[u8],
    _rng: &mut R,
) -> Result<Pattern, SecretError> {
    todo!("Registration will be updated in step-04")
}

/// Core registration logic. All public entry points funnel here.
/// Registration rework — step-04 will implement this with the unified Pattern model.
pub(crate) fn register_with_options_rng<R: rand::RngCore>(
    _secret: &[u8],
    _opts: &SecretOptions,
    _rng: &mut R,
) -> Result<Pattern, SecretError> {
    todo!("Registration will be updated in step-04")
}
