use crate::segment::Segment;
use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::Sha256;
use std::sync::LazyLock;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FakeError {
    #[error(
        "could not generate a fake distinct from original after {attempts} attempts (charset too small)"
    )]
    CollisionLimit { attempts: u32 },
}

pub(crate) mod charsets {
    /// [A-Za-z0-9]
    #[allow(dead_code)]
    pub fn alphanumeric() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .collect();
        v.sort_unstable();
        v
    }

    /// [A-Z0-9] (uppercase only)
    #[allow(dead_code)]
    pub fn uppercase_alphanumeric() -> Vec<u8> {
        let mut v: Vec<u8> = (b'A'..=b'Z').chain(b'0'..=b'9').collect();
        v.sort_unstable();
        v
    }

    /// [A-Za-z0-9_-]
    #[allow(dead_code)]
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

    /// [0-9a-f] (lowercase hex)
    #[allow(dead_code)]
    pub fn hex_lower() -> Vec<u8> {
        let mut v: Vec<u8> = (b'0'..=b'9').chain(b'a'..=b'f').collect();
        v.sort_unstable();
        v
    }

    /// [0-9]
    #[allow(dead_code)]
    pub fn digits() -> Vec<u8> {
        (b'0'..=b'9').collect()
    }

    /// Standard wide charset used for registered-secret fakes by default.
    ///
    /// 92 printable ASCII chars that are safe in JSON strings and most API contexts.
    /// Excludes `"` (0x22) and `\` (0x5C) to avoid breaking JSON payloads.
    pub fn wide() -> Vec<u8> {
        // Printable ASCII 0x21..=0x7E minus '"' (0x22) and '\\' (0x5C).
        (0x21u8..=0x7E)
            .filter(|&b| b != b'\"' && b != b'\\')
            .collect()
    }
}

/// A 256-element bitmap for O(1) charset membership tests.
#[derive(Clone)]
pub(crate) struct CharsetBitmap([bool; 256]);

impl CharsetBitmap {
    #[allow(dead_code)]
    pub(crate) const fn empty() -> Self {
        Self([false; 256])
    }

    /// Check if byte is in the charset. O(1).
    #[inline]
    pub(crate) fn contains(&self, b: u8) -> bool {
        self.0[b as usize]
    }
}

/// A charset with both bitmap (for membership) and byte slice (for iteration).
pub(crate) struct Charset {
    pub(crate) bitmap: CharsetBitmap,
    pub(crate) bytes: &'static [u8],
}

impl Charset {
    /// Check if byte is in the charset. O(1).
    #[inline]
    pub(crate) fn contains(&self, b: u8) -> bool {
        self.bitmap.contains(b)
    }

    /// Get the bytes for iteration (e.g., fake generation).
    #[inline]
    pub(crate) fn bytes(&self) -> &'static [u8] {
        self.bytes
    }

    /// Number of bytes in charset.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
}

fn build_bitmap(bytes: &[u8]) -> CharsetBitmap {
    let mut bits = [false; 256];
    for &b in bytes {
        bits[b as usize] = true;
    }
    CharsetBitmap(bits)
}

static ALPHANUMERIC_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static URL_SAFE_BASE64_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static UPPERCASE_ALPHANUMERIC_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static DIGITS_BYTES: &[u8] = b"0123456789";
static HEX_LOWER_BYTES: &[u8] = b"0123456789abcdef";
static BASE64_ANY_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=";

pub(crate) static ALPHANUMERIC: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(ALPHANUMERIC_BYTES),
    bytes: ALPHANUMERIC_BYTES,
});

pub(crate) static URL_SAFE_BASE64: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(URL_SAFE_BASE64_BYTES),
    bytes: URL_SAFE_BASE64_BYTES,
});

pub(crate) static UPPERCASE_ALPHANUMERIC: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(UPPERCASE_ALPHANUMERIC_BYTES),
    bytes: UPPERCASE_ALPHANUMERIC_BYTES,
});

pub(crate) static DIGITS: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(DIGITS_BYTES),
    bytes: DIGITS_BYTES,
});

pub(crate) static HEX_LOWER: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(HEX_LOWER_BYTES),
    bytes: HEX_LOWER_BYTES,
});

pub(crate) static BASE64_ANY: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(BASE64_ANY_BYTES),
    bytes: BASE64_ANY_BYTES,
});

pub(crate) fn alphanumeric_ref() -> &'static Charset {
    &ALPHANUMERIC
}

pub(crate) fn url_safe_base64_ref() -> &'static Charset {
    &URL_SAFE_BASE64
}

pub(crate) fn uppercase_alphanumeric_ref() -> &'static Charset {
    &UPPERCASE_ALPHANUMERIC
}

pub(crate) fn digits_ref() -> &'static Charset {
    &DIGITS
}

pub(crate) fn hex_lower_ref() -> &'static Charset {
    &HEX_LOWER
}

pub(crate) fn base64_any_ref() -> &'static Charset {
    &BASE64_ANY
}

pub(crate) static WIDE: LazyLock<Charset> = LazyLock::new(|| {
    let bytes: &'static [u8] = Box::leak(charsets::wide().into_boxed_slice());
    Charset {
        bitmap: build_bitmap(bytes),
        bytes,
    }
});

pub(crate) fn wide_ref() -> &'static Charset {
    &WIDE
}

/// Derive a structurally-equivalent fake for a structural-pattern secret using the segment model.
///
/// Walks `segments` in order:
/// - `Literal` bytes are reproduced verbatim (INV-28).
/// - `Variable` segments are filled with CSPRNG bytes from the segment's charset,
///   using exactly `variable_lengths[i]` bytes for the i-th Variable segment (INV-29).
/// - `Opaque` segments fill `value.len()` bytes from the segment's charset via
///   HMAC-seeded PRNG (fixed length, not taken from `variable_lengths`) (INV-28).
///
/// Deterministic: same (salt, segments, variable_lengths, original) always produces the
/// same fake (INV-13). Resamples if fake == original (INV-15).
pub(crate) fn derive_fake_structural_segments(
    salt: &[u8; 32],
    segments: &[Segment],
    variable_lengths: &[usize],
    original: &[u8],
) -> Result<Vec<u8>, FakeError> {
    assert!(!segments.is_empty(), "segment list must not be empty");
    assert!(
        !any_charset_is_empty(segments),
        "all Variable and Opaque segments must have non-empty charsets"
    );
    debug_assert_eq!(
        variable_lengths.len(),
        segments
            .iter()
            .filter(|s| matches!(s, Segment::Variable { .. }))
            .count(),
        "variable_lengths.len() must equal number of Variable segments"
    );

    let total_len: usize = {
        let mut var_idx = 0usize;
        let mut len = 0usize;
        for seg in segments {
            match seg {
                Segment::Literal(bytes) => len += bytes.len(),
                Segment::Variable { .. } => {
                    len += variable_lengths[var_idx];
                    var_idx += 1;
                }
                Segment::Opaque { value, .. } => len += value.len(),
            }
        }
        len
    };

    // Opaque segment start positions are fixed by segment layout, not by attempt.
    let opaque_positions: Vec<(usize, &[u8])> = {
        let mut positions = Vec::new();
        let mut pos = 0usize;
        let mut var_idx = 0usize;
        for seg in segments {
            match seg {
                Segment::Literal(bytes) => pos += bytes.len(),
                Segment::Variable { .. } => {
                    pos += variable_lengths[var_idx];
                    var_idx += 1;
                }
                Segment::Opaque { value, .. } => {
                    positions.push((pos, value.as_slice()));
                    pos += value.len();
                }
            }
        }
        positions
    };

    const MAX_ATTEMPTS: u32 = 1_000;

    for attempt in 0u32..MAX_ATTEMPTS {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key size");
        mac.update(original);
        mac.update(&attempt.to_le_bytes());
        let seed_bytes: [u8; 32] = mac.finalize().into_bytes().into();

        let mut rng = StdRng::from_seed(seed_bytes);
        let mut fake = Vec::with_capacity(total_len);
        let mut var_idx = 0usize;

        for seg in segments {
            match seg {
                Segment::Literal(bytes) => fake.extend_from_slice(bytes),
                Segment::Variable { charset, .. } => {
                    let cs = charset.resolve();
                    let var_len = variable_lengths[var_idx];
                    var_idx += 1;
                    let cs_len = cs.len() as u32;
                    let threshold = u32::MAX - (u32::MAX % cs_len);
                    for _ in 0..var_len {
                        let idx = loop {
                            let r = rng.next_u32();
                            if r < threshold {
                                break (r % cs_len) as usize;
                            }
                        };
                        fake.push(cs.bytes()[idx]);
                    }
                }
                Segment::Opaque { value, charset } => {
                    // INV-28: opaque bytes are derived, never verbatim
                    let cs = charset.resolve();
                    let cs_len = cs.len() as u32;
                    let threshold = u32::MAX - (u32::MAX % cs_len);
                    for _ in 0..value.len() {
                        let idx = loop {
                            let r = rng.next_u32();
                            if r < threshold {
                                break (r % cs_len) as usize;
                            }
                        };
                        fake.push(cs.bytes()[idx]);
                    }
                }
            }
        }

        if fake == original {
            continue;
        }
        // INV-28: defense-in-depth — opaque segment bytes must not match originals
        if opaque_collision(&fake, &opaque_positions) {
            continue;
        }
        return Ok(fake);
    }

    Err(FakeError::CollisionLimit {
        attempts: MAX_ATTEMPTS,
    })
}

fn opaque_collision(fake: &[u8], opaque_positions: &[(usize, &[u8])]) -> bool {
    opaque_positions.iter().any(|(start, original)| {
        let end = *start + original.len();
        fake.get(*start..end) == Some(*original)
    })
}

fn any_charset_is_empty(segments: &[Segment]) -> bool {
    segments.iter().any(|seg| match seg {
        Segment::Variable { charset, .. } | Segment::Opaque { charset, .. } => {
            charset.resolve().len() == 0
        }
        Segment::Literal(_) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{CharsetName, Segment};

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

    #[test]
    fn test_derive_fake_structural_segments_stability() {
        let salt = [42u8; 32];
        let segs = [
            Segment::Literal(b"sk-ant-api03-".to_vec()),
            Segment::Variable {
                charset: CharsetName::UrlSafeBase64,
                min: 93,
                max: 93,
            },
            Segment::Literal(b"AA".to_vec()),
        ];
        let var_lens = [93usize];
        let original = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let f1 = derive_fake_structural_segments(&salt, &segs, &var_lens, original).unwrap();
        let f2 = derive_fake_structural_segments(&salt, &segs, &var_lens, original).unwrap();
        assert_eq!(f1, f2, "INV-13: stability");
    }

    #[test]
    fn test_derive_fake_structural_segments_literal_reproduced() {
        let salt = [1u8; 32];
        let segs = [
            Segment::Literal(b"sk-ant-api03-".to_vec()),
            Segment::Variable {
                charset: CharsetName::UrlSafeBase64,
                min: 93,
                max: 93,
            },
            Segment::Literal(b"AA".to_vec()),
        ];
        let var_lens = [93usize];
        let original = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fake = derive_fake_structural_segments(&salt, &segs, &var_lens, original).unwrap();
        assert_eq!(fake.len(), original.len(), "same length");
        assert!(
            fake.starts_with(b"sk-ant-api03-"),
            "INV-28: leading literal preserved"
        );
        assert!(fake.ends_with(b"AA"), "INV-28: trailing literal preserved");
        assert_ne!(fake, original.as_slice(), "INV-15: fake != original");
    }

    #[test]
    fn test_derive_fake_structural_segments_variable_bytes_in_charset() {
        let salt = [2u8; 32];
        let segs = [
            Segment::Literal(b"xoxb-".to_vec()),
            Segment::Variable {
                charset: CharsetName::Digits,
                min: 10,
                max: 13,
            },
            Segment::Literal(b"-".to_vec()),
            Segment::Variable {
                charset: CharsetName::Digits,
                min: 10,
                max: 13,
            },
            Segment::Literal(b"-".to_vec()),
            Segment::Variable {
                charset: CharsetName::Alphanumeric,
                min: 24,
                max: 24,
            },
        ];
        let var_lens = [10usize, 10usize, 24usize];
        let original = b"xoxb-1234567890-1234567890-AAAAAAAAAAAAAAAAAAAAAAAA";
        let fake = derive_fake_structural_segments(&salt, &segs, &var_lens, original).unwrap();
        assert_eq!(fake.len(), original.len());
        assert!(fake.starts_with(b"xoxb-"), "INV-28: prefix literal");
        let digits_cs = charsets::digits();
        assert!(
            fake[5..15].iter().all(|b| digits_cs.contains(b)),
            "INV-29: seg1 digits"
        );
        assert_eq!(&fake[15..16], b"-", "INV-28: inner literal");
        assert!(
            fake[16..26].iter().all(|b| digits_cs.contains(b)),
            "INV-29: seg3 digits"
        );
        assert_eq!(&fake[26..27], b"-", "INV-28: inner literal");
        let alnum_cs = charsets::alphanumeric();
        assert!(
            fake[27..51].iter().all(|b| alnum_cs.contains(b)),
            "INV-29: seg5 alnum"
        );
    }

    #[test]
    fn test_opaque_segment_not_verbatim() {
        // INV-28: opaque bytes must be derived, never a verbatim copy
        let salt = [0u8; 32];
        let segments = [
            Segment::Opaque {
                value: b"ABC".to_vec(),
                charset: CharsetName::Alphanumeric,
            },
            Segment::Variable {
                charset: CharsetName::Alphanumeric,
                min: 10,
                max: 10,
            },
        ];
        let original = b"ABCdefghijklm";
        let variable_lengths = [10usize];
        let fake =
            derive_fake_structural_segments(&salt, &segments, &variable_lengths, original).unwrap();
        assert_ne!(&fake[0..3], b"ABC", "opaque must not be verbatim copy");
        assert_eq!(fake.len(), original.len(), "same total length");
    }
}

#[cfg(test)]
mod bitmap_tests {
    use super::*;

    #[test]
    fn test_bitmap_matches_vec() {
        let vec_alphanum = charsets::alphanumeric();
        for b in 0u8..=255 {
            assert_eq!(
                ALPHANUMERIC.contains(b),
                vec_alphanum.contains(&b),
                "mismatch at byte {}",
                b
            );
        }
    }

    #[test]
    fn test_charset_bytes_iteration() {
        assert_eq!(ALPHANUMERIC.bytes().len(), 62);
        assert_eq!(DIGITS.bytes().len(), 10);
        assert_eq!(HEX_LOWER.bytes().len(), 16);
    }

    #[test]
    fn test_bitmap_url_safe_base64() {
        let vec = charsets::url_safe_base64();
        for b in 0u8..=255 {
            assert_eq!(
                URL_SAFE_BASE64.contains(b),
                vec.contains(&b),
                "mismatch at byte {b}"
            );
        }
    }

    #[test]
    fn test_bitmap_uppercase_alphanumeric() {
        let vec = charsets::uppercase_alphanumeric();
        for b in 0u8..=255 {
            assert_eq!(
                UPPERCASE_ALPHANUMERIC.contains(b),
                vec.contains(&b),
                "mismatch at byte {b}"
            );
        }
    }

    #[test]
    fn test_bitmap_digits() {
        let vec = charsets::digits();
        for b in 0u8..=255 {
            assert_eq!(DIGITS.contains(b), vec.contains(&b), "mismatch at byte {b}");
        }
    }

    #[test]
    fn test_bitmap_hex_lower() {
        let vec = charsets::hex_lower();
        for b in 0u8..=255 {
            assert_eq!(
                HEX_LOWER.contains(b),
                vec.contains(&b),
                "mismatch at byte {b}"
            );
        }
    }
}
