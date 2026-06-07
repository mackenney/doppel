//! Segment types for structural pattern definitions.
//!
//! `Segment` is the runtime representation; [`SegmentDef`] is the serializable
//! TOML form. `BuiltinSegment` is the `const`-friendly form used in static arrays.

use serde::{Deserialize, Serialize};
/// A single structural element of a built-in structural pattern.
///
/// Patterns are sequences of segments matched left-to-right against the payload.
/// Detection records how many bytes each Variable segment consumed; that per-segment
/// length drives fake generation (SPEC.md §Structural Patterns).
///
/// This type uses static lifetime byte slices and function pointers; it is `Copy`
/// and used in `const` arrays. The owned runtime equivalent is [`Segment`].
#[derive(Clone, Copy)]
pub(crate) enum BuiltinSegment {
    /// Fixed bytes that must appear verbatim at the current position.
    /// Reproduced verbatim in every fake (INV-28).
    Literal(&'static [u8]),
    /// A run of bytes all belonging to `charset`, with length in `[min, max]`.
    /// Filled with HMAC-derived PRNG bytes from `charset` in every fake (INV-29).
    Variable {
        charset: CharsetName,
        min: usize,
        max: usize,
    },
    /// Fixed bytes for detection, but derived (not verbatim) in fake generation.
    /// Charset defaults to detected from value bytes; can be overridden.
    #[allow(dead_code)]
    Opaque {
        value: &'static [u8],
        charset: CharsetName,
    },
}

/// Owned segment used at runtime by `StructuralDef`, `match_segments`, and fake derivation.
///
/// Unlike `BuiltinSegment`, this type is heap-allocated and serializable. It is the runtime
/// representation for both built-in (converted from `BuiltinSegment` via `From`) and user-defined
/// structural patterns.
#[derive(Clone, Debug)]
pub(crate) enum Segment {
    Literal(Vec<u8>),
    Variable {
        charset: CharsetName,
        min: usize,
        max: usize,
    },
    /// Fixed bytes for detection, derived bytes for fake generation.
    /// See SPEC.md §Segment Types: opaque segment.
    Opaque {
        value: Vec<u8>,
        charset: CharsetName,
    },
}

impl From<&BuiltinSegment> for Segment {
    fn from(b: &BuiltinSegment) -> Self {
        match b {
            BuiltinSegment::Literal(bytes) => Segment::Literal(bytes.to_vec()),
            BuiltinSegment::Variable { charset, min, max } => Segment::Variable {
                charset: *charset,
                min: *min,
                max: *max,
            },
            BuiltinSegment::Opaque { value, charset } => Segment::Opaque {
                value: value.to_vec(),
                charset: *charset,
            },
        }
    }
}

impl Segment {
    /// Convert from a validated `SegmentDef` (patterns file representation).
    /// The caller MUST have validated charset names via `validate_segment_defs` first.
    pub(crate) fn from_def(def: &SegmentDef) -> Result<Self, SegmentDefError> {
        match def {
            SegmentDef::Literal { value } => Ok(Segment::Literal(value.as_bytes().to_vec())),
            SegmentDef::Variable { charset, min, max } => {
                let charset_name = CharsetName::from_name(charset).ok_or_else(|| {
                    SegmentDefError::UnknownCharset {
                        index: 0,
                        name: charset.clone(),
                    }
                })?;
                Ok(Segment::Variable {
                    charset: charset_name,
                    min: *min,
                    max: *max,
                })
            }
            SegmentDef::Opaque { value, charset } => {
                let value_bytes = value.as_bytes().to_vec();
                let charset_name = match charset {
                    Some(name) => CharsetName::from_name(name).ok_or_else(|| {
                        SegmentDefError::UnknownCharset {
                            index: 0,
                            name: name.clone(),
                        }
                    })?,
                    None => detect_charset_name(value_bytes.as_slice()),
                };
                Ok(Segment::Opaque {
                    value: value_bytes,
                    charset: charset_name,
                })
            }
        }
    }

    /// Convert to the serializable `SegmentDef` representation.
    pub(crate) fn to_def(&self) -> SegmentDef {
        match self {
            Segment::Literal(bytes) => SegmentDef::Literal {
                value: String::from_utf8_lossy(bytes).into_owned(),
            },
            Segment::Variable { charset, min, max } => SegmentDef::Variable {
                charset: charset.as_str().to_string(),
                min: *min,
                max: *max,
            },
            Segment::Opaque { value, charset } => SegmentDef::Opaque {
                value: String::from_utf8_lossy(value).into_owned(),
                charset: Some(charset.as_str().to_owned()),
            },
        }
    }
}

/// Result of a successful structural pattern match.
pub(crate) struct MatchCapture {
    /// Exclusive end position of the match in the payload.
    pub(crate) end: usize,
    /// Number of bytes consumed by each Variable segment, in segment order.
    /// Length equals the number of Variable segments in the matched pattern.
    pub(crate) variable_lengths: Vec<usize>,
}

/// Named character set for Variable segments.
///
/// Maps 1:1 to the charset names in SPEC.md §Patterns File line 90:
/// `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`, `digits`, `hex_lower`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CharsetName {
    Alphanumeric,
    UrlSafeBase64,
    UppercaseAlphanumeric,
    Digits,
    HexLower,
    Wide,
}

impl CharsetName {
    /// Resolve this charset name to the concrete byte set.
    pub(crate) fn resolve(&self) -> &'static crate::fake::Charset {
        match self {
            CharsetName::Alphanumeric => crate::fake::alphanumeric_ref(),
            CharsetName::UrlSafeBase64 => crate::fake::url_safe_base64_ref(),
            CharsetName::UppercaseAlphanumeric => crate::fake::uppercase_alphanumeric_ref(),
            CharsetName::Digits => crate::fake::digits_ref(),
            CharsetName::HexLower => crate::fake::hex_lower_ref(),
            CharsetName::Wide => crate::fake::wide_ref(),
        }
    }

    /// Parse a charset name string. Returns `None` for unrecognised names.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "alphanumeric" => Some(CharsetName::Alphanumeric),
            "url_safe_base64" => Some(CharsetName::UrlSafeBase64),
            "uppercase_alphanumeric" => Some(CharsetName::UppercaseAlphanumeric),
            "digits" => Some(CharsetName::Digits),
            "hex_lower" => Some(CharsetName::HexLower),
            "wide" => Some(CharsetName::Wide),
            _ => None,
        }
    }

    /// The canonical string name (matches TOML/CLI charset identifiers).
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CharsetName::Alphanumeric => "alphanumeric",
            CharsetName::UrlSafeBase64 => "url_safe_base64",
            CharsetName::UppercaseAlphanumeric => "uppercase_alphanumeric",
            CharsetName::Digits => "digits",
            CharsetName::HexLower => "hex_lower",
            CharsetName::Wide => "wide",
        }
    }
}

/// Serializable segment definition for the patterns file TOML format.
///
/// This is the data-transfer representation. The internally-tagged `type` field
/// maps to SPEC.md §Patterns File line 90:
/// `{ type = "literal", value = "..." }` or `{ type = "variable", charset = "...", min = N, max = N }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SegmentDef {
    /// A fixed byte string that must appear verbatim in this position.
    Literal {
        /// The literal byte string as a UTF-8 string.
        value: String,
    },
    /// A variable-length run of bytes from a named charset.
    Variable {
        /// Name of the charset (e.g. `"alphanumeric"`, `"url_safe_base64"`).
        charset: String,
        /// Minimum number of bytes in this segment (inclusive).
        min: usize,
        /// Maximum number of bytes in this segment (inclusive).
        max: usize,
    },
    /// Opaque segment: exact detection, charset-derived in fake.
    /// charset is optional; default is detected from value bytes.
    Opaque {
        /// The opaque byte string as a UTF-8 string (used for exact detection).
        value: String,
        /// Charset for fake generation. `None` defaults to the minimal charset detected from the value bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        charset: Option<String>,
    },
}

/// Validate a list of segment definitions per SPEC.md §Behavioral Invariants.
///
/// Returns `Ok(())` if all constraints are satisfied:
/// - At least one Variable segment (INV-30)
/// - All charset names are recognised
/// - All Variable segments have min <= max
/// - All Variable segments have min >= 1
pub(crate) fn validate_segment_defs(defs: &[SegmentDef]) -> Result<(), SegmentDefError> {
    let mut has_variable = false;
    match defs.first() {
        Some(SegmentDef::Literal { .. }) | Some(SegmentDef::Opaque { .. }) => {}
        Some(SegmentDef::Variable { .. }) => {
            return Err(SegmentDefError::FirstSegmentVariable);
        }
        None => {
            return Err(SegmentDefError::EmptySegmentList);
        }
    }
    for (i, def) in defs.iter().enumerate() {
        match def {
            SegmentDef::Variable { charset, min, max } => {
                has_variable = true;
                if CharsetName::from_name(charset).is_none() {
                    return Err(SegmentDefError::UnknownCharset {
                        index: i,
                        name: charset.clone(),
                    });
                }
                if min > max {
                    return Err(SegmentDefError::MinExceedsMax {
                        index: i,
                        min: *min,
                        max: *max,
                    });
                }
                if *min < 1 {
                    return Err(SegmentDefError::MinTooSmall { index: i });
                }
            }
            SegmentDef::Opaque {
                charset: Some(name),
                ..
            } if CharsetName::from_name(name).is_none() => {
                return Err(SegmentDefError::UnknownCharset {
                    index: i,
                    name: name.clone(),
                });
            }
            _ => {}
        }
    }
    if !has_variable {
        return Err(SegmentDefError::NoVariableSegment);
    }
    Ok(())
}

/// Detect the most appropriate `CharsetName` for a byte sequence.
///
/// Returns the minimal named charset that covers all bytes: Digits, HexLower,
/// UppercaseAlphanumeric, Alphanumeric, UrlSafeBase64, or Wide.
pub(crate) fn detect_charset_name(bytes: &[u8]) -> CharsetName {
    if bytes.iter().all(|&b| b.is_ascii_digit()) {
        CharsetName::Digits
    } else if bytes
        .iter()
        .all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        CharsetName::HexLower
    } else if bytes
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        CharsetName::UppercaseAlphanumeric
    } else if bytes.iter().all(|&b| b.is_ascii_alphanumeric()) {
        CharsetName::Alphanumeric
    } else if bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        CharsetName::UrlSafeBase64
    } else {
        CharsetName::Wide
    }
}

/// Errors returned by `validate_segment_defs` and `Segment::from_def`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SegmentDefError {
    /// The segment list contains no `Variable` segments.
    #[error("segment list must contain at least one variable segment")]
    NoVariableSegment,

    /// A `Variable` segment references an unrecognised charset name.
    #[error(
        "unknown charset \"{name}\" in segment {index}; valid: alphanumeric, url_safe_base64, uppercase_alphanumeric, digits, hex_lower, wide (variable and opaque segments)"
    )]
    UnknownCharset {
        /// Zero-based index of the offending segment.
        index: usize,
        /// The unrecognised charset name.
        name: String,
    },

    /// A `Variable` segment has `min > max`.
    #[error("segment {index}: min ({min}) must not exceed max ({max})")]
    MinExceedsMax {
        /// Zero-based index of the offending segment.
        index: usize,
        /// The `min` value that was given.
        min: usize,
        /// The `max` value that was given.
        max: usize,
    },

    /// A `Variable` segment has `min < 1`.
    #[error("segment {index}: min must be at least 1")]
    MinTooSmall {
        /// Zero-based index of the offending segment.
        index: usize,
    },

    /// The first segment is a Variable segment (must be Literal or Opaque; INV-30).
    #[error("first segment must be literal or opaque, not variable")]
    FirstSegmentVariable,

    /// The segment list is empty.
    #[error("segment list must not be empty")]
    EmptySegmentList,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charset_name_serde_round_trip() {
        let names = [
            (CharsetName::Alphanumeric, "\"alphanumeric\""),
            (CharsetName::UrlSafeBase64, "\"url_safe_base64\""),
            (
                CharsetName::UppercaseAlphanumeric,
                "\"uppercase_alphanumeric\"",
            ),
            (CharsetName::Digits, "\"digits\""),
            (CharsetName::HexLower, "\"hex_lower\""),
        ];
        for (variant, expected_json) in &names {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected_json);
            let parsed: CharsetName = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, variant);
        }
    }

    #[test]
    fn segment_def_tagged_serde() {
        let lit = SegmentDef::Literal {
            value: "sk-".into(),
        };
        let var = SegmentDef::Variable {
            charset: "alphanumeric".into(),
            min: 32,
            max: 48,
        };
        let json_lit = serde_json::to_string(&lit).unwrap();
        assert!(json_lit.contains("\"type\":\"literal\""));
        assert!(json_lit.contains("\"value\":\"sk-\""));
        let json_var = serde_json::to_string(&var).unwrap();
        assert!(json_var.contains("\"type\":\"variable\""));
        assert!(json_var.contains("\"charset\":\"alphanumeric\""));

        let round: SegmentDef = serde_json::from_str(&json_lit).unwrap();
        assert_eq!(round, lit);
        let round: SegmentDef = serde_json::from_str(&json_var).unwrap();
        assert_eq!(round, var);
    }

    #[test]
    fn validate_segment_defs_rejects_no_variable() {
        let defs = vec![SegmentDef::Literal {
            value: "prefix".into(),
        }];
        let err = validate_segment_defs(&defs).unwrap_err();
        assert!(err.to_string().contains("at least one variable segment"));
    }

    #[test]
    fn validate_segment_defs_rejects_unknown_charset() {
        let defs = vec![
            SegmentDef::Literal {
                value: "prefix_".into(),
            },
            SegmentDef::Variable {
                charset: "bogus".into(),
                min: 1,
                max: 10,
            },
        ];
        let err = validate_segment_defs(&defs).unwrap_err();
        assert!(err.to_string().contains("unknown charset \"bogus\""));
    }

    #[test]
    fn builtin_to_owned_conversion() {
        let builtin_lit = BuiltinSegment::Literal(b"sk-ant-");
        let owned = Segment::from(&builtin_lit);
        match owned {
            Segment::Literal(v) => assert_eq!(v, b"sk-ant-"),
            _ => panic!("expected Literal"),
        }

        let builtin_var = BuiltinSegment::Variable {
            charset: CharsetName::Alphanumeric,
            min: 10,
            max: 20,
        };
        let owned = Segment::from(&builtin_var);
        match owned {
            Segment::Variable { charset, min, max } => {
                assert_eq!(charset, CharsetName::Alphanumeric);
                assert_eq!(min, 10);
                assert_eq!(max, 20);
            }
            _ => panic!("expected Variable"),
        }
    }
}
