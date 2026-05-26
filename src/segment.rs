use serde::{Deserialize, Serialize};
/// A single structural element of a built-in Tier 1 pattern.
///
/// Patterns are sequences of segments matched left-to-right against the payload.
/// Detection records how many bytes each Variable segment consumed; that per-segment
/// length drives fake generation (SPEC.md §Tier 1).
///
/// This type uses static lifetime byte slices and function pointers; it is `Copy`
/// and used in `const` arrays. The owned runtime equivalent is [`Segment`].
#[derive(Clone, Copy)]
pub(crate) enum BuiltinSegment {
    /// Fixed bytes that must appear verbatim at the current position.
    /// Reproduced verbatim in every fake (INV-28).
    Literal(&'static [u8]),
    /// A run of bytes all belonging to `charset`, with length in `[min, max]`.
    /// Filled with CSPRNG bytes from `charset` in every fake (INV-29).
    Variable {
        charset: fn() -> Vec<u8>,
        min: usize,
        max: usize,
    },
}

/// Owned segment used at runtime by `Tier1Def`, `match_segments`, and `derive_fake_tier1_segments`.
///
/// Unlike `BuiltinSegment`, this type is heap-allocated and serializable. It is the runtime
/// representation for both built-in (converted from `BuiltinSegment` via `From`) and user-defined
/// Tier 1 patterns.
#[derive(Clone, Debug)]
pub(crate) enum Segment {
    Literal(Vec<u8>),
    Variable {
        charset: CharsetName,
        min: usize,
        max: usize,
    },
}

impl From<&BuiltinSegment> for Segment {
    fn from(b: &BuiltinSegment) -> Self {
        match b {
            BuiltinSegment::Literal(bytes) => Segment::Literal(bytes.to_vec()),
            BuiltinSegment::Variable { charset, min, max } => {
                let cs_bytes = charset();
                let charset_name = resolve_charset_fn_to_name(&cs_bytes);
                Segment::Variable {
                    charset: charset_name,
                    min: *min,
                    max: *max,
                }
            }
        }
    }
}

fn resolve_charset_fn_to_name(bytes: &[u8]) -> CharsetName {
    use crate::fake::charsets;
    let candidates = [
        (CharsetName::Alphanumeric, charsets::alphanumeric()),
        (CharsetName::UrlSafeBase64, charsets::url_safe_base64()),
        (
            CharsetName::UppercaseAlphanumeric,
            charsets::uppercase_alphanumeric(),
        ),
        (CharsetName::Digits, charsets::digits()),
        (CharsetName::HexLower, charsets::hex_lower()),
    ];
    for (name, cs) in &candidates {
        if cs.as_slice() == bytes {
            return name.clone();
        }
    }
    unreachable!("all built-in charsets must be known")
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
        }
    }
}

/// Result of a successful Tier 1 pattern match.
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CharsetName {
    Alphanumeric,
    UrlSafeBase64,
    UppercaseAlphanumeric,
    Digits,
    HexLower,
}

impl CharsetName {
    /// Resolve this charset name to the concrete byte set.
    pub(crate) fn resolve(&self) -> Vec<u8> {
        use crate::fake::charsets;
        match self {
            CharsetName::Alphanumeric => charsets::alphanumeric(),
            CharsetName::UrlSafeBase64 => charsets::url_safe_base64(),
            CharsetName::UppercaseAlphanumeric => charsets::uppercase_alphanumeric(),
            CharsetName::Digits => charsets::digits(),
            CharsetName::HexLower => charsets::hex_lower(),
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
    Literal {
        value: String,
    },
    Variable {
        charset: String,
        min: usize,
        max: usize,
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
    for (i, def) in defs.iter().enumerate() {
        if let SegmentDef::Variable { charset, min, max } = def {
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
    }
    if !has_variable {
        return Err(SegmentDefError::NoVariableSegment);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SegmentDefError {
    #[error("segment list must contain at least one variable segment")]
    NoVariableSegment,

    #[error(
        "unknown charset \"{name}\" in segment {index}; valid: alphanumeric, url_safe_base64, uppercase_alphanumeric, digits, hex_lower"
    )]
    UnknownCharset { index: usize, name: String },

    #[error("segment {index}: min ({min}) must not exceed max ({max})")]
    MinExceedsMax {
        index: usize,
        min: usize,
        max: usize,
    },

    #[error("segment {index}: min must be at least 1")]
    MinTooSmall { index: usize },
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
        let defs = vec![SegmentDef::Variable {
            charset: "bogus".into(),
            min: 1,
            max: 10,
        }];
        let err = validate_segment_defs(&defs).unwrap_err();
        assert!(err.to_string().contains("unknown charset \"bogus\""));
    }

    #[test]
    fn builtin_to_owned_conversion() {
        use crate::fake::charsets;
        let builtin_lit = BuiltinSegment::Literal(b"sk-ant-");
        let owned = Segment::from(&builtin_lit);
        match owned {
            Segment::Literal(v) => assert_eq!(v, b"sk-ant-"),
            _ => panic!("expected Literal"),
        }

        let builtin_var = BuiltinSegment::Variable {
            charset: charsets::alphanumeric,
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
