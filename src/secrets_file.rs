use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::segment::SegmentDef;
use crate::serde_helpers::{hex_32, hex_vec, hex_vec_option};
use crate::patterns::{self, Pattern, Tier1Def};
use crate::secrets::Tier2Pat;

/// Top-level patterns file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsFile {
    pub version: u64,
    pub tier1: Vec<PatternEntry>,
    pub tier2: Vec<SecretEntry>,
}

/// A Tier 1 entry: identifier, salt, and optional user-defined segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    pub identifier: String,
    #[serde(with = "hex_32")]
    pub salt: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<SegmentDef>>,
}

/// A Tier 2 entry: detection fingerprint + derivation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(with = "hex_vec")]
    pub start_fragment: Vec<u8>,
    #[serde(with = "hex_vec")]
    pub end_fragment: Vec<u8>,
    pub exact_length: usize,
    #[serde(with = "hex_32")]
    pub hmac_salt: [u8; 32],
    #[serde(with = "hex_32")]
    pub hmac_digest: [u8; 32],
    pub preserve_prefix: usize,
    pub preserve_suffix: usize,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_vec_option"
    )]
    pub charset: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretsFileError {
    #[error("{0}")]
    Toml(String),

    #[error("invalid UTF-8 in patterns file")]
    InvalidUtf8,

    #[error("unsupported patterns file version: {found} (expected 2)")]
    UnsupportedVersion { found: u64 },

    #[error("missing Tier 1 class: {class}")]
    MissingTier1Class { class: String },

    #[error("invalid Tier 2 entry at index {index}: {reason}")]
    InvalidTier2 { index: usize, reason: String },

    #[error("wrong pattern type: expected Tier 2")]
    WrongPatternType,

    #[error("duplicate Tier 1 identifier: {identifier}")]
    DuplicateIdentifier { identifier: String },

    #[error("duplicate Tier 2 label: {label}")]
    DuplicateLabel { label: String },

    #[error("invalid segment definition: {0}")]
    InvalidSegment(#[from] crate::segment::SegmentDefError),

    #[error("user-defined Tier 1 entry \"{identifier}\" requires a segments field")]
    MissingSegments { identifier: String },
}

impl SecretsFile {
    /// Create an empty patterns file (version 2, no entries).
    pub fn new() -> Self {
        Self {
            version: 2,
            tier1: Vec::new(),
            tier2: Vec::new(),
        }
    }

    /// Serialize to TOML bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, SecretsFileError> {
        let s = toml::to_string_pretty(self).map_err(|e| SecretsFileError::Toml(e.to_string()))?;
        Ok(s.into_bytes())
    }

    /// Deserialize from TOML bytes with validation.
    pub fn deserialize(data: &[u8]) -> Result<Self, SecretsFileError> {
        let s = std::str::from_utf8(data).map_err(|_| SecretsFileError::InvalidUtf8)?;
        let file: SecretsFile =
            toml::from_str(s).map_err(|e| SecretsFileError::Toml(e.to_string()))?;
        file.validate()?;
        Ok(file)
    }

    fn validate(&self) -> Result<(), SecretsFileError> {
        if self.version != 2 {
            return Err(SecretsFileError::UnsupportedVersion {
                found: self.version,
            });
        }

        let mut seen_ids = std::collections::HashSet::new();
        for entry in &self.tier1 {
            if !seen_ids.insert(&entry.identifier) {
                return Err(SecretsFileError::DuplicateIdentifier {
                    identifier: entry.identifier.clone(),
                });
            }

            if let Some(ref segments) = entry.segments {
                crate::segment::validate_segment_defs(segments)?;
            }
        }

        let mut seen_labels = std::collections::HashSet::new();
        for (index, entry) in self.tier2.iter().enumerate() {
            if let Some(ref label) = entry.label {
                if !seen_labels.insert(label) {
                    return Err(SecretsFileError::DuplicateLabel {
                        label: label.clone(),
                    });
                }
            }

            if entry.exact_length == 0 {
                return Err(SecretsFileError::InvalidTier2 {
                    index,
                    reason: "exact_length must not be zero".into(),
                });
            }
            if entry.start_fragment.is_empty() {
                return Err(SecretsFileError::InvalidTier2 {
                    index,
                    reason: "start_fragment must not be empty".into(),
                });
            }
            if entry.end_fragment.is_empty() {
                return Err(SecretsFileError::InvalidTier2 {
                    index,
                    reason: "end_fragment must not be empty".into(),
                });
            }
            if let Some(ref cs) = entry.charset {
                if cs.is_empty() {
                    return Err(SecretsFileError::InvalidTier2 {
                        index,
                        reason: "charset must not be empty when present".into(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Reconstruct `Vec<Pattern>` from this patterns file.
    ///
    /// For each Tier 1 entry:
    /// - If `segments` is present, use them (overrides any compiled-in definition).
    /// - If `segments` is absent and the identifier matches a built-in, use the compiled-in
    ///   definition.
    /// - If `segments` is absent and the identifier is not a built-in, return
    ///   `MissingSegments`.
    ///
    /// Built-in identifiers absent from the file are silently skipped (INV-32).
    pub fn into_patterns(self) -> Result<Vec<Pattern>, SecretsFileError> {
        use crate::segment::Segment;

        let builtin_defs = patterns::all_defs();
        let mut patterns = Vec::new();

        for entry in &self.tier1 {
            let builtin = builtin_defs
                .iter()
                .find(|d| d.identifier == entry.identifier);

            let segments: Arc<[Segment]> = match (&entry.segments, builtin) {
                (Some(seg_defs), _) => {
                    let segs: Result<Vec<Segment>, _> =
                        seg_defs.iter().map(Segment::from_def).collect();
                    segs?.into()
                }
                (None, Some(def)) => def.segments.clone(),
                (None, None) => {
                    return Err(SecretsFileError::MissingSegments {
                        identifier: entry.identifier.clone(),
                    });
                }
            };

            patterns.push(Pattern::Tier1(Tier1Def {
                identifier: entry.identifier.clone(),
                segments,
                salt: entry.salt,
            }));
        }

        for entry in self.tier2 {
            let charset = match entry.charset {
                Some(cs) => cs,
                None => crate::fake::charsets::wide(),
            };

            let pat = Tier2Pat {
                start_fragment: entry.start_fragment,
                end_fragment: entry.end_fragment,
                exact_length: entry.exact_length,
                hmac_salt: entry.hmac_salt,
                hmac_digest: entry.hmac_digest,
                preserve_prefix: entry.preserve_prefix,
                preserve_suffix: entry.preserve_suffix,
                charset,
            };

            patterns.push(Pattern::Tier2(Arc::new(pat)));
        }

        Ok(patterns)
    }

    /// Extract a Tier 2 entry from a Pattern and append it to this file.
    /// Returns error if the pattern is not Tier 2 or if the label is a duplicate.
    pub fn add_secret_pattern(
        &mut self,
        pattern: &Pattern,
        label: Option<String>,
    ) -> Result<(), SecretsFileError> {
        match pattern {
            Pattern::Tier2(arc) => {
                if let Some(ref l) = label {
                    let duplicate = self.tier2.iter().any(|e| e.label.as_deref() == Some(l));
                    if duplicate {
                        return Err(SecretsFileError::DuplicateLabel { label: l.clone() });
                    }
                }

                let p = arc.as_ref();
                let charset = if p.charset == crate::fake::charsets::wide() {
                    None
                } else {
                    Some(p.charset.clone())
                };

                self.tier2.push(SecretEntry {
                    label,
                    start_fragment: p.start_fragment.clone(),
                    end_fragment: p.end_fragment.clone(),
                    exact_length: p.exact_length,
                    hmac_salt: p.hmac_salt,
                    hmac_digest: p.hmac_digest,
                    preserve_prefix: p.preserve_prefix,
                    preserve_suffix: p.preserve_suffix,
                    charset,
                });

                Ok(())
            }
            _ => Err(SecretsFileError::WrongPatternType),
        }
    }

    /// Add a user-defined Tier 1 entry to this patterns file.
    ///
    /// The caller provides a pre-generated salt. Validates:
    /// - Identifier uniqueness (INV-31)
    /// - Segment list validity (INV-30: at least one Variable, valid charsets, min <= max)
    pub fn add_tier1_entry(
        &mut self,
        identifier: String,
        segments: Vec<SegmentDef>,
        salt: [u8; 32],
    ) -> Result<(), SecretsFileError> {
        let duplicate = self.tier1.iter().any(|e| e.identifier == identifier);
        if duplicate {
            return Err(SecretsFileError::DuplicateIdentifier { identifier });
        }

        crate::segment::validate_segment_defs(&segments)?;

        self.tier1.push(PatternEntry {
            identifier,
            salt,
            segments: Some(segments),
        });

        Ok(())
    }

    /// Fill in salts for any built-in Tier 1 classes not already in the file.
    /// Uses OsRng for fresh salt generation.
    pub fn generate_missing_tier1_salts(&mut self) {
        use rand::RngCore;

        for def in patterns::all_defs() {
            let already_present = self.tier1.iter().any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                self.tier1.push(PatternEntry {
                    identifier: def.identifier.clone(),
                    salt,
                    segments: None,
                });
            }
        }
    }

    /// Fill in salts and segment definitions for any built-in Tier 1 classes not in the file.
    /// Unlike `generate_missing_tier1_salts`, this also embeds the compiled-in segment
    /// definitions so the output file is self-describing (used by `init`).
    pub fn generate_missing_tier1_salts_with_segments(&mut self) {
        use rand::RngCore;

        for def in patterns::all_defs() {
            let already_present = self.tier1.iter().any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);

                let seg_defs: Vec<SegmentDef> = def.segments.iter().map(|s| s.to_def()).collect();

                self.tier1.push(PatternEntry {
                    identifier: def.identifier.clone(),
                    salt,
                    segments: Some(seg_defs),
                });
            }
        }
    }

    /// Check if an identifier matches a compiled-in Tier 1 definition.
    pub fn is_builtin_identifier(identifier: &str) -> bool {
        patterns::all_defs().iter().any(|d| d.identifier == identifier)
    }
}

impl Default for SecretsFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_serialize_deserialize() {
        let mut pf = SecretsFile::new();
        pf.generate_missing_tier1_salts();
        let bytes = pf.serialize().unwrap();
        let pf2 = SecretsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.version, 2);
        assert_eq!(pf2.tier1.len(), 15);
        let orig_salt = pf
            .tier1
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap()
            .salt;
        let deser_salt = pf2
            .tier1
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap()
            .salt;
        assert_eq!(orig_salt, deser_salt);
    }

    #[test]
    fn test_version_rejection() {
        let data = b"version = 1\ntier1 = []\ntier2 = []\n";
        let err = SecretsFile::deserialize(data).unwrap_err();
        assert!(matches!(
            err,
            SecretsFileError::UnsupportedVersion { found: 1 }
        ));
    }

    #[test]
    fn test_empty_tier1_into_patterns_succeeds() {
        let pf = SecretsFile {
            version: 2,
            tier1: vec![],
            tier2: vec![],
        };
        let patterns = pf.into_patterns().unwrap();
        assert_eq!(patterns.len(), 0);
    }

    #[test]
    fn test_generate_missing_fills_all_fifteen() {
        let mut pf = SecretsFile::new();
        pf.generate_missing_tier1_salts();
        assert_eq!(pf.tier1.len(), 15);
        for def in crate::patterns::all_defs() {
            assert!(pf.tier1.iter().any(|e| e.identifier == def.identifier));
        }
    }

    #[test]
    fn test_generate_missing_does_not_overwrite() {
        let custom_salt = [0xAB; 32];
        let mut pf = SecretsFile::new();
        pf.tier1.push(PatternEntry {
            identifier: "anthropic".into(),
            salt: custom_salt,
            segments: None,
        });
        pf.generate_missing_tier1_salts();
        let entry = pf
            .tier1
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap();
        assert_eq!(entry.salt, custom_salt);
    }

    #[test]
    fn test_invalid_tier2_exact_length_zero() {
        let data = br#"
version = 2
tier1 = []

[[tier2]]
start_fragment = "aabb"
end_fragment = "ccdd"
exact_length = 0
hmac_salt = "0000000000000000000000000000000000000000000000000000000000000000"
hmac_digest = "0000000000000000000000000000000000000000000000000000000000000000"
preserve_prefix = 0
preserve_suffix = 0
"#;
        let err = SecretsFile::deserialize(data).unwrap_err();
        assert!(err.to_string().contains("exact_length"), "error: {err}");
    }

    #[test]
    fn test_invalid_tier2_empty_start_fragment() {
        let data = br#"
version = 2
tier1 = []

[[tier2]]
start_fragment = ""
end_fragment = "ccdd"
exact_length = 32
hmac_salt = "0000000000000000000000000000000000000000000000000000000000000000"
hmac_digest = "0000000000000000000000000000000000000000000000000000000000000000"
preserve_prefix = 0
preserve_suffix = 0
"#;
        let err = SecretsFile::deserialize(data).unwrap_err();
        assert!(err.to_string().contains("start_fragment"), "error: {err}");
    }

    #[test]
    fn test_tier2_with_charset_round_trips() {
        use crate::{SecretOptions, register_with_options};
        let secret = b"my-custom-api-token-round-trip-test";
        let opts = SecretOptions {
            preserve_prefix: 3,
            preserve_suffix: 0,
            restrict_charset: false,
        };
        let pat = register_with_options(secret, &opts).unwrap();
        let mut pf = SecretsFile::new();
        pf.add_secret_pattern(&pat, None).unwrap();
        let bytes = pf.serialize().unwrap();
        let pf2 = SecretsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.tier2.len(), 1);
    }

    #[test]
    fn test_tier2_without_charset_uses_wide() {
        use crate::{SecretOptions, register_with_options};
        let secret = b"my-custom-api-token-wide-charset-test";
        let opts = SecretOptions::default();
        let pat = register_with_options(secret, &opts).unwrap();
        let mut pf = SecretsFile::new();
        pf.add_secret_pattern(&pat, None).unwrap();
        assert!(pf.tier2[0].charset.is_none());
    }

    #[test]
    fn test_duplicate_identifier_rejected() {
        // tier2 must come before [[tier1]] sections in TOML
        let pf_data = br#"
version = 2
tier2 = []

[[tier1]]
identifier = "my_pattern"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [{ type = "variable", charset = "alphanumeric", min = 10, max = 10 }]

[[tier1]]
identifier = "my_pattern"
salt = "0000000000000000000000000000000000000000000000000000000000000002"
segments = [{ type = "variable", charset = "digits", min = 5, max = 5 }]
"#;
        let err = SecretsFile::deserialize(pf_data).unwrap_err();
        assert!(err.to_string().contains("duplicate Tier 1 identifier"));
    }

    #[test]
    fn test_duplicate_label_rejected() {
        let pf_data = br#"
version = 2
tier1 = []

[[tier2]]
label = "my-secret"
start_fragment = "aabbccdd"
end_fragment = "eeff0011"
exact_length = 32
hmac_salt = "0000000000000000000000000000000000000000000000000000000000000000"
hmac_digest = "0000000000000000000000000000000000000000000000000000000000000000"
preserve_prefix = 0
preserve_suffix = 0

[[tier2]]
label = "my-secret"
start_fragment = "11223344"
end_fragment = "55667788"
exact_length = 16
hmac_salt = "0000000000000000000000000000000000000000000000000000000000000001"
hmac_digest = "0000000000000000000000000000000000000000000000000000000000000001"
preserve_prefix = 0
preserve_suffix = 0
"#;
        let err = SecretsFile::deserialize(pf_data).unwrap_err();
        assert!(err.to_string().contains("duplicate Tier 2 label"));
    }

    #[test]
    fn test_version_1_error_message() {
        let data = b"version = 1\ntier1 = []\ntier2 = []\n";
        let err = SecretsFile::deserialize(data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported"), "error: {msg}");
        assert!(msg.contains("expected 2"), "error: {msg}");
    }

    #[test]
    fn test_user_defined_tier1_into_patterns() {
        use crate::segment::SegmentDef;
        let pf = SecretsFile {
            version: 2,
            tier1: vec![PatternEntry {
                identifier: "custom".into(),
                salt: [0xAA; 32],
                segments: Some(vec![
                    SegmentDef::Literal {
                        value: "tok_".into(),
                    },
                    SegmentDef::Variable {
                        charset: "alphanumeric".into(),
                        min: 20,
                        max: 20,
                    },
                ]),
            }],
            tier2: vec![],
        };
        let patterns = pf.into_patterns().unwrap();
        assert_eq!(patterns.len(), 1);
    }

    #[test]
    fn test_user_defined_without_segments_errors() {
        let pf = SecretsFile {
            version: 2,
            tier1: vec![PatternEntry {
                identifier: "unknown_thing".into(),
                salt: [0u8; 32],
                segments: None,
            }],
            tier2: vec![],
        };
        let err = pf
            .into_patterns()
            .err()
            .expect("expected MissingSegments error");
        assert!(err.to_string().contains("requires a segments field"));
    }
}
