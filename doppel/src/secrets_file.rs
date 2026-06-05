//! Patterns file serialization and deserialization (TOML, version 2).
//!
//! The [`SecretsFile`] type is the on-disk representation of structural patterns
//! and registered secrets. Use [`SecretsFile::deserialize`] to load and
//! [`SecretsFile::to_patterns`] to obtain [`Pattern`] values for [`crate::swap`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::patterns::{self, Pattern, StructuralDef};
use crate::secrets::RegisteredPat;
use crate::segment::SegmentDef;
use crate::serde_helpers::{hex_32, hex_vec, hex_vec_option};

/// Top-level patterns file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsFile {
    /// File format version. Must be `2`; other values are rejected by [`SecretsFile::deserialize`].
    pub version: u64,
    /// Structural pattern entries, one per detected secret class.
    pub structural: Vec<PatternEntry>,
    /// Registered secret entries, one per registered secret.
    pub registered: Vec<SecretEntry>,
}

/// A structural pattern entry: identifier, salt, and optional user-defined segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    /// Unique string identifier for this pattern class (e.g. `"anthropic"`).
    pub identifier: String,
    /// 32-byte salt used for fake derivation; must be unique per pattern.
    #[serde(with = "hex_32")]
    pub salt: [u8; 32],
    /// Optional segment definitions; overrides built-in segments when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<SegmentDef>>,
}

/// A registered secret entry: detection fingerprint + derivation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Optional human-readable label, unique within the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// First bytes of the original secret used as a detection anchor.
    #[serde(with = "hex_vec")]
    pub start_fragment: Vec<u8>,
    /// Last bytes of the original secret used as a detection anchor.
    #[serde(with = "hex_vec")]
    pub end_fragment: Vec<u8>,
    /// Exact byte length of the original secret.
    pub exact_length: usize,
    /// Unique random salt used for HMAC-SHA256 verification.
    #[serde(with = "hex_32")]
    pub hmac_salt: [u8; 32],
    /// HMAC-SHA256 digest of the original secret under `hmac_salt`.
    #[serde(with = "hex_32")]
    pub hmac_digest: [u8; 32],
    /// Number of leading bytes preserved verbatim in the fake.
    pub preserve_prefix: usize,
    /// Number of trailing bytes preserved verbatim in the fake.
    pub preserve_suffix: usize,
    /// Optional byte set for fake variable bytes; `None` means the wide default.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_vec_option"
    )]
    pub charset: Option<Vec<u8>>,
}

/// Errors returned by [`SecretsFile`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretsFileError {
    /// TOML serialization or deserialization error.
    #[error("{0}")]
    Toml(String),

    /// The patterns file bytes are not valid UTF-8.
    #[error("invalid UTF-8 in patterns file")]
    InvalidUtf8,

    /// The `version` field is not `2`.
    #[error("unsupported patterns file version: {found} (expected 2)")]
    UnsupportedVersion {
        /// The version value that was found.
        found: u64,
    },

    /// A structural pattern class referenced in the file is missing.
    #[error("missing structural pattern class: {class}")]
    MissingStructuralClass {
        /// The identifier that was not found.
        class: String,
    },

    /// A registered secret entry contains an invalid field value.
    #[error("invalid registered secret entry at index {index}: {reason}")]
    InvalidRegistered {
        /// Zero-based index of the invalid entry.
        index: usize,
        /// Description of the invalid field.
        reason: String,
    },

    /// The supplied `Pattern` was not a registered secret.
    #[error("wrong pattern type: expected registered secret")]
    WrongPatternType,

    /// Two structural pattern entries share the same identifier.
    #[error("duplicate structural pattern identifier: {identifier}")]
    DuplicateIdentifier {
        /// The duplicated identifier.
        identifier: String,
    },

    /// Two registered secret entries share the same label.
    #[error("duplicate registered secret label: {label}")]
    DuplicateLabel {
        /// The duplicated label.
        label: String,
    },

    /// A segment definition in a structural pattern is malformed.
    #[error("invalid segment definition: {0}")]
    InvalidSegment(#[from] crate::segment::SegmentDefError),

    /// A user-defined structural pattern entry is missing its `segments` field.
    #[error("user-defined structural pattern \"{identifier}\" requires a segments field")]
    MissingSegments {
        /// The identifier of the entry missing segments.
        identifier: String,
    },
}

impl SecretsFile {
    /// Create an empty patterns file (version 2, no entries).
    pub fn new() -> Self {
        Self {
            version: 2,
            structural: Vec::new(),
            registered: Vec::new(),
        }
    }

    /// Serialize to TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsFileError::Toml`] if serialization fails.
    pub fn serialize(&self) -> Result<Vec<u8>, SecretsFileError> {
        let s = toml::to_string_pretty(self).map_err(|e| SecretsFileError::Toml(e.to_string()))?;
        Ok(s.into_bytes())
    }

    /// Deserialize from TOML bytes with validation.
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::InvalidUtf8`] if `data` is not valid UTF-8.
    /// - [`SecretsFileError::Toml`] if TOML parsing fails.
    /// - [`SecretsFileError::UnsupportedVersion`] if `version` is not `2`.
    /// - [`SecretsFileError::DuplicateIdentifier`] if two structural entries share an identifier.
    /// - [`SecretsFileError::DuplicateLabel`] if two registered entries share a label.
    /// - [`SecretsFileError::InvalidRegistered`] if a registered entry has an invalid field.
    /// - [`SecretsFileError::InvalidSegment`] if a segment definition is malformed.
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
        for entry in &self.structural {
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
        for (index, entry) in self.registered.iter().enumerate() {
            if let Some(ref label) = entry.label {
                if !seen_labels.insert(label) {
                    return Err(SecretsFileError::DuplicateLabel {
                        label: label.clone(),
                    });
                }
            }

            if entry.exact_length == 0 {
                return Err(SecretsFileError::InvalidRegistered {
                    index,
                    reason: "exact_length must not be zero".into(),
                });
            }
            if entry.start_fragment.is_empty() {
                return Err(SecretsFileError::InvalidRegistered {
                    index,
                    reason: "start_fragment must not be empty".into(),
                });
            }
            if entry.end_fragment.is_empty() {
                return Err(SecretsFileError::InvalidRegistered {
                    index,
                    reason: "end_fragment must not be empty".into(),
                });
            }
            if let Some(ref cs) = entry.charset {
                if cs.is_empty() {
                    return Err(SecretsFileError::InvalidRegistered {
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
    /// For each structural pattern entry:
    /// - If `segments` is present, use them (overrides any compiled-in definition).
    /// - If `segments` is absent and the identifier matches a built-in, use the compiled-in
    ///   definition.
    /// - If `segments` is absent and the identifier is not a built-in, return
    ///   `MissingSegments`.
    ///
    /// Built-in identifiers absent from the file are silently skipped (INV-32).
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::UnsupportedVersion`] if the version field is not `2`.
    /// - [`SecretsFileError::DuplicateIdentifier`] if any identifier appears more than once.
    /// - [`SecretsFileError::MissingSegments`] if a non-built-in identifier has no `segments` field.
    /// - [`SecretsFileError::InvalidSegment`] if a segment definition is malformed.
    pub fn to_patterns(&self) -> Result<Vec<Pattern>, SecretsFileError> {
        self.validate()?;
        use crate::segment::Segment;

        let builtin_defs = patterns::all_defs();
        let mut patterns = Vec::new();

        for entry in &self.structural {
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

            patterns.push(Pattern::Structural(StructuralDef {
                identifier: entry.identifier.clone(),
                segments,
                salt: entry.salt,
            }));
        }

        for entry in &self.registered {
            let charset = match &entry.charset {
                Some(cs) => cs.clone(),
                None => crate::fake::charsets::wide(),
            };

            let pat = RegisteredPat {
                start_fragment: entry.start_fragment.clone(),
                end_fragment: entry.end_fragment.clone(),
                exact_length: entry.exact_length,
                hmac_salt: entry.hmac_salt,
                hmac_digest: entry.hmac_digest,
                preserve_prefix: entry.preserve_prefix,
                preserve_suffix: entry.preserve_suffix,
                charset,
            };

            patterns.push(Pattern::Registered(Arc::new(pat)));
        }

        Ok(patterns)
    }

    /// Extract a registered secret entry from a Pattern and append it to this file.
    /// Returns error if the pattern is not a registered secret or if the label is a duplicate.
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::WrongPatternType`] if `pattern` is not a registered secret.
    /// - [`SecretsFileError::DuplicateLabel`] if `label` is already present in the file.
    pub fn add_secret_pattern(
        &mut self,
        pattern: &Pattern,
        label: Option<String>,
    ) -> Result<(), SecretsFileError> {
        match pattern {
            Pattern::Registered(arc) => {
                if let Some(ref l) = label {
                    let duplicate = self
                        .registered
                        .iter()
                        .any(|e| e.label.as_deref() == Some(l));
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

                self.registered.push(SecretEntry {
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

    /// Add a user-defined structural pattern to this patterns file.
    ///
    /// The caller provides a pre-generated salt. Validates:
    /// - Identifier uniqueness (INV-31)
    /// - Segment list validity (INV-30: at least one Variable, valid charsets, min <= max)
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::DuplicateIdentifier`] if `identifier` already exists.
    /// - [`SecretsFileError::InvalidSegment`] if the segment list fails validation.
    pub fn add_structural_entry(
        &mut self,
        identifier: String,
        segments: Vec<SegmentDef>,
        salt: [u8; 32],
    ) -> Result<(), SecretsFileError> {
        let duplicate = self.structural.iter().any(|e| e.identifier == identifier);
        if duplicate {
            return Err(SecretsFileError::DuplicateIdentifier { identifier });
        }

        crate::segment::validate_segment_defs(&segments)?;

        self.structural.push(PatternEntry {
            identifier,
            salt,
            segments: Some(segments),
        });

        Ok(())
    }

    /// Fill in salts for any built-in structural pattern classes not already in the file.
    /// Uses OsRng for fresh salt generation.
    pub fn generate_missing_structural_salts(&mut self) {
        use rand::RngCore;

        for def in patterns::all_defs() {
            let already_present = self
                .structural
                .iter()
                .any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                self.structural.push(PatternEntry {
                    identifier: def.identifier.clone(),
                    salt,
                    segments: None,
                });
            }
        }
    }

    /// Fill in salts and segment definitions for any built-in structural pattern classes not in the file.
    /// Unlike `generate_missing_structural_salts`, this also embeds the compiled-in segment
    /// definitions so the output file is self-describing (used by `init`).
    pub fn generate_missing_structural_salts_with_segments(&mut self) {
        use rand::RngCore;

        for def in patterns::all_defs() {
            let already_present = self
                .structural
                .iter()
                .any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);

                let seg_defs: Vec<SegmentDef> = def.segments.iter().map(|s| s.to_def()).collect();

                self.structural.push(PatternEntry {
                    identifier: def.identifier.clone(),
                    salt,
                    segments: Some(seg_defs),
                });
            }
        }
    }

    /// Check if an identifier matches a compiled-in structural pattern definition.
    pub fn is_builtin_identifier(identifier: &str) -> bool {
        patterns::all_defs()
            .iter()
            .any(|d| d.identifier == identifier)
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
        pf.generate_missing_structural_salts();
        let bytes = pf.serialize().unwrap();
        let pf2 = SecretsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.version, 2);
        assert_eq!(pf2.structural.len(), 15);
        let orig_salt = pf
            .structural
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap()
            .salt;
        let deser_salt = pf2
            .structural
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap()
            .salt;
        assert_eq!(orig_salt, deser_salt);
    }

    #[test]
    fn test_version_rejection() {
        let data = b"version = 1\nstructural = []\nregistered = []\n";
        let err = SecretsFile::deserialize(data).unwrap_err();
        assert!(matches!(
            err,
            SecretsFileError::UnsupportedVersion { found: 1 }
        ));
    }

    #[test]
    fn test_empty_structural_into_patterns_succeeds() {
        let pf = SecretsFile {
            version: 2,
            structural: vec![],
            registered: vec![],
        };
        let patterns = pf.to_patterns().unwrap();
        assert_eq!(patterns.len(), 0);
    }

    #[test]
    fn test_generate_missing_fills_all_fifteen() {
        let mut pf = SecretsFile::new();
        pf.generate_missing_structural_salts();
        assert_eq!(pf.structural.len(), 15);
        for def in crate::patterns::all_defs() {
            assert!(pf.structural.iter().any(|e| e.identifier == def.identifier));
        }
    }

    #[test]
    fn test_generate_missing_does_not_overwrite() {
        let custom_salt = [0xAB; 32];
        let mut pf = SecretsFile::new();
        pf.structural.push(PatternEntry {
            identifier: "anthropic".into(),
            salt: custom_salt,
            segments: None,
        });
        pf.generate_missing_structural_salts();
        let entry = pf
            .structural
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap();
        assert_eq!(entry.salt, custom_salt);
    }

    #[test]
    fn test_invalid_registered_exact_length_zero() {
        let data = br#"
version = 2
structural = []

[[registered]]
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
    fn test_invalid_registered_empty_start_fragment() {
        let data = br#"
version = 2
structural = []

[[registered]]
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
    fn test_registered_with_charset_round_trips() {
        use crate::{SecretOptions, register_with_options};
        let secret = b"my-custom-api-token-round-trip-test";
        let opts = SecretOptions {
            preserve_prefix: 3,
            preserve_suffix: 0,
            restrict_charset: false,
            ..Default::default()
        };
        let pat = register_with_options(secret, &opts).unwrap();
        let mut pf = SecretsFile::new();
        pf.add_secret_pattern(&pat, None).unwrap();
        let bytes = pf.serialize().unwrap();
        let pf2 = SecretsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.registered.len(), 1);
    }

    #[test]
    fn test_registered_without_charset_uses_wide() {
        use crate::{SecretOptions, register_with_options};
        let secret = b"my-custom-api-token-wide-charset-test";
        let opts = SecretOptions::default();
        let pat = register_with_options(secret, &opts).unwrap();
        let mut pf = SecretsFile::new();
        pf.add_secret_pattern(&pat, None).unwrap();
        assert!(pf.registered[0].charset.is_none());
    }

    #[test]
    fn test_duplicate_identifier_rejected() {
        // registered sections must come before [[structural]] sections in TOML
        let pf_data = br#"
version = 2
registered = []

[[structural]]
identifier = "my_pattern"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [{ type = "variable", charset = "alphanumeric", min = 10, max = 10 }]

[[structural]]
identifier = "my_pattern"
salt = "0000000000000000000000000000000000000000000000000000000000000002"
segments = [{ type = "variable", charset = "digits", min = 5, max = 5 }]
"#;
        let err = SecretsFile::deserialize(pf_data).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate structural pattern identifier")
        );
    }

    #[test]
    fn test_duplicate_label_rejected() {
        let pf_data = br#"
version = 2
structural = []

[[registered]]
label = "my-secret"
start_fragment = "aabbccdd"
end_fragment = "eeff0011"
exact_length = 32
hmac_salt = "0000000000000000000000000000000000000000000000000000000000000000"
hmac_digest = "0000000000000000000000000000000000000000000000000000000000000000"
preserve_prefix = 0
preserve_suffix = 0

[[registered]]
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
        assert!(
            err.to_string()
                .contains("duplicate registered secret label")
        );
    }

    #[test]
    fn test_version_1_error_message() {
        let data = b"version = 1\nstructural = []\nregistered = []\n";
        let err = SecretsFile::deserialize(data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported"), "error: {msg}");
        assert!(msg.contains("expected 2"), "error: {msg}");
    }

    #[test]
    fn test_user_defined_structural_into_patterns() {
        use crate::segment::SegmentDef;
        let pf = SecretsFile {
            version: 2,
            structural: vec![PatternEntry {
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
            registered: vec![],
        };
        let patterns = pf.to_patterns().unwrap();
        assert_eq!(patterns.len(), 1);
    }

    #[test]
    fn test_user_defined_without_segments_errors() {
        let pf = SecretsFile {
            version: 2,
            structural: vec![PatternEntry {
                identifier: "unknown_thing".into(),
                salt: [0u8; 32],
                segments: None,
            }],
            registered: vec![],
        };
        let err = pf
            .to_patterns()
            .err()
            .expect("expected MissingSegments error");
        assert!(err.to_string().contains("requires a segments field"));
    }
}
