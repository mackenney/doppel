//! Patterns file serialization and deserialization (TOML, version 3).
//!
//! The [`SecretsFile`] type is the on-disk representation of unified patterns.
//! Use [`SecretsFile::deserialize`] to load and [`SecretsFile::to_patterns`]
//! to obtain [`Pattern`] values for [`crate::swap`].

use serde::{Deserialize, Serialize};

use crate::patterns::{self, Pattern};
use crate::segment::{Segment, SegmentDef};
use crate::serde_helpers::{hex_32, hex_vec_32};

/// Top-level patterns file structure (version 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsFile {
    /// File format version. Must be `3`; other values are rejected by [`SecretsFile::deserialize`].
    pub version: u64,
    /// Unified pattern entries (family and instance patterns).
    #[serde(default)]
    pub pattern: Vec<PatternEntry>,
}

/// On-disk TOML (version 3) serialization form for a single pattern entry.
/// Holds an identifier, 32-byte salt, optional HMAC digests, and ordered segment definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    /// Unique string identifier for this pattern (e.g. `"anthropic"`, `"prod-db-password"`).
    pub identifier: String,
    /// 32-byte salt for HMAC computation and fake derivation; hex-encoded.
    #[serde(with = "hex_32")]
    pub salt: [u8; 32],
    /// HMAC digests; empty/absent = family pattern, non-empty = instance/group pattern.
    /// Each digest is 64 lowercase hex characters (32 bytes).
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "hex_vec_32")]
    pub digests: Vec<[u8; 32]>,
    /// Ordered segment definitions defining detection structure and fake generation.
    pub segments: Vec<SegmentDef>,
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

    /// The `version` field is not `3`.
    #[error("unsupported patterns file version: {found} (expected 3)")]
    UnsupportedVersion {
        /// The version value that was found.
        found: u64,
    },

    /// Two pattern entries share the same identifier.
    #[error("duplicate pattern identifier: {identifier}")]
    DuplicateIdentifier {
        /// The duplicated identifier.
        identifier: String,
    },

    /// A segment definition in a pattern is malformed.
    #[error("invalid segment in pattern '{identifier}': {reason}")]
    InvalidSegment {
        /// The pattern identifier.
        identifier: String,
        /// Description of the problem.
        reason: String,
    },

    /// The supplied `Pattern` was not an instance pattern (digests were empty).
    #[error("wrong pattern type: expected instance pattern with non-empty digests")]
    WrongPatternType,

    /// No pattern with the given identifier was found.
    #[error("no pattern with identifier '{identifier}'")]
    NotFound {
        /// The identifier that was looked up.
        identifier: String,
    },
}

impl SecretsFile {
    /// Create an empty patterns file (version 3, no entries).
    pub fn new() -> Self {
        Self {
            version: 3,
            pattern: Vec::new(),
        }
    }

    /// Serialize to TOML version 3 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsFileError::Toml`] if serialization fails.
    pub fn serialize(&self) -> Result<Vec<u8>, SecretsFileError> {
        let s = toml::to_string_pretty(self).map_err(|e| SecretsFileError::Toml(e.to_string()))?;
        Ok(s.into_bytes())
    }

    /// Deserialize from TOML version 3 bytes with validation.
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::InvalidUtf8`] if `data` is not valid UTF-8.
    /// - [`SecretsFileError::Toml`] if TOML parsing fails.
    /// - [`SecretsFileError::UnsupportedVersion`] if `version` is not `3`.
    /// - [`SecretsFileError::DuplicateIdentifier`] if two entries share an identifier.
    /// - [`SecretsFileError::InvalidSegment`] if a segment definition is malformed.
    pub fn deserialize(data: &[u8]) -> Result<Self, SecretsFileError> {
        let s = std::str::from_utf8(data).map_err(|_| SecretsFileError::InvalidUtf8)?;
        let file: SecretsFile =
            toml::from_str(s).map_err(|e| SecretsFileError::Toml(e.to_string()))?;

        if file.version != 3 {
            return Err(SecretsFileError::UnsupportedVersion {
                found: file.version,
            });
        }

        let mut seen_ids = std::collections::HashSet::new();
        for entry in &file.pattern {
            if !seen_ids.insert(&entry.identifier) {
                return Err(SecretsFileError::DuplicateIdentifier {
                    identifier: entry.identifier.clone(),
                });
            }
        }

        for entry in &file.pattern {
            crate::segment::validate_segment_defs(&entry.segments).map_err(|e| {
                SecretsFileError::InvalidSegment {
                    identifier: entry.identifier.clone(),
                    reason: e.to_string(),
                }
            })?;

            // INV-31: instance patterns must have fixed-length variable segments.
            if !entry.digests.is_empty() {
                for (i, seg) in entry.segments.iter().enumerate() {
                    if let SegmentDef::Variable { min, max, .. } = seg {
                        if min != max {
                            return Err(SecretsFileError::InvalidSegment {
                                identifier: entry.identifier.clone(),
                                reason: format!(
                                    "instance pattern variable segment at index {} has min ({}) != max ({})",
                                    i, min, max
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(file)
    }

    /// Convert to runtime [`Pattern`] values.
    ///
    /// Salts are read from the file entries and remain stable across process restarts.
    /// This differs from [`patterns::all`] which generates a fresh ephemeral salt each
    /// time — important when you need the same secret to produce the same fake across runs.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsFileError::InvalidSegment`] if a segment definition is malformed.
    pub fn to_patterns(&self) -> Result<Vec<Pattern>, SecretsFileError> {
        self.pattern
            .iter()
            .map(|entry| {
                // Validate segment structure (defense-in-depth for programmatically
                // constructed SecretsFile values that bypass deserialize/add_structural_entry).
                crate::segment::validate_segment_defs(&entry.segments).map_err(|e| {
                    SecretsFileError::InvalidSegment {
                        identifier: entry.identifier.clone(),
                        reason: e.to_string(),
                    }
                })?;
                let segments: Result<Vec<Segment>, _> = entry
                    .segments
                    .iter()
                    .map(|def| {
                        Segment::from_def(def).map_err(|e| SecretsFileError::InvalidSegment {
                            identifier: entry.identifier.clone(),
                            reason: e.to_string(),
                        })
                    })
                    .collect();
                let segments = segments?;

                // INV-31: instance patterns must have fixed-length variable segments.
                if !entry.digests.is_empty() {
                    for (i, seg) in entry.segments.iter().enumerate() {
                        if let crate::segment::SegmentDef::Variable { min, max, .. } = seg {
                            if min != max {
                                return Err(SecretsFileError::InvalidSegment {
                                    identifier: entry.identifier.clone(),
                                    reason: format!(
                                        "instance pattern variable segment at index {} has min ({}) != max ({})",
                                        i, min, max
                                    ),
                                });
                            }
                        }
                    }
                }

                Ok(Pattern {
                    identifier: entry.identifier.clone(),
                    segments: segments.into(),
                    salt: entry.salt,
                    digests: entry.digests.clone(),
                    // Patterns-file entries don't carry a guard field yet; wiring
                    // this to the schema is a separate step.
                    trailing_run_guard: None,
                })
            })
            .collect()
    }

    /// Add an instance pattern (registered secret) to this patterns file.
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::WrongPatternType`] if `pattern` has no HMAC digests.
    /// - [`SecretsFileError::DuplicateIdentifier`] if `identifier` already exists.
    pub fn add_secret_pattern(
        &mut self,
        identifier: String,
        pattern: &Pattern,
    ) -> Result<(), SecretsFileError> {
        if pattern.digests.is_empty() {
            return Err(SecretsFileError::WrongPatternType);
        }
        let duplicate = self.pattern.iter().any(|e| e.identifier == identifier);
        if duplicate {
            return Err(SecretsFileError::DuplicateIdentifier { identifier });
        }
        let seg_defs: Result<Vec<_>, _> = pattern
            .segments
            .iter()
            .map(|s| {
                s.try_to_def()
                    .map_err(|e| SecretsFileError::InvalidSegment {
                        identifier: identifier.clone(),
                        reason: e.to_string(),
                    })
            })
            .collect();
        let seg_defs = seg_defs?;
        self.pattern.push(PatternEntry {
            identifier: identifier.clone(),
            salt: pattern.salt,
            digests: pattern.digests.clone(),
            segments: seg_defs,
        });
        Ok(())
    }

    /// Append an HMAC digest for `secret` to an existing instance/group pattern.
    ///
    /// Computes `HMAC-SHA256(entry.salt, secret)` and pushes it to the entry's digest list,
    /// allowing multiple secrets to share one detection pattern.
    ///
    /// # Errors
    ///
    /// - [`SecretsFileError::WrongPatternType`] if the target entry is a family pattern (has no digests).
    /// - [`SecretsFileError::NotFound`] if no entry with `group_id` exists.
    pub fn add_secret_to_group(
        &mut self,
        group_id: &str,
        secret: &[u8],
    ) -> Result<(), SecretsFileError> {
        let entry = self
            .pattern
            .iter_mut()
            .find(|e| e.identifier == group_id)
            .ok_or_else(|| SecretsFileError::NotFound {
                identifier: group_id.to_string(),
            })?;
        if entry.digests.is_empty() {
            return Err(SecretsFileError::WrongPatternType);
        }
        let digest = crate::crypto::hmac_sha256(&entry.salt, secret);
        entry.digests.push(digest);
        Ok(())
    }

    /// Add a user-defined pattern to this patterns file.
    ///
    /// The caller provides a pre-generated salt. Validates:
    /// - Identifier uniqueness
    /// - Segment list validity (at least one Variable, valid charsets, min <= max)
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
        let duplicate = self.pattern.iter().any(|e| e.identifier == identifier);
        if duplicate {
            return Err(SecretsFileError::DuplicateIdentifier { identifier });
        }

        crate::segment::validate_segment_defs(&segments).map_err(|e| {
            SecretsFileError::InvalidSegment {
                identifier: identifier.clone(),
                reason: e.to_string(),
            }
        })?;

        self.pattern.push(PatternEntry {
            identifier,
            salt,
            digests: vec![],
            segments,
        });

        Ok(())
    }

    /// Fill in all built-in family patterns not already present in the file.
    ///
    /// Generates random salts and embeds compiled-in segment definitions.
    pub fn generate_missing_structural_salts(&mut self) {
        use rand::RngCore;

        for def in patterns::all_defs() {
            let already_present = self.pattern.iter().any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let seg_defs: Vec<SegmentDef> = def.segments.iter().map(|s| s.to_def()).collect();
                self.pattern.push(PatternEntry {
                    identifier: def.identifier.clone(),
                    salt,
                    digests: vec![],
                    segments: seg_defs,
                });
            }
        }
    }

    /// Fill in all built-in family patterns not already present, embedding segment definitions.
    ///
    /// Equivalent to [`Self::generate_missing_structural_salts`] in v3 (segments always required).
    pub fn generate_missing_structural_salts_with_segments(&mut self) {
        self.generate_missing_structural_salts();
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
        assert_eq!(pf2.version, 3);
        assert_eq!(pf2.pattern.len(), 27);
        let orig_salt = pf
            .pattern
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap()
            .salt;
        let deser_salt = pf2
            .pattern
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap()
            .salt;
        assert_eq!(orig_salt, deser_salt);
    }

    #[test]
    fn test_version_rejection() {
        let data = b"version = 1\n";
        let err = SecretsFile::deserialize(data).unwrap_err();
        assert!(matches!(
            err,
            SecretsFileError::UnsupportedVersion { found: 1 }
        ));
    }

    #[test]
    fn test_empty_pattern_into_patterns_succeeds() {
        let pf = SecretsFile {
            version: 3,
            pattern: vec![],
        };
        let patterns = pf.to_patterns().unwrap();
        assert_eq!(patterns.len(), 0);
    }

    #[test]
    fn test_generate_missing_fills_all_builtins() {
        let mut pf = SecretsFile::new();
        pf.generate_missing_structural_salts();
        assert_eq!(pf.pattern.len(), 27);
        for def in crate::patterns::all_defs() {
            assert!(pf.pattern.iter().any(|e| e.identifier == def.identifier));
        }
    }

    #[test]
    fn test_generate_missing_does_not_overwrite() {
        use crate::segment::SegmentDef;
        let custom_salt = [0xAB; 32];
        let mut pf = SecretsFile::new();
        pf.pattern.push(PatternEntry {
            identifier: "anthropic".into(),
            salt: custom_salt,
            digests: vec![],
            segments: vec![
                SegmentDef::Literal {
                    value: "sk-ant-api03-".into(),
                },
                SegmentDef::Variable {
                    charset: "url_safe_base64".into(),
                    min: 93,
                    max: 93,
                },
                SegmentDef::Literal { value: "AA".into() },
            ],
        });
        pf.generate_missing_structural_salts();
        let entry = pf
            .pattern
            .iter()
            .find(|e| e.identifier == "anthropic")
            .unwrap();
        assert_eq!(entry.salt, custom_salt);
    }

    #[test]
    fn test_duplicate_identifier_rejected() {
        let pf_data = br#"
version = 3

[[pattern]]
identifier = "my_pattern"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [{ type = "variable", charset = "alphanumeric", min = 10, max = 10 }]

[[pattern]]
identifier = "my_pattern"
salt = "0000000000000000000000000000000000000000000000000000000000000002"
segments = [{ type = "variable", charset = "digits", min = 5, max = 5 }]
"#;
        let err = SecretsFile::deserialize(pf_data).unwrap_err();
        assert!(
            err.to_string().contains("duplicate pattern identifier"),
            "error: {err}"
        );
    }

    #[test]
    fn test_version_3_error_message() {
        let data = b"version = 1\n";
        let err = SecretsFile::deserialize(data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported"), "error: {msg}");
        assert!(msg.contains("expected 3"), "error: {msg}");
    }

    #[test]
    fn test_user_defined_pattern_into_patterns() {
        use crate::segment::SegmentDef;
        let pf = SecretsFile {
            version: 3,
            pattern: vec![PatternEntry {
                identifier: "custom".into(),
                salt: [0xAA; 32],
                digests: vec![],
                segments: vec![
                    SegmentDef::Literal {
                        value: "tok_".into(),
                    },
                    SegmentDef::Variable {
                        charset: "alphanumeric".into(),
                        min: 20,
                        max: 20,
                    },
                ],
            }],
        };
        let patterns = pf.to_patterns().unwrap();
        assert_eq!(patterns.len(), 1);
    }

    #[test]
    fn test_instance_pattern_round_trip() {
        // An instance pattern entry (non-empty digests) survives serialize/deserialize.
        let digest = [0xBBu8; 32];
        let pf = SecretsFile {
            version: 3,
            pattern: vec![PatternEntry {
                identifier: "my-instance".into(),
                salt: [0xCC; 32],
                digests: vec![digest],
                segments: vec![
                    SegmentDef::Literal {
                        value: "pfx_".into(),
                    },
                    SegmentDef::Variable {
                        charset: "alphanumeric".into(),
                        min: 16,
                        max: 16,
                    },
                ],
            }],
        };
        let bytes = pf.serialize().unwrap();
        let pf2 = SecretsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.pattern.len(), 1);
        assert_eq!(pf2.pattern[0].digests.len(), 1);
        assert_eq!(pf2.pattern[0].digests[0], digest);
    }
}
