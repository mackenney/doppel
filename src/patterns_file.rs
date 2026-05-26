use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::segment::SegmentDef;
use crate::serde_helpers::{hex_32, hex_vec, hex_vec_option};
use crate::tier1::{self, Pattern, Tier1Def};
use crate::tier2::Tier2Pat;

/// Top-level patterns file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternsFile {
    pub version: u64,
    pub tier1: Vec<Tier1Entry>,
    pub tier2: Vec<Tier2Entry>,
}

/// A Tier 1 entry: identifier, salt, and optional user-defined segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier1Entry {
    pub identifier: String,
    #[serde(with = "hex_32")]
    pub salt: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<SegmentDef>>,
}

/// A Tier 2 entry: detection fingerprint + derivation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2Entry {
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
pub enum PatternsFileError {
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

impl PatternsFile {
    /// Create an empty patterns file (version 2, no entries).
    pub fn new() -> Self {
        Self {
            version: 2,
            tier1: Vec::new(),
            tier2: Vec::new(),
        }
    }

    /// Serialize to TOML bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, PatternsFileError> {
        let s = toml::to_string_pretty(self).map_err(|e| PatternsFileError::Toml(e.to_string()))?;
        Ok(s.into_bytes())
    }

    /// Deserialize from TOML bytes with validation.
    pub fn deserialize(data: &[u8]) -> Result<Self, PatternsFileError> {
        let s = std::str::from_utf8(data).map_err(|_| PatternsFileError::InvalidUtf8)?;
        let file: PatternsFile =
            toml::from_str(s).map_err(|e| PatternsFileError::Toml(e.to_string()))?;
        file.validate()?;
        Ok(file)
    }

    fn validate(&self) -> Result<(), PatternsFileError> {
        if self.version != 2 {
            return Err(PatternsFileError::UnsupportedVersion {
                found: self.version,
            });
        }

        let mut seen_ids = std::collections::HashSet::new();
        for entry in &self.tier1 {
            if !seen_ids.insert(&entry.identifier) {
                return Err(PatternsFileError::DuplicateIdentifier {
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
                    return Err(PatternsFileError::DuplicateLabel {
                        label: label.clone(),
                    });
                }
            }

            if entry.exact_length == 0 {
                return Err(PatternsFileError::InvalidTier2 {
                    index,
                    reason: "exact_length must not be zero".into(),
                });
            }
            if entry.start_fragment.is_empty() {
                return Err(PatternsFileError::InvalidTier2 {
                    index,
                    reason: "start_fragment must not be empty".into(),
                });
            }
            if entry.end_fragment.is_empty() {
                return Err(PatternsFileError::InvalidTier2 {
                    index,
                    reason: "end_fragment must not be empty".into(),
                });
            }
            if let Some(ref cs) = entry.charset {
                if cs.is_empty() {
                    return Err(PatternsFileError::InvalidTier2 {
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
    pub fn into_patterns(self) -> Result<Vec<Pattern>, PatternsFileError> {
        use crate::segment::Segment;

        let builtin_defs = tier1::all_defs();
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
                    return Err(PatternsFileError::MissingSegments {
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
    pub fn add_tier2_pattern(
        &mut self,
        pattern: &Pattern,
        label: Option<String>,
    ) -> Result<(), PatternsFileError> {
        match pattern {
            Pattern::Tier2(arc) => {
                if let Some(ref l) = label {
                    let duplicate = self.tier2.iter().any(|e| e.label.as_deref() == Some(l));
                    if duplicate {
                        return Err(PatternsFileError::DuplicateLabel { label: l.clone() });
                    }
                }

                let p = arc.as_ref();
                let charset = if p.charset == crate::fake::charsets::wide() {
                    None
                } else {
                    Some(p.charset.clone())
                };

                self.tier2.push(Tier2Entry {
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
            _ => Err(PatternsFileError::WrongPatternType),
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
    ) -> Result<(), PatternsFileError> {
        let duplicate = self.tier1.iter().any(|e| e.identifier == identifier);
        if duplicate {
            return Err(PatternsFileError::DuplicateIdentifier { identifier });
        }

        crate::segment::validate_segment_defs(&segments)?;

        self.tier1.push(Tier1Entry {
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

        for def in tier1::all_defs() {
            let already_present = self.tier1.iter().any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                self.tier1.push(Tier1Entry {
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

        for def in tier1::all_defs() {
            let already_present = self.tier1.iter().any(|e| e.identifier == def.identifier);
            if !already_present {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);

                let seg_defs: Vec<SegmentDef> = def.segments.iter().map(|s| s.to_def()).collect();

                self.tier1.push(Tier1Entry {
                    identifier: def.identifier.clone(),
                    salt,
                    segments: Some(seg_defs),
                });
            }
        }
    }

    /// Check if an identifier matches a compiled-in Tier 1 definition.
    pub fn is_builtin_identifier(identifier: &str) -> bool {
        tier1::all_defs().iter().any(|d| d.identifier == identifier)
    }
}

impl Default for PatternsFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    // Unit tests for the TOML-based PatternsFile are implemented in step-10.
    // The previous tests used HashMap API and JSON fixtures incompatible with the
    // Vec-based tier1 and TOML serialization introduced in steps 06-07.
}
