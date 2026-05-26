use std::collections::HashMap;
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

/// A Tier 1 entry: just the salt (all other fields are compiled in).
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
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported patterns file version: {found} (expected 1)")]
    UnsupportedVersion { found: u64 },

    #[error("missing Tier 1 class: {class}")]
    MissingTier1Class { class: String },

    #[error("invalid Tier 2 entry at index {index}: {reason}")]
    InvalidTier2 { index: usize, reason: String },

    #[error("expected a Tier 2 pattern, got Tier 1")]
    WrongPatternType,
}

impl PatternsFile {
    /// Create an empty patterns file (version 1, no entries).
    pub fn new() -> Self {
        Self {
            version: 2,
            tier1: Vec::new(),
            tier2: Vec::new(),
        }
    }

    /// Serialize to pretty-printed JSON bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Deserialize from JSON bytes with validation.
    pub fn deserialize(data: &[u8]) -> Result<Self, PatternsFileError> {
        let file: PatternsFile = serde_json::from_slice(data)?;
        file.validate()?;
        Ok(file)
    }

    fn validate(&self) -> Result<(), PatternsFileError> {
        if self.version != 1 {
            return Err(PatternsFileError::UnsupportedVersion {
                found: self.version,
            });
        }

        for (i, entry) in self.tier2.iter().enumerate() {
            if entry.start_fragment.is_empty() {
                return Err(PatternsFileError::InvalidTier2 {
                    index: i,
                    reason: "start_fragment must not be empty".into(),
                });
            }
            if entry.exact_length == 0 {
                return Err(PatternsFileError::InvalidTier2 {
                    index: i,
                    reason: "exact_length must be > 0".into(),
                });
            }
            if entry.preserve_prefix + entry.preserve_suffix >= entry.exact_length {
                return Err(PatternsFileError::InvalidTier2 {
                    index: i,
                    reason: format!(
                        "preserve_prefix ({}) + preserve_suffix ({}) >= exact_length ({})",
                        entry.preserve_prefix, entry.preserve_suffix, entry.exact_length
                    ),
                });
            }
            if let Some(ref cs) = entry.charset {
                if cs.is_empty() {
                    return Err(PatternsFileError::InvalidTier2 {
                        index: i,
                        reason: "charset must not be empty when present".into(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Reconstruct `Vec<Pattern>` from this patterns file.
    ///
    /// For Tier 1: constructs owned `Tier1Def` values via struct-update syntax, injecting the
    /// salt from the file. No global state mutation.
    /// Returns error if any built-in Tier 1 class is missing from the file.
    ///
    /// For Tier 2: constructs `Tier2Pat` values from the entries.
    pub fn into_patterns(self) -> Result<Vec<Pattern>, PatternsFileError> {
        let mut patterns = Vec::new();

        for def in tier1::all_defs() {
            let entry = self.tier1.get(def.identifier.as_str()).ok_or_else(|| {
                PatternsFileError::MissingTier1Class {
                    class: def.identifier.clone(),
                }
            })?;

            patterns.push(Pattern::Tier1(Tier1Def {
                salt: entry.salt,
                ..(*def).clone()
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
    /// Returns error if the pattern is not Tier 2.
    pub fn add_tier2_pattern(&mut self, pattern: &Pattern) -> Result<(), PatternsFileError> {
        match pattern {
            Pattern::Tier2(arc) => {
                let p = arc.as_ref();
                let charset = if p.charset == crate::fake::charsets::wide() {
                    None
                } else {
                    Some(p.charset.clone())
                };

                self.tier2.push(Tier2Entry {
                    label: None,
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

    /// Fill in salts for any built-in Tier 1 classes not already in the file.
    /// Uses OsRng for fresh salt generation.
    pub fn generate_missing_tier1_salts(&mut self) {
        use rand::RngCore;

        for def in tier1::all_defs() {
            self.tier1
                .entry(def.identifier.to_string())
                .or_insert_with(|| {
                    let mut salt = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut salt);
                    Tier1Entry { salt }
                });
        }
    }
}

impl Default for PatternsFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_serialize_deserialize() {
        let mut pf = PatternsFile::new();
        pf.generate_missing_tier1_salts();
        let bytes = pf.serialize().unwrap();
        let pf2 = PatternsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.version, 1);
        assert_eq!(pf2.tier1.len(), 15);
        assert!(pf2.tier2.is_empty());
        for (k, v) in &pf.tier1 {
            assert_eq!(&pf2.tier1[k].salt, &v.salt);
        }
    }

    #[test]
    fn test_version_rejection() {
        let json = r#"{"version": 2, "tier1": {}, "tier2": []}"#;
        let result = PatternsFile::deserialize(json.as_bytes());
        assert!(matches!(
            result,
            Err(PatternsFileError::UnsupportedVersion { found: 2 })
        ));
    }

    #[test]
    fn test_missing_tier1_class_error() {
        let mut pf = PatternsFile::new();
        // Add only one class
        pf.tier1
            .insert("anthropic".into(), Tier1Entry { salt: [1u8; 32] });
        let result = pf.into_patterns();
        assert!(matches!(
            result,
            Err(PatternsFileError::MissingTier1Class { .. })
        ));
    }

    #[test]
    fn test_generate_missing_fills_all_fifteen() {
        let mut pf = PatternsFile::new();
        pf.generate_missing_tier1_salts();
        assert_eq!(pf.tier1.len(), 15);
        let expected_ids = [
            "anthropic",
            "anthropic_admin01",
            "anthropic_admin03",
            "openai_classic",
            "openai_project",
            "openai_svcacct",
            "aws_akia",
            "aws_asia",
            "github_classic",
            "github_fine_grained",
            "gcp",
            "openrouter",
            "google_oauth_secret",
            "slack_bot",
            "linear",
        ];
        for id in &expected_ids {
            assert!(pf.tier1.contains_key(*id), "missing class: {id}");
        }
    }

    #[test]
    fn test_generate_missing_does_not_overwrite() {
        let mut pf = PatternsFile::new();
        let fixed_salt = [42u8; 32];
        pf.tier1
            .insert("anthropic".into(), Tier1Entry { salt: fixed_salt });
        pf.generate_missing_tier1_salts();
        assert_eq!(pf.tier1["anthropic"].salt, fixed_salt);
        assert_eq!(pf.tier1.len(), 15);
    }

    #[test]
    fn test_invalid_tier2_exact_length_zero() {
        let json = r#"{"version": 1, "tier1": {}, "tier2": [{"start_fragment": "AA==", "end_fragment": "AA==", "exact_length": 0, "hmac_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "hmac_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "preserve_prefix": 0, "preserve_suffix": 0}]}"#;
        let result = PatternsFile::deserialize(json.as_bytes());
        assert!(matches!(
            result,
            Err(PatternsFileError::InvalidTier2 { index: 0, .. })
        ));
    }

    #[test]
    fn test_tier2_with_charset_round_trips() {
        let secret = b"abcdef1234567890abcdef";
        let opts = crate::tier2::RegistrationOptions {
            preserve_prefix: 0,
            preserve_suffix: 0,
            restrict_charset: true,
        };
        let pat = crate::tier2::register_with_options(secret, &opts).unwrap();

        let mut pf = PatternsFile::new();
        pf.generate_missing_tier1_salts();
        pf.add_tier2_pattern(&pat).unwrap();

        let bytes = pf.serialize().unwrap();
        let pf2 = PatternsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.tier2.len(), 1);
        assert!(pf2.tier2[0].charset.is_some());
    }

    #[test]
    fn test_tier2_without_charset_uses_wide() {
        let secret = b"my-arbitrary-secret-value-12345";
        let pat = crate::tier2::register(secret).unwrap();

        let mut pf = PatternsFile::new();
        pf.generate_missing_tier1_salts();
        pf.add_tier2_pattern(&pat).unwrap();

        let bytes = pf.serialize().unwrap();
        let pf2 = PatternsFile::deserialize(&bytes).unwrap();
        assert_eq!(pf2.tier2.len(), 1);
        assert!(
            pf2.tier2[0].charset.is_none(),
            "wide charset should not be serialized"
        );
    }
    #[test]
    fn test_invalid_tier2_empty_start_fragment() {
        let json = r#"{"version": 1, "tier1": {}, "tier2": [{"start_fragment": "", "end_fragment": "AA==", "exact_length": 1, "hmac_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "hmac_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "preserve_prefix": 0, "preserve_suffix": 0}]}"#;
        let result = PatternsFile::deserialize(json.as_bytes());
        assert!(matches!(
            result,
            Err(PatternsFileError::InvalidTier2 { index: 0, .. })
        ));
    }
}
