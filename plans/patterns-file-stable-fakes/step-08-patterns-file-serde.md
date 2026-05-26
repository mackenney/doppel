# Step 08: Patterns File Serde Module

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 4. Depends on step-04 (`Tier1Def.identifier` + `all_defs()`), step-06 (`Tier2Pat.fake` removed),
and step-07 (`Tier1Def` is a plain `Copy` struct with `salt: [u8; 32]`; `Pattern::Tier1` is by value).
This step creates the `patterns_file` module that defines the JSON file format, serde types,
serialization/deserialization, pattern reconstruction, and pattern extraction.

### This Step
Create `src/patterns_file.rs` with: serde types (`PatternsFile`, `Tier1Entry`, `Tier2Entry`), `serialize`/`deserialize` with validation, `into_patterns` for reconstruction, `add_tier2_pattern` for extraction, `generate_missing_tier1_salts` for initialization. Wire into `src/lib.rs`. Extract shared base64 serde helpers from `types.rs`.

## Prerequisites
- Step 04 complete (Tier1Def has `identifier` field, `all_defs()` exists)
- Step 06 complete (Tier2Pat has no `fake` field, has `preserve_prefix`/`preserve_suffix`/`charset`)
- Step 07 complete (`Tier1Def` has plain `salt: [u8; 32]`; `Pattern::Tier1(Tier1Def)` by value; no `init_salt()`)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier1.rs` — `Tier1Def` (Copy struct with `salt: [u8; 32]`), `all_defs()`, `Pattern` enum
- `/home/ignacio/pr/its-classified/src/tier2.rs` — `Tier2Pat` struct (fields after step-06)
- `/home/ignacio/pr/its-classified/src/types.rs` — `base64_serde` module at lines 81–93
- `/home/ignacio/pr/its-classified/src/lib.rs` — module declarations

## Implementation

### Task 1: Extract `base64_serde` helpers to `src/serde_helpers.rs`

Create `src/serde_helpers.rs`:

```rust
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod base64_vec {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod base64_32 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let decoded = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len())))?;
        Ok(arr)
    }
}

pub mod base64_vec_option {
    use super::*;

    pub fn serialize<S: Serializer>(opt: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(bytes) => STANDARD.encode(bytes).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => {
                let decoded = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}
```

Then update `src/types.rs` to use the shared helpers. Replace the `mod base64_serde` block (lines 81–93) with:

```rust
use crate::serde_helpers::base64_vec as base64_serde;
```

Keep the `#[serde(with = "base64_serde")]` annotations on `Entry` fields unchanged — they'll resolve to the re-imported module.

### Task 2: Create `src/patterns_file.rs`

Create the file with the following content:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::serde_helpers::{base64_32, base64_vec, base64_vec_option};
use crate::tier1::{self, Pattern, Tier1Def};
use crate::tier2::Tier2Pat;

/// Top-level patterns file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternsFile {
    pub version: u64,
    pub tier1: HashMap<String, Tier1Entry>,
    pub tier2: Vec<Tier2Entry>,
}

/// A Tier 1 entry: just the salt (all other fields are compiled in).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier1Entry {
    #[serde(with = "base64_32")]
    pub salt: [u8; 32],
}

/// A Tier 2 entry: detection fingerprint + derivation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2Entry {
    #[serde(with = "base64_vec")]
    pub start_fragment: Vec<u8>,
    #[serde(with = "base64_vec")]
    pub end_fragment: Vec<u8>,
    pub exact_length: usize,
    #[serde(with = "base64_32")]
    pub hmac_salt: [u8; 32],
    #[serde(with = "base64_32")]
    pub hmac_digest: [u8; 32],
    pub preserve_prefix: usize,
    pub preserve_suffix: usize,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "base64_vec_option"
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

    #[error("Tier 1 salt initialization failed for class {class}: already set")]
    SaltAlreadySet { class: String },
}

impl PatternsFile {
    /// Create an empty patterns file (version 1, no entries).
    pub fn new() -> Self {
        Self {
            version: 1,
            tier1: HashMap::new(),
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
            let entry = self.tier1.get(def.identifier).ok_or_else(|| {
                PatternsFileError::MissingTier1Class {
                    class: def.identifier.to_string(),
                }
            })?;

            patterns.push(Pattern::Tier1(Tier1Def {
                salt: entry.salt,
                ..*def
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
            _ => Err(PatternsFileError::InvalidTier2 {
                index: self.tier2.len(),
                reason: "expected a Tier 2 pattern".into(),
            }),
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
        assert_eq!(pf2.tier1.len(), 8);
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
        pf.tier1.insert(
            "anthropic".into(),
            Tier1Entry { salt: [1u8; 32] },
        );
        let result = pf.into_patterns();
        assert!(matches!(
            result,
            Err(PatternsFileError::MissingTier1Class { .. })
        ));
    }

    #[test]
    fn test_generate_missing_fills_all_eight() {
        let mut pf = PatternsFile::new();
        pf.generate_missing_tier1_salts();
        assert_eq!(pf.tier1.len(), 8);
        let expected_ids = [
            "anthropic", "openai_classic", "openai_project",
            "aws_akia", "aws_asia", "github_classic",
            "github_fine_grained", "gcp",
        ];
        for id in &expected_ids {
            assert!(pf.tier1.contains_key(*id), "missing class: {id}");
        }
    }

    #[test]
    fn test_generate_missing_does_not_overwrite() {
        let mut pf = PatternsFile::new();
        let fixed_salt = [42u8; 32];
        pf.tier1.insert("anthropic".into(), Tier1Entry { salt: fixed_salt });
        pf.generate_missing_tier1_salts();
        assert_eq!(pf.tier1["anthropic"].salt, fixed_salt);
        assert_eq!(pf.tier1.len(), 8);
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
        use rand::{SeedableRng, rngs::StdRng};
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
        assert!(pf2.tier2[0].charset.is_none(), "wide charset should not be serialized");
    }
}
```

### Task 3: Wire module into `src/lib.rs`

In `src/lib.rs`, add after `pub(crate) mod fake;`:

```rust
pub(crate) mod serde_helpers;
pub mod patterns_file;
```

Add to the public re-exports at the bottom:

```rust
pub use patterns_file::{PatternsFile, PatternsFileError, Tier1Entry, Tier2Entry};
```

### Task 4: Update `src/types.rs` to use shared helpers

Replace the `mod base64_serde` block in `src/types.rs` (lines 81–93) with:

```rust
use crate::serde_helpers::base64_vec as base64_serde;
```

### Task 5: Make `Tier2Pat` fields accessible for `patterns_file.rs`

The `patterns_file.rs` module needs to construct `Tier2Pat` instances directly (in `into_patterns`). Since `Tier2Pat` fields are `pub(crate)`, and `patterns_file` is within the crate, this works. No changes needed.

However, `into_patterns` also needs to construct `Tier2Pat` directly. Verify that `Tier2Pat` has no private fields and all fields are `pub(crate)`. After step-06, the struct should be:

```rust
pub struct Tier2Pat {
    pub(crate) start_fragment: Vec<u8>,
    pub(crate) end_fragment: Vec<u8>,
    pub(crate) exact_length: usize,
    pub(crate) hmac_salt: [u8; 32],
    pub(crate) hmac_digest: [u8; 32],
    pub(crate) preserve_prefix: usize,
    pub(crate) preserve_suffix: usize,
    pub(crate) charset: Vec<u8>,
}
```

This is accessible from within the crate. Good.

### Task 6: Run tests

```sh
cargo nextest run -p its-classified --lib
cargo nextest run -p its-classified --test spec
cargo nextest run -p its-classified --test integration
```

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run -p its-classified --lib 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test spec 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test integration 2>&1 | tail -3` shows 0 failures
- [ ] `test -f /home/ignacio/pr/its-classified/src/patterns_file.rs && echo "exists"` outputs `exists`
- [ ] `test -f /home/ignacio/pr/its-classified/src/serde_helpers.rs && echo "exists"` outputs `exists`
- [ ] `grep -c "pub mod patterns_file" /home/ignacio/pr/its-classified/src/lib.rs` outputs `1`
- [ ] `grep -c "pub use patterns_file" /home/ignacio/pr/its-classified/src/lib.rs` outputs `1`
- [ ] `grep -c "fn test_round_trip_serialize_deserialize" /home/ignacio/pr/its-classified/src/patterns_file.rs` outputs `1`
- [ ] `grep -c "fn test_version_rejection" /home/ignacio/pr/its-classified/src/patterns_file.rs` outputs `1`
- [ ] `grep -c "fn test_missing_tier1_class_error" /home/ignacio/pr/its-classified/src/patterns_file.rs` outputs `1`
- [ ] `cargo build -p its-classified 2>&1 | grep -c "error"` outputs `0`

## Reviewer Instructions

You are reviewing Step 08. Verify:
1. Run `cargo nextest run -p its-classified --lib` — all tests must pass
2. Run `cargo nextest run -p its-classified --test spec` — all spec tests must pass
3. `src/patterns_file.rs` exists with: `PatternsFile`, `Tier1Entry`, `Tier2Entry`, `PatternsFileError`
4. `PatternsFile::serialize` and `PatternsFile::deserialize` work (test passes)
5. `PatternsFile::into_patterns` validates all Tier 1 classes present, constructs patterns
6. `PatternsFile::add_tier2_pattern` extracts fields from `Pattern::Tier2`
7. `PatternsFile::generate_missing_tier1_salts` fills all 8 classes
8. `src/serde_helpers.rs` contains `base64_vec`, `base64_32`, `base64_vec_option`
9. `src/types.rs` uses shared `base64_serde` from `serde_helpers` — no duplicated module
10. Binary fields use base64 encoding in JSON (check serialized output)
11. `charset` field is `skip_serializing_if = "Option::is_none"` — not present for wide charset
12. Run `cargo clippy -p its-classified --lib 2>&1` — no new warnings
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/patterns_file.rs src/serde_helpers.rs src/types.rs src/lib.rs
```
