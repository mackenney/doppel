# Step 04: Tier 1 Built-in Pattern Definitions

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration.

### Phase Context
Wave 2 (parallel with step-05). Defines the six built-in Tier 1 secret classes required
by SPEC.md INV-22 and exposes them as public Pattern constants. These patterns are
canonical singletons — one per class — and are used in all `scrub()` calls to detect
well-known API key formats.

### This Step
Implement `src/tier1.rs` with all six Tier 1 pattern definitions. Define the `Pattern`
enum (shared with Tier 2 from step-05). Export public constants and an `all()` convenience
function. Embed the stable `OnceLock<[u8; 32]>` salt per definition for fake derivation.

## Prerequisites

- Step 01 complete (deps, module stubs)
- Step 02 complete (SessionKey, Entry types)
- Step 03 complete (derive_fake_tier1, charsets)

## Files to Read Before Starting

- `src/tier1.rs` — current stub
- `src/types.rs` — existing types
- `src/fake.rs` — charsets, derive_fake_tier1
- `SPEC.md INV-22` — exact list of required Tier 1 classes

## Implementation

### Task 1: Define Pattern enum and Tier1Def

In `src/tier1.rs` (or split Pattern enum into `src/pattern.rs` and re-export — either works):

```rust
use std::sync::OnceLock;
use crate::fake::{charsets, derive_fake_tier1};

/// Structural definition of a Tier 1 built-in secret class.
pub(crate) struct Tier1Def {
    /// Fixed literal prefix that a secret of this class starts with.
    pub prefix: &'static [u8],
    /// Valid byte values for the payload portion (after the prefix).
    pub charset: fn() -> Vec<u8>,  // function to avoid large static arrays
    /// Minimum total length in bytes (including prefix).
    pub min_len: usize,
    /// Maximum total length in bytes (including prefix).
    pub max_len: usize,
    /// Stable derivation salt, initialized once per process lifetime.
    pub salt: OnceLock<[u8; 32]>,
}

impl Tier1Def {
    pub(crate) fn get_salt(&self) -> &[u8; 32] {
        self.salt.get_or_init(|| {
            use rand::RngCore;
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            s
        })
    }

    /// Check if `payload[pos..]` starts with this pattern and validate the payload portion.
    /// Returns the end position (exclusive) if matched, None otherwise.
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<usize> {
        if !payload[pos..].starts_with(self.prefix) {
            return None;
        }
        let charset = (self.charset)();
        // Try each valid length from max_len down to min_len (longest first for leftmost-longest)
        for total_len in (self.min_len..=self.max_len).rev() {
            let end = pos + total_len;
            if end > payload.len() {
                continue;
            }
            let payload_bytes = &payload[pos + self.prefix.len()..end];
            if payload_bytes.iter().all(|b| charset.contains(b)) {
                return Some(end);
            }
        }
        None
    }
}
```

### Task 2: Six built-in Tier 1 definitions

Based on public documentation of known API key formats:

```rust
pub(crate) static ANTHROPIC_DEF: Tier1Def = Tier1Def {
    prefix: b"sk-ant-",
    charset: charsets::url_safe_base64,
    min_len: 80,
    max_len: 120,
    salt: OnceLock::new(),
};

pub(crate) static OPENAI_CLASSIC_DEF: Tier1Def = Tier1Def {
    prefix: b"sk-",
    charset: charsets::alphanumeric,
    min_len: 51,
    max_len: 51,  // classic keys are fixed-length 51
    salt: OnceLock::new(),
};

pub(crate) static OPENAI_PROJECT_DEF: Tier1Def = Tier1Def {
    prefix: b"sk-proj-",
    charset: charsets::url_safe_base64,
    min_len: 56,
    max_len: 72,
    salt: OnceLock::new(),
};

pub(crate) static AWS_AKIA_DEF: Tier1Def = Tier1Def {
    prefix: b"AKIA",
    charset: charsets::uppercase_alphanumeric,
    min_len: 20,
    max_len: 20,  // AWS IAM access key IDs are exactly 20 chars
    salt: OnceLock::new(),
};

pub(crate) static AWS_ASIA_DEF: Tier1Def = Tier1Def {
    prefix: b"ASIA",
    charset: charsets::uppercase_alphanumeric,
    min_len: 20,
    max_len: 20,
    salt: OnceLock::new(),
};

pub(crate) static GITHUB_CLASSIC_DEF: Tier1Def = Tier1Def {
    prefix: b"ghp_",
    charset: charsets::alphanumeric,
    min_len: 40,
    max_len: 40,
    salt: OnceLock::new(),
};

pub(crate) static GITHUB_FG_DEF: Tier1Def = Tier1Def {
    prefix: b"github_pat_",
    charset: charsets::url_safe_base64,
    min_len: 82,
    max_len: 100,
    salt: OnceLock::new(),
};

pub(crate) static GCP_DEF: Tier1Def = Tier1Def {
    prefix: b"AIza",
    charset: charsets::url_safe_base64,
    min_len: 39,
    max_len: 39,
    salt: OnceLock::new(),
};
```

**Note on OpenAI**: `sk-proj-` has a longer prefix than `sk-`; in leftmost-longest matching,
the scrub engine checks ALL patterns at each position and picks the longest match.
At a `sk-proj-...` position, `OPENAI_PROJECT_DEF` will produce a longer match than
`OPENAI_CLASSIC_DEF` (longer prefix → extends into payload further to meet min_len),
so the project key correctly wins. If both patterns match the same total length at the
same position, `OPENAI_PROJECT_DEF` wins by virtue of its longer prefix (it's more specific).
Document this edge case explicitly in src/tier1.rs.

### Task 3: Pattern enum and public exports

In `src/tier1.rs`:

```rust
use crate::tier2::Tier2Pat;
use std::sync::Arc;

/// A detection descriptor for scrub(). Opaque to callers.
///
/// Tier1 variant is a reference to a static built-in definition.
/// Tier2 variant is a heap-allocated registered pattern.
#[derive(Clone)]
pub enum Pattern {
    Tier1(&'static Tier1Def),
    Tier2(Arc<Tier2Pat>),
}

/// Built-in Tier 1 patterns. Pass these to scrub() to detect well-known API key formats.
pub mod patterns {
    use super::*;

    pub fn anthropic() -> Pattern { Pattern::Tier1(&ANTHROPIC_DEF) }
    pub fn openai_classic() -> Pattern { Pattern::Tier1(&OPENAI_CLASSIC_DEF) }
    pub fn openai_project() -> Pattern { Pattern::Tier1(&OPENAI_PROJECT_DEF) }
    pub fn aws_akia() -> Pattern { Pattern::Tier1(&AWS_AKIA_DEF) }
    pub fn aws_asia() -> Pattern { Pattern::Tier1(&AWS_ASIA_DEF) }
    pub fn github_classic() -> Pattern { Pattern::Tier1(&GITHUB_CLASSIC_DEF) }
    pub fn github_fine_grained() -> Pattern { Pattern::Tier1(&GITHUB_FG_DEF) }
    pub fn gcp() -> Pattern { Pattern::Tier1(&GCP_DEF) }

    /// All built-in patterns. Convenient for "scrub everything known".
    pub fn all() -> Vec<Pattern> {
        vec![
            anthropic(), openai_classic(), openai_project(),
            aws_akia(), aws_asia(),
            github_classic(), github_fine_grained(),
            gcp(),
        ]
    }
}
```

**Note**: Functions returning `Pattern` (not constants) because `Pattern::Tier1` contains
a `&'static Tier1Def` which is `Copy`; the function returns a fresh `Pattern` value
each time (cheap, just a pointer). `OnceLock` inside `Tier1Def` is shared across all
instances since they all point to the same static.

### Task 4: Update lib.rs exports

```rust
pub use tier1::{Pattern, patterns};
pub use tier2::register;  // (once tier2.rs is implemented in step-05)
```

### Task 5: Unit tests

```rust
#[test]
fn test_tier1_all_six_classes_present() {
    // INV-22: all required classes present
    let all = patterns::all();
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"sk-ant-")));
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"sk-")));
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"sk-proj-")));
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"AKIA")));
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"ghp_")));
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"github_pat_")));
    assert!(all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"AIza")));
}

#[test]
fn test_aws_akia_try_match() {
    // AWS IAM key IDs are exactly 20 uppercase alphanumeric chars
    let payload = b"access_key: AKIAIOSFODNN7EXAMPLE";
    let pos = payload.iter().position(|&b| b == b'A').unwrap();  // finds 'A' in "AKIA..."
    // Find the actual AKIA position
    let akia_pos = payload.windows(4).position(|w| w == b"AKIA").unwrap();
    let result = AWS_AKIA_DEF.try_match(payload, akia_pos);
    assert_eq!(result, Some(akia_pos + 20));
}

#[test]
fn test_gcp_key_try_match() {
    let payload = b"AIzaSyD-AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result = GCP_DEF.try_match(payload, 0);
    assert_eq!(result, Some(39));
}

#[test]
fn test_tier1_prefix_mismatch_returns_none() {
    let payload = b"not-a-key";
    assert!(ANTHROPIC_DEF.try_match(payload, 0).is_none());
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --lib` exits 0
- [ ] `test_tier1_all_six_classes_present` passes (all required prefixes present)
- [ ] `test_aws_akia_try_match` passes (exactly 20 chars matched)
- [ ] `test_gcp_key_try_match` passes (exactly 39 chars matched)
- [ ] `patterns::all()` returns at least 7 patterns (6 minimum classes, possibly 8 with both OpenAI + both AWS)
- [ ] `cargo clippy -- -D warnings` exits 0
- [ ] `Pattern` enum is `Clone` (needed for caller-held pattern reuse)

## Reviewer Instructions

You are reviewing Step 04. Verify:

1. Run `cargo nextest run --lib` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Run `cargo nextest run --lib -E 'test(tier1)'` — must pass
4. Count pattern defs in `patterns::all()`: `cargo test` output or code inspection shows ≥7 patterns
5. Confirm `Pattern` is `#[derive(Clone)]` or manually `impl Clone`

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-04 commit.
