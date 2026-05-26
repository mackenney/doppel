use std::sync::OnceLock;

use crate::fake::charsets;
use crate::tier2::Tier2Pat;
use std::sync::Arc;

/// Structural definition of a Tier 1 built-in secret class.
pub struct Tier1Def {
    /// Fixed literal prefix that a secret of this class starts with.
    pub(crate) prefix: &'static [u8],
    /// Valid byte values for the payload portion (after the prefix).
    pub(crate) charset: fn() -> Vec<u8>,
    /// Minimum total length in bytes (including prefix).
    pub(crate) min_len: usize,
    /// Maximum total length in bytes (including prefix).
    pub(crate) max_len: usize,
    /// Stable derivation salt, initialized once per process lifetime.
    pub(crate) salt: OnceLock<[u8; 32]>,
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
    ///
    /// Tries from max_len down to min_len (longest first, for leftmost-longest matching).
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<usize> {
        if !payload[pos..].starts_with(self.prefix) {
            return None;
        }
        let charset = (self.charset)();
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

// Note on sk-proj- vs sk-: at a "sk-proj-..." position, OPENAI_PROJECT_DEF produces a longer
// match than OPENAI_CLASSIC_DEF (because sk-proj- contains '-' which is not alphanumeric,
// so OPENAI_CLASSIC_DEF fails), and the scrub engine picks the longest match per INV-18.

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
    max_len: 51,
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
    max_len: 20,
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

/// A detection descriptor for [`crate::scrub`].
///
/// Obtain via [`patterns`] functions or [`crate::register`]/[`crate::register_with_options`].
/// Pass to [`crate::scrub`] — do not match on variants in stable code; the variant
/// set may change in future versions.
#[derive(Clone)]
#[non_exhaustive]
pub enum Pattern {
    Tier1(&'static Tier1Def),
    Tier2(Arc<Tier2Pat>),
}

/// Built-in Tier 1 patterns. Pass these to scrub() to detect well-known API key formats.
pub mod patterns {
    use super::*;

    pub fn anthropic() -> Pattern {
        Pattern::Tier1(&ANTHROPIC_DEF)
    }
    pub fn openai_classic() -> Pattern {
        Pattern::Tier1(&OPENAI_CLASSIC_DEF)
    }
    pub fn openai_project() -> Pattern {
        Pattern::Tier1(&OPENAI_PROJECT_DEF)
    }
    pub fn aws_akia() -> Pattern {
        Pattern::Tier1(&AWS_AKIA_DEF)
    }
    pub fn aws_asia() -> Pattern {
        Pattern::Tier1(&AWS_ASIA_DEF)
    }
    pub fn github_classic() -> Pattern {
        Pattern::Tier1(&GITHUB_CLASSIC_DEF)
    }
    pub fn github_fine_grained() -> Pattern {
        Pattern::Tier1(&GITHUB_FG_DEF)
    }
    pub fn gcp() -> Pattern {
        Pattern::Tier1(&GCP_DEF)
    }

    /// All built-in Tier 1 patterns.
    ///
    /// Covers: Anthropic (`sk-ant-`), OpenAI classic (`sk-`), OpenAI project
    /// (`sk-proj-`), AWS AKIA, AWS ASIA, GitHub classic (`ghp_`), GitHub
    /// fine-grained (`github_pat_`), and GCP (`AIza`).
    pub fn all() -> Vec<Pattern> {
        vec![
            anthropic(),
            openai_classic(),
            openai_project(),
            aws_akia(),
            aws_asia(),
            github_classic(),
            github_fine_grained(),
            gcp(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_all_eight_classes_present() {
        // INV-22: all eight built-in classes present
        let all = patterns::all();
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"sk-ant-"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"sk-"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"sk-proj-"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"AKIA"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"ASIA"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"ghp_"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"github_pat_"))
        );
        assert!(
            all.iter()
                .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == b"AIza"))
        );
    }

    #[test]
    fn test_aws_akia_try_match() {
        let payload = b"access_key: AKIAIOSFODNN7EXAMPLE";
        let akia_pos = payload.windows(4).position(|w| w == b"AKIA").unwrap();
        let result = AWS_AKIA_DEF.try_match(payload, akia_pos);
        assert_eq!(result, Some(akia_pos + 20));
    }

    #[test]
    fn test_gcp_key_try_match() {
        let payload = b"AIzaSyD-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = GCP_DEF.try_match(payload, 0);
        assert_eq!(result, Some(39));
    }

    #[test]
    fn test_tier1_prefix_mismatch_returns_none() {
        let payload = b"not-a-key";
        assert!(ANTHROPIC_DEF.try_match(payload, 0).is_none());
    }
}
