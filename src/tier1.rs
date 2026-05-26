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
    /// Derivation salt for fake generation.
    ///
    /// FIXME: currently initialized lazily with OsRng on first access, which means
    /// the salt (and therefore the fake) differs on every process restart. This
    /// violates INV-13 across process boundaries. The salt must become an explicit,
    /// caller-supplied value loaded from the patterns file so fakes are stable
    /// across runs. See Known Gaps in MASTER_PROGRESS.md.
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
    // sk-ant-api03-<93 url_safe_base64 chars>AA = 108 chars total
    // Source: gitleaks `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`
    prefix: b"sk-ant-api03-",
    charset: charsets::url_safe_base64,
    min_len: 108,
    max_len: 108,
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
    // sk-proj-<payload>T3BlbkFJ<payload>: three observed total lengths.
    // Original (pre-Aug 2024): 56 chars (8 prefix + 48 payload).
    // New (post-Aug 2024): 132 chars (8+58+8+58) or 164 chars (8+74+8+74).
    // All chars are url_safe_base64; T3BlbkFJ is within that charset.
    // Source: gitleaks openai-api-key rule + OpenAI community reports.
    prefix: b"sk-proj-",
    charset: charsets::url_safe_base64,
    min_len: 56,
    max_len: 164,
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
    // github_pat_<82 chars of [a-zA-Z0-9_]> = 93 chars total.
    // Structure: 11-char prefix + 22 alnum + '_' + 59 alnum = 93.
    // Source: gitleaks `github_pat_\w{82}` and magnetikonline gist.
    prefix: b"github_pat_",
    charset: charsets::url_safe_base64,
    min_len: 93,
    max_len: 93,
    salt: OnceLock::new(),
};

pub(crate) static GCP_DEF: Tier1Def = Tier1Def {
    prefix: b"AIza",
    charset: charsets::url_safe_base64,
    min_len: 39,
    max_len: 39,
    salt: OnceLock::new(),
};

pub(crate) static OPENROUTER_DEF: Tier1Def = Tier1Def {
    // sk-or-v1-<64 lowercase hex chars> = 73 chars total.
    // Source: xchecker-dev `sk-or-v1-[0-9a-fA-F]{64}`,
    //   nuclei-templates, example key confirms 64-char hex payload.
    prefix: b"sk-or-v1-",
    charset: charsets::hex_lower,
    min_len: 73,
    max_len: 73,
    salt: OnceLock::new(),
};

pub(crate) static OPENAI_SVCACCT_DEF: Tier1Def = Tier1Def {
    // sk-svcacct-<payload>T3BlbkFJ<payload>: same structure as sk-proj- new format.
    // sk-svcacct- (11) + {58|74} + T3BlbkFJ(8) + {58|74} = 135 or 167 chars.
    // Source: gitleaks `sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|...{58})T3BlbkFJ...`
    prefix: b"sk-svcacct-",
    charset: charsets::url_safe_base64,
    min_len: 135,
    max_len: 167,
    salt: OnceLock::new(),
};

pub(crate) static GOOGLE_OAUTH_SECRET_DEF: Tier1Def = Tier1Def {
    // GOCSPX-<28 url_safe_base64 chars> = 35 chars total.
    // Source: secretgate docs "GOCSPX- + 28 chars".
    prefix: b"GOCSPX-",
    charset: charsets::url_safe_base64,
    min_len: 35,
    max_len: 35,
    salt: OnceLock::new(),
};

pub(crate) static SLACK_BOT_DEF: Tier1Def = Tier1Def {
    // xoxb-<10-13 digits>-<10-13 digits>-<24 alnum> = 51-57 chars total.
    // Embedded '-' separators are within url_safe_base64 charset.
    // Source: gitleaks `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
    //   RedHunt Labs `xoxb-{12}-{12}-{24}`, real examples confirm 24-char final segment.
    prefix: b"xoxb-",
    charset: charsets::url_safe_base64,
    min_len: 51,
    max_len: 57,
    salt: OnceLock::new(),
};

pub(crate) static ANTHROPIC_ADMIN01_DEF: Tier1Def = Tier1Def {
    // sk-ant-admin01-<93 url_safe_base64 chars>AA = 110 chars total.
    // Source: gitleaks `sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`
    prefix: b"sk-ant-admin01-",
    charset: charsets::url_safe_base64,
    min_len: 110,
    max_len: 110,
    salt: OnceLock::new(),
};

pub(crate) static ANTHROPIC_ADMIN03_DEF: Tier1Def = Tier1Def {
    // sk-ant-admin03-<93 url_safe_base64 chars>AA = 110 chars total.
    // Same structure as admin01, newer generation. Source: Anthropic Terraform provider docs.
    prefix: b"sk-ant-admin03-",
    charset: charsets::url_safe_base64,
    min_len: 110,
    max_len: 110,
    salt: OnceLock::new(),
};

pub(crate) static LINEAR_DEF: Tier1Def = Tier1Def {
    // lin_api_<40 alphanumeric chars> = 48 chars total.
    // Source: gitleaks `lin_api_(?i)[a-z0-9]{40}`
    prefix: b"lin_api_",
    charset: charsets::alphanumeric,
    min_len: 48,
    max_len: 48,
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
    pub fn openrouter() -> Pattern {
        Pattern::Tier1(&OPENROUTER_DEF)
    }
    pub fn openai_svcacct() -> Pattern {
        Pattern::Tier1(&OPENAI_SVCACCT_DEF)
    }
    pub fn google_oauth_secret() -> Pattern {
        Pattern::Tier1(&GOOGLE_OAUTH_SECRET_DEF)
    }
    pub fn slack_bot() -> Pattern {
        Pattern::Tier1(&SLACK_BOT_DEF)
    }
    pub fn anthropic_admin01() -> Pattern {
        Pattern::Tier1(&ANTHROPIC_ADMIN01_DEF)
    }
    pub fn anthropic_admin03() -> Pattern {
        Pattern::Tier1(&ANTHROPIC_ADMIN03_DEF)
    }
    pub fn linear() -> Pattern {
        Pattern::Tier1(&LINEAR_DEF)
    }

    /// All built-in Tier 1 patterns.
    ///
    /// Covers: Anthropic API (`sk-ant-api03-`), Anthropic Admin (`sk-ant-admin01-`,
    /// `sk-ant-admin03-`), OpenAI classic (`sk-`), OpenAI project (`sk-proj-`),
    /// OpenAI service account (`sk-svcacct-`), AWS AKIA/ASIA, GitHub classic/fine-grained,
    /// GCP/Gemini (`AIza`), OpenRouter (`sk-or-v1-`), Google OAuth secret (`GOCSPX-`),
    /// Slack bot (`xoxb-`), Linear (`lin_api_`).
    pub fn all() -> Vec<Pattern> {
        vec![
            anthropic(),
            anthropic_admin01(),
            anthropic_admin03(),
            openai_classic(),
            openai_project(),
            openai_svcacct(),
            aws_akia(),
            aws_asia(),
            github_classic(),
            github_fine_grained(),
            gcp(),
            openrouter(),
            google_oauth_secret(),
            slack_bot(),
            linear(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_all_classes_present() {
        // INV-22: all built-in classes present
        let all = patterns::all();
        let prefixes: &[&[u8]] = &[
            b"sk-ant-api03-",
            b"sk-ant-admin01-",
            b"sk-ant-admin03-",
            b"sk-",
            b"sk-proj-",
            b"sk-svcacct-",
            b"AKIA",
            b"ASIA",
            b"ghp_",
            b"github_pat_",
            b"AIza",
            b"sk-or-v1-",
            b"GOCSPX-",
            b"xoxb-",
            b"lin_api_",
        ];
        for prefix in prefixes {
            assert!(
                all.iter()
                    .any(|p| matches!(p, Pattern::Tier1(d) if d.prefix == *prefix)),
                "missing prefix: {}",
                std::str::from_utf8(prefix).unwrap()
            );
        }
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
