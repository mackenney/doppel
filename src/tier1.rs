use std::sync::OnceLock;

use crate::fake::charsets;
use crate::segment::{MatchCapture, Segment};
use crate::tier2::Tier2Pat;
use std::sync::Arc;

/// Structural definition of a Tier 1 built-in secret class.
pub struct Tier1Def {
    /// Ordered sequence of structural segments for this secret class.
    /// See SPEC.md §Tier 1.
    pub(crate) segments: &'static [Segment],
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

    /// Walk `payload[pos..]` against the segment list. Returns `Some(MatchCapture)`
    /// on a complete match, `None` otherwise.
    ///
    /// Variable segments try lengths from max down to min (longest-first, INV-18).
    /// When a Variable segment is followed by a Literal, the Literal boundary is
    /// located within the valid Variable range — handling embedded markers like
    /// `T3BlbkFJ` that are themselves valid Variable-charset bytes.
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<MatchCapture> {
        let mut variable_lengths = Vec::new();
        let end = match_segments(payload, pos, self.segments, &mut variable_lengths)?;
        Some(MatchCapture {
            end,
            variable_lengths,
        })
    }
}

/// Recursive segment-list matcher. Returns the exclusive end position on success.
/// Appends one entry to `var_lens` for each Variable segment that matches.
/// On failure, any entries appended in the failing sub-tree are removed by the caller.
fn match_segments(
    payload: &[u8],
    cur: usize,
    segs: &[Segment],
    var_lens: &mut Vec<usize>,
) -> Option<usize> {
    if segs.is_empty() {
        return Some(cur);
    }
    match &segs[0] {
        Segment::Literal(bytes) => {
            let end = cur + bytes.len();
            if payload.get(cur..end)? == *bytes {
                match_segments(payload, end, &segs[1..], var_lens)
            } else {
                None
            }
        }
        Segment::Variable { charset, min, max } => {
            let cs = charset();
            // Try lengths from max down to min (longest-first, INV-18).
            for var_len in (*min..=*max).rev() {
                let end = cur + var_len;
                if end > payload.len() {
                    continue;
                }
                if payload[cur..end].iter().all(|b| cs.contains(b)) {
                    let saved = var_lens.len();
                    var_lens.push(var_len);
                    if let Some(result) = match_segments(payload, end, &segs[1..], var_lens) {
                        return Some(result);
                    }
                    var_lens.truncate(saved);
                }
            }
            None
        }
    }
}

// Note on sk-proj- vs sk-: at a "sk-proj-..." position, OPENAI_PROJECT_DEF produces a longer
// match because it finds T3BlbkFJ at the correct offset; OPENAI_CLASSIC_DEF fails because
// 'proj-' contains '-' which is not alphanumeric. The scrub engine picks the longest match (INV-18).

const ANTHROPIC_SEGS: [Segment; 3] = [
    Segment::Literal(b"sk-ant-api03-"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 93,
        max: 93,
    },
    Segment::Literal(b"AA"),
];
pub(crate) static ANTHROPIC_DEF: Tier1Def = Tier1Def {
    // sk-ant-api03-<93 url_safe_base64>AA = 108 chars total
    // Source: gitleaks `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`
    segments: &ANTHROPIC_SEGS,
    salt: OnceLock::new(),
};

const OPENAI_CLASSIC_SEGS: [Segment; 2] = [
    Segment::Literal(b"sk-"),
    Segment::Variable {
        charset: charsets::alphanumeric,
        min: 48,
        max: 48,
    },
];
pub(crate) static OPENAI_CLASSIC_DEF: Tier1Def = Tier1Def {
    // sk-<48 alphanumeric> = 51 chars total
    segments: &OPENAI_CLASSIC_SEGS,
    salt: OnceLock::new(),
};

const OPENAI_PROJECT_SEGS: [Segment; 4] = [
    Segment::Literal(b"sk-proj-"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
    Segment::Literal(b"T3BlbkFJ"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
];
pub(crate) static OPENAI_PROJECT_DEF: Tier1Def = Tier1Def {
    // sk-proj-<58|74 url_safe_b64>T3BlbkFJ<58|74 url_safe_b64> = 132 or 164 chars total.
    // The pre-Aug-2024 56-char format (sk-proj-<48 url_safe_b64>, no T3BlbkFJ) is intentionally
    // not detected: those keys are ~2 years old and structurally indistinguishable from noise
    // without the embedded marker. Best-effort coverage per SPEC.md §Known Limitations.
    // Source: gitleaks openai-api-key rule + OpenAI community reports.
    segments: &OPENAI_PROJECT_SEGS,
    salt: OnceLock::new(),
};

const AWS_AKIA_SEGS: [Segment; 2] = [
    Segment::Literal(b"AKIA"),
    Segment::Variable {
        charset: charsets::uppercase_alphanumeric,
        min: 16,
        max: 16,
    },
];
pub(crate) static AWS_AKIA_DEF: Tier1Def = Tier1Def {
    // AKIA<16 uppercase_alphanumeric> = 20 chars total
    segments: &AWS_AKIA_SEGS,
    salt: OnceLock::new(),
};

const AWS_ASIA_SEGS: [Segment; 2] = [
    Segment::Literal(b"ASIA"),
    Segment::Variable {
        charset: charsets::uppercase_alphanumeric,
        min: 16,
        max: 16,
    },
];
pub(crate) static AWS_ASIA_DEF: Tier1Def = Tier1Def {
    // ASIA<16 uppercase_alphanumeric> = 20 chars total
    segments: &AWS_ASIA_SEGS,
    salt: OnceLock::new(),
};

const GITHUB_CLASSIC_SEGS: [Segment; 2] = [
    Segment::Literal(b"ghp_"),
    Segment::Variable {
        charset: charsets::alphanumeric,
        min: 36,
        max: 36,
    },
];
pub(crate) static GITHUB_CLASSIC_DEF: Tier1Def = Tier1Def {
    // ghp_<36 alphanumeric> = 40 chars total
    segments: &GITHUB_CLASSIC_SEGS,
    salt: OnceLock::new(),
};

const GITHUB_FG_SEGS: [Segment; 4] = [
    Segment::Literal(b"github_pat_"),
    Segment::Variable {
        charset: charsets::alphanumeric,
        min: 22,
        max: 22,
    },
    Segment::Literal(b"_"),
    Segment::Variable {
        charset: charsets::alphanumeric,
        min: 59,
        max: 59,
    },
];
pub(crate) static GITHUB_FG_DEF: Tier1Def = Tier1Def {
    // github_pat_<22 alnum>_<59 alnum> = 93 chars total
    // Source: gitleaks `github_pat_\w{82}` (82 = 22 + 1 separator + 59)
    segments: &GITHUB_FG_SEGS,
    salt: OnceLock::new(),
};

const GCP_SEGS: [Segment; 2] = [
    Segment::Literal(b"AIza"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 35,
        max: 35,
    },
];
pub(crate) static GCP_DEF: Tier1Def = Tier1Def {
    // AIza<35 url_safe_base64> = 39 chars total
    segments: &GCP_SEGS,
    salt: OnceLock::new(),
};

const OPENROUTER_SEGS: [Segment; 2] = [
    Segment::Literal(b"sk-or-v1-"),
    Segment::Variable {
        charset: charsets::hex_lower,
        min: 64,
        max: 64,
    },
];
pub(crate) static OPENROUTER_DEF: Tier1Def = Tier1Def {
    // sk-or-v1-<64 hex_lower> = 73 chars total
    // Source: xchecker-dev `sk-or-v1-[0-9a-fA-F]{64}`
    segments: &OPENROUTER_SEGS,
    salt: OnceLock::new(),
};

const OPENAI_SVCACCT_SEGS: [Segment; 4] = [
    Segment::Literal(b"sk-svcacct-"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
    Segment::Literal(b"T3BlbkFJ"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
];
pub(crate) static OPENAI_SVCACCT_DEF: Tier1Def = Tier1Def {
    // sk-svcacct-<58|74>T3BlbkFJ<58|74> = 135 or 167 chars total
    // Source: gitleaks `sk-(?:proj|svcacct|admin)-...T3BlbkFJ...`
    segments: &OPENAI_SVCACCT_SEGS,
    salt: OnceLock::new(),
};

const GOOGLE_OAUTH_SEGS: [Segment; 2] = [
    Segment::Literal(b"GOCSPX-"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 28,
        max: 28,
    },
];
pub(crate) static GOOGLE_OAUTH_SECRET_DEF: Tier1Def = Tier1Def {
    // GOCSPX-<28 url_safe_base64> = 35 chars total
    // Source: secretgate docs "GOCSPX- + 28 chars"
    segments: &GOOGLE_OAUTH_SEGS,
    salt: OnceLock::new(),
};

const SLACK_BOT_SEGS: [Segment; 6] = [
    Segment::Literal(b"xoxb-"),
    Segment::Variable {
        charset: charsets::digits,
        min: 10,
        max: 13,
    },
    Segment::Literal(b"-"),
    Segment::Variable {
        charset: charsets::digits,
        min: 10,
        max: 13,
    },
    Segment::Literal(b"-"),
    Segment::Variable {
        charset: charsets::alphanumeric,
        min: 24,
        max: 24,
    },
];
pub(crate) static SLACK_BOT_DEF: Tier1Def = Tier1Def {
    // xoxb-<10-13 digits>-<10-13 digits>-<24 alnum> = 51-57 chars total
    // Source: gitleaks `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`
    segments: &SLACK_BOT_SEGS,
    salt: OnceLock::new(),
};

const ANTHROPIC_ADMIN01_SEGS: [Segment; 3] = [
    Segment::Literal(b"sk-ant-admin01-"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 93,
        max: 93,
    },
    Segment::Literal(b"AA"),
];
pub(crate) static ANTHROPIC_ADMIN01_DEF: Tier1Def = Tier1Def {
    // sk-ant-admin01-<93 url_safe_base64>AA = 110 chars total
    // Source: gitleaks `sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`
    segments: &ANTHROPIC_ADMIN01_SEGS,
    salt: OnceLock::new(),
};

const ANTHROPIC_ADMIN03_SEGS: [Segment; 3] = [
    Segment::Literal(b"sk-ant-admin03-"),
    Segment::Variable {
        charset: charsets::url_safe_base64,
        min: 93,
        max: 93,
    },
    Segment::Literal(b"AA"),
];
pub(crate) static ANTHROPIC_ADMIN03_DEF: Tier1Def = Tier1Def {
    // sk-ant-admin03-<93 url_safe_base64>AA = 110 chars total
    // Source: Anthropic Terraform provider docs
    segments: &ANTHROPIC_ADMIN03_SEGS,
    salt: OnceLock::new(),
};

const LINEAR_SEGS: [Segment; 2] = [
    Segment::Literal(b"lin_api_"),
    Segment::Variable {
        charset: charsets::alphanumeric,
        min: 40,
        max: 40,
    },
];
pub(crate) static LINEAR_DEF: Tier1Def = Tier1Def {
    // lin_api_<40 alphanumeric> = 48 chars total
    // Source: gitleaks `lin_api_(?i)[a-z0-9]{40}`
    segments: &LINEAR_SEGS,
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
        // INV-22: all built-in classes present in patterns::all()
        let all = patterns::all();
        // Verify by probing each pattern's first Literal segment
        let leading_lits: Vec<&[u8]> = all
            .iter()
            .filter_map(|p| match p {
                Pattern::Tier1(d) => match d.segments.first()? {
                    Segment::Literal(b) => Some(*b),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        for expected in &[
            b"sk-ant-api03-".as_slice(),
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
        ] {
            assert!(
                leading_lits.contains(expected),
                "missing leading literal: {}",
                std::str::from_utf8(expected).unwrap()
            );
        }
    }

    #[test]
    fn test_aws_akia_try_match_returns_capture() {
        let payload = b"access_key: AKIAIOSFODNN7EXAMPLE";
        let akia_pos = payload.windows(4).position(|w| w == b"AKIA").unwrap();
        let cap = AWS_AKIA_DEF.try_match(payload, akia_pos).unwrap();
        assert_eq!(cap.end, akia_pos + 20);
        assert_eq!(cap.variable_lengths, vec![16]);
    }

    #[test]
    fn test_gcp_key_try_match_returns_capture() {
        let payload = b"AIzaSyD-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let cap = GCP_DEF.try_match(payload, 0).unwrap();
        assert_eq!(cap.end, 39);
        assert_eq!(cap.variable_lengths, vec![35]);
    }

    #[test]
    fn test_anthropic_suffix_aa_enforced() {
        // AA suffix must appear; pure A payload still works because A+A == "AA"
        let good = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(ANTHROPIC_DEF.try_match(good, 0).is_some());
        // Payload with wrong suffix (BB) must not match
        let mut bad = good.to_vec();
        let len = bad.len();
        bad[len - 2] = b'B';
        bad[len - 1] = b'B';
        assert!(ANTHROPIC_DEF.try_match(&bad, 0).is_none());
    }

    #[test]
    fn test_openai_project_requires_t3blbkfj() {
        // Must contain T3BlbkFJ at position 8+58 or 8+74
        let good: Vec<u8> = b"sk-proj-"
            .iter()
            .chain(b"B".repeat(58).iter())
            .chain(b"T3BlbkFJ".iter())
            .chain(b"B".repeat(58).iter())
            .copied()
            .collect();
        assert!(OPENAI_PROJECT_DEF.try_match(&good, 0).is_some());

        // Without T3BlbkFJ — should not match
        let bad: Vec<u8> = b"sk-proj-"
            .iter()
            .chain(b"B".repeat(124).iter())
            .copied()
            .collect();
        assert!(OPENAI_PROJECT_DEF.try_match(&bad, 0).is_none());
    }

    #[test]
    fn test_github_fg_requires_underscore_separator() {
        // Must have _ at position 11+22
        let good: Vec<u8> = b"github_pat_"
            .iter()
            .chain(b"A".repeat(22).iter())
            .chain(b"_".iter())
            .chain(b"B".repeat(59).iter())
            .copied()
            .collect();
        assert!(GITHUB_FG_DEF.try_match(&good, 0).is_some());

        // All A's without embedded _ must not match
        let bad: Vec<u8> = b"github_pat_"
            .iter()
            .chain(b"A".repeat(82).iter())
            .copied()
            .collect();
        assert!(GITHUB_FG_DEF.try_match(&bad, 0).is_none());
    }

    #[test]
    fn test_slack_requires_digit_segments() {
        // Valid: digit-digit-alnum
        let good = b"xoxb-1234567890-1234567890-AAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(SLACK_BOT_DEF.try_match(good, 0).is_some());

        // Invalid: letters in digit position
        let bad = b"xoxb-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(SLACK_BOT_DEF.try_match(bad, 0).is_none());
    }

    #[test]
    fn test_prefix_mismatch_returns_none() {
        let payload = b"not-a-key";
        assert!(ANTHROPIC_DEF.try_match(payload, 0).is_none());
    }
}
