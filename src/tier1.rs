use crate::fake::charsets;
use crate::segment::{BuiltinSegment, MatchCapture, Segment};
use crate::tier2::Tier2Pat;
use std::sync::{Arc, LazyLock};

/// Structural definition of a Tier 1 built-in secret class.
#[derive(Clone)]
pub struct Tier1Def {
    /// Stable string identifier for this class, used as the key in patterns files.
    pub(crate) identifier: String,
    /// Ordered sequence of structural segments for this secret class.
    /// See SPEC.md §Tier 1.
    pub(crate) segments: Arc<[Segment]>,
    /// Derivation salt for fake generation. Zero in static template definitions;
    /// set to a real (random or loaded) value when constructing a Pattern.
    pub(crate) salt: [u8; 32],
}

impl Tier1Def {
    /// Walk `payload[pos..]` against the segment list. Returns `Some(MatchCapture)`
    /// on a complete match, `None` otherwise.
    ///
    /// Variable segments try lengths from max down to min (longest-first, INV-18).
    /// When a Variable segment is followed by a Literal, the Literal boundary is
    /// located within the valid Variable range — handling embedded markers like
    /// `T3BlbkFJ` that are themselves valid Variable-charset bytes.
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<MatchCapture> {
        let mut variable_lengths = Vec::new();
        let end = match_segments(payload, pos, &self.segments, &mut variable_lengths)?;
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
            if payload.get(cur..end)? == bytes.as_slice() {
                match_segments(payload, end, &segs[1..], var_lens)
            } else {
                None
            }
        }
        Segment::Variable { charset, min, max } => {
            let cs = charset.resolve();
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

const ANTHROPIC_SEGS: [BuiltinSegment; 3] = [
    BuiltinSegment::Literal(b"sk-ant-api03-"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 93,
        max: 93,
    },
    BuiltinSegment::Literal(b"AA"),
];
static ANTHROPIC_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "anthropic".into(),
    // sk-ant-api03-<93 url_safe_base64>AA = 108 chars total
    // Source: gitleaks `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`
    segments: ANTHROPIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const OPENAI_CLASSIC_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk-"),
    BuiltinSegment::Variable {
        charset: charsets::alphanumeric,
        min: 48,
        max: 48,
    },
];
static OPENAI_CLASSIC_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "openai_classic".into(),
    // sk-<48 alphanumeric> = 51 chars total
    segments: OPENAI_CLASSIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const OPENAI_PROJECT_SEGS: [BuiltinSegment; 4] = [
    BuiltinSegment::Literal(b"sk-proj-"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
    BuiltinSegment::Literal(b"T3BlbkFJ"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
];
static OPENAI_PROJECT_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "openai_project".into(),
    // sk-proj-<58|74 url_safe_b64>T3BlbkFJ<58|74 url_safe_b64> = 132 or 164 chars total.
    // The pre-Aug-2024 56-char format (sk-proj-<48 url_safe_b64>, no T3BlbkFJ) is intentionally
    // not detected: those keys are ~2 years old and structurally indistinguishable from noise
    // without the embedded marker. Best-effort coverage per SPEC.md §Known Limitations.
    // Source: gitleaks openai-api-key rule + OpenAI community reports.
    segments: OPENAI_PROJECT_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const AWS_AKIA_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"AKIA"),
    BuiltinSegment::Variable {
        charset: charsets::uppercase_alphanumeric,
        min: 16,
        max: 16,
    },
];
static AWS_AKIA_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "aws_akia".into(),
    // AKIA<16 uppercase_alphanumeric> = 20 chars total
    segments: AWS_AKIA_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const AWS_ASIA_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ASIA"),
    BuiltinSegment::Variable {
        charset: charsets::uppercase_alphanumeric,
        min: 16,
        max: 16,
    },
];
static AWS_ASIA_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "aws_asia".into(),
    // ASIA<16 uppercase_alphanumeric> = 20 chars total
    segments: AWS_ASIA_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const GITHUB_CLASSIC_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ghp_"),
    BuiltinSegment::Variable {
        charset: charsets::alphanumeric,
        min: 36,
        max: 36,
    },
];
static GITHUB_CLASSIC_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "github_classic".into(),
    // ghp_<36 alphanumeric> = 40 chars total
    segments: GITHUB_CLASSIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const GITHUB_FG_SEGS: [BuiltinSegment; 4] = [
    BuiltinSegment::Literal(b"github_pat_"),
    BuiltinSegment::Variable {
        charset: charsets::alphanumeric,
        min: 22,
        max: 22,
    },
    BuiltinSegment::Literal(b"_"),
    BuiltinSegment::Variable {
        charset: charsets::alphanumeric,
        min: 59,
        max: 59,
    },
];
static GITHUB_FG_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "github_fine_grained".into(),
    // github_pat_<22 alnum>_<59 alnum> = 93 chars total
    // Source: gitleaks `github_pat_\w{82}` (82 = 22 + 1 separator + 59)
    segments: GITHUB_FG_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const GCP_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"AIza"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 35,
        max: 35,
    },
];
static GCP_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "gcp".into(),
    // AIza<35 url_safe_base64> = 39 chars total
    segments: GCP_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const OPENROUTER_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk-or-v1-"),
    BuiltinSegment::Variable {
        charset: charsets::hex_lower,
        min: 64,
        max: 64,
    },
];
static OPENROUTER_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "openrouter".into(),
    // sk-or-v1-<64 hex_lower> = 73 chars total
    // Source: xchecker-dev `sk-or-v1-[0-9a-fA-F]{64}`
    segments: OPENROUTER_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const OPENAI_SVCACCT_SEGS: [BuiltinSegment; 4] = [
    BuiltinSegment::Literal(b"sk-svcacct-"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
    BuiltinSegment::Literal(b"T3BlbkFJ"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 58,
        max: 74,
    },
];
static OPENAI_SVCACCT_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "openai_svcacct".into(),
    // sk-svcacct-<58|74>T3BlbkFJ<58|74> = 135 or 167 chars total
    // Source: gitleaks `sk-(?:proj|svcacct|admin)-...T3BlbkFJ...`
    segments: OPENAI_SVCACCT_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const GOOGLE_OAUTH_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"GOCSPX-"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 28,
        max: 28,
    },
];
static GOOGLE_OAUTH_SECRET_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "google_oauth_secret".into(),
    // GOCSPX-<28 url_safe_base64> = 35 chars total
    // Source: secretgate docs "GOCSPX- + 28 chars"
    segments: GOOGLE_OAUTH_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const SLACK_BOT_SEGS: [BuiltinSegment; 6] = [
    BuiltinSegment::Literal(b"xoxb-"),
    BuiltinSegment::Variable {
        charset: charsets::digits,
        min: 10,
        max: 13,
    },
    BuiltinSegment::Literal(b"-"),
    BuiltinSegment::Variable {
        charset: charsets::digits,
        min: 10,
        max: 13,
    },
    BuiltinSegment::Literal(b"-"),
    BuiltinSegment::Variable {
        charset: charsets::alphanumeric,
        min: 24,
        max: 24,
    },
];
static SLACK_BOT_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "slack_bot".into(),
    // xoxb-<10-13 digits>-<10-13 digits>-<24 alnum> = 51-57 chars total
    // Source: gitleaks `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`
    segments: SLACK_BOT_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const ANTHROPIC_ADMIN01_SEGS: [BuiltinSegment; 3] = [
    BuiltinSegment::Literal(b"sk-ant-admin01-"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 93,
        max: 93,
    },
    BuiltinSegment::Literal(b"AA"),
];
static ANTHROPIC_ADMIN01_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "anthropic_admin01".into(),
    // sk-ant-admin01-<93 url_safe_base64>AA = 110 chars total
    // Source: gitleaks `sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`
    segments: ANTHROPIC_ADMIN01_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const ANTHROPIC_ADMIN03_SEGS: [BuiltinSegment; 3] = [
    BuiltinSegment::Literal(b"sk-ant-admin03-"),
    BuiltinSegment::Variable {
        charset: charsets::url_safe_base64,
        min: 93,
        max: 93,
    },
    BuiltinSegment::Literal(b"AA"),
];
static ANTHROPIC_ADMIN03_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "anthropic_admin03".into(),
    // sk-ant-admin03-<93 url_safe_base64>AA = 110 chars total
    // Source: Anthropic Terraform provider docs
    segments: ANTHROPIC_ADMIN03_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

const LINEAR_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"lin_api_"),
    BuiltinSegment::Variable {
        charset: charsets::alphanumeric,
        min: 40,
        max: 40,
    },
];
static LINEAR_DEF: LazyLock<Tier1Def> = LazyLock::new(|| Tier1Def {
    identifier: "linear".into(),
    // lin_api_<40 alphanumeric> = 48 chars total
    // Source: gitleaks `lin_api_(?i)[a-z0-9]{40}`
    segments: LINEAR_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    salt: [0u8; 32],
});

static ALL_TIER1_DEFS: LazyLock<Vec<&'static Tier1Def>> = LazyLock::new(|| {
    vec![
        &*ANTHROPIC_DEF,
        &*ANTHROPIC_ADMIN01_DEF,
        &*ANTHROPIC_ADMIN03_DEF,
        &*OPENAI_CLASSIC_DEF,
        &*OPENAI_PROJECT_DEF,
        &*OPENAI_SVCACCT_DEF,
        &*AWS_AKIA_DEF,
        &*AWS_ASIA_DEF,
        &*GITHUB_CLASSIC_DEF,
        &*GITHUB_FG_DEF,
        &*GCP_DEF,
        &*OPENROUTER_DEF,
        &*GOOGLE_OAUTH_SECRET_DEF,
        &*SLACK_BOT_DEF,
        &*LINEAR_DEF,
    ]
});

/// Returns references to all 15 built-in Tier 1 definitions.
/// Used by patterns file loading to iterate and inject salts.
pub(crate) fn all_defs() -> &'static [&'static Tier1Def] {
    &ALL_TIER1_DEFS
}

/// A detection descriptor for [`crate::scrub`].
///
/// Obtain via [`patterns`] functions or [`crate::register`]/[`crate::register_with_options`].
/// Pass to [`crate::scrub`] — do not match on variants in stable code; the variant
/// set may change in future versions.
#[derive(Clone)]
#[non_exhaustive]
pub enum Pattern {
    Tier1(Tier1Def),
    Tier2(Arc<Tier2Pat>),
}

/// Built-in Tier 1 patterns. Pass these to scrub() to detect well-known API key formats.
pub mod patterns {
    use super::*;
    use rand::RngCore;
    use rand::rngs::OsRng;

    fn random_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Returns an Anthropic key pattern with an ephemeral salt.
    ///
    /// Fakes are stable for the lifetime of the returned `Pattern` value but differ
    /// across calls and process restarts. For cross-restart stability, use
    /// `PatternsFile::into_patterns()`.
    pub fn anthropic() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..ANTHROPIC_DEF.clone()
        })
    }

    pub fn anthropic_admin01() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..ANTHROPIC_ADMIN01_DEF.clone()
        })
    }

    pub fn anthropic_admin03() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..ANTHROPIC_ADMIN03_DEF.clone()
        })
    }

    pub fn openai_classic() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..OPENAI_CLASSIC_DEF.clone()
        })
    }

    pub fn openai_project() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..OPENAI_PROJECT_DEF.clone()
        })
    }

    pub fn openai_svcacct() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..OPENAI_SVCACCT_DEF.clone()
        })
    }

    pub fn aws_akia() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..AWS_AKIA_DEF.clone()
        })
    }

    pub fn aws_asia() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..AWS_ASIA_DEF.clone()
        })
    }

    pub fn github_classic() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..GITHUB_CLASSIC_DEF.clone()
        })
    }

    pub fn github_fine_grained() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..GITHUB_FG_DEF.clone()
        })
    }

    pub fn gcp() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..GCP_DEF.clone()
        })
    }

    pub fn openrouter() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..OPENROUTER_DEF.clone()
        })
    }

    pub fn google_oauth_secret() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..GOOGLE_OAUTH_SECRET_DEF.clone()
        })
    }

    pub fn slack_bot() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..SLACK_BOT_DEF.clone()
        })
    }

    pub fn linear() -> Pattern {
        Pattern::Tier1(Tier1Def {
            salt: random_salt(),
            ..LINEAR_DEF.clone()
        })
    }

    /// Returns all built-in Tier 1 patterns with ephemeral per-call salts.
    ///
    /// Fakes produced by these patterns are stable within the returned `Vec<Pattern>`
    /// instance but differ across calls to `all()` and across process restarts.
    /// For persistent cross-restart stability, use `PatternsFile::into_patterns()`.
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
    use crate::segment::Segment;

    #[test]
    fn test_tier1_all_classes_present() {
        // INV-22: all built-in classes present in patterns::all()
        let all = patterns::all();
        // Verify by probing each pattern's first Literal segment
        let leading_lits: Vec<&[u8]> = all
            .iter()
            .filter_map(|p| match p {
                Pattern::Tier1(d) => match d.segments.first()? {
                    Segment::Literal(b) => Some(b.as_slice()),
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

    #[test]
    fn test_all_defs_identifiers_unique() {
        let defs = all_defs();
        assert_eq!(defs.len(), 15, "must have 15 built-in Tier 1 defs");
        let mut ids: Vec<&str> = defs.iter().map(|d| d.identifier.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 15, "all identifiers must be unique");
    }

    #[test]
    fn test_all_defs_matches_all_patterns() {
        let defs = all_defs();
        let all = patterns::all();
        assert_eq!(
            defs.len(),
            all.len(),
            "all_defs and patterns::all must have same count"
        );
        for def in defs {
            assert!(
                all.iter()
                    .any(|p| matches!(p, Pattern::Tier1(d) if d.identifier == def.identifier)),
                "all_defs entry {} must appear in patterns::all()",
                def.identifier
            );
        }
    }
}
