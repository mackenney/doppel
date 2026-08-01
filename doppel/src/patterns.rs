//! Built-in structural patterns and per-call constructor functions.
//!
//! Each `pub fn` in this module returns a [`Pattern`] with an ephemeral salt.
//! For persistent cross-restart fake stability, use [`crate::SecretsFile::to_patterns`].

use crate::segment::{BuiltinSegment, CharsetName, MatchCapture, Segment};
use aho_corasick::AhoCorasick;
use std::sync::{Arc, LazyLock};

/// Internal structural definition used as a static template for built-in patterns.
/// Holds the identifier and segment list; salt is supplied by the per-call constructor.
#[derive(Clone)]
pub(crate) struct StructuralDef {
    /// Stable string identifier for this class, used as the key in patterns files.
    pub(crate) identifier: String,
    /// Ordered sequence of structural segments for this secret class.
    /// See SPEC.md §Structural Patterns.
    pub(crate) segments: Arc<[Segment]>,
    /// Optional trailing run guard threshold in bytes (SPEC §Trailing Run Guard).
    /// `None` = unconditional detection (Behavioral Invariants item 48).
    pub(crate) trailing_run_guard: Option<usize>,
}

#[cfg(test)]
impl StructuralDef {
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
                if payload[cur..end].iter().all(|&b| cs.contains(b)) {
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
        Segment::Opaque { value, .. } => {
            let end = cur + value.len();
            if payload.get(cur..end)? == value.as_slice() {
                match_segments(payload, end, &segs[1..], var_lens)
            } else {
                None
            }
        }
    }
}

/// Charset of the last Variable segment in `segs`. `None` if none exists.
/// Used by `Pattern::last_variable_charset`, which `swap::guard_fires` calls
/// on every winning match to resolve the trailing-run guard's charset.
fn last_variable_charset(segs: &[Segment]) -> Option<CharsetName> {
    segs.iter().rev().find_map(|s| match s {
        Segment::Variable { charset, .. } => Some(*charset),
        _ => None,
    })
}

// Note on sk-proj- vs sk-: at a "sk-proj-..." position, OPENAI_PROJECT_DEF produces a longer
// match because it finds T3BlbkFJ at the correct offset; OPENAI_CLASSIC_DEF fails because
// 'proj-' contains '-' which is not alphanumeric. The swap engine picks the longest match (INV-18).

const ANTHROPIC_SEGS: [BuiltinSegment; 3] = [
    BuiltinSegment::Literal(b"sk-ant-api03-"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 93,
        max: 93,
    },
    BuiltinSegment::Literal(b"AA"),
];
static ANTHROPIC_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "anthropic".into(),
    // sk-ant-api03-<93 url_safe_base64>AA = 108 chars total
    // Source: gitleaks `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`
    segments: ANTHROPIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const OPENAI_CLASSIC_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk-"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 48,
        max: 48,
    },
];
static OPENAI_CLASSIC_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "openai_classic".into(),
    // sk-<48 alphanumeric> = 51 chars total
    segments: OPENAI_CLASSIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const OPENAI_PROJECT_SEGS: [BuiltinSegment; 4] = [
    BuiltinSegment::Literal(b"sk-proj-"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 58,
        max: 74,
    },
    BuiltinSegment::Literal(b"T3BlbkFJ"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 58,
        max: 74,
    },
];
static OPENAI_PROJECT_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
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
    trailing_run_guard: None,
});

const AWS_AKIA_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"AKIA"),
    BuiltinSegment::Variable {
        charset: CharsetName::UppercaseAlphanumeric,
        min: 16,
        max: 16,
    },
];
static AWS_AKIA_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "aws_akia".into(),
    // AKIA<16 uppercase_alphanumeric> = 20 chars total
    segments: AWS_AKIA_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const AWS_ASIA_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ASIA"),
    BuiltinSegment::Variable {
        charset: CharsetName::UppercaseAlphanumeric,
        min: 16,
        max: 16,
    },
];
static AWS_ASIA_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "aws_asia".into(),
    // ASIA<16 uppercase_alphanumeric> = 20 chars total
    segments: AWS_ASIA_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GITHUB_CLASSIC_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ghp_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 36,
        max: 36,
    },
];
static GITHUB_CLASSIC_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "github_classic".into(),
    // ghp_<36 alphanumeric> = 40 chars total
    segments: GITHUB_CLASSIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GITHUB_FG_SEGS: [BuiltinSegment; 4] = [
    BuiltinSegment::Literal(b"github_pat_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 22,
        max: 22,
    },
    BuiltinSegment::Literal(b"_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 59,
        max: 59,
    },
];
static GITHUB_FG_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "github_fine_grained".into(),
    // github_pat_<22 alnum>_<59 alnum> = 93 chars total
    // Source: gitleaks `github_pat_\w{82}` (82 = 22 + 1 separator + 59)
    segments: GITHUB_FG_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

/// GCP guard threshold: a genuine standalone key is delimited by structural
/// context (quote, whitespace, punctuation) within tens of bytes of its end;
/// base64-encoded binary blobs (the false-positive source) run uninterrupted
/// for far longer — real-world screenshot uploads observed at 15–400 KB.
/// 2048 is a deliberately coarse point in the wide gap between those two
/// regimes: ~2 orders of magnitude above real-key trailing contexts, well
/// below observed blob sizes, and it bounds probe cost at 2KB per candidate
/// (candidates occur ~once per 16.7MB of uniform base64).
pub(crate) const GCP_TRAILING_RUN_GUARD: usize = 2048;

const GCP_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"AIza"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 35,
        max: 35,
    },
];
static GCP_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "gcp".into(),
    // AIza<35 url_safe_base64> = 39 chars total
    segments: GCP_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: Some(GCP_TRAILING_RUN_GUARD),
});

const OPENROUTER_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk-or-v1-"),
    BuiltinSegment::Variable {
        charset: CharsetName::HexLower,
        min: 64,
        max: 64,
    },
];
static OPENROUTER_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "openrouter".into(),
    // sk-or-v1-<64 hex_lower> = 73 chars total
    // Source: xchecker-dev `sk-or-v1-[0-9a-fA-F]{64}` — pattern uses lowercase-only
    // (HexLower); uppercase hex not observed in OpenRouter keys in practice.
    segments: OPENROUTER_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const OPENAI_SVCACCT_SEGS: [BuiltinSegment; 4] = [
    BuiltinSegment::Literal(b"sk-svcacct-"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 58,
        max: 74,
    },
    BuiltinSegment::Literal(b"T3BlbkFJ"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 58,
        max: 74,
    },
];
static OPENAI_SVCACCT_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "openai_svcacct".into(),
    // sk-svcacct-<58|74>T3BlbkFJ<58|74> = 135 or 167 chars total
    // Source: gitleaks `sk-(?:proj|svcacct|admin)-...T3BlbkFJ...`
    segments: OPENAI_SVCACCT_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GOOGLE_OAUTH_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"GOCSPX-"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 28,
        max: 28,
    },
];
static GOOGLE_OAUTH_SECRET_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "google_oauth_secret".into(),
    // GOCSPX-<28 url_safe_base64> = 35 chars total
    // Source: secretgate docs "GOCSPX- + 28 chars"
    segments: GOOGLE_OAUTH_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const SLACK_BOT_SEGS: [BuiltinSegment; 6] = [
    BuiltinSegment::Literal(b"xoxb-"),
    BuiltinSegment::Variable {
        charset: CharsetName::Digits,
        min: 10,
        max: 13,
    },
    BuiltinSegment::Literal(b"-"),
    BuiltinSegment::Variable {
        charset: CharsetName::Digits,
        min: 10,
        max: 13,
    },
    BuiltinSegment::Literal(b"-"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 24,
        max: 24,
    },
];
static SLACK_BOT_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "slack_bot".into(),
    // xoxb-<10-13 digits>-<10-13 digits>-<24 alnum> = 51-57 chars total
    // Source: gitleaks `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`
    segments: SLACK_BOT_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const ANTHROPIC_ADMIN01_SEGS: [BuiltinSegment; 3] = [
    BuiltinSegment::Literal(b"sk-ant-admin01-"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 93,
        max: 93,
    },
    BuiltinSegment::Literal(b"AA"),
];
static ANTHROPIC_ADMIN01_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "anthropic_admin01".into(),
    // sk-ant-admin01-<93 url_safe_base64>AA = 110 chars total
    // Source: gitleaks `sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`
    segments: ANTHROPIC_ADMIN01_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const ANTHROPIC_ADMIN03_SEGS: [BuiltinSegment; 3] = [
    BuiltinSegment::Literal(b"sk-ant-admin03-"),
    BuiltinSegment::Variable {
        charset: CharsetName::UrlSafeBase64,
        min: 93,
        max: 93,
    },
    BuiltinSegment::Literal(b"AA"),
];
static ANTHROPIC_ADMIN03_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "anthropic_admin03".into(),
    // sk-ant-admin03-<93 url_safe_base64>AA = 110 chars total
    // Source: Anthropic Terraform provider docs
    segments: ANTHROPIC_ADMIN03_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const LINEAR_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"lin_api_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 40,
        max: 40,
    },
];
static LINEAR_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "linear".into(),
    // lin_api_<40 alphanumeric> = 48 chars total
    // Source: gitleaks `lin_api_(?i)[a-z0-9]{40}`
    segments: LINEAR_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GROQ_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"gsk_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 52,
        max: 52,
    },
];
static GROQ_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "groq".into(),
    // gsk_<52 alphanumeric> = 56 chars total
    // Source: gitleaks groq api key rule
    segments: GROQ_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const PERPLEXITY_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"pplx-"),
    BuiltinSegment::Variable {
        charset: CharsetName::HexLower,
        min: 48,
        max: 48,
    },
];
static PERPLEXITY_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "perplexity".into(),
    // pplx-<48 hex_lower> = 53 chars total
    segments: PERPLEXITY_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const CEREBRAS_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"csk-"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 48,
        max: 48,
    },
];
static CEREBRAS_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "cerebras".into(),
    // csk-<48 alphanumeric> = 52 chars total
    segments: CEREBRAS_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const STRIPE_LIVE_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk_live_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 24,
        max: 32,
    },
];
static STRIPE_LIVE_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "stripe_live".into(),
    // sk_live_<24-32 alphanumeric> = 32-40 chars total
    // Source: Stripe docs, gitleaks stripe_sk rule
    segments: STRIPE_LIVE_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const STRIPE_TEST_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk_test_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 24,
        max: 32,
    },
];
static STRIPE_TEST_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "stripe_test".into(),
    // sk_test_<24-32 alphanumeric> = 32-40 chars total
    segments: STRIPE_TEST_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const CLERK_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"sk_live_"),
    // Clerk live keys are longer than Stripe; length difference distinguishes them.
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 45,
        max: 55,
    },
];
static CLERK_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "clerk".into(),
    // sk_live_<45-55 alphanumeric> = 53-63 chars total
    // Shares prefix with stripe_live; longer variable range distinguishes them.
    segments: CLERK_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const SVIX_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"svix_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 30,
        max: 50,
    },
];
static SVIX_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "svix".into(),
    // svix_<30-50 alphanumeric>
    segments: SVIX_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const CHROMATIC_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"chpt_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 30,
        max: 50,
    },
];
static CHROMATIC_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "chromatic".into(),
    // chpt_<30-50 alphanumeric>
    segments: CHROMATIC_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GITHUB_OAUTH_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"gho_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 36,
        max: 36,
    },
];
static GITHUB_OAUTH_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "github_oauth".into(),
    // gho_<36 alphanumeric> = 40 chars total
    // Source: GitHub docs on token formats (GitHub OAuth token)
    segments: GITHUB_OAUTH_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GITHUB_APP_SERVER_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ghs_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 36,
        max: 36,
    },
];
static GITHUB_APP_SERVER_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "github_app_server".into(),
    // ghs_<36 alphanumeric> = 40 chars total
    // Source: GitHub docs — GitHub App server-to-server token
    segments: GITHUB_APP_SERVER_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GITHUB_APP_USER_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ghu_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 36,
        max: 36,
    },
];
static GITHUB_APP_USER_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "github_app_user".into(),
    // ghu_<36 alphanumeric> = 40 chars total
    // Source: GitHub docs — GitHub App user-to-server token
    segments: GITHUB_APP_USER_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});

const GITHUB_REFRESH_SEGS: [BuiltinSegment; 2] = [
    BuiltinSegment::Literal(b"ghr_"),
    BuiltinSegment::Variable {
        charset: CharsetName::Alphanumeric,
        min: 36,
        max: 76,
    },
];
static GITHUB_REFRESH_DEF: LazyLock<StructuralDef> = LazyLock::new(|| StructuralDef {
    identifier: "github_refresh".into(),
    // ghr_<36-76 alphanumeric> = 40-80 chars total
    // Source: GitHub docs — GitHub App refresh token
    segments: GITHUB_REFRESH_SEGS
        .iter()
        .map(Segment::from)
        .collect::<Vec<_>>()
        .into(),
    trailing_run_guard: None,
});
static ALL_STRUCTURAL_DEFS: LazyLock<Vec<&'static StructuralDef>> = LazyLock::new(|| {
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
        &*GROQ_DEF,
        &*PERPLEXITY_DEF,
        &*CEREBRAS_DEF,
        &*STRIPE_LIVE_DEF,
        &*STRIPE_TEST_DEF,
        &*CLERK_DEF,
        &*SVIX_DEF,
        &*CHROMATIC_DEF,
        &*GITHUB_OAUTH_DEF,
        &*GITHUB_APP_SERVER_DEF,
        &*GITHUB_APP_USER_DEF,
        &*GITHUB_REFRESH_DEF,
    ]
});

/// Returns references to all 27 built-in structural pattern definitions.
/// Used by patterns file loading to iterate and inject salts.
pub(crate) fn all_defs() -> &'static [&'static StructuralDef] {
    &ALL_STRUCTURAL_DEFS
}

/// Build an Aho-Corasick automaton from the first-segment bytes of each pattern.
///
/// Patterns whose first segment is `literal` or `opaque` contribute their value bytes
/// as AC keywords. Patterns with a `variable` first segment are excluded; this cannot
/// occur in practice because the First-Segment Invariant (SPEC.md §First-Segment
/// Invariant) requires every Pattern to start with a `literal` or `opaque` segment,
/// enforced at load and registration time.
pub(crate) fn build_ac_automaton(patterns: &[Pattern]) -> AhoCorasick {
    let prefixes: Vec<&[u8]> = patterns
        .iter()
        .filter_map(|p| p.first_segment_bytes())
        .collect();
    AhoCorasick::new(&prefixes).expect("AC build should not fail for valid patterns")
}

/// Unified detection descriptor for both family and instance patterns.
///
/// Obtain via [`crate::patterns`] functions or [`crate::register`]/[`crate::register_with_options`].
/// Pass to [`crate::swap`].
///
/// - Family pattern (`digests` is empty): matches any candidate satisfying the segment list.
/// - Instance/group pattern (`digests` is non-empty): additionally requires HMAC verification.
#[derive(Clone)]
pub struct Pattern {
    /// Unique identifier for this pattern (e.g., "anthropic", "prod-credentials").
    pub(crate) identifier: String,
    /// Ordered segment list defining detection structure.
    pub(crate) segments: Arc<[Segment]>,
    /// 32-byte salt for HMAC computation and fake derivation.
    pub(crate) salt: [u8; 32],
    /// HMAC digests; empty = family pattern, non-empty = instance/group pattern.
    pub(crate) digests: Vec<[u8; 32]>,
    /// Opt-in trailing run guard threshold in bytes (SPEC §Trailing Run Guard).
    /// `None` (the default for every constructor except [`gcp`]) preserves
    /// unconditional detection (Behavioral Invariants item 48); `Some(n)`
    /// suppresses the winning match when at least `n` trailing bytes belong
    /// to its variable segment's charset.
    pub(crate) trailing_run_guard: Option<usize>,
}

impl Pattern {
    /// Returns the string identifier for this pattern (e.g. `"anthropic"`, `"prod-db"`).
    pub fn id(&self) -> &str {
        &self.identifier
    }

    /// Returns true if the first segment is a Literal (for INV-18 tiebreaker precedence).
    pub(crate) fn first_segment_is_literal(&self) -> bool {
        matches!(self.segments.first(), Some(Segment::Literal(_)))
    }

    /// Returns the first segment's anchor bytes for AC automaton building.
    /// Returns `None` for patterns whose first segment has no fixed prefix bytes.
    pub(crate) fn first_segment_bytes(&self) -> Option<&[u8]> {
        match self.segments.first() {
            Some(Segment::Literal(bytes)) => Some(bytes),
            Some(Segment::Opaque { value, .. }) => Some(value),
            _ => None,
        }
    }

    /// Charset of the last Variable segment — the guard charset per
    /// Behavioral Invariants item 45. `None` if no Variable segment exists.
    pub(crate) fn last_variable_charset(&self) -> Option<CharsetName> {
        last_variable_charset(&self.segments)
    }

    /// Attempt to match this pattern against the payload at the given position.
    ///
    /// For family patterns (empty digests): returns a match on segment success alone.
    /// For instance patterns (non-empty digests): additionally requires HMAC verification
    /// against one of the stored digests (INV-16: HMAC failure → pass through unchanged).
    pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<MatchCapture> {
        let mut variable_lengths = Vec::new();
        let end = match_segments(payload, pos, &self.segments, &mut variable_lengths)?;

        if !self.digests.is_empty() {
            let candidate = &payload[pos..end];
            // SPEC §Detection Algorithm step 4: compute HMAC once, compare against each digest
            // in constant time. Accumulate in subtle::Choice throughout the fold to prevent
            // the optimizer from eliding ct_eq calls once a match is found; convert to bool
            // only after all digests have been evaluated.
            use subtle::{Choice, ConstantTimeEq};
            let computed_hmac = crate::crypto::hmac_sha256(&self.salt, candidate);
            let matches_any =
                bool::from(self.digests.iter().fold(Choice::from(0u8), |acc, digest| {
                    acc | computed_hmac.ct_eq(digest)
                }));
            if !matches_any {
                return None;
            }
        }

        Some(MatchCapture {
            end,
            variable_lengths,
        })
    }
}

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
/// `SecretsFile::to_patterns()`.
pub fn anthropic() -> Pattern {
    Pattern {
        identifier: ANTHROPIC_DEF.identifier.clone(),
        segments: ANTHROPIC_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: ANTHROPIC_DEF.trailing_run_guard,
    }
}

/// Returns an Anthropic Admin v1 key pattern (`sk-ant-admin01-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn anthropic_admin01() -> Pattern {
    Pattern {
        identifier: ANTHROPIC_ADMIN01_DEF.identifier.clone(),
        segments: ANTHROPIC_ADMIN01_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: ANTHROPIC_ADMIN01_DEF.trailing_run_guard,
    }
}

/// Returns an Anthropic Admin v3 key pattern (`sk-ant-admin03-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn anthropic_admin03() -> Pattern {
    Pattern {
        identifier: ANTHROPIC_ADMIN03_DEF.identifier.clone(),
        segments: ANTHROPIC_ADMIN03_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: ANTHROPIC_ADMIN03_DEF.trailing_run_guard,
    }
}

/// Returns an OpenAI classic secret key pattern (`sk-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn openai_classic() -> Pattern {
    Pattern {
        identifier: OPENAI_CLASSIC_DEF.identifier.clone(),
        segments: OPENAI_CLASSIC_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: OPENAI_CLASSIC_DEF.trailing_run_guard,
    }
}

/// Returns an OpenAI project key pattern (`sk-proj-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn openai_project() -> Pattern {
    Pattern {
        identifier: OPENAI_PROJECT_DEF.identifier.clone(),
        segments: OPENAI_PROJECT_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: OPENAI_PROJECT_DEF.trailing_run_guard,
    }
}

/// Returns an OpenAI service account key pattern (`sk-svcacct-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn openai_svcacct() -> Pattern {
    Pattern {
        identifier: OPENAI_SVCACCT_DEF.identifier.clone(),
        segments: OPENAI_SVCACCT_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: OPENAI_SVCACCT_DEF.trailing_run_guard,
    }
}

/// Returns an AWS IAM access key ID pattern (`AKIA`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn aws_akia() -> Pattern {
    Pattern {
        identifier: AWS_AKIA_DEF.identifier.clone(),
        segments: AWS_AKIA_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: AWS_AKIA_DEF.trailing_run_guard,
    }
}

/// Returns an AWS STS temporary credential pattern (`ASIA`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn aws_asia() -> Pattern {
    Pattern {
        identifier: AWS_ASIA_DEF.identifier.clone(),
        segments: AWS_ASIA_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: AWS_ASIA_DEF.trailing_run_guard,
    }
}

/// Returns a GitHub classic personal access token pattern (`ghp_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn github_classic() -> Pattern {
    Pattern {
        identifier: GITHUB_CLASSIC_DEF.identifier.clone(),
        segments: GITHUB_CLASSIC_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GITHUB_CLASSIC_DEF.trailing_run_guard,
    }
}

/// Returns a GitHub fine-grained personal access token pattern (`github_pat_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn github_fine_grained() -> Pattern {
    Pattern {
        identifier: GITHUB_FG_DEF.identifier.clone(),
        segments: GITHUB_FG_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GITHUB_FG_DEF.trailing_run_guard,
    }
}

/// Returns a GCP/Gemini API key pattern (`AIza`) with an ephemeral salt.
///
/// Ships with a trailing run guard (SPEC §Trailing Run Guard) by default: its
/// 4-byte prefix and single base64-charset variable region is the
/// statistically weakest structure in the built-in set against large
/// base64-encoded payloads (SPEC §Built-in Family Patterns). To remove the
/// guard, load patterns from a patterns file and delete the
/// `trailing_run_guard` key from the `gcp` entry.
///
/// See [`anthropic`] for salt stability semantics.
pub fn gcp() -> Pattern {
    Pattern {
        identifier: GCP_DEF.identifier.clone(),
        segments: GCP_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GCP_DEF.trailing_run_guard,
    }
}

/// Returns an OpenRouter API key pattern (`sk-or-v1-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn openrouter() -> Pattern {
    Pattern {
        identifier: OPENROUTER_DEF.identifier.clone(),
        segments: OPENROUTER_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: OPENROUTER_DEF.trailing_run_guard,
    }
}

/// Returns a Google OAuth client secret pattern (`GOCSPX-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn google_oauth_secret() -> Pattern {
    Pattern {
        identifier: GOOGLE_OAUTH_SECRET_DEF.identifier.clone(),
        segments: GOOGLE_OAUTH_SECRET_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GOOGLE_OAUTH_SECRET_DEF.trailing_run_guard,
    }
}

/// Returns a Slack bot token pattern (`xoxb-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn slack_bot() -> Pattern {
    Pattern {
        identifier: SLACK_BOT_DEF.identifier.clone(),
        segments: SLACK_BOT_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: SLACK_BOT_DEF.trailing_run_guard,
    }
}

/// Returns a Linear API key pattern (`lin_api_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn linear() -> Pattern {
    Pattern {
        identifier: LINEAR_DEF.identifier.clone(),
        segments: LINEAR_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: LINEAR_DEF.trailing_run_guard,
    }
}

/// Returns a Groq API key pattern (`gsk_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn groq() -> Pattern {
    Pattern {
        identifier: GROQ_DEF.identifier.clone(),
        segments: GROQ_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GROQ_DEF.trailing_run_guard,
    }
}

/// Returns a Perplexity API key pattern (`pplx-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn perplexity() -> Pattern {
    Pattern {
        identifier: PERPLEXITY_DEF.identifier.clone(),
        segments: PERPLEXITY_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: PERPLEXITY_DEF.trailing_run_guard,
    }
}

/// Returns a Cerebras API key pattern (`csk-`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn cerebras() -> Pattern {
    Pattern {
        identifier: CEREBRAS_DEF.identifier.clone(),
        segments: CEREBRAS_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: CEREBRAS_DEF.trailing_run_guard,
    }
}

/// Returns a Stripe live secret key pattern (`sk_live_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn stripe_live() -> Pattern {
    Pattern {
        identifier: STRIPE_LIVE_DEF.identifier.clone(),
        segments: STRIPE_LIVE_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: STRIPE_LIVE_DEF.trailing_run_guard,
    }
}

/// Returns a Stripe test secret key pattern (`sk_test_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn stripe_test() -> Pattern {
    Pattern {
        identifier: STRIPE_TEST_DEF.identifier.clone(),
        segments: STRIPE_TEST_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: STRIPE_TEST_DEF.trailing_run_guard,
    }
}

/// Returns a Clerk live secret key pattern (`sk_live_`) with an ephemeral salt.
///
/// Clerk live keys share the `sk_live_` prefix with Stripe; the longer variable
/// segment (45–55 chars vs Stripe's 24–32) distinguishes them at detection time.
/// See [`anthropic`] for salt stability semantics.
pub fn clerk() -> Pattern {
    Pattern {
        identifier: CLERK_DEF.identifier.clone(),
        segments: CLERK_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: CLERK_DEF.trailing_run_guard,
    }
}

/// Returns a Svix API key pattern (`svix_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn svix() -> Pattern {
    Pattern {
        identifier: SVIX_DEF.identifier.clone(),
        segments: SVIX_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: SVIX_DEF.trailing_run_guard,
    }
}

/// Returns a Chromatic project token pattern (`chpt_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn chromatic() -> Pattern {
    Pattern {
        identifier: CHROMATIC_DEF.identifier.clone(),
        segments: CHROMATIC_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: CHROMATIC_DEF.trailing_run_guard,
    }
}

/// Returns a GitHub OAuth token pattern (`gho_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn github_oauth() -> Pattern {
    Pattern {
        identifier: GITHUB_OAUTH_DEF.identifier.clone(),
        segments: GITHUB_OAUTH_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GITHUB_OAUTH_DEF.trailing_run_guard,
    }
}

/// Returns a GitHub App server-to-server token pattern (`ghs_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn github_app_server() -> Pattern {
    Pattern {
        identifier: GITHUB_APP_SERVER_DEF.identifier.clone(),
        segments: GITHUB_APP_SERVER_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GITHUB_APP_SERVER_DEF.trailing_run_guard,
    }
}

/// Returns a GitHub App user-to-server token pattern (`ghu_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn github_app_user() -> Pattern {
    Pattern {
        identifier: GITHUB_APP_USER_DEF.identifier.clone(),
        segments: GITHUB_APP_USER_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GITHUB_APP_USER_DEF.trailing_run_guard,
    }
}

/// Returns a GitHub App refresh token pattern (`ghr_`) with an ephemeral salt.
///
/// See [`anthropic`] for salt stability semantics.
pub fn github_refresh() -> Pattern {
    Pattern {
        identifier: GITHUB_REFRESH_DEF.identifier.clone(),
        segments: GITHUB_REFRESH_DEF.segments.clone(),
        salt: random_salt(),
        digests: vec![],
        trailing_run_guard: GITHUB_REFRESH_DEF.trailing_run_guard,
    }
}

/// Returns all built-in structural patterns with ephemeral per-call salts.
///
/// Fakes produced by these patterns are stable within the returned `Vec<Pattern>`
/// instance but differ across calls to `all()` and across process restarts.
/// For persistent cross-restart stability, use `SecretsFile::to_patterns()`.
///
/// Covers: Anthropic API (`sk-ant-api03-`), Anthropic Admin (`sk-ant-admin01-`,
/// `sk-ant-admin03-`), OpenAI classic (`sk-`), OpenAI project (`sk-proj-`),
/// OpenAI service account (`sk-svcacct-`), AWS AKIA/ASIA, GitHub classic/fine-grained/
/// OAuth (`gho_`)/app-server (`ghs_`)/app-user (`ghu_`)/refresh (`ghr_`),
/// GCP/Gemini (`AIza`), OpenRouter (`sk-or-v1-`), Google OAuth secret (`GOCSPX-`),
/// Slack bot (`xoxb-`), Linear (`lin_api_`), Groq (`gsk_`), Perplexity (`pplx-`),
/// Cerebras (`csk-`), Stripe live/test (`sk_live_`/`sk_test_`), Clerk (`sk_live_`),
/// Svix (`svix_`), Chromatic (`chpt_`).
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
        groq(),
        perplexity(),
        cerebras(),
        stripe_live(),
        stripe_test(),
        clerk(),
        svix(),
        chromatic(),
        github_oauth(),
        github_app_server(),
        github_app_user(),
        github_refresh(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::Segment;

    #[test]
    fn test_structural_all_classes_present() {
        // INV-22: all built-in classes present in patterns::all()
        let all = all();
        // Verify by probing each pattern's first Literal segment
        let leading_lits: Vec<&[u8]> = all
            .iter()
            .filter_map(|p| match p.segments.first() {
                Some(Segment::Literal(b)) => Some(b.as_slice()),
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
            b"gsk_",
            b"pplx-",
            b"csk-",
            b"sk_live_",
            b"sk_test_",
            b"svix_",
            b"chpt_",
            b"gho_",
            b"ghs_",
            b"ghu_",
            b"ghr_",
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
        assert_eq!(defs.len(), 27, "must have 27 built-in structural defs");
        let mut ids: Vec<&str> = defs.iter().map(|d| d.identifier.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 27, "all identifiers must be unique");
    }

    #[test]
    fn test_all_defs_matches_all_patterns() {
        let defs = all_defs();
        let all = all();
        assert_eq!(
            defs.len(),
            all.len(),
            "all_defs and patterns::all must have same count"
        );
        for def in defs {
            assert!(
                all.iter().any(|p| p.identifier == def.identifier),
                "all_defs entry {} must appear in patterns::all()",
                def.identifier
            );
        }
    }

    #[test]
    fn test_gcp_has_trailing_run_guard_default_others_none() {
        for p in all() {
            if p.identifier == "gcp" {
                assert_eq!(p.trailing_run_guard, Some(GCP_TRAILING_RUN_GUARD));
            } else {
                assert_eq!(
                    p.trailing_run_guard, None,
                    "{} must not have a trailing_run_guard",
                    p.identifier
                );
            }
        }
    }

    #[test]
    fn test_gcp_trailing_run_guard_is_2048() {
        assert_eq!(gcp().trailing_run_guard, Some(2048));
    }

    /// Every built-in def with a guard must have at least one Variable segment
    /// (a guard on a fixed-length pattern is meaningless).
    #[test]
    fn assert_builtin_guards_valid() {
        for def in all_defs() {
            if def.trailing_run_guard.is_some() {
                assert!(
                    last_variable_charset(&def.segments).is_some(),
                    "{} has a trailing_run_guard but no Variable segment",
                    def.identifier
                );
            }
        }
    }

    #[test]
    fn test_last_variable_charset_returns_last_of_multiple() {
        let segs: Arc<[Segment]> = vec![
            Segment::Literal(b"prefix-".to_vec()),
            Segment::Variable {
                charset: CharsetName::Digits,
                min: 4,
                max: 4,
            },
            Segment::Literal(b"-mid-".to_vec()),
            Segment::Variable {
                charset: CharsetName::HexLower,
                min: 8,
                max: 8,
            },
        ]
        .into();
        let def = StructuralDef {
            identifier: "test_multi_variable".into(),
            segments: segs,
            trailing_run_guard: None,
        };
        assert_eq!(
            last_variable_charset(&def.segments),
            Some(CharsetName::HexLower)
        );

        let pattern = Pattern {
            identifier: def.identifier.clone(),
            segments: def.segments.clone(),
            salt: random_salt(),
            digests: vec![],
            trailing_run_guard: def.trailing_run_guard,
        };
        assert_eq!(pattern.last_variable_charset(), Some(CharsetName::HexLower));
    }
}
