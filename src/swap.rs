use std::collections::HashMap;

use crate::crypto::encrypt_secret;
use crate::crypto::generate_session_key;
use crate::fake::FakeError;
use crate::patterns::{Pattern, StructuralDef, prefix_filter};
use crate::secrets::RegisteredPat;
use crate::types::{Entry, SwapError, SwapResult};

struct Match<'a> {
    start: usize,
    end: usize,
    is_structural: bool,
    pattern_ref: PatternRef<'a>,
    structural_capture: Option<crate::segment::MatchCapture>,
    derived_fake: Option<Vec<u8>>,
}

enum PatternRef<'a> {
    Tier1(&'a StructuralDef),
    Tier2(&'a RegisteredPat),
}

fn find_best_match<'a>(
    payload: &[u8],
    pos: usize,
    patterns: &'a [Pattern],
) -> Result<Option<Match<'a>>, FakeError> {
    let mut best: Option<Match<'a>> = None;

    for pattern in patterns {
        let candidate = match pattern {
            Pattern::Structural(def) => def.try_match(payload, pos).map(|capture| Match {
                start: pos,
                end: capture.end,
                is_structural: true,
                pattern_ref: PatternRef::Tier1(def),
                structural_capture: Some(capture),
                derived_fake: None,
            }),
            Pattern::Registered(arc) => arc.try_match(payload, pos)?.map(|(end, fake)| Match {
                start: pos,
                end,
                is_structural: false,
                pattern_ref: PatternRef::Tier2(arc.as_ref()),
                structural_capture: None,
                derived_fake: Some(fake),
            }),
        };

        if let Some(candidate) = candidate {
            best = Some(match best {
                None => candidate,
                Some(b) if candidate.end > b.end => candidate,
                // Tier1 wins on tie (INV-18)
                Some(b)
                    if candidate.end == b.end && candidate.is_structural && !b.is_structural =>
                {
                    candidate
                }
                Some(b) => b,
            });
        }
    }

    Ok(best)
}

fn generate_fake_for_match(m: &Match<'_>, secret: &[u8]) -> Result<Vec<u8>, FakeError> {
    match &m.pattern_ref {
        PatternRef::Tier1(def) => {
            let capture = m
                .structural_capture
                .as_ref()
                .expect("Tier1 match always has a capture");
            crate::fake::derive_fake_structural_segments(
                &def.salt,
                &def.segments,
                &capture.variable_lengths,
                secret,
            )
        }
        PatternRef::Tier2(_pat) => Ok(m
            .derived_fake
            .clone()
            .expect("registered match must have derived_fake")),
    }
}

/// Scan `payload` for secrets matching `patterns`, replace each with a
/// structurally-equivalent fake, and return the swapped payload, encrypted
/// entries, and a fresh session key.
///
/// # Examples
///
/// ```
/// use doppel::{swap, patterns};
///
/// let payload = b"key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let result = swap(payload, &patterns::all()).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// assert_ne!(result.payload, payload.to_vec());
/// ```
pub fn swap(payload: &[u8], patterns: &[Pattern]) -> Result<SwapResult, SwapError> {
    let session_key = generate_session_key();
    let mut output = Vec::with_capacity(payload.len());
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: HashMap<&[u8], usize> = HashMap::new();
    let mut pos = 0;
    let has_registered = patterns.iter().any(|p| p.is_registered());

    while pos < payload.len() {
        if !has_registered {
            // Jump to next structural-pattern prefix candidate, bulk-copying non-candidate bytes.
            let next_candidate = prefix_filter()
                .find(&payload[pos..])
                .map(|m| pos + m.start())
                .unwrap_or(payload.len());
            if next_candidate > pos {
                output.extend_from_slice(&payload[pos..next_candidate]);
                pos = next_candidate;
            }
            if pos >= payload.len() {
                break;
            }
        }

        match find_best_match(payload, pos, patterns)? {
            None => {
                // INV-2: copy this byte unchanged
                output.push(payload[pos]);
                pos += 1;
            }
            Some(m) => {
                let matched_slice = &payload[m.start..m.end];

                let (fake, _entry_idx) = if let Some(&idx) = seen.get(matched_slice) {
                    // INV-14: same secret → reuse existing fake and entry
                    (entries[idx].fake.clone(), idx)
                } else {
                    // New secret: generate fake, encrypt, create entry
                    let fake = generate_fake_for_match(&m, matched_slice)?;
                    let entry = encrypt_secret(&session_key, fake.clone(), matched_slice)?;
                    let idx = entries.len();
                    entries.push(entry);
                    seen.insert(matched_slice, idx);
                    (fake, idx)
                };

                // INV-1: replace secret with fake
                output.extend_from_slice(&fake);
                pos = m.end;
            }
        }
    }

    // INV-23: if no patterns matched, output == payload, entries is empty
    Ok(SwapResult {
        payload: output,
        entries,
        session_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;

    const TEST_ANTHROPIC_KEY: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn test_swap_structural_basic() {
        // INV-1: secret replaced with fake
        let payload = [b"Authorization: ".as_slice(), TEST_ANTHROPIC_KEY, b" end"].concat();
        let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        assert_ne!(result.payload, payload, "payload must be modified");
        assert_eq!(
            result.entries.len(),
            1,
            "INV-3: one entry for one distinct secret"
        );
    }

    #[test]
    fn test_swap_no_modification_outside_secret() {
        // INV-2: bytes outside detected secrets are unchanged
        let prefix = b"Authorization: ";
        let suffix = b" end";
        let payload = [prefix.as_slice(), TEST_ANTHROPIC_KEY, suffix.as_slice()].concat();
        let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        assert!(
            result.payload.starts_with(prefix),
            "INV-2: prefix unchanged"
        );
        assert!(result.payload.ends_with(suffix), "INV-2: suffix unchanged");
    }

    #[test]
    fn test_swap_empty_patterns() {
        // INV-23: empty patterns → payload unchanged, entries empty
        let payload = b"some payload with stuff";
        let result = swap(payload, &[]).expect("swap failed");
        assert_eq!(result.payload, payload, "INV-23: payload unchanged");
        assert!(result.entries.is_empty(), "INV-23: entries empty");
    }

    #[test]
    fn test_swap_no_secrets_in_payload() {
        // INV-23: payload with no detectable secrets → unchanged, empty entries
        let payload = b"Hello, world! No secrets here.";
        let result = swap(payload, &patterns::all()).expect("swap failed");
        assert_eq!(result.payload, payload.as_slice());
        assert!(result.entries.is_empty());
    }

    #[test]
    fn test_swap_multiple_occurrences_same_secret() {
        // INV-14: two occurrences of same secret → same fake, ONE entry
        let secret = TEST_ANTHROPIC_KEY;
        let payload = [secret, b" separator ", secret].concat();
        let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        assert_eq!(
            result.entries.len(),
            1,
            "INV-14: one entry for repeated secret"
        );
        let fake = &result.entries[0].fake;
        let first_occurrence = result.payload[..fake.len()].to_vec();
        let last_occurrence = result.payload[result.payload.len() - fake.len()..].to_vec();
        assert_eq!(first_occurrence, *fake);
        assert_eq!(last_occurrence, *fake);
    }

    #[test]
    fn test_swap_entries_contain_no_plaintext() {
        // INV-9: entries must not contain plaintext secret bytes
        let secret = TEST_ANTHROPIC_KEY;
        let payload = [b"token: ".as_slice(), secret].concat();
        let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        for entry in &result.entries {
            assert!(
                !entry.ciphertext.windows(secret.len()).any(|w| w == secret),
                "INV-9: entry ciphertext must not contain plaintext secret"
            );
        }
    }

    #[test]
    fn test_swap_registered_hmac_failure_passthrough() {
        // INV-16: registered structural match + HMAC failure → pass through
        use rand::{SeedableRng, rngs::StdRng};
        let real_secret = b"my-registered-secret-value-here";
        let pat =
            crate::secrets::register_with_rng(real_secret, &mut StdRng::seed_from_u64(42)).unwrap();
        let mut fake_secret = real_secret.to_vec();
        fake_secret[10] ^= 0xFF;
        let payload = fake_secret.clone();
        let result = swap(&payload, &[pat]).expect("swap failed");
        assert_eq!(
            result.payload, payload,
            "INV-16: HMAC failure → pass through unchanged"
        );
        assert!(
            result.entries.is_empty(),
            "INV-16: no entry produced for HMAC failure"
        );
    }

    #[test]
    fn test_swap_fake_stability() {
        // INV-13: same secret + same Pattern → same fake across calls
        let payload = [b"token: ".as_slice(), TEST_ANTHROPIC_KEY].concat();
        let pat = patterns::anthropic();
        let result1 = swap(&payload, std::slice::from_ref(&pat)).expect("swap failed");
        let result2 = swap(&payload, std::slice::from_ref(&pat)).expect("swap failed");
        assert_eq!(
            result1.entries[0].fake, result2.entries[0].fake,
            "INV-13: fake must be stable"
        );
    }
}
