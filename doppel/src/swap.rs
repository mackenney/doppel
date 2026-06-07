use std::collections::HashMap;

use crate::crypto::encrypt_secret;
use crate::crypto::generate_session_key;
use crate::fake::FakeError;
use crate::patterns::{Pattern, build_ac_automaton};
use crate::types::{Entry, SwapError, SwapResult};

fn find_best_match<'a>(
    payload: &[u8],
    pos: usize,
    patterns: &'a [Pattern],
) -> Option<(&'a Pattern, crate::segment::MatchCapture)> {
    let mut best: Option<(&'a Pattern, crate::segment::MatchCapture)> = None;

    for pattern in patterns {
        if let Some(capture) = pattern.try_match(payload, pos) {
            best = Some(match best {
                None => (pattern, capture),
                Some((_bp, bc)) if capture.end > bc.end => (pattern, capture),
                // INV-18: literal-first wins on length tie
                Some((bp, bc))
                    if capture.end == bc.end
                        && pattern.first_segment_is_literal()
                        && !bp.first_segment_is_literal() =>
                {
                    (pattern, capture)
                }
                Some(b) => b,
            });
        }
    }

    best
}

fn generate_fake_for_match(
    pattern: &Pattern,
    capture: &crate::segment::MatchCapture,
    secret: &[u8],
) -> Result<Vec<u8>, FakeError> {
    if pattern.is_family() {
        crate::fake::derive_fake_structural_segments(
            &pattern.salt,
            &pattern.segments,
            &capture.variable_lengths,
            secret,
        )
    } else {
        // Instance pattern fake generation is reworked in step-04.
        todo!("instance pattern fake generation — step-04")
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

    let ac = build_ac_automaton(patterns);

    while pos < payload.len() {
        // Jump to the next AC match candidate, bulk-copying non-candidate bytes.
        let next_candidate = ac
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

        match find_best_match(payload, pos, patterns) {
            None => {
                // INV-2: copy this byte unchanged
                output.push(payload[pos]);
                pos += 1;
            }
            Some((pattern, capture)) => {
                let matched_slice = &payload[pos..capture.end];

                let (fake, _entry_idx) = if let Some(&idx) = seen.get(matched_slice) {
                    // INV-14: same secret → reuse existing fake and entry
                    (entries[idx].fake.clone(), idx)
                } else {
                    // New secret: generate fake, encrypt, create entry
                    let fake = generate_fake_for_match(pattern, &capture, matched_slice)?;
                    let entry = encrypt_secret(&session_key, fake.clone(), matched_slice)?;
                    let idx = entries.len();
                    entries.push(entry);
                    seen.insert(matched_slice, idx);
                    (fake, idx)
                };

                // INV-1: replace secret with fake
                output.extend_from_slice(&fake);
                pos = capture.end;
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
