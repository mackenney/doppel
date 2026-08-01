use std::collections::HashMap;

use crate::crypto::encrypt_secret;
use crate::crypto::generate_session_key;
use crate::fake::Charset;
use crate::fake::FakeError;
use crate::patterns::{Pattern, build_ac_automaton};
use crate::types::{Entry, SwapError, SwapResult};

/// Selects the single best-matching pattern at `pos` from `patterns`.
///
/// Selection chain (SPEC §Pattern Detection step 5; Behavioral Invariants
/// item 18):
/// 1. Longest match wins (`capture.end` maximized).
/// 2. On a length tie, a first-segment-Literal pattern beats a non-literal one.
/// 3. On a further tie (same end, same first-segment kind), a guarded
///    Pattern (`trailing_run_guard` is `Some`) beats an unguarded one.
/// 4. Between two guarded Patterns tied through rule 3, the larger
///    threshold wins.
/// 5. Any remaining tie keeps the incumbent — pattern-set order, left
///    unspecified by SPEC.
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
                // INV-18: on persistent tie (same end, same first-segment kind), a
                // guarded pattern beats an unguarded one, and between guarded patterns
                // the larger threshold wins. Option<usize>'s derived ordering encodes
                // both sub-clauses in one comparison: None < Some(t) covers
                // guarded-beats-unguarded, Some(a) < Some(b) covers the threshold rule.
                // Equal guards (including None vs None) fall through to the incumbent.
                Some((bp, bc))
                    if capture.end == bc.end
                        && pattern.first_segment_is_literal() == bp.first_segment_is_literal()
                        && pattern.trailing_run_guard > bp.trailing_run_guard =>
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
    crate::fake::derive_fake_structural_segments(
        &pattern.salt,
        &pattern.segments,
        &capture.variable_lengths,
        secret,
    )
}

/// Scan `payload` for secrets matching `patterns`, replace each with a
/// structurally-equivalent fake, and return the swapped payload, encrypted
/// entries, and a fresh session key. If the winning match at a position
/// declares a trailing run guard (SPEC §Trailing Run Guard), the guard's
/// forward-only probe can suppress that single detection with no cascade
/// to a losing candidate.
///
/// For repeated calls with a fixed pattern set, prefer [`Detector`] to avoid
/// rebuilding the Aho-Corasick automaton on every call.
///
/// [`Detector`]: crate::Detector
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
    let ac = build_ac_automaton(patterns);
    swap_with_ac(payload, patterns, &ac)
}

/// Inner swap implementation reusing a pre-built Aho-Corasick automaton.
/// Guard suppression semantics are identical to [`swap`] (SPEC §Trailing
/// Run Guard).
///
/// # Contract
///
/// `ac` MUST have been built from `patterns` via [`build_ac_automaton`].
/// Passing a mismatched pair produces silent detection failures.
pub(crate) fn swap_with_ac(
    payload: &[u8],
    patterns: &[Pattern],
    ac: &aho_corasick::AhoCorasick,
) -> Result<SwapResult, SwapError> {
    let session_key = generate_session_key();
    let mut output = Vec::with_capacity(payload.len());
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: HashMap<&[u8], usize> = HashMap::new();
    let mut pos = 0;

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
            Some((pattern, capture)) if !guard_fires(pattern, payload, &capture) => {
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
            _ => {
                // INV-2: copy this byte unchanged
                // Item 46: suppression yields no detection at this position;
                // no cascade to a losing candidate. Scanning resumes at pos+1,
                // so any secret inside the probe window is still detected
                // independently at its own position (item 47 / VC-20).
                output.push(payload[pos]);
                pos += 1;
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

/// Returns true when the winning match's trailing run guard suppresses the
/// detection: the pattern declares a threshold, its final Variable segment
/// charset is resolvable, and the run of that charset immediately following
/// the match extends at least `threshold` bytes (SPEC §Trailing Run Guard,
/// items 44-46). Applies only to the single selected winner; never re-enters
/// candidate selection (item 46) and does not fire when the pattern has no
/// guard configured (item 48).
fn guard_fires(pattern: &Pattern, payload: &[u8], capture: &crate::segment::MatchCapture) -> bool {
    let Some(threshold) = pattern.trailing_run_guard else {
        return false;
    };
    let Some(charset) = pattern.last_variable_charset() else {
        // Unreachable for validated patterns (item 45 enforced at load);
        // fail open to "no suppression" rather than panic.
        return false;
    };
    trailing_run_reaches(payload, capture.end, charset.resolve(), threshold)
}

/// Returns true when at least `threshold` consecutive bytes starting at
/// `start` all belong to `charset`. Early-exits at the first non-charset
/// byte, at end of payload, or as soon as `threshold` bytes are confirmed —
/// never reads past `start + threshold` (SPEC §Trailing Run Guard:
/// "MAY stop reading as soon as the threshold is reached").
fn trailing_run_reaches(payload: &[u8], start: usize, charset: &Charset, threshold: usize) -> bool {
    let end = start.saturating_add(threshold);
    if end > payload.len() {
        return false; // EOF before threshold → match stands (item 44)
    }
    payload[start..end].iter().all(|&b| charset.contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;
    use crate::segment::{CharsetName, Segment};

    const TEST_ANTHROPIC_KEY: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_GCP_KEY: &[u8] = b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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

    #[test]
    fn test_trailing_run_reaches_exact_threshold() {
        let payload = b"0123456789";
        let charset = crate::fake::digits_ref();
        assert!(trailing_run_reaches(payload, 0, charset, 10));
    }

    #[test]
    fn test_trailing_run_reaches_non_charset_byte_before_threshold() {
        let mut payload = b"012345678".to_vec();
        payload.push(b'x'); // 10th byte is not a digit
        let charset = crate::fake::digits_ref();
        assert!(!trailing_run_reaches(&payload, 0, charset, 10));
    }

    #[test]
    fn test_trailing_run_reaches_eof_before_threshold() {
        let payload = b"12345";
        let charset = crate::fake::digits_ref();
        assert!(!trailing_run_reaches(payload, 0, charset, 10));
    }

    #[test]
    fn test_trailing_run_reaches_threshold_one() {
        let payload = b"9";
        let charset = crate::fake::digits_ref();
        assert!(trailing_run_reaches(payload, 0, charset, 1));
    }

    #[test]
    fn test_trailing_run_reaches_start_at_payload_end_does_not_panic() {
        let payload = b"12345";
        let charset = crate::fake::digits_ref();
        assert!(!trailing_run_reaches(payload, payload.len(), charset, 1));
    }

    #[test]
    fn test_swap_gcp_suppressed_by_long_base64_trailing_run() {
        // Item 44-46: GCP key immediately followed by >= threshold base64
        // bytes suppresses the match entirely.
        let trailing = vec![b'a'; 2048];
        let payload = [TEST_GCP_KEY, &trailing].concat();
        let result = swap(&payload, &[patterns::gcp()]).expect("swap failed");
        assert_eq!(result.payload, payload, "suppressed: payload unchanged");
        assert!(result.entries.is_empty(), "suppressed: no entries");
    }

    #[test]
    fn test_swap_gcp_match_stands_run_terminated_before_threshold() {
        // Item 44: trailing run terminated by a non-charset byte before
        // reaching the threshold — match stands.
        let mut trailing = vec![b'a'; 2047];
        trailing.push(b'"');
        let payload = [TEST_GCP_KEY, &trailing].concat();
        let result = swap(&payload, &[patterns::gcp()]).expect("swap failed");
        assert_ne!(result.payload, payload, "match must stand");
        assert_eq!(result.entries.len(), 1, "one entry for the standing match");
    }

    #[test]
    fn test_swap_gcp_match_stands_eof_before_threshold() {
        // Item 44: payload ends before threshold bytes accumulate — match stands.
        let trailing = vec![b'a'; 100];
        let payload = [TEST_GCP_KEY, &trailing].concat();
        let result = swap(&payload, &[patterns::gcp()]).expect("swap failed");
        assert_ne!(result.payload, payload, "match must stand");
        assert_eq!(result.entries.len(), 1, "one entry for the standing match");
    }

    #[test]
    fn test_swap_gcp_match_stands_zero_trailing_bytes() {
        // Item 44: key at the very end of the payload — zero trailing bytes,
        // well under the threshold — match stands.
        let result = swap(TEST_GCP_KEY, &[patterns::gcp()]).expect("swap failed");
        assert_ne!(result.payload, TEST_GCP_KEY, "match must stand");
        assert_eq!(result.entries.len(), 1, "one entry for the standing match");
    }

    fn tok_payload(var_len: usize) -> Vec<u8> {
        let mut payload = b"tok_".to_vec();
        payload.extend(std::iter::repeat_n(b'a', var_len));
        payload
    }

    fn literal_pattern(identifier: &str, var_len: usize, guard: Option<usize>) -> Pattern {
        Pattern {
            identifier: identifier.to_string(),
            segments: vec![
                Segment::Literal(b"tok_".to_vec()),
                Segment::Variable {
                    charset: CharsetName::Alphanumeric,
                    min: var_len,
                    max: var_len,
                },
            ]
            .into(),
            salt: [0u8; 32],
            digests: vec![],
            trailing_run_guard: guard,
        }
    }

    fn opaque_pattern(identifier: &str, var_len: usize, guard: Option<usize>) -> Pattern {
        Pattern {
            identifier: identifier.to_string(),
            segments: vec![
                Segment::Opaque {
                    value: b"tok_".to_vec(),
                    charset: CharsetName::Alphanumeric,
                },
                Segment::Variable {
                    charset: CharsetName::Alphanumeric,
                    min: var_len,
                    max: var_len,
                },
            ]
            .into(),
            salt: [0u8; 32],
            digests: vec![],
            trailing_run_guard: guard,
        }
    }

    #[test]
    fn test_find_best_match_guard_beats_unguarded_on_tie() {
        // INV-18: on persistent tie, a guarded pattern beats an unguarded one,
        // in both pattern-set orders.
        let payload = tok_payload(30);
        let guarded = literal_pattern("guarded", 30, Some(64));
        let unguarded = literal_pattern("unguarded", 30, None);

        let patterns = [guarded.clone(), unguarded.clone()];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(winner.identifier, "guarded", "guarded wins tie (order A)");

        let patterns = [unguarded, guarded];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(winner.identifier, "guarded", "guarded wins tie (order B)");
    }

    #[test]
    fn test_find_best_match_larger_threshold_wins_on_tie() {
        // INV-18: between two guarded patterns tied on end and first-segment
        // kind, the larger threshold wins, in both pattern-set orders.
        let payload = tok_payload(30);
        let large = literal_pattern("large_threshold", 30, Some(64));
        let small = literal_pattern("small_threshold", 30, Some(8));

        let patterns = [large.clone(), small.clone()];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(
            winner.identifier, "large_threshold",
            "larger threshold wins tie (order A)"
        );

        let patterns = [small, large];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(
            winner.identifier, "large_threshold",
            "larger threshold wins tie (order B)"
        );
    }

    #[test]
    fn test_find_best_match_longest_match_not_overridden_by_guard() {
        // INV-18: the guard tie-break arm MUST NOT override the longest-match
        // rule — a longer unguarded match beats a shorter guarded one.
        let payload = tok_payload(34);
        let longer_unguarded = literal_pattern("longer_unguarded", 34, None);
        let shorter_guarded = literal_pattern("shorter_guarded", 30, Some(64));

        let patterns = [shorter_guarded, longer_unguarded];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(
            winner.identifier, "longer_unguarded",
            "longest match wins regardless of guard"
        );
    }

    #[test]
    fn test_find_best_match_literal_first_not_overridden_by_guard() {
        // INV-18: the guard tie-break arm MUST NOT override the literal-first
        // rule — an unguarded literal-first match beats a guarded opaque-first
        // match of the same total length.
        let payload = tok_payload(30);
        let literal_unguarded = literal_pattern("literal_unguarded", 30, None);
        let opaque_guarded = opaque_pattern("opaque_guarded", 30, Some(64));

        let patterns = [opaque_guarded, literal_unguarded];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(
            winner.identifier, "literal_unguarded",
            "literal-first wins regardless of guard"
        );
    }

    #[test]
    fn test_find_best_match_none_guard_tie_keeps_incumbent() {
        // Fallback unchanged: both patterns unguarded and otherwise tied ->
        // first-in-set kept, per pattern-set order left unspecified by SPEC.
        let payload = tok_payload(30);
        let first = literal_pattern("first", 30, None);
        let second = literal_pattern("second", 30, None);

        let patterns = [first, second];
        let winner = find_best_match(&payload, 0, &patterns).expect("match").0;
        assert_eq!(winner.identifier, "first", "first-in-set kept on full tie");
    }
}
