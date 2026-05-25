use std::collections::HashMap;

use crate::crypto::{encrypt_secret, generate_session_key};
use crate::tier1::{Pattern, Tier1Def};
use crate::tier2::Tier2Pat;
use crate::types::{Entry, ScrubResult};

struct Match<'a> {
    start: usize,
    end: usize,
    is_tier1: bool,
    pattern_ref: PatternRef<'a>,
}

enum PatternRef<'a> {
    Tier1(&'a Tier1Def),
    Tier2(&'a Tier2Pat),
}

fn find_best_match<'a>(payload: &[u8], pos: usize, patterns: &'a [Pattern]) -> Option<Match<'a>> {
    let mut best: Option<Match<'a>> = None;

    for pattern in patterns {
        let result = match pattern {
            Pattern::Tier1(def) => def.try_match(payload, pos).map(|end| Match {
                start: pos,
                end,
                is_tier1: true,
                pattern_ref: PatternRef::Tier1(def),
            }),
            Pattern::Tier2(arc) => arc.try_match(payload, pos).map(|end| Match {
                start: pos,
                end,
                is_tier1: false,
                pattern_ref: PatternRef::Tier2(arc.as_ref()),
            }),
        };

        if let Some(candidate) = result {
            best = Some(match best {
                None => candidate,
                Some(b) if candidate.end > b.end => candidate,
                // Tier1 wins on tie (INV-18)
                Some(b) if candidate.end == b.end && candidate.is_tier1 && !b.is_tier1 => candidate,
                Some(b) => b,
            });
        }
    }

    best
}

fn generate_fake_for_match(m: &Match<'_>, secret: &[u8]) -> Vec<u8> {
    match &m.pattern_ref {
        PatternRef::Tier1(def) => {
            let charset = (def.charset)();
            crate::fake::derive_fake_tier1(
                def.get_salt(),
                def.prefix,
                &charset,
                secret.len(),
                secret,
            )
        }
        PatternRef::Tier2(pat) => {
            // Tier 2 fake is pre-generated at registration time; return it directly.
            // Stability: same pattern → same fake for any detection of the registered secret.
            pat.fake.clone()
        }
    }
}

pub fn scrub(payload: &[u8], patterns: &[Pattern]) -> ScrubResult {
    let session_key = generate_session_key();
    let mut output = Vec::with_capacity(payload.len());
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut pos = 0;

    while pos < payload.len() {
        match find_best_match(payload, pos, patterns) {
            None => {
                // INV-2: copy this byte unchanged
                output.push(payload[pos]);
                pos += 1;
            }
            Some(m) => {
                let secret = payload[m.start..m.end].to_vec();

                let (fake, _entry_idx) = if let Some(&idx) = seen.get(&secret) {
                    // INV-14: same secret → reuse existing fake and entry
                    (entries[idx].fake.clone(), idx)
                } else {
                    // New secret: generate fake, encrypt, create entry
                    let fake = generate_fake_for_match(&m, &secret);
                    let entry = encrypt_secret(&session_key, fake.clone(), &secret);
                    let idx = entries.len();
                    entries.push(entry);
                    seen.insert(secret, idx);
                    (fake, idx)
                };

                // INV-1: replace secret with fake
                output.extend_from_slice(&fake);
                pos = m.end;
            }
        }
    }

    // INV-23: if no patterns matched, output == payload, entries is empty
    ScrubResult {
        payload: output,
        entries,
        session_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier1::patterns;

    const TEST_ANTHROPIC_KEY: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";

    #[test]
    fn test_scrub_tier1_basic() {
        // INV-1: secret replaced with fake
        let payload = [b"Authorization: ".as_slice(), TEST_ANTHROPIC_KEY, b" end"].concat();
        let result = scrub(&payload, &[patterns::anthropic()]);
        assert_ne!(result.payload, payload, "payload must be modified");
        assert_eq!(
            result.entries.len(),
            1,
            "INV-3: one entry for one distinct secret"
        );
    }

    #[test]
    fn test_scrub_no_modification_outside_secret() {
        // INV-2: bytes outside detected secrets are unchanged
        let prefix = b"Authorization: ";
        let suffix = b" end";
        let payload = [prefix.as_slice(), TEST_ANTHROPIC_KEY, suffix.as_slice()].concat();
        let result = scrub(&payload, &[patterns::anthropic()]);
        assert!(
            result.payload.starts_with(prefix),
            "INV-2: prefix unchanged"
        );
        assert!(result.payload.ends_with(suffix), "INV-2: suffix unchanged");
    }

    #[test]
    fn test_scrub_empty_patterns() {
        // INV-23: empty patterns → payload unchanged, entries empty
        let payload = b"some payload with stuff";
        let result = scrub(payload, &[]);
        assert_eq!(result.payload, payload, "INV-23: payload unchanged");
        assert!(result.entries.is_empty(), "INV-23: entries empty");
    }

    #[test]
    fn test_scrub_no_secrets_in_payload() {
        // INV-23: payload with no detectable secrets → unchanged, empty entries
        let payload = b"Hello, world! No secrets here.";
        let result = scrub(payload, &patterns::all());
        assert_eq!(result.payload, payload.as_slice());
        assert!(result.entries.is_empty());
    }

    #[test]
    fn test_scrub_multiple_occurrences_same_secret() {
        // INV-14: two occurrences of same secret → same fake, ONE entry
        let secret = TEST_ANTHROPIC_KEY;
        let payload = [secret, b" separator ", secret].concat();
        let result = scrub(&payload, &[patterns::anthropic()]);
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
    fn test_scrub_entries_contain_no_plaintext() {
        // INV-9: entries must not contain plaintext secret bytes
        let secret = TEST_ANTHROPIC_KEY;
        let payload = [b"token: ".as_slice(), secret].concat();
        let result = scrub(&payload, &[patterns::anthropic()]);
        for entry in &result.entries {
            assert!(
                !entry.ciphertext.windows(secret.len()).any(|w| w == secret),
                "INV-9: entry ciphertext must not contain plaintext secret"
            );
        }
    }

    #[test]
    fn test_scrub_tier2_hmac_failure_passthrough() {
        // INV-16: Tier 2 structural match + HMAC failure → pass through
        use rand::{SeedableRng, rngs::StdRng};
        let real_secret = b"my-registered-secret-value-here";
        let pat = crate::tier2::register_with_rng(real_secret, &mut StdRng::seed_from_u64(42));
        let mut fake_secret = real_secret.to_vec();
        fake_secret[10] ^= 0xFF;
        let payload = fake_secret.clone();
        let result = scrub(&payload, &[pat]);
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
    fn test_scrub_fake_stability() {
        // INV-13: same secret + same Pattern → same fake across calls
        let payload = [b"token: ".as_slice(), TEST_ANTHROPIC_KEY].concat();
        let pat = patterns::anthropic();
        let result1 = scrub(&payload, &[pat.clone()]);
        let result2 = scrub(&payload, &[pat]);
        assert_eq!(
            result1.entries[0].fake, result2.entries[0].fake,
            "INV-13: fake must be stable"
        );
    }
}
