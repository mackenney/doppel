# Step 06: Scrub Engine

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration.

### Phase Context
Wave 3 (sequential after Wave 2). Implements the core `scrub()` public function and the
leftmost-longest scan engine. This is the highest-complexity library component — it must
correctly handle all 23 behavioral invariants that apply to the scrub path: INV-1 through
INV-3, INV-9, INV-13 through INV-18, INV-23. All pattern-related steps must be complete
before this step begins.

### This Step
Implement `src/scrub.rs`: the leftmost-longest scan loop, Tier 1 and Tier 2 structural
validation, secret deduplication (INV-14), fake generation dispatch, entry creation, and
the public `scrub()` function. Wire up to `src/lib.rs`.

## Prerequisites

- Step 02 complete (Entry, SessionKey, ScrubResult, encrypt_secret)
- Step 03 complete (derive_fake_tier1, generate_fake_tier2)
- Step 04 complete (Tier1Def, try_match, Pattern enum)
- Step 05 complete (Tier2Pat, register, Tier2Pat::try_match)

## Files to Read Before Starting

- `src/scrub.rs` — current stub
- `src/tier1.rs` — Tier1Def, Pattern, try_match
- `src/tier2.rs` — Tier2Pat, try_match
- `src/crypto.rs` — encrypt_secret, generate_session_key
- `src/fake.rs` — derive_fake_tier1, generate_fake_tier2
- `SPEC.md §Core Mental Model` — scrub() contract
- `SPEC.md INV-1 through INV-3, INV-9, INV-13, INV-14, INV-15, INV-16, INV-18, INV-23`

## Implementation

### Task 1: Match type

```rust
struct Match {
    start: usize,
    end: usize,
    is_tier1: bool,
    pattern_ref: PatternRef,  // a reference to the Pattern that matched
}

// Internal enum to hold the matching pattern without cloning
enum PatternRef<'a> {
    Tier1(&'a Tier1Def),
    Tier2(&'a Tier2Pat),
}
```

### Task 2: find_best_match — leftmost-longest (INV-18)

```rust
fn find_best_match<'a>(payload: &[u8], pos: usize, patterns: &'a [Pattern]) -> Option<Match<'a>> {
    let mut best: Option<Match<'a>> = None;

    for pattern in patterns {
        let result = match pattern {
            Pattern::Tier1(def) => def.try_match(payload, pos).map(|end| Match {
                start: pos, end, is_tier1: true,
                pattern_ref: PatternRef::Tier1(def),
            }),
            Pattern::Tier2(arc) => arc.try_match(payload, pos).map(|end| Match {
                start: pos, end, is_tier1: false,
                pattern_ref: PatternRef::Tier2(arc.as_ref()),
            }),
        };

        if let Some(candidate) = result {
            best = Some(match best {
                None => candidate,
                Some(b) if candidate.end > b.end => candidate,  // longer match wins
                Some(b) if candidate.end == b.end && candidate.is_tier1 && !b.is_tier1 => candidate,  // Tier1 tie-break
                Some(b) => b,
            });
        }
    }

    best
}
```

### Task 3: Fake generation dispatch

```rust
fn generate_fake_for_match(m: &Match<'_>, secret: &[u8]) -> Vec<u8> {
    match &m.pattern_ref {
        PatternRef::Tier1(def) => {
            let charset = (def.charset)();
            crate::fake::derive_fake_tier1(def.get_salt(), def.prefix, &charset, secret.len(), secret)
        }
        PatternRef::Tier2(pat) => {
            // Tier 2 fake is pre-generated at registration time; return it directly.
            // Stability: same pattern → same fake for any detection of any secret
            // (the HMAC in try_match already verified this is the registered secret)
            pat.fake.clone()
        }
    }
}
```

### Task 4: scrub() public function

```rust
use std::collections::HashMap;
use crate::types::{Entry, ScrubResult, SessionKey};
use crate::crypto::{generate_session_key, encrypt_secret};
use crate::tier1::Pattern;

pub fn scrub(payload: &[u8], patterns: &[Pattern]) -> ScrubResult {
    let session_key = generate_session_key();
    let mut output = Vec::with_capacity(payload.len());
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();  // secret_bytes → entry_idx
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
    ScrubResult { payload: output, entries, session_key }
}
```

### Task 5: Wire up in lib.rs

```rust
pub fn scrub(payload: &[u8], patterns: &[Pattern]) -> ScrubResult {
    crate::scrub::scrub(payload, patterns)
}

pub fn register(secret: impl AsRef<[u8]>) -> Pattern {
    crate::tier2::register(secret)
}
```

### Task 6: Unit tests

```rust
// Use a synthetic Anthropic-format key for testing (NOT a real key)
const TEST_ANTHROPIC_KEY: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";

#[test]
fn test_scrub_tier1_basic() {
    // INV-1: secret replaced with fake
    let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA end";
    let result = scrub(payload, &[patterns::anthropic()]);
    assert_ne!(result.payload, payload, "payload must be modified");
    assert_eq!(result.entries.len(), 1, "INV-3: one entry for one distinct secret");
    // The original secret must not appear in scrubbed output (INV-1 corollary)
    let secret_start = b"sk-ant-";
    let secret_appears = result.payload.windows(7).any(|w| w == secret_start);
    // Note: the fake also starts with "sk-ant-" (prefix preserved), so we check full match
}

#[test]
fn test_scrub_no_modification_outside_secret() {
    // INV-2: bytes outside detected secrets are unchanged
    let prefix = b"Authorization: ";
    let suffix = b" end";
    let payload = [prefix.as_slice(), TEST_ANTHROPIC_KEY, suffix.as_slice()].concat();
    let result = scrub(&payload, &[patterns::anthropic()]);
    assert!(result.payload.starts_with(prefix), "INV-2: prefix unchanged");
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
    assert_eq!(result.entries.len(), 1, "INV-14: one entry for repeated secret");
    // Both occurrences replaced with same fake
    let fake = &result.entries[0].fake;
    let first_occurrence = result.payload[..fake.len()].to_vec();
    let last_occurrence = result.payload[result.payload.len()-fake.len()..].to_vec();
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
        // The ciphertext field should NOT contain the raw secret bytes
        assert!(
            !entry.ciphertext.windows(secret.len()).any(|w| w == secret),
            "INV-9: entry ciphertext must not contain plaintext secret"
        );
    }
}

#[test]
fn test_scrub_tier2_hmac_failure_passthrough() {
    // INV-16: Tier 2 structural match + HMAC failure → pass through
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let real_secret = b"my-registered-secret-value-here";
    let pat = crate::tier2::register_with_rng(real_secret, &mut StdRng::seed_from_u64(42));
    // Create a "similar" payload that matches start/end fragments but fails HMAC
    let mut fake_secret = real_secret.to_vec();
    fake_secret[10] ^= 0xFF;  // flip a middle byte
    let payload = fake_secret.clone();
    let result = scrub(&payload, &[pat]);
    assert_eq!(result.payload, payload, "INV-16: HMAC failure → pass through unchanged");
    assert!(result.entries.is_empty(), "INV-16: no entry produced for HMAC failure");
}

#[test]
fn test_scrub_fake_stability() {
    // INV-13: same secret + same Pattern → same fake across calls
    let payload = [b"token: ".as_slice(), TEST_ANTHROPIC_KEY].concat();
    let pat = patterns::anthropic();
    let result1 = scrub(&payload, &[pat.clone()]);
    let result2 = scrub(&payload, &[pat]);
    assert_eq!(result1.entries[0].fake, result2.entries[0].fake, "INV-13: fake must be stable");
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --lib` exits 0
- [ ] `test_scrub_empty_patterns` passes (INV-23)
- [ ] `test_scrub_no_secrets_in_payload` passes (INV-23)
- [ ] `test_scrub_no_modification_outside_secret` passes (INV-2)
- [ ] `test_scrub_multiple_occurrences_same_secret` passes (INV-14)
- [ ] `test_scrub_entries_contain_no_plaintext` passes (INV-9)
- [ ] `test_scrub_tier2_hmac_failure_passthrough` passes (INV-16)
- [ ] `test_scrub_fake_stability` passes (INV-13)
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 06. Verify:

1. Run `cargo nextest run --lib` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Run `cargo nextest run --lib -E 'test(scrub)'` — all pass
4. Confirm `find_best_match` applies Tier1 > Tier2 tie-break for same-length matches (inspect source)
5. Confirm deduplication `HashMap` maps `secret_bytes → entry_idx` (INV-14)

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-06 commit.
