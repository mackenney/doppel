# Step 02: Entries leak no plaintext and embed no session key (INV-9 / VC-7)

## Context

### Overall Objective
Add four proptest properties to `doppel/tests/property/` that close SPEC.md
coverage gaps: INV-8 hold bound, INV-9/VC-7 entry confidentiality,
registration trailing-run-guard end-to-end (VC-22/26/28, INV-49/51), and
`Detector` reuse/thread safety (INV-39/40). Tests only; no `src/` changes.

### Phase Context
Wave 1, second of four strictly sequential steps. Depends on step-01 only
because a single writer works in the worktree; there is no code dependency.

### This Step
Create `doppel/tests/property/entries_no_leak.rs`. For generated swap cases it
collects every surface the entries expose and checks that none contains a run
of any detected secret's variable/opaque bytes, and none contains session-key
bytes.

What `Entry` exposes (verified):
- `doppel/src/types.rs:30-43` — `#[derive(Debug, Clone, Serialize, Deserialize)] pub struct Entry { pub fake: Vec<u8>, pub(crate) nonce: Vec<u8>, pub(crate) ciphertext: Vec<u8> }`, `#[non_exhaustive]`. Only `fake` is readable from tests; `nonce`/`ciphertext` are reachable only through `Debug` and serialization.
- `doppel/src/types.rs:69` — `Entry::serialize_entries(&[Entry]) -> Result<Vec<u8>, serde_json::Error>`: pretty JSON array; every field is **standard base64** (`doppel/src/serde_helpers.rs:4-15`, `base64::engine::general_purpose::STANDARD`). Therefore a raw-byte search of the JSON can never see a plaintext leak in `nonce`/`ciphertext` — the fields must be **decoded**. (The existing check in `restore_sync.rs` searches the raw JSON only; this step closes that gap.)
- `Debug` (derived) prints each `Vec<u8>` as a decimal list, e.g. `fake: [97, 98]`; so a Debug leak is searched by its decimal rendering.
- `doppel/src/types.rs:54` — `#[doc(hidden)] pub fn Entry::new_for_testing(fake, nonce, ciphertext) -> Entry` lets the checker self-tests craft leaking entries.
- `doppel/src/types.rs:21` — `SessionKey::as_bytes(&self) -> &[u8; 32]`.

Window rule (the "≥ 8-byte run" made flake-free):
- Surfaces made of cryptographically random bytes — decoded `nonce`, decoded
  `ciphertext` (and any other non-`fake` field), and their Debug rendering —
  are searched with **8-byte** windows of each maximal variable/opaque region
  (regions split at literal segments). Chance coincidence: 2^-64 per alignment.
- Surfaces that legitimately carry charset-derived fake bytes — `entry.fake`
  and the raw serialized JSON — are searched per **variable segment** with a
  window of `max(8, ceil(64 / log2 |charset|))` bytes (digits 20, hex_lower 16,
  uppercase_alphanumeric 13, alphanumeric / url_safe_base64 / base64_any 11,
  wide 10), so a chance match needs ≥ 64 bits of coincidence. Opaque anchor
  bytes are excluded on these surfaces: the generators draw anchors from the
  fixed alphabet `abPQ`, which legitimately reappears verbatim as another
  pattern's literal anchor inside a fake (a public, non-secret coincidence).
  Every generated capacity variable segment is at least this long
  (`floor_len`), so every detection is checked.
- Session key: every 8-byte window of `as_bytes()` is searched in all decoded
  fields, `entry.fake`, the raw JSON and full Debug.

## Prerequisites
- Step 01 complete (single writer; no code dependency).
- `doppel/tests/property.rs` contains `#[path = "property/entries_no_leak.rs"] mod entries_no_leak;` (added by the parent). Check: `grep -n 'property/entries_no_leak.rs' doppel/tests/property.rs`.
- If `doppel/tests/property/entries_no_leak.rs` exists as a placeholder, overwrite it.

## Files to Read Before Starting
- `doppel/src/types.rs` — `Entry`, `serialize_entries`, `new_for_testing`, `SessionKey::as_bytes`.
- `doppel/src/serde_helpers.rs` — `base64_vec` uses `STANDARD`.
- `doppel/src/crypto.rs:21-43` — `encrypt_secret` (what fills nonce/ciphertext).
- `doppel/tests/property/restore_sync.rs` — `secret_regions` (lines ~66-108): the segmentation walk you adapt below.
- `doppel/tests/property/oracle.rs` — `segmentations`, `scan`, `Scan`, `Span`, `Seg`, `Cs`.
- `doppel/tests/property/generators.rs` — `arb_case`, `build`, `floor_len`.
- Integration tests may use the crate's normal dependencies: `serde_json` and `base64` (`doppel/Cargo.toml` `[dependencies]`) — no Cargo.toml change.

## Implementation

Only file you create/overwrite: `doppel/tests/property/entries_no_leak.rs`.
Do not edit any other file; no helper additions to shared files are needed.

### Task 1: write the module (near-final code)

```rust
// P-LEAK: SPEC.md Behavioral Invariant 9 / Verifiable Condition 7. Entries
// must expose no run of a detected secret's variable or opaque bytes through
// any field, their serialized form or their Debug form, and must not embed
// the session key. Serialized fields are base64, so they are decoded before
// searching; a raw search would miss a plaintext ciphertext.

use crate::generators::{self, PatternSpec};
use crate::oracle::{self, Cs, OPattern, Scan, Seg, Span};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use doppel::{Entry, SwapResult};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// Window for surfaces of cryptographically random bytes: a chance 8-byte
/// match has probability 2^-64 per alignment.
const STRICT_WINDOW: usize = 8;

/// Surfaces holding charset-derived fake bytes can coincide with a secret by
/// chance, so their windows must carry at least this much entropy.
const DERIVED_WINDOW_BITS: f64 = 64.0;

fn derived_window(cs: Cs) -> usize {
    let bits = (cs.bytes().len() as f64).log2();
    ((DERIVED_WINDOW_BITS / bits).ceil() as usize).max(STRICT_WINDOW)
}

#[derive(Debug, Default)]
struct SecretBytes {
    /// Maximal runs of adjacent variable/opaque segment bytes; literals split
    /// them because literal bytes appear in every fake by design (INV-27).
    strict: Vec<Vec<u8>>,
    /// One entry per variable segment, with its entropy-scaled window.
    derived: Vec<(Vec<u8>, usize)>,
}

fn collect_secret_bytes(
    span: &Span,
    pattern: &OPattern,
    payload: &[u8],
    out: &mut SecretBytes,
) -> Result<(), TestCaseError> {
    for (end, lens) in oracle::segmentations(&pattern.segs, payload, span.start) {
        if end != span.end {
            continue;
        }
        let candidate = &payload[span.start..end];
        let accepted = match &pattern.accepted {
            None => true,
            Some(set) => set.iter().any(|c| c.as_slice() == candidate),
        };
        if !accepted {
            continue;
        }
        let mut current: Vec<u8> = Vec::new();
        let mut off = span.start;
        for (seg, &len) in pattern.segs.iter().zip(lens.iter()) {
            let bytes = &payload[off..off + len];
            match seg {
                Seg::Lit(_) => {
                    if !current.is_empty() {
                        out.strict.push(std::mem::take(&mut current));
                    }
                }
                Seg::Opq(_, _) => current.extend_from_slice(bytes),
                Seg::Var(cs, _, _) => {
                    current.extend_from_slice(bytes);
                    out.derived.push((bytes.to_vec(), derived_window(*cs)));
                }
            }
            off += len;
        }
        if !current.is_empty() {
            out.strict.push(current);
        }
        return Ok(());
    }
    Err(TestCaseError::fail(format!(
        "no accepted oracle segmentation reproduces span {}..{}",
        span.start, span.end
    )))
}

/// Every byte surface the entries expose.
#[derive(Debug, Default)]
struct Surfaces {
    /// Decoded serialized fields other than `fake` (nonce, ciphertext, and any
    /// field added later): random bytes.
    random: Vec<(String, Vec<u8>)>,
    /// Surfaces that legitimately contain charset-derived fake bytes: the raw
    /// serialized JSON and every entry's fake.
    derived: Vec<(String, Vec<u8>)>,
    /// Debug of each entry with its own fake rendering elided.
    debug_without_fake: Vec<String>,
    /// Full Debug of each entry.
    debug_full: Vec<String>,
}

fn entry_surfaces(entries: &[Entry]) -> Result<Surfaces, String> {
    let json = Entry::serialize_entries(entries)
        .map_err(|e| format!("serialize_entries failed: {e}"))?;
    let value: serde_json::Value = serde_json::from_slice(&json)
        .map_err(|e| format!("serialized entries are not JSON: {e}"))?;
    let array = value
        .as_array()
        .ok_or("serialized entries are not a JSON array")?;
    if array.len() != entries.len() {
        return Err(format!(
            "serialized {} entries, expected {}",
            array.len(),
            entries.len()
        ));
    }
    let mut s = Surfaces::default();
    s.derived.push(("serialized JSON".to_string(), json.clone()));
    for (i, (object, entry)) in array.iter().zip(entries).enumerate() {
        let map = object
            .as_object()
            .ok_or_else(|| format!("entry {i} is not a JSON object"))?;
        if !map.contains_key("fake") {
            return Err(format!("entry {i} has no fake field"));
        }
        for (key, field) in map {
            let text = field
                .as_str()
                .ok_or_else(|| format!("entry {i} field {key} is not a string"))?;
            let decoded = STANDARD
                .decode(text)
                .map_err(|e| format!("entry {i} field {key} is not base64: {e}"))?;
            if key == "fake" {
                if decoded != entry.fake {
                    return Err(format!("entry {i}: serialized fake differs from Entry::fake"));
                }
            } else {
                s.random.push((format!("entry {i} {key}"), decoded));
            }
        }
        s.derived.push((format!("entry {i} fake"), entry.fake.clone()));
        let full = format!("{entry:?}");
        let fake_rendering = format!("fake: {:?}", entry.fake);
        s.debug_without_fake
            .push(full.replacen(&fake_rendering, "fake: <elided>", 1));
        s.debug_full.push(full);
    }
    Ok(s)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// How `{:?}` renders these bytes inside a byte-vector Debug list.
fn debug_rendering(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn find_secret_leak(s: &Surfaces, secret: &SecretBytes) -> Option<String> {
    for region in &secret.strict {
        for window in region.windows(STRICT_WINDOW) {
            for (name, bytes) in &s.random {
                if contains(bytes, window) {
                    return Some(format!(
                        "{STRICT_WINDOW}-byte secret window {window:?} found in {name}"
                    ));
                }
            }
            let rendered = debug_rendering(window);
            for (i, text) in s.debug_without_fake.iter().enumerate() {
                if text.contains(&rendered) {
                    return Some(format!(
                        "secret window {window:?} found in Debug of entry {i}"
                    ));
                }
            }
        }
    }
    for (region, width) in &secret.derived {
        for window in region.windows(*width) {
            for (name, bytes) in &s.derived {
                if contains(bytes, window) {
                    return Some(format!(
                        "{width}-byte secret window {window:?} found in {name}"
                    ));
                }
            }
        }
    }
    None
}

/// Never prints key bytes: diagnostics name only the surface.
fn find_key_leak(s: &Surfaces, key: &[u8; 32]) -> Option<String> {
    for window in key.windows(STRICT_WINDOW) {
        for (name, bytes) in s.random.iter().chain(s.derived.iter()) {
            if contains(bytes, window) {
                return Some(format!("session key bytes found in {name}"));
            }
        }
        let rendered = debug_rendering(window);
        for (i, text) in s.debug_full.iter().enumerate() {
            if text.contains(&rendered) {
                return Some(format!("session key bytes found in Debug of entry {i}"));
            }
        }
    }
    None
}

/// Swap the case and collect the detected secrets' bytes. `None` for a full
/// tie the spec leaves unspecified (oracle `Scan::Unspecified`).
fn prepare(
    specs: &[PatternSpec],
    payload: &[u8],
) -> Result<Option<(SwapResult, SecretBytes)>, TestCaseError> {
    let (_file, patterns, oracles) = generators::build(specs);
    let spans = match oracle::scan(&oracles, payload) {
        Scan::Spans(spans) => spans,
        Scan::Unspecified { .. } => return Ok(None),
    };
    let swapped = doppel::swap(payload, &patterns)
        .map_err(|e| TestCaseError::fail(format!("generated swap failed: {e}")))?;
    let mut secret = SecretBytes::default();
    for span in &spans {
        for &winner in &span.winners {
            collect_secret_bytes(span, &oracles[winner], payload, &mut secret)?;
        }
    }
    Ok(Some((swapped, secret)))
}

proptest! {
    #![proptest_config(crate::support::config(128))]

    #[test]
    fn prop_entries_expose_no_secret_bytes((specs, payload) in generators::arb_case(3)) {
        let Some((swapped, secret)) = prepare(&specs, &payload)? else {
            return Ok(());
        };
        let surfaces = entry_surfaces(&swapped.entries).map_err(TestCaseError::fail)?;
        if let Some(leak) = find_secret_leak(&surfaces, &secret) {
            return Err(TestCaseError::fail(format!("INV-9/VC-7: {leak}")));
        }
    }

    #[test]
    fn prop_entries_do_not_embed_session_key((specs, payload) in generators::arb_case(3)) {
        let (_file, patterns, _oracles) = generators::build(&specs);
        let swapped = doppel::swap(&payload, &patterns).expect("generated swap must succeed");
        let surfaces = entry_surfaces(&swapped.entries).map_err(TestCaseError::fail)?;
        if let Some(leak) = find_key_leak(&surfaces, swapped.session_key.as_bytes()) {
            return Err(TestCaseError::fail(format!("INV-9/INV-10: {leak}")));
        }
    }
}

/// Synthetic secret bytes (not a real credential) for the checker self-tests.
fn synthetic_secret() -> SecretBytes {
    let region = b"Qx7Lm2Vp9Rt4Wz8K".to_vec();
    SecretBytes {
        strict: vec![region.clone()],
        derived: vec![(region, derived_window(Cs::Alphanumeric))],
    }
}

/// The ciphertext field is base64 in JSON, so only the decoded search can see
/// a plaintext ciphertext; this proves the checker does that decode.
#[test]
fn leak_checker_flags_plaintext_in_ciphertext() {
    let secret = synthetic_secret();
    let entry = Entry::new_for_testing(
        b"zzzzzzzzzzzzzzzz".to_vec(),
        vec![7u8; 24],
        secret.strict[0].clone(),
    );
    let surfaces = entry_surfaces(&[entry]).expect("synthetic entry must serialize");
    assert!(find_secret_leak(&surfaces, &secret).is_some());
}

#[test]
fn leak_checker_flags_secret_bytes_in_fake() {
    let secret = synthetic_secret();
    let entry = Entry::new_for_testing(secret.strict[0].clone(), vec![7u8; 24], vec![9u8; 32]);
    let surfaces = entry_surfaces(&[entry]).expect("synthetic entry must serialize");
    assert!(find_secret_leak(&surfaces, &secret).is_some());
}

#[test]
fn leak_checker_flags_session_key_in_nonce() {
    let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(5));
    let entry = Entry::new_for_testing(b"zzzzzzzzzzzzzzzz".to_vec(), key[..24].to_vec(), vec![9u8; 32]);
    let surfaces = entry_surfaces(&[entry]).expect("synthetic entry must serialize");
    assert!(find_key_leak(&surfaces, &key).is_some());
}

/// Guards against a checker that flags everything.
#[test]
fn leak_checker_accepts_unrelated_entry() {
    let secret = synthetic_secret();
    let key = [0xA5u8; 32];
    let entry = Entry::new_for_testing(b"zzzzzzzzzzzzzzzz".to_vec(), vec![7u8; 24], vec![9u8; 32]);
    let surfaces = entry_surfaces(&[entry]).expect("synthetic entry must serialize");
    assert_eq!(find_secret_leak(&surfaces, &secret), None);
    assert_eq!(find_key_leak(&surfaces, &key), None);
}

#[test]
fn derived_window_meets_entropy_and_capacity_floor() {
    let expected = [
        (Cs::Alphanumeric, 11),
        (Cs::UrlSafeBase64, 11),
        (Cs::Base64Any, 11),
        (Cs::UppercaseAlphanumeric, 13),
        (Cs::Digits, 20),
        (Cs::HexLower, 16),
        (Cs::Wide, 10),
    ];
    for (cs, want) in expected {
        assert_eq!(derived_window(cs), want, "derived_window({})", cs.name());
        // Every generated capacity variable segment is at least floor_len
        // long, so each detection yields at least one searched window.
        assert!(want <= generators::floor_len(cs), "{} window exceeds floor_len", cs.name());
    }
}

/// Coverage guard, not a correctness check: detections must produce regions
/// long enough to be searched, or the properties above are vacuous. Fixed seed.
#[test]
fn entries_no_leak_checks_are_exercised() {
    use proptest::test_runner::TestRunner;

    const CASES: u32 = 256;
    let strategy = generators::arb_case(3);
    let mut runner = TestRunner::deterministic();
    let mut exercised = 0u32;
    for _ in 0..CASES {
        let (specs, payload) = strategy
            .new_tree(&mut runner)
            .expect("coverage sample must generate a case")
            .current();
        let Some((_swapped, secret)) = prepare(&specs, &payload).expect("prepare must succeed")
        else {
            continue;
        };
        let strict = secret.strict.iter().any(|r| r.len() >= STRICT_WINDOW);
        let derived = secret.derived.iter().any(|(r, w)| r.len() >= *w);
        if strict && derived {
            exercised += 1;
        }
    }
    println!("entries_no_leak exercised {exercised} of {CASES}");
    assert!(
        exercised * 4 >= CASES,
        "too few cases exercise the leak checks: {exercised}/{CASES}"
    );
}
```

Notes for the implementer:
- Keep the exact test names (gates and mutation scripts grep
  `prop_entries_expose_no_secret_bytes` and `prop_entries_do_not_embed_session_key`).
- `ok_or("...")?` into a `Result<_, String>` compiles because `String: From<&str>`.
- If clippy flags `needless_range_loop`/style lints, fix them inside this file only
  without changing behaviour.
- Run `cargo fmt` before committing. No section-separator comments.

### Task 2: run gates, then the two mutation checks
`g-unit-2` makes `encrypt_secret` skip encryption (ciphertext = plaintext);
`g-unit-3` puts session-key bytes in the nonce. Both scripts revert
`doppel/src/crypto.rs` via `git checkout` on exit; afterwards
`git status --porcelain doppel/src` must print nothing.

### Task 3: commit
`git add doppel/tests/property/entries_no_leak.rs`; commit
`step-02: add entries confidentiality property` (only that file).

## Stop / ask conditions
- A property fails on the unmodified tree: candidate real INV-9/INV-10 defect.
  STOP; do not edit `src/`, do not widen windows, do not commit. Report the
  shrunk input, the failure message (which names the surface), and the
  `.proptest-regressions` file contents.
- `serialize_entries` JSON is not an array of objects of base64 strings
  (an `entry_surfaces` error): STOP and report — the serialized shape changed.
- Coverage guard fails: report counts; do not lower the threshold.
- A mutation script prints `MUTANT SURVIVED`: report; do not edit the script.

## Success Gates

Sidecar: `step-02-entries-no-leak.gates.json` (authoritative).

- [ ] g-build-1: `cargo nextest run -p doppel --all-features --test property --no-run` exits 0
- [ ] g-static-1: clippy over all doppel targets exits 0 and reports nothing in `tests/property/entries_no_leak.rs`
- [ ] g-static-2: `cargo fmt --check` exits 0
- [ ] g-static-3: the step commit touches only `doppel/tests/property/entries_no_leak.rs`
- [ ] g-unit-1: `cargo nextest run -p doppel --all-features --test property entries_no_leak::` passes (8 tests); fails before the step ("no tests to run")
- [ ] g-unit-2: `bash plans/proptest-gaps/mutations/step-02-ciphertext-is-plaintext.sh` prints `MUTANT KILLED`
- [ ] g-unit-3: `bash plans/proptest-gaps/mutations/step-02-key-in-nonce.sh` prints `MUTANT KILLED`
- [ ] g-e2e-smoke-1: `env PROPTEST_CASES=1024 cargo nextest run -p doppel --all-features --test property entries_no_leak::` passes
- [ ] g-regress-1: `cargo nextest run -p doppel --all-features --test property` passes
- [ ] g-integ-1: N/A — owned by step-04

Coverage matrix:
- serialized form (raw JSON) → g-unit-1
- decoded base64 fields nonce/ciphertext (non-fake fields) → g-unit-1, g-unit-2
- `Debug` form (fake elided / full) → g-unit-1
- public `fake` field → g-unit-1 (`leak_checker_flags_secret_bytes_in_fake`)
- session key embedded in entries → g-unit-1, g-unit-3
- instance (registered-style) specs from `arb_case` (p = 0.25) → g-unit-1
- entropy-scaled window per charset → g-unit-1 (`derived_window_meets_entropy_and_capacity_floor`)

## Reviewer Instructions
Reviewer is `wf-step-reviewer`; re-runs sidecar gates, checks g-unit-1 fails
before the step, audits `git show --stat`, checks the coverage matrix.

## Rollback
`git revert <step-02 commit>`.
