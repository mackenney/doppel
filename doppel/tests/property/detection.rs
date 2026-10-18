// P-DET-1: single-family-pattern swap agrees with the independent oracle.
// The spans `swap` replaced cannot be recovered from its output (fakes are
// random), so the oracle predicts them first and the checks below compare the
// output against that prediction. Never read the session key, nonce, or
// ciphertext.

use std::collections::HashMap;

use crate::generators::{self, PatternSpec};
use crate::oracle::{self, Scan};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// Returns Ok(()) or a TestCaseError describing the first divergence.
///
/// Reused by later detection properties. A full tie the spec leaves
/// unspecified (`Scan::Unspecified`, ambiguity A-6) is passed over: it is not
/// a divergence. `patterns` and `oracle` MUST describe the same pattern list
/// in the same order.
pub fn check_swap_against_oracle(
    patterns: &[doppel::Pattern],
    oracle: &[oracle::OPattern],
    payload: &[u8],
) -> Result<(), TestCaseError> {
    let spans = match oracle::scan(oracle, payload) {
        Scan::Spans(spans) => spans,
        Scan::Unspecified { .. } => return Ok(()),
    };

    // Generated patterns always contain a Variable segment, so the only error
    // variant that can occur is Crypto; a Fake error here would be a finding.
    let r = match doppel::swap(payload, patterns) {
        Ok(r) => r,
        Err(e) => {
            return Err(TestCaseError::fail(format!(
                "swap failed on generated input: {e}"
            )));
        }
    };

    prop_assert_eq!(r.payload.len(), payload.len());

    let mut seen: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut prev_end = 0usize;
    for span in &spans {
        prop_assert!(span.start >= prev_end, "oracle spans must advance");
        // INV-2: bytes outside a detected span are copied verbatim.
        prop_assert_eq!(
            &r.payload[prev_end..span.start],
            &payload[prev_end..span.start],
            "bytes between spans must be unchanged"
        );

        let orig = &payload[span.start..span.end];
        let fake = &r.payload[span.start..span.end];
        // INV-15/27/28/29: the fake fits some winning pattern's structure.
        prop_assert!(
            span.winners
                .iter()
                .any(|&i| oracle::fake_conforms(&oracle[i], orig, fake)),
            "fake does not conform to a winning pattern at span {}..{}",
            span.start,
            span.end
        );

        // INV-14: the same secret always maps to the same fake.
        match seen.get(orig) {
            Some(previous) => prop_assert_eq!(
                previous.as_slice(),
                fake,
                "repeated secret mapped to a different fake"
            ),
            None => {
                seen.insert(orig.to_vec(), fake.to_vec());
            }
        }
        prev_end = span.end;
    }
    // INV-2: the tail after the last span is copied verbatim.
    prop_assert_eq!(
        &r.payload[prev_end..],
        &payload[prev_end..],
        "bytes after the last span must be unchanged"
    );

    // INV-3: one entry per distinct secret; INV-14: distinct-secret fakes match.
    prop_assert_eq!(
        r.entries.len(),
        seen.len(),
        "entry count must match distinct secrets"
    );
    let mut distinct_fakes: Vec<Vec<u8>> = seen.values().cloned().collect();
    let mut entry_fakes: Vec<Vec<u8>> = r.entries.iter().map(|e| e.fake.clone()).collect();
    distinct_fakes.sort();
    entry_fakes.sort();
    prop_assert_eq!(
        entry_fakes,
        distinct_fakes,
        "entry fake multiset must match distinct span fakes"
    );

    Ok(())
}

/// A single family-pattern case: exactly one spec (no instance spec) and a
/// payload built for it. `generators::arb_case(1)` also adds an instance spec
/// with probability 0.25, so this builds the family-only case locally.
fn single_family_case() -> BoxedStrategy<(Vec<PatternSpec>, Vec<u8>)> {
    generators::arb_family_spec()
        .prop_flat_map(|spec| {
            let payload = generators::arb_payload(std::slice::from_ref(&spec));
            (Just(vec![spec]), payload)
        })
        .boxed()
}

proptest! {
    #![proptest_config(crate::support::config(64))]

    #[test]
    fn prop_single_family_pattern_swap_matches_oracle(
        (specs, payload) in single_family_case(),
    ) {
        let (_file, patterns, oracles) = generators::build(&specs);
        prop_assert_eq!(patterns.len(), oracles.len());
        check_swap_against_oracle(&patterns, &oracles, &payload)?;
    }

    #[test]
    fn prop_swap_is_stable_and_detector_matches_free_swap(
        (specs, payload) in single_family_case(),
    ) {
        let (_file, patterns, _oracles) = generators::build(&specs);

        // INV-13: a fixed Pattern set produces the same fake for the same secret.
        let first = doppel::swap(&payload, &patterns)
            .expect("generated family swap must succeed");
        let second = doppel::swap(&payload, &patterns)
            .expect("generated family swap must succeed");
        prop_assert_eq!(&first.payload, &second.payload, "INV-13: swap payload must be stable");
        let fakes_first: Vec<Vec<u8>> = first.entries.iter().map(|e| e.fake.clone()).collect();
        let fakes_second: Vec<Vec<u8>> = second.entries.iter().map(|e| e.fake.clone()).collect();
        prop_assert_eq!(&fakes_first, &fakes_second, "INV-13: fakes must be stable");

        // INV-39/VC-3: Detector::swap matches the free function byte for byte.
        let detector = doppel::Detector::new(patterns.clone());
        let detected = detector.swap(&payload).expect("generated Detector swap must succeed");
        prop_assert_eq!(&detected.payload, &first.payload, "INV-39: payload parity");
        let fakes_detector: Vec<Vec<u8>> = detected.entries.iter().map(|e| e.fake.clone()).collect();
        prop_assert_eq!(&fakes_detector, &fakes_first, "INV-39: entry fake parity");
    }
}

/// Coverage guard, not a correctness check: the generator must produce cases
/// the oracle actually flags, otherwise the properties above are vacuous.
/// Fixed seed via `TestRunner::deterministic`, so it cannot flake.
#[test]
fn prop_classification_has_detections() {
    use proptest::test_runner::TestRunner;

    const CASES: u32 = 256;
    let strategy = single_family_case();
    let mut runner = TestRunner::deterministic();

    let mut detected = 0u32;
    let mut no_match = 0u32;
    let mut unspecified = 0u32;
    for _ in 0..CASES {
        let (specs, payload) = strategy
            .new_tree(&mut runner)
            .expect("coverage sample must generate a case")
            .current();
        let (_file, _patterns, oracles) = generators::build(&specs);
        match oracle::scan(&oracles, &payload) {
            Scan::Spans(spans) if !spans.is_empty() => detected += 1,
            Scan::Spans(_) => no_match += 1,
            Scan::Unspecified { .. } => unspecified += 1,
        }
    }
    // Reported for the parent; the assertion below is the actual guard.
    println!(
        "classification over {CASES} cases: detected={detected} no_match={no_match} unspecified={unspecified}"
    );
    assert!(
        detected * 4 >= CASES,
        "detection coverage too low: detected={detected} no_match={no_match} unspecified={unspecified} of {CASES}"
    );
}
