// P-DET-REUSE: SPEC.md Behavioral Invariants 39 and 40. One Detector,
// reused across many payloads and shared across threads without external
// synchronisation, must produce exactly what the free `swap` produces for the
// same Pattern values. Session keys, nonces and ciphertexts are fresh per
// call, so they are never compared; each call's entries are only checked to
// decrypt under that call's own key.

use crate::generators::{self, PatternSpec};
use doppel::{Detector, SwapResult};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// The deterministic part of a swap: payload bytes and entry fakes in order.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Outcome {
    payload: Vec<u8>,
    fakes: Vec<Vec<u8>>,
}

fn outcome(r: &SwapResult) -> Outcome {
    Outcome {
        payload: r.payload.clone(),
        fakes: r.entries.iter().map(|e| e.fake.clone()).collect(),
    }
}

/// Every fake of one call restores without an AEAD error under that call's
/// own key, so keys and entries were not mixed between calls or threads.
fn entries_decrypt(r: &SwapResult) -> Result<(), String> {
    for (i, entry) in r.entries.iter().enumerate() {
        let mut input = entry.fake.as_slice();
        let mut out = Vec::new();
        doppel::restore(&mut input, &mut out, &r.entries, &r.session_key)
            .map_err(|e| format!("entry {i}: restore failed: {e}"))?;
        if out.len() != entry.fake.len() {
            return Err(format!(
                "entry {i}: restored length differs from fake length"
            ));
        }
    }
    Ok(())
}

/// A pattern set plus 2..=6 payloads built for it.
fn reuse_case() -> BoxedStrategy<(Vec<PatternSpec>, Vec<Vec<u8>>)> {
    generators::arb_case(3)
        .prop_flat_map(|(specs, first)| {
            let more = prop::collection::vec(generators::arb_payload(&specs), 1..=5);
            (Just(specs), Just(first), more)
        })
        .prop_map(|(specs, first, mut more)| {
            more.insert(0, first);
            (specs, more)
        })
        .boxed()
}

/// One worker-thread observation: payload index, deterministic outcome, and
/// whether that call's entries decrypted under its own session key.
type ThreadSample = (usize, Outcome, Result<(), String>);

fn reference(patterns: &[doppel::Pattern], payloads: &[Vec<u8>]) -> Vec<Outcome> {
    payloads
        .iter()
        .map(|p| outcome(&doppel::swap(p, patterns).expect("free swap must succeed")))
        .collect()
}

proptest! {
    #![proptest_config(crate::support::config(64))]

    #[test]
    fn prop_detector_reused_sequentially_matches_free_swap(
        (specs, payloads) in reuse_case(),
    ) {
        let (_file, patterns, _oracles) = generators::build(&specs);
        let expected = reference(&patterns, &payloads);
        let detector = Detector::new(patterns.clone());
        // Forward then reverse, so every payload is swapped after different
        // predecessors on the same Detector.
        let n = payloads.len();
        let order: Vec<usize> = (0..n).chain((0..n).rev()).collect();
        for &i in &order {
            let reused = detector.swap(&payloads[i]).expect("Detector swap must succeed");
            prop_assert_eq!(
                &outcome(&reused),
                &expected[i],
                "INV-39: reused Detector diverged from free swap on payload {}",
                i
            );
            entries_decrypt(&reused).map_err(TestCaseError::fail)?;
            let fresh = Detector::new(patterns.clone())
                .swap(&payloads[i])
                .expect("fresh Detector swap must succeed");
            prop_assert_eq!(
                &outcome(&fresh),
                &expected[i],
                "INV-39: fresh Detector diverged from free swap on payload {}",
                i
            );
        }
    }
}

proptest! {
    #![proptest_config(crate::support::config(32))]

    #[test]
    fn prop_detector_shared_across_threads_matches_free_swap(
        ((specs, payloads), threads) in (reuse_case(), 2usize..=4),
    ) {
        let (_file, patterns, _oracles) = generators::build(&specs);
        let expected = reference(&patterns, &payloads);
        let detector = Detector::new(patterns.clone());
        let n = payloads.len();
        // Each thread walks the payloads twice from a different offset, so
        // the same payload is swapped concurrently by different threads.
        let results: Vec<Vec<ThreadSample>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    let detector = &detector;
                    let payloads = &payloads;
                    s.spawn(move || {
                        (0..2 * n)
                            .map(|step| {
                                let i = (t + step) % n;
                                let r = detector
                                    .swap(&payloads[i])
                                    .expect("Detector swap must succeed");
                                (i, outcome(&r), entries_decrypt(&r))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("worker thread panicked"))
                .collect()
        });
        for (t, per_thread) in results.iter().enumerate() {
            for (i, got, decrypt) in per_thread {
                prop_assert_eq!(
                    got,
                    &expected[*i],
                    "INV-40: thread {} diverged from free swap on payload {}",
                    t,
                    i
                );
                prop_assert!(decrypt.is_ok(), "thread {} payload {}: {:?}", t, i, decrypt);
            }
        }
    }
}

/// Coverage guard, not a correctness check: most cases must contain a
/// detection, otherwise equal outputs would be trivially equal. Fixed seed.
#[test]
fn detector_reuse_cases_have_detections() {
    use proptest::test_runner::TestRunner;

    const CASES: u32 = 256;
    let strategy = reuse_case();
    let mut runner = TestRunner::deterministic();
    let mut with_detection = 0u32;
    for _ in 0..CASES {
        let (specs, payloads) = strategy
            .new_tree(&mut runner)
            .expect("coverage sample must generate a case")
            .current();
        let (_file, patterns, _oracles) = generators::build(&specs);
        if reference(&patterns, &payloads)
            .iter()
            .any(|o| !o.fakes.is_empty())
        {
            with_detection += 1;
        }
    }
    println!("detector_reuse: {with_detection} of {CASES} cases contain a detection");
    assert!(
        with_detection * 2 >= CASES,
        "too few cases with a detection: {with_detection}/{CASES}"
    );
}
