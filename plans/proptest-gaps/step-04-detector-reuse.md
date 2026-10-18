# Step 04: Detector reuse and cross-thread sharing (INV-39 / INV-40)

## Context

### Overall Objective
Add four proptest properties to `doppel/tests/property/` that close SPEC.md
coverage gaps: INV-8 hold bound, INV-9/VC-7 entry confidentiality,
registration trailing-run-guard end-to-end (VC-22/26/28, INV-49/51), and
`Detector` reuse/thread safety (INV-39/40). Tests only; no `src/` changes.

### Phase Context
Wave 3, last of four strictly sequential steps. It also carries the plan-level
integration gate (full workspace suite) because it is the final step.

### This Step
Create `doppel/tests/property/detector_reuse.rs`. The existing property
`detection.rs::prop_swap_is_stable_and_detector_matches_free_swap` checks a
*fresh* `Detector` on *one* payload of a *single family* pattern. This step
checks that **one** `Detector` reused across many payloads (in two orders) and
shared by 2–4 `std::thread::scope` threads produces exactly what the free
`doppel::swap` (the reference) and a fresh `Detector` produce: same swapped
payload bytes and same entry fakes in the same order. It also checks each
call's entries decrypt under that call's own session key (no cross-call or
cross-thread mixing of keys/entries).

Verified API facts:
- `doppel/src/detector.rs:61` — `pub fn new(patterns: Vec<Pattern>) -> Self` (`#[must_use]`); `:73` — `pub fn swap(&self, payload: &[u8]) -> Result<SwapResult, SwapError>` delegating to `swap_with_ac` (`:74`). `Detector` is `Send + Sync` (`:89-94`).
- `doppel/src/swap.rs:98` — `pub fn swap(payload: &[u8], patterns: &[Pattern]) -> Result<SwapResult, SwapError>`; both paths call the same `swap_with_ac` (`swap.rs:109`), which generates a fresh session key and nonces via `OsRng` per call — so ciphertext/nonce/key are never compared, only payload bytes and fakes (fakes are deterministic from the pattern salt, SPEC §Fake Generation "Stability").
- `Pattern: Clone` (`doppel/src/patterns.rs:806`). `SwapResult { payload, entries, session_key }` (`doppel/src/types.rs:85-93`), `Entry::fake` is `pub`.
- `doppel::restore(&mut R, &mut W, &[Entry], &SessionKey)` (`doppel/src/restore.rs:67`) returns `Err(AeadTagFailure)` if an entry does not decrypt under the key.
- Full ties the SPEC leaves unspecified are resolved by pattern-set order inside the shared `find_best_match` (`swap.rs:24`), identically for both paths, so no case is skipped.
- INV-41 (automaton built once) is a structural property not observable through the public API; out of scope.

## Prerequisites
- Steps 01–03 complete (single writer).
- `doppel/tests/property.rs` contains `#[path = "property/detector_reuse.rs"] mod detector_reuse;` (added by the parent). Check with `grep -n 'property/detector_reuse.rs' doppel/tests/property.rs`.
- If `doppel/tests/property/detector_reuse.rs` exists as a placeholder, overwrite it.

## Files to Read Before Starting
- `doppel/src/detector.rs`
- `doppel/src/swap.rs` (lines 1–60, 98–175)
- `doppel/tests/property/detection.rs` (lines 125–152, the existing parity property)
- `doppel/tests/property/generators.rs` — `arb_case` (line 351), `arb_payload` (line 272, `pub fn arb_payload(specs: &[PatternSpec]) -> BoxedStrategy<Vec<u8>>`), `build` (line 73)
- `doppel/tests/integration/detector.rs` (lines 130–172) — existing non-property thread test, for conventions

## Implementation

Only file you create/overwrite: `doppel/tests/property/detector_reuse.rs`.
No other file is edited; no helper additions to shared files.

### Task 1: write the module (near-final code)

```rust
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
            return Err(format!("entry {i}: restored length differs from fake length"));
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
        let results: Vec<Vec<(usize, Outcome, Result<(), String>)>> = std::thread::scope(|s| {
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
```

Notes for the implementer:
- Keep the exact test names (gates and the mutation script grep them).
- `std::thread::scope` needs `&Detector: Send`, i.e. `Detector: Sync`; that
  compiling is itself the INV-40 compile-time check — do not wrap it in `Arc`/`Mutex`.
- If the `results` type annotation does not infer, keep it explicit as written;
  fix compile errors only inside this file.
- Run `cargo fmt` before committing. No section-separator comments.

### Task 2: run gates and the mutation check
`g-unit-2` makes `Detector::swap` ignore its first pattern; the reused and
threaded properties must fail against the free-swap reference. The script
reverts `doppel/src/detector.rs` via `git checkout` on exit; afterwards
`git status --porcelain doppel/src` must print nothing.

### Task 3: commit
`git add doppel/tests/property/detector_reuse.rs`; commit
`step-04: add Detector reuse and thread-sharing property` (only that file).
Then run g-integ-1 (full workspace suite) — the plan-level integration gate.

## Stop / ask conditions
- A property fails on the unmodified tree: candidate real INV-39/40 defect.
  STOP; no `src/` edits, no weakening, no commit. Report the shrunk case,
  the message (which payload/thread diverged) and `.proptest-regressions`.
- A thread panics (`worker thread panicked`): treat as a finding; report.
- Coverage guard fails: report counts; do not lower the threshold.
- The mutation script prints `MUTANT SURVIVED`: report; do not edit the script.
- g-integ-1 fails in a test outside `doppel/tests/property/`: report the
  failing test names; do not fix unrelated files.

## Success Gates

Sidecar: `step-04-detector-reuse.gates.json` (authoritative).

- [ ] g-build-1: `cargo nextest run -p doppel --all-features --test property --no-run` exits 0
- [ ] g-static-1: clippy over all doppel targets exits 0 and reports nothing in `tests/property/detector_reuse.rs`
- [ ] g-static-2: `cargo fmt --check` exits 0
- [ ] g-static-3: the step commit touches only `doppel/tests/property/detector_reuse.rs`
- [ ] g-unit-1: `cargo nextest run -p doppel --all-features --test property detector_reuse::` passes (3 tests); fails before the step ("no tests to run")
- [ ] g-unit-2: `bash plans/proptest-gaps/mutations/step-04-detector-drops-first-pattern.sh` prints `MUTANT KILLED`
- [ ] g-e2e-smoke-1: `env PROPTEST_CASES=512 cargo nextest run -p doppel --all-features --test property detector_reuse::` passes
- [ ] g-regress-1: `cargo nextest run -p doppel --all-features --test property` passes
- [ ] g-integ-1: `cargo nextest run --workspace` passes (plan-level integration: all lib + CLI tests with the four new modules present)
- [ ] g-integ-2: `env PROPTEST_CASES=1024 cargo nextest run -p doppel --all-features --test property restore_holdback:: entries_no_leak:: registration_guard:: detector_reuse::` passes (plan-level scaled run of all four new modules)

Coverage matrix:
- one Detector reused sequentially, forward and reverse payload order → g-unit-1
- fresh Detector per payload → g-unit-1
- Detector shared across 2–4 scoped threads, overlapping payloads → g-unit-1
- entries/session key coherent per call (AEAD round trip) → g-unit-1
- instance pattern in the set (`arb_case`, p = 0.25) → g-unit-1
- Detector diverging from free swap is detected → g-unit-2
- whole workspace with all four new modules → g-integ-1, g-integ-2

## Reviewer Instructions
Reviewer is `wf-step-reviewer`; re-runs sidecar gates, checks g-unit-1 fails
before the step, audits `git show --stat`, checks the coverage matrix.

## Rollback
`git revert <step-04 commit>`.
