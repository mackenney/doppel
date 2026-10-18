# Step 01: Restore holdback bound (INV-8) under adversarial streams

## Context

### Overall Objective
Add four proptest properties to `doppel/tests/property/` that close SPEC.md
coverage gaps: INV-8 hold bound, INV-9/VC-7 entry confidentiality,
registration trailing-run-guard end-to-end (VC-22/26/28, INV-49/51), and
`Detector` reuse/thread safety (INV-39/40). Tests only; no `src/` changes.

### Phase Context
Wave 0, first of four strictly sequential steps (one writer in the worktree).
It comes first because it is the most self-contained and establishes the
per-module file pattern the later steps follow.

### This Step
Create `doppel/tests/property/restore_holdback.rs`. It feeds arbitrary
streams (not only the swapped payload) through the synchronous
`doppel::restore` in arbitrary chunk partitions and checks, at every chunk
boundary, that `bytes fed − bytes emitted <= max |fake_i|`, and after EOF
that every byte was emitted.

Existing overlap (read it, do not edit it): `doppel/tests/property/restore_sync.rs`
`ChunkReader` (around lines 110–145) already checks INV-8, but only for the
swapped payload itself and chunk sizes 1..=7. This step widens the domain to:
streams of planted full fakes, fake *prefixes* (the bytes restore must hold),
random bytes and the swapped payload in any order; chunk sizes up to 5000
(above restore's 4096-byte read buffer); the empty-entries passthrough path;
and an explicit EOF-flush check. It also adds a non-vacuity guard proving the
bound is actually reached (so a +1 regression is observable).

## Prerequisites
- `doppel/tests/property.rs` already contains (added by the parent, NOT by you):
  `#[path = "property/restore_holdback.rs"] mod restore_holdback;`
  Check: `grep -n 'property/restore_holdback.rs' doppel/tests/property.rs` prints one line.
- Every other module that `property.rs` declares must exist on disk (the parent
  creates placeholder files for later steps' modules if it adds all `mod` lines
  up front). If `cargo nextest run -p doppel --all-features --test property --no-run`
  fails *before you write anything* because a module file is missing: STOP and
  report; do not create or edit any other file.
- If `doppel/tests/property/restore_holdback.rs` exists as a placeholder, overwrite it.

## Files to Read Before Starting
- `doppel/src/restore.rs` — `pub fn restore<R: Read, W: Write>(input: &mut R, output: &mut W, entries: &[Entry], session_key: &SessionKey) -> Result<(), RestoreError>` (line 67). Reads into a 4096-byte buffer (`CHUNK_SIZE`, line 35), so a reader returns at most 4096 bytes per call. `max_hold` = longest fake (line 102). Empty `entries` takes a passthrough loop (lines 73–83).
- `doppel/src/restore_core.rs` — `process_safe_region` keeps at most `max_hold` bytes after each chunk (lines 52–60); on EOF it flushes everything.
- `doppel/src/types.rs` — `Entry` (`pub fake: Vec<u8>`, line 34), `SessionKey`, `SwapResult { payload, entries, session_key }`.
- `doppel/tests/property/restore_sync.rs` — the existing `ChunkReader`/`SharedWriter` pattern you are generalising (copy the idea; those items are private and cannot be imported).
- `doppel/tests/property/generators.rs` — `arb_case(max_patterns) -> (Vec<PatternSpec>, Vec<u8>)` (line 351) and `build(&[PatternSpec]) -> (SecretsFile, Vec<Pattern>, Vec<OPattern>)` (line 73).
- `doppel/tests/property/support.rs` — `crate::support::config(routine_cases)`.

## Implementation

Only file you create/overwrite: `doppel/tests/property/restore_holdback.rs`.
Do not edit `property.rs`, `support.rs`, `generators.rs`, `oracle.rs`, any other test file, or anything under `doppel/src/`. No helper additions to shared files are needed.

### Why the observation point is the `read` call
The sync API only exposes `Read`/`Write`. `restore` processes each chunk fully
(`process_safe_region`) before it calls `read` again, so when `read` is entered
the bytes handed out so far (`pos`) have all been processed: `pos − emitted`
is exactly what restore is holding "after the previous chunk". The final
`read` that returns 0 is also checked. EOF/finish is checked after `restore`
returns: output length must equal stream length because every original has
its fake's length (SPEC §Fake Generation "Same length"). Checking inside
`write` would be wrong: mid-chunk, a freshly read chunk is legitimately
unprocessed.

### Task 1: write the module (near-final code)

```rust
// P-HOLD: SPEC.md Behavioral Invariant 8 (restore hold bound) under
// adversarial streams: planted fakes, fake prefixes, random bytes and the
// swapped payload, fed in arbitrary chunk partitions, including chunks larger
// than restore's internal read buffer. Session key, nonce and ciphertext are
// never inspected; restore only needs them to decrypt.

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::rc::Rc;

use crate::generators::{self, PatternSpec};
use doppel::{Entry, SessionKey};
use proptest::prelude::*;
use proptest::sample::Index;

/// One piece of the response stream. Indices are resolved against the entries
/// produced by the case's swap, so shrinking keeps pieces valid.
#[derive(Clone, Debug)]
enum Piece {
    Fake(Index),
    /// A 1..=len prefix of a fake: the bytes restore has to hold back.
    FakePrefix(Index, Index),
    Bytes(Vec<u8>),
    Swapped,
}

fn arb_piece() -> BoxedStrategy<Piece> {
    prop_oneof![
        3 => any::<Index>().prop_map(Piece::Fake),
        3 => (any::<Index>(), any::<Index>()).prop_map(|(e, k)| Piece::FakePrefix(e, k)),
        2 => prop::collection::vec(any::<u8>(), 1..=16).prop_map(Piece::Bytes),
        1 => Just(Piece::Swapped),
    ]
    .boxed()
}

/// Chunk sizes cycled by the reader. 4000..=5000 exceeds restore's 4096-byte
/// read buffer, so the reader is clamped by `buf.len()` on that path.
fn arb_chunk_sizes() -> BoxedStrategy<Vec<usize>> {
    prop::collection::vec(
        prop_oneof![
            4 => 1usize..=8,
            2 => 9usize..=64,
            1 => 4000usize..=5000,
        ],
        1..=8,
    )
    .boxed()
}

type HoldCase = ((Vec<PatternSpec>, Vec<u8>), Vec<Piece>, Vec<usize>);

fn holdback_case() -> BoxedStrategy<HoldCase> {
    (
        generators::arb_case(3),
        prop::collection::vec(arb_piece(), 0..=24),
        arb_chunk_sizes(),
    )
        .boxed()
}

fn build_stream(entries: &[Entry], swapped: &[u8], pieces: &[Piece]) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in pieces {
        match piece {
            Piece::Bytes(bytes) => out.extend_from_slice(bytes),
            Piece::Swapped => out.extend_from_slice(swapped),
            Piece::Fake(i) if !entries.is_empty() => {
                out.extend_from_slice(&entries[i.index(entries.len())].fake);
            }
            Piece::FakePrefix(i, k) if !entries.is_empty() => {
                let fake = &entries[i.index(entries.len())].fake;
                let n = 1 + k.index(fake.len());
                out.extend_from_slice(&fake[..n]);
            }
            // No entries means there is no fake to plant.
            _ => {}
        }
    }
    out
}

#[derive(Clone, Copy, Debug, Default)]
struct Observation {
    worst_hold: usize,
    /// (bytes fed, bytes emitted) at the first read where the bound was exceeded.
    first_violation: Option<(usize, usize)>,
}

struct ProbeReader<'a> {
    data: &'a [u8],
    pos: usize,
    sizes: &'a [usize],
    next: usize,
    emitted: Rc<RefCell<Vec<u8>>>,
    max_hold: usize,
    obs: Observation,
}

impl Read for ProbeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // restore has processed every byte handed out so far, so this is the
        // observable "after a chunk" point.
        let emitted = self.emitted.borrow().len();
        let held = self.pos.saturating_sub(emitted);
        self.obs.worst_hold = self.obs.worst_hold.max(held);
        if held > self.max_hold && self.obs.first_violation.is_none() {
            self.obs.first_violation = Some((self.pos, emitted));
        }
        let remaining = self.data.len() - self.pos;
        if remaining == 0 {
            return Ok(0);
        }
        let size = self.sizes[self.next % self.sizes.len()];
        self.next += 1;
        let n = size.min(buf.len()).min(remaining);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct SharedWriter(Rc<RefCell<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Outcome {
    obs: Observation,
    max_hold: usize,
    emitted_len: usize,
}

fn run_holdback(entries: &[Entry], key: &SessionKey, stream: &[u8], sizes: &[usize]) -> Outcome {
    let max_hold = entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);
    let emitted = Rc::new(RefCell::new(Vec::new()));
    let mut reader = ProbeReader {
        data: stream,
        pos: 0,
        sizes,
        next: 0,
        emitted: emitted.clone(),
        max_hold,
        obs: Observation::default(),
    };
    let mut writer = SharedWriter(emitted.clone());
    doppel::restore(&mut reader, &mut writer, entries, key)
        .expect("restore with entries produced by swap must succeed");
    let emitted_len = emitted.borrow().len();
    Outcome {
        obs: reader.obs,
        max_hold,
        emitted_len,
    }
}

proptest! {
    #![proptest_config(crate::support::config(128))]

    #[test]
    fn prop_restore_holdback_bound_after_every_chunk(
        ((specs, payload), pieces, sizes) in holdback_case(),
    ) {
        let (_file, patterns, _oracles) = generators::build(&specs);
        let swapped = doppel::swap(&payload, &patterns).expect("generated swap must succeed");
        let stream = build_stream(&swapped.entries, &swapped.payload, &pieces);
        let out = run_holdback(&swapped.entries, &swapped.session_key, &stream, &sizes);
        prop_assert!(
            out.obs.first_violation.is_none(),
            "INV-8: held more than max_hold={} bytes; (fed, emitted)={:?} sizes={:?}",
            out.max_hold,
            out.obs.first_violation,
            sizes
        );
        prop_assert!(out.obs.worst_hold <= out.max_hold);
        // EOF: every held byte must be flushed; originals and fakes have equal
        // length, so the output length equals the stream length.
        prop_assert_eq!(
            out.emitted_len,
            stream.len(),
            "restore must emit every byte by EOF"
        );
    }
}

/// Coverage guard, not a correctness check: the bound must actually be
/// reached in a meaningful share of cases, otherwise a restore that held one
/// byte too many could go unnoticed. Fixed seed, so it cannot flake.
#[test]
fn restore_holdback_bound_is_reached() {
    use proptest::test_runner::TestRunner;

    const CASES: u32 = 256;
    let strategy = holdback_case();
    let mut runner = TestRunner::deterministic();
    let mut with_entries = 0u32;
    let mut tight = 0u32;
    for _ in 0..CASES {
        let ((specs, payload), pieces, sizes) = strategy
            .new_tree(&mut runner)
            .expect("coverage sample must generate a case")
            .current();
        let (_file, patterns, _oracles) = generators::build(&specs);
        let swapped = doppel::swap(&payload, &patterns).expect("generated swap must succeed");
        let stream = build_stream(&swapped.entries, &swapped.payload, &pieces);
        let out = run_holdback(&swapped.entries, &swapped.session_key, &stream, &sizes);
        if swapped.entries.is_empty() {
            continue;
        }
        with_entries += 1;
        if out.max_hold > 0 && out.obs.worst_hold == out.max_hold {
            tight += 1;
        }
    }
    println!("restore_holdback over {CASES}: with_entries={with_entries} tight={tight}");
    assert!(
        tight * 4 >= CASES,
        "hold bound reached too rarely: tight={tight} with_entries={with_entries} of {CASES}"
    );
}
```

Notes for the implementer:
- Keep the exact test names `prop_restore_holdback_bound_after_every_chunk`
  and `restore_holdback_bound_is_reached` (the gates and mutation script grep them).
- `.boxed()` and `.new_tree()` come from `proptest::strategy::Strategy`, which
  `proptest::prelude::*` re-exports; no extra import is needed.
- If a compile error appears, fix it inside this file only, keeping the case
  shape, the assertions and the test names unchanged.
- Run `cargo fmt` before committing (it may reflow lines).
- No section-separator comments; comments explain why.

### Task 2: run gates, then the mutation check
Run every command in "Success Gates" in order. `g-unit-2` temporarily mutates
`doppel/src/restore.rs` (`max_hold` + 1) and restores it via `git checkout`
on exit; afterwards `git status --porcelain doppel/src` must print nothing.

### Task 3: commit
`git add doppel/tests/property/restore_holdback.rs` and commit with message
`step-01: add restore holdback bound property` (only that file). Then run
g-static-3 (it inspects `HEAD~1..HEAD`).

## Stop / ask conditions
- `prop_restore_holdback_bound_after_every_chunk` fails on the unmodified tree:
  candidate real INV-8 or EOF defect. STOP. Do not edit `src/`, do not
  loosen the assertion, do not commit. Report the shrunk counterexample
  (proptest prints `minimal failing input`) and the contents of
  `doppel/tests/property/restore_holdback.proptest-regressions`.
- `restore_holdback_bound_is_reached` fails: report the printed counts; do not
  lower the 25% threshold without a supervisor decision.
- The mutation script reports `MUTANT SURVIVED`: report; do not change the script.
- Any gate fails for a reason outside `restore_holdback.rs` (e.g. a pre-existing
  clippy/fmt issue elsewhere): report, do not fix other files.

## Success Gates

Sidecar: `step-01-restore-holdback.gates.json` (authoritative; this list mirrors it).

- [ ] g-build-1: `cargo nextest run -p doppel --all-features --test property --no-run` exits 0
- [ ] g-static-1: clippy over all doppel targets exits 0 and reports nothing in `tests/property/restore_holdback.rs`
- [ ] g-static-2: `cargo fmt --check` exits 0
- [ ] g-static-3: the step commit touches only `doppel/tests/property/restore_holdback.rs`
- [ ] g-unit-1: `cargo nextest run -p doppel --all-features --test property restore_holdback::` passes (2 tests); before this step it fails ("no tests to run")
- [ ] g-unit-2: `bash plans/proptest-gaps/mutations/step-01-max-hold-plus-one.sh` prints `MUTANT KILLED` and exits 0
- [ ] g-e2e-smoke-1: `env PROPTEST_CASES=1024 cargo nextest run -p doppel --all-features --test property restore_holdback::` passes
- [ ] g-regress-1: `cargo nextest run -p doppel --all-features --test property` passes
- [ ] g-integ-1: N/A — plan-level integration run is owned by step-04

Coverage matrix (rows → gate):
- entries non-empty, chunk sizes 1..=64 (cycled) → g-unit-1
- chunk size > 4096 (`buf.len()` clamp in restore's read loop) → g-unit-1
- entries empty → passthrough path, max_hold = 0 → g-unit-1
- fake prefix at end of stream (EOF flush of a held partial fake) → g-unit-1
- bound tightness / non-vacuity → g-unit-1 (`restore_holdback_bound_is_reached`) and g-unit-2
- `PROPTEST_CASES` env override honoured by `support::config` → g-e2e-smoke-1

## Reviewer Instructions
Reviewer is `wf-step-reviewer`; it re-runs the sidecar gates, checks g-unit-1
fails before the step (no tests matched), audits `git show --stat`, and checks
the coverage matrix. No ad-hoc reviewer prose.

## Rollback
`git revert <step-01 commit>` (removes the new test file only).
