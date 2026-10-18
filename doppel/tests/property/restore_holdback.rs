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
