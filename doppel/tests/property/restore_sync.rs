// P-RST: synchronous restore round trip under arbitrary partitions, the INV-8
// hold bound, INV-7 identity, and EOF partial-fake forwarding.
//
// Every case is generated constructively and checked against the independent
// oracle. Fakes are stable and salt-derived, so round-trip correctness is
// asserted on the restored bytes. Session key, nonce, and ciphertext are never
// read, and no crypto observable is inspected.

use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use std::rc::Rc;

use crate::generators::{self, PatternSpec};
use crate::oracle::{self, Cs, OPattern, Scan, Seg, Span};
use doppel::Entry;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// One sync restore case: the shared floor-meeting generator only. The former
/// prefix-prone sub-strategy was a low-entropy generator whose collisions are
/// accepted contract behavior; the D-2 prefix topology now lives in the
/// purpose-specific fixture below.
fn sync_case() -> BoxedStrategy<(Vec<PatternSpec>, Vec<u8>)> {
    generators::arb_case(3).boxed()
}

/// VC-2 domain precondition (spec ambiguity A-1): every occurrence of every fake
/// in `swapped` must lie inside a replaced span. Otherwise the original payload
/// itself already contained a fake's bytes outside a replacement, and restore is
/// required to rewrite those bytes too, so a byte-identical round trip cannot hold.
/// Brute-force window scan; checks the condition explicitly instead of filtering
/// generator output.
fn natural_domain(swapped: &[u8], spans: &[(usize, usize)], fakes: &[Vec<u8>]) -> bool {
    for fake in fakes {
        if fake.is_empty() {
            continue;
        }
        // `windows` yields nothing when the fake is longer than `swapped`, so
        // there is no out-of-bounds slice and no fake to check.
        for (start, window) in swapped.windows(fake.len()).enumerate() {
            if window != fake.as_slice() {
                continue;
            }
            let covered = spans
                .iter()
                .any(|&(s, e)| start >= s && start + fake.len() <= e);
            if !covered {
                return false;
            }
        }
    }
    true
}

fn span_pairs(spans: &[Span]) -> Vec<(usize, usize)> {
    spans.iter().map(|s| (s.start, s.end)).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Bytes of the span's variable and opaque segments under the winning pattern's
/// oracle segmentation at `span.end`, split into one region per maximal run of
/// adjacent non-literal segments. Regions are never concatenated across a
/// literal: literal bytes are reproduced verbatim in the fake by design
/// (INV-27), so a window spanning a literal would not be a leaked secret.
fn secret_regions(
    span: &Span,
    pattern: &OPattern,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, TestCaseError> {
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
        let mut regions: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut off = span.start;
        for (seg, &len) in pattern.segs.iter().zip(lens.iter()) {
            if matches!(seg, Seg::Lit(_)) {
                if !current.is_empty() {
                    regions.push(std::mem::take(&mut current));
                }
            } else {
                current.extend_from_slice(&payload[off..off + len]);
            }
            off += len;
        }
        if !current.is_empty() {
            regions.push(current);
        }
        return Ok(regions);
    }
    Err(TestCaseError::fail(format!(
        "no accepted oracle segmentation reproduces span end {} at start {}",
        span.end, span.start
    )))
}

/// A reader that feeds `data` in a repeating pattern of chunk sizes and, before
/// supplying each new chunk, checks the INV-8 hold bound against the bytes
/// supplied so far. The check runs before `pos` advances: newly returned bytes
/// have not been processed by `restore` yet, so comparing the emitted length to
/// the advanced position would be a false positive. Output offsets match input
/// offsets because fakes have the same length as the originals.
struct ChunkReader<'a> {
    data: &'a [u8],
    pos: usize,
    sizes: Vec<usize>,
    i: usize,
    emitted: Rc<RefCell<Vec<u8>>>,
    max_hold: usize,
    violation: Rc<Cell<bool>>,
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.emitted.borrow().len() + self.max_hold < self.pos {
            self.violation.set(true);
        }
        let remaining = self.data.len() - self.pos;
        if remaining == 0 {
            return Ok(0);
        }
        let size = self.sizes[self.i % self.sizes.len()].max(1);
        let n = size.min(buf.len()).min(remaining);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.i += 1;
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

/// VC-2/VC-4/INV-4/INV-7/INV-8/INV-19 plus the A-3 entry-confidentiality check.
fn check_round_trip(
    specs: &[PatternSpec],
    payload: &[u8],
    sizes: &[usize],
) -> Result<(), TestCaseError> {
    let (_file, patterns, oracles) = generators::build(specs);
    let spans = match oracle::scan(&oracles, payload) {
        Scan::Spans(spans) => spans,
        Scan::Unspecified { .. } => return Ok(()),
    };
    let swapped = doppel::swap(payload, &patterns).expect("generated swap must succeed");
    let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
    if !natural_domain(&swapped.payload, &span_pairs(&spans), &fakes) {
        return Ok(());
    }

    // VC-4: whole-slice restore reproduces the original payload.
    let mut whole = swapped.payload.as_slice();
    let mut whole_out = Vec::new();
    doppel::restore(
        &mut whole,
        &mut whole_out,
        &swapped.entries,
        &swapped.session_key,
    )
    .expect("whole-slice restore must succeed");
    prop_assert_eq!(
        &whole_out,
        payload,
        "whole-slice restore must reproduce the original payload"
    );

    // INV-4/INV-8: arbitrary partitioning restores identically and never holds
    // more than max_hold bytes unemitted.
    let emitted = Rc::new(RefCell::new(Vec::new()));
    let violation = Rc::new(Cell::new(false));
    let max_hold = swapped
        .entries
        .iter()
        .map(|e| e.fake.len())
        .max()
        .unwrap_or(0);
    let mut reader = ChunkReader {
        data: &swapped.payload,
        pos: 0,
        sizes: sizes.to_vec(),
        i: 0,
        emitted: emitted.clone(),
        max_hold,
        violation: violation.clone(),
    };
    let mut writer = SharedWriter(emitted.clone());
    doppel::restore(
        &mut reader,
        &mut writer,
        &swapped.entries,
        &swapped.session_key,
    )
    .expect("chunked restore must succeed");
    let out = emitted.borrow().clone();
    prop_assert_eq!(
        &out,
        payload,
        "partitioned restore must reproduce the original payload"
    );
    prop_assert!(
        !violation.get(),
        "INV-8: restore held more than max_hold bytes unemitted"
    );

    // A-3/INV-9: no 16-byte window of a span's variable/opaque bytes appears in
    // the serialized entries. Conservative: only windows fully inside the
    // variable/opaque region; literal bytes are excluded by design.
    let serialized = Entry::serialize_entries(&swapped.entries).expect("entries must serialize");
    for span in &spans {
        for &winner in &span.winners {
            for region in secret_regions(span, &oracles[winner], payload)? {
                if region.len() < 16 {
                    continue;
                }
                for window in region.windows(16) {
                    prop_assert!(
                        !serialized.windows(16).any(|w| w == window),
                        "INV-9: serialized entries contain a secret window"
                    );
                }
            }
        }
    }
    Ok(())
}

/// D-2 purpose-specific low-entropy fixture. One pattern `[Lit("PQ"), Var(Digits, 1, 2)]`
/// and a payload with exactly one 1-digit and one 2-digit candidate. Fakes keep their
/// originals' lengths, so the two fakes can never be equal: distinctness holds by
/// construction and no fake-distinctness skip is needed. Some salts derive a fake whose
/// shorter counter is a proper prefix of the longer one, which is the prefix-shadowing
/// topology D-2 mangled before restore switched to LeftmostLongest.
#[test]
fn restore_sync_prefix_related_fakes_fixture() {
    const SYNTH_PREFIX_PAYLOAD: &[u8] = b"a PQ1 b PQ12 c";
    const PARTITIONS: [&[usize]; 3] = [&[1], &[2, 3], &[7]];

    let mut prefix_related_seeds = 0u32;
    for seed in 0..200u32 {
        let mut salt = [0u8; 32];
        salt[..4].copy_from_slice(&seed.to_le_bytes());
        let specs = vec![PatternSpec {
            segs: vec![Seg::Lit(b"PQ".to_vec()), Seg::Var(Cs::Digits, 1, 2)],
            guard: None,
            guard_cs: None,
            salt,
            accepted: None,
        }];
        for &sizes in &PARTITIONS {
            check_round_trip(&specs, SYNTH_PREFIX_PAYLOAD, sizes)
                .unwrap_or_else(|e| panic!("seed {seed}, partitions {sizes:?}: {e:?}"));
        }

        let (_file, patterns, _oracles) = generators::build(&specs);
        let swapped =
            doppel::swap(SYNTH_PREFIX_PAYLOAD, &patterns).expect("fixture swap must succeed");
        let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
        if fakes.len() == 2 {
            let (short, long) = if fakes[0].len() <= fakes[1].len() {
                (&fakes[0], &fakes[1])
            } else {
                (&fakes[1], &fakes[0])
            };
            if short.len() < long.len() && long.starts_with(short.as_slice()) {
                prefix_related_seeds += 1;
            }
        }
    }
    assert!(
        prefix_related_seeds > 0,
        "fixture produced no prefix-related fake pair"
    );
}

/// A fake longer than the swapped payload yields no windows; the old
/// `0..=len.saturating_sub(fake.len())` loop sliced out of bounds and panicked.
#[test]
fn natural_domain_handles_fake_longer_than_input() {
    assert!(natural_domain(b"ab", &[], &[b"abc".to_vec()]));
}

/// Regions are maximal runs of non-literal segments, so a literal separator splits
/// them and no window spans the literal.
#[test]
fn secret_regions_split_at_literals() {
    let pattern = OPattern {
        segs: vec![
            Seg::Opq(b"ab".to_vec(), Cs::Alphanumeric),
            Seg::Var(Cs::Digits, 1, 1),
            Seg::Lit(b"_".to_vec()),
            Seg::Var(Cs::Digits, 1, 1),
        ],
        guard: None,
        guard_cs: None,
        accepted: None,
    };
    let payload = b"ab1_2";
    let span = Span {
        start: 0,
        end: payload.len(),
        winners: vec![0],
    };
    let regions =
        secret_regions(&span, &pattern, payload).expect("segmentation must reproduce span end");
    assert_eq!(regions, vec![b"ab1".to_vec(), b"2".to_vec()]);
    for region in &regions {
        assert!(
            !region.contains(&b'_'),
            "a secret region crossed the literal separator"
        );
    }
}

proptest! {
    #![proptest_config(crate::support::config(48))]

    #[test]
    fn prop_restore_round_trips_under_any_partition(
        (case, sizes) in (
            sync_case(),
            prop::collection::vec(1usize..=7, 1..=6),
        ),
    ) {
        let (specs, payload) = case;
        check_round_trip(&specs, &payload, &sizes)?;
    }

    #[test]
    fn prop_restore_without_fakes_is_identity(
        (case, stream) in (
            sync_case(),
            prop::collection::vec(any::<u8>(), 0..512),
        ),
    ) {
        let (specs, payload) = case;
        let (_file, patterns, _oracles) = generators::build(&specs);
        let swapped = doppel::swap(&payload, &patterns).expect("generated swap must succeed");
        if swapped
            .entries
            .iter()
            .any(|e| contains(&stream, &e.fake))
        {
            return Ok(());
        }
        let mut input = stream.as_slice();
        let mut out = Vec::new();
        doppel::restore(&mut input, &mut out, &swapped.entries, &swapped.session_key)
            .expect("INV-7: no fake means no error");
        prop_assert_eq!(&out, &stream, "INV-7: output must equal input byte-for-byte");
    }

    #[test]
    fn prop_partial_fake_at_eof_is_forwarded(
        (case, (idx, frac)) in (sync_case(), (any::<usize>(), any::<u32>())),
    ) {
        let (specs, payload) = case;
        let (_file, patterns, oracles) = generators::build(&specs);
        let spans = match oracle::scan(&oracles, &payload) {
            Scan::Spans(spans) => spans,
            Scan::Unspecified { .. } => return Ok(()),
        };
        let swapped = doppel::swap(&payload, &patterns).expect("generated swap must succeed");
        if swapped.entries.is_empty() {
            return Ok(());
        }
        let entry = &swapped.entries[idx % swapped.entries.len()];
        let fake = entry.fake.clone();
        if fake.len() < 2 {
            return Ok(());
        }
        let k = 1 + frac as usize % (fake.len() - 1);

        let mut stream = swapped.payload.clone();
        stream.extend_from_slice(&fake[..k]);

        // Skip when the partial fake could complete another fake: any occurrence
        // outside a replaced span (a smaller complete fake in the appended prefix,
        // or a fake spanning the boundary) would legitimately be restored.
        let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
        if !natural_domain(&stream, &span_pairs(&spans), &fakes) {
            return Ok(());
        }

        let mut input = stream.as_slice();
        let mut out = Vec::new();
        doppel::restore(&mut input, &mut out, &swapped.entries, &swapped.session_key)
            .expect("restore with an EOF partial fake must succeed");
        let mut expected = payload.clone();
        expected.extend_from_slice(&fake[..k]);
        prop_assert_eq!(&out, &expected, "EOF partial fake must be forwarded unchanged");
    }
}

/// Coverage guard: the natural-domain precondition must not reject a large share
/// of cases, or the round-trip property is nearly vacuous. Deterministic fixed
/// seed, so it cannot flake. Reported, and bounded here rather than loosened.
#[test]
fn restore_sync_domain_skip_share() {
    use proptest::test_runner::TestRunner;

    const CASES: u32 = 512;
    let mut runner = TestRunner::deterministic();
    let mut evaluated = 0u32;
    let mut skipped = 0u32;
    let mut unspecified = 0u32;

    for _ in 0..CASES {
        let (specs, payload) = sync_case()
            .new_tree(&mut runner)
            .expect("coverage sample must generate a case")
            .current();
        let (_file, patterns, oracles) = generators::build(&specs);
        let spans = match oracle::scan(&oracles, &payload) {
            Scan::Spans(spans) => spans,
            Scan::Unspecified { .. } => {
                unspecified += 1;
                continue;
            }
        };
        let swapped = doppel::swap(&payload, &patterns).expect("generated swap must succeed");
        let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
        evaluated += 1;
        if !natural_domain(&swapped.payload, &span_pairs(&spans), &fakes) {
            skipped += 1;
        }
    }
    println!(
        "restore_sync domain over {CASES}: evaluated={evaluated} skipped={skipped} unspecified={unspecified}"
    );
    assert!(evaluated > 0, "no cases reached the natural-domain check");
    assert!(
        skipped * 10 <= evaluated * 3,
        "natural_domain rejects too many cases: skipped={skipped} of evaluated={evaluated}"
    );
}
