// P-TMP: AEAD tag tamper behavior over randomly chosen entries, sync and async.
//
// Contracts: INV-5 (no plaintext before tag verification), INV-6 (a tag failure is
// an error and the stream does not continue), VC-6. Each case tampers exactly one
// entry through the public hidden helper `Entry::flip_last_ciphertext_byte_for_testing`
// and asserts only what every reading of the spec ambiguity A-2 allows: the error
// carries the tampered entry index, the emitted bytes are a prefix of the original
// payload, and no emitted byte reaches the start of the tampered fake's first span.
//
// Session key, nonce, and ciphertext are never read or printed. Cases reuse the
// shared constructive generators, so every generated pattern meets the D5 = A 83-bit
// fake-capacity floor.

#[cfg(feature = "async")]
use std::io;

use crate::generators;
use crate::oracle::{self, Scan, Span};
use doppel::RestoreError;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

#[cfg(feature = "async")]
use bytes::Bytes;
#[cfg(feature = "async")]
use futures::{Stream, StreamExt};

/// VC-2 domain precondition (spec ambiguity A-1): every occurrence of every fake
/// in `swapped` must lie inside a replaced span. Otherwise the original payload
/// itself already contained a fake's bytes outside a replacement, and restore is
/// required to rewrite those bytes too, so a byte-identical round trip cannot hold.
/// Mirrors `restore_sync.rs`; `windows` yields nothing for a fake longer than
/// `swapped`, so there is no out-of-bounds slice.
fn natural_domain(swapped: &[u8], spans: &[(usize, usize)], fakes: &[Vec<u8>]) -> bool {
    for fake in fakes {
        if fake.is_empty() {
            continue;
        }
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

/// A prepared tamper case: the swapped payload with its entries, the oracle's
/// replaced spans, the chosen entry index, and the start of its first replaced span.
struct TamperCase {
    swapped: doppel::SwapResult,
    spans: Vec<Span>,
    index: usize,
    first_start_i: usize,
}

/// Shared precondition pipeline for the tamper properties: build pattern + oracle
/// from the generated case, require a scan with at least one replaced span, reject
/// cases outside the natural domain, pick an entry, and locate `first_start_i`, the
/// smallest replaced-span start whose swapped bytes equal that entry's fake.
///
/// Returns `None` for a case outside the domain, and fails the property when an
/// entry's fake does not occur at any replaced span start.
fn prepare(
    specs: &[generators::PatternSpec],
    payload: &[u8],
    index: &prop::sample::Index,
) -> Result<Option<TamperCase>, TestCaseError> {
    let (_file, patterns, oracles) = generators::build(specs);
    let spans = match oracle::scan(&oracles, payload) {
        Scan::Spans(spans) => spans,
        Scan::Unspecified { .. } => return Ok(None),
    };
    if spans.is_empty() {
        return Ok(None);
    }
    let swapped = doppel::swap(payload, &patterns).expect("generated swap must succeed");
    if swapped.entries.is_empty() {
        return Ok(None);
    }
    let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
    if !natural_domain(&swapped.payload, &span_pairs(&spans), &fakes) {
        return Ok(None);
    }

    let index = index.index(swapped.entries.len());
    let fake_i = &swapped.entries[index].fake;
    let first_start_i = spans
        .iter()
        .filter(|s| swapped.payload[s.start..s.end] == fake_i[..])
        .map(|s| s.start)
        .min();
    // Every entry's fake is present at the span it replaced, so this must hold.
    prop_assert!(
        first_start_i.is_some(),
        "every swapped entry's fake must occur at a replaced span start"
    );
    Ok(Some(TamperCase {
        swapped,
        spans,
        index,
        first_start_i: first_start_i.unwrap(),
    }))
}

#[cfg(feature = "async")]
fn build_chunks(payload: &[u8], sizes: &[usize]) -> Vec<Result<Bytes, io::Error>> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < payload.len() {
        let size = sizes[i % sizes.len()].max(1);
        let end = (offset + size).min(payload.len());
        chunks.push(Ok(Bytes::copy_from_slice(&payload[offset..end])));
        offset = end;
        i += 1;
    }
    chunks
}

/// Drive an async restore stream to `None`, collecting emitted bytes, the first
/// error, and the number of items seen after that error.
#[cfg(feature = "async")]
fn collect<S>(stream: S) -> (Vec<u8>, Option<RestoreError>, usize)
where
    S: Stream<Item = Result<Bytes, RestoreError>> + Unpin,
{
    futures::executor::block_on(async {
        let mut stream = stream;
        let mut out = Vec::new();
        let mut error: Option<RestoreError> = None;
        let mut items_after_error = 0usize;
        while let Some(item) = stream.next().await {
            match item {
                Ok(bytes) => {
                    if error.is_some() {
                        items_after_error += 1;
                    }
                    out.extend_from_slice(&bytes);
                }
                Err(e) => {
                    if error.is_some() {
                        items_after_error += 1;
                    } else {
                        error = Some(e);
                    }
                }
            }
        }
        (out, error, items_after_error)
    })
}

proptest! {
    #![proptest_config(crate::support::config(32))]

    #[test]
    fn prop_tampered_entry_fails_exactly_when_its_fake_occurs(
        (case, index) in (generators::arb_case(3), any::<prop::sample::Index>()),
    ) {
        let (specs, payload) = case;
        let Some(TamperCase {
            mut swapped,
            index: i,
            first_start_i,
            ..
        }) = prepare(&specs, &payload, &index)?
        else {
            return Ok(());
        };
        swapped.entries[i].flip_last_ciphertext_byte_for_testing();

        let mut input = swapped.payload.as_slice();
        let mut out = Vec::new();
        let result = doppel::restore(&mut input, &mut out, &swapped.entries, &swapped.session_key);
        match result {
            Err(RestoreError::AeadTagFailure { entry_index }) => {
                prop_assert_eq!(
                    entry_index,
                    i,
                    "the failing entry index must be the tampered entry"
                );
            }
            Ok(()) => prop_assert!(false, "tampered fake occurred but restore returned Ok"),
            Err(other) => prop_assert!(false, "expected AeadTagFailure, got {other:?}"),
        }
        prop_assert!(
            payload.starts_with(&out),
            "emitted bytes must be a prefix of the original payload"
        );
        prop_assert!(
            out.len() <= first_start_i,
            "emitted bytes must not reach the tampered fake's first span start"
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn prop_tampered_entry_async_stops_after_error(
        (case, index, sizes) in (
            generators::arb_case(3),
            any::<prop::sample::Index>(),
            prop::collection::vec(1usize..=7, 1..=8),
        ),
    ) {
        let (specs, payload) = case;
        let Some(TamperCase {
            mut swapped,
            index: i,
            first_start_i,
            ..
        }) = prepare(&specs, &payload, &index)?
        else {
            return Ok(());
        };
        swapped.entries[i].flip_last_ciphertext_byte_for_testing();

        let chunks = build_chunks(&swapped.payload, &sizes);
        let stream = doppel::restore_stream(
            futures::stream::iter(chunks.into_iter()),
            swapped.entries,
            swapped.session_key,
        )
        .expect("restore_stream must build from swap entries");
        let (out, error, items_after_error) = collect(stream);

        match error {
            Some(RestoreError::AeadTagFailure { entry_index }) => {
                prop_assert_eq!(
                    entry_index,
                    i,
                    "the failing entry index must be the tampered entry"
                );
            }
            other => prop_assert!(false, "expected exactly one AeadTagFailure, got {other:?}"),
        }
        prop_assert_eq!(items_after_error, 0, "no items may follow the tamper error");
        prop_assert!(
            payload.starts_with(&out),
            "emitted bytes must be a prefix of the original payload"
        );
        prop_assert!(
            out.len() <= first_start_i,
            "emitted bytes must not reach the tampered fake's first span start"
        );
    }

    #[test]
    fn prop_tampered_entry_absent_from_stream_is_harmless(
        (case, index) in (generators::arb_case(3), any::<prop::sample::Index>()),
    ) {
        let (specs, payload) = case;
        let Some(TamperCase {
            mut swapped,
            spans,
            index: i,
            ..
        }) = prepare(&specs, &payload, &index)?
        else {
            return Ok(());
        };
        let fake_i = swapped.entries[i].fake.clone();
        swapped.entries[i].flip_last_ciphertext_byte_for_testing();

        // Partially restored stream: the swapped payload with every span carrying
        // fake_i put back to its original bytes, so fake_i never occurs while the
        // other fakes — and hence their entries — remain in the stream.
        let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
        let mut partial = swapped.payload.clone();
        for span in &spans {
            if partial[span.start..span.end] == fake_i[..] {
                partial[span.start..span.end].copy_from_slice(&payload[span.start..span.end]);
            }
        }
        if contains(&partial, &fake_i) {
            return Ok(());
        }
        if !natural_domain(&partial, &span_pairs(&spans), &fakes) {
            return Ok(());
        }

        let mut input = partial.as_slice();
        let mut out = Vec::new();
        doppel::restore(&mut input, &mut out, &swapped.entries, &swapped.session_key)
            .expect("a tampered entry whose fake is never matched must be harmless");
        prop_assert_eq!(
            &out,
            &payload,
            "the partially restored stream must restore to the original payload"
        );
    }
}
