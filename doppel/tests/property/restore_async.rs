// P-ASY: the async `restore_stream` adapter checked against the synchronous
// `restore` function over a differential oracle, plus its upstream-error
// termination contract. The whole module is compiled only under the `async`
// feature (the `mod` line in `property.rs` carries the `cfg`).
//
// Cases reuse the shared constructive generators, so every generated pattern
// meets the D5 = A 83-bit fake-capacity floor. Session key, nonce, and
// ciphertext are never read, and no crypto observable is inspected.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use crate::generators;
use crate::oracle;
use doppel::RestoreError;

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

fn span_pairs(spans: &[oracle::Span]) -> Vec<(usize, usize)> {
    spans.iter().map(|s| (s.start, s.end)).collect()
}

/// Cut `payload` into `Bytes` chunks according to the cycling `sizes` plan.
///
/// A size of 0 emits an empty chunk. A plan whose sizes are all zero would never
/// advance the offset, so it emits one empty chunk followed by the whole payload:
/// forward progress is guaranteed and the empty-chunk path is still exercised.
fn build_chunks(payload: &[u8], sizes: &[usize]) -> VecDeque<Result<Bytes, io::Error>> {
    let mut chunks: Vec<Result<Bytes, io::Error>> = Vec::new();
    if sizes.iter().sum::<usize>() == 0 {
        chunks.push(Ok(Bytes::new()));
        if !payload.is_empty() {
            chunks.push(Ok(Bytes::copy_from_slice(payload)));
        }
    } else {
        let mut offset = 0;
        let mut i = 0;
        while offset < payload.len() {
            let size = sizes[i % sizes.len()];
            let end = (offset + size).min(payload.len());
            chunks.push(Ok(Bytes::copy_from_slice(&payload[offset..end])));
            offset = end;
            i += 1;
        }
    }
    chunks.into()
}

/// A `Stream` of scripted chunks that injects `Pending` polls according to a
/// cycling mask. It wakes itself before returning `Pending` so no wakeup is lost,
/// and it never returns `Pending` on two consecutive polls, so a mask of all
/// `true` still makes forward progress. Every field is `Unpin`.
struct ScriptedStream {
    chunks: VecDeque<Result<Bytes, io::Error>>,
    pending_mask: Vec<bool>,
    polls: usize,
    last_pending: bool,
}

impl ScriptedStream {
    fn new(chunks: VecDeque<Result<Bytes, io::Error>>, pending_mask: Vec<bool>) -> Self {
        assert!(!pending_mask.is_empty(), "pending mask must not be empty");
        Self {
            chunks,
            pending_mask,
            polls: 0,
            last_pending: false,
        }
    }
}

impl Stream for ScriptedStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let was_pending = this.last_pending;
        this.last_pending = false;
        let mask_index = this.polls % this.pending_mask.len();
        this.polls += 1;
        if !was_pending && this.pending_mask[mask_index] {
            this.last_pending = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(this.chunks.pop_front())
    }
}

/// Drive an async restore stream to `None`, collecting emitted bytes,
/// the first error, and the number of items seen after that error. Reaching
/// `None` proves the stream terminates; nothing is left un-polled.
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

/// Swap `payload`, return `None` when no round trip is required, or the swapped
/// result together with the oracle's replaced spans.
fn swapped_case(
    specs: &[generators::PatternSpec],
    payload: &[u8],
) -> Result<Option<doppel::SwapResult>, TestCaseError> {
    let (_file, patterns, oracles) = generators::build(specs);
    let spans = match oracle::scan(&oracles, payload) {
        oracle::Scan::Spans(spans) => spans,
        oracle::Scan::Unspecified { .. } => return Ok(None),
    };
    let swapped = doppel::swap(payload, &patterns).expect("generated swap must succeed");
    let fakes: Vec<Vec<u8>> = swapped.entries.iter().map(|e| e.fake.clone()).collect();
    if !natural_domain(&swapped.payload, &span_pairs(&spans), &fakes) {
        return Ok(None);
    }
    Ok(Some(swapped))
}

proptest! {
    #![proptest_config(crate::support::config(32))]

    #[test]
    fn prop_async_restore_equals_sync_restore(
        (case, sizes, pending_mask) in (
            generators::arb_case(3),
            prop::collection::vec(0usize..=8, 1..=8),
            prop::collection::vec(any::<bool>(), 1..=4),
        ),
    ) {
        let (specs, payload) = case;
        let Some(swapped) = swapped_case(&specs, &payload)? else {
            return Ok(());
        };

        // Sync restore borrows the session key and fixes the expected output.
        let mut input = swapped.payload.as_slice();
        let mut sync_out = Vec::new();
        doppel::restore(
            &mut input,
            &mut sync_out,
            &swapped.entries,
            &swapped.session_key,
        )
        .expect("sync restore must succeed");
        prop_assert_eq!(&sync_out, &payload, "sync restore must reproduce the original");

        // Async restore takes its own entries copy and owns the session key.
        let chunks = build_chunks(&swapped.payload, &sizes);
        let inner = ScriptedStream::new(chunks, pending_mask);
        let stream = doppel::restore_stream(inner, swapped.entries.clone(), swapped.session_key)
            .expect("restore_stream must build from swap entries");
        let (out, error, items_after_error) = collect(stream);
        prop_assert!(error.is_none(), "async restore must not error: {error:?}");
        prop_assert_eq!(items_after_error, 0, "no items may follow stream termination");
        prop_assert_eq!(out, sync_out, "async restore must equal sync restore");
    }

    #[test]
    fn prop_async_upstream_error_terminates_with_prefix_output(
        (case, (sizes, pending_mask, kindex)) in (
            generators::arb_case(3),
            (
                prop::collection::vec(0usize..=8, 1..=8),
                prop::collection::vec(any::<bool>(), 1..=4),
                any::<prop::sample::Index>(),
            ),
        ),
    ) {
        let (specs, payload) = case;
        let Some(swapped) = swapped_case(&specs, &payload)? else {
            return Ok(());
        };

        let mut chunks = build_chunks(&swapped.payload, &sizes);
        let insert_at = kindex.index(chunks.len() + 1);
        chunks.insert(insert_at, Err(io::Error::other("synthetic upstream error")));

        let inner = ScriptedStream::new(chunks, pending_mask);
        let stream = doppel::restore_stream(inner, swapped.entries.clone(), swapped.session_key)
            .expect("restore_stream must build from swap entries");
        let (out, error, items_after_error) = collect(stream);

        match error {
            Some(RestoreError::Io(_)) => {}
            other => prop_assert!(false, "expected exactly one upstream I/O error, got {other:?}"),
        }
        prop_assert_eq!(items_after_error, 0, "no items may follow the upstream error");
        prop_assert!(
            payload.starts_with(&out),
            "bytes emitted before the error must be an original prefix"
        );
    }
}
