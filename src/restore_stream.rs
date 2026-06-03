use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aho_corasick::{AhoCorasick, MatchKind};
use bytes::Bytes;
use futures_core::Stream;

use crate::restore::RestoreError;
use crate::restore_core::process_safe_region;
use crate::types::{Entry, SessionKey};

/// Async stream adapter that restores swapped secrets as bytes flow through.
///
/// Constructed via [`restore_stream`]. Applies the same sliding-window
/// algorithm as the synchronous [`restore`] function: fakes are replaced
/// with decrypted originals; all other bytes are forwarded unchanged.
///
/// The stream terminates with [`RestoreError::AeadTagFailure`] if a fake is
/// matched but its AEAD tag does not verify. No plaintext is emitted for a
/// failing entry (INV-5/INV-6).
///
/// [`restore`]: crate::restore
pub struct RestoreStream<S> {
    inner: S,
    /// None when entries is empty — skips AC lookup entirely.
    ac: Option<AhoCorasick>,
    entries: Vec<Entry>,
    session_key: SessionKey,
    buffer: Vec<u8>,
    /// Maximum fake length across all entries — defines the hold window.
    max_hold: usize,
    eof: bool,
    /// Output items ready to yield before pulling more input.
    pending: VecDeque<Result<Bytes, RestoreError>>,
    done: bool,
}

/// Wrap `inner` in an async restore adapter.
///
/// Each [`Bytes`] chunk from `inner` is processed through a sliding-window
/// algorithm: fakes present in `entries` are replaced with their decrypted
/// originals using `session_key`; all other bytes are forwarded unchanged.
///
/// The stream is runtime-agnostic — it only requires [`futures_core::Stream`]
/// and makes no tokio assumptions.
///
/// `inner` must be [`Unpin`]. Wrap a non-`Unpin` stream with `Box::pin`
/// before passing it here.
///
/// Returns `Err` immediately if the [`AhoCorasick`] automaton cannot be
/// built from the provided entries (degenerate input only; does not happen
/// with entries produced by [`swap`]).
///
/// [`swap`]: crate::swap
///
/// # Ownership
///
/// Takes `SessionKey` by value (unlike sync [`restore`] which borrows).
/// The stream must own the key for its `'static` lifetime across poll cycles.
///
/// [`restore`]: crate::restore
#[must_use = "the stream must be polled to process data"]
pub fn restore_stream<S>(
    inner: S,
    entries: Vec<Entry>,
    session_key: SessionKey,
) -> Result<RestoreStream<S>, RestoreError>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    let ac = if entries.is_empty() {
        None
    } else {
        for (idx, e) in entries.iter().enumerate() {
            if e.fake.is_empty() {
                return Err(RestoreError::Build {
                    msg: format!("empty fake in entry at index {idx}"),
                });
            }
        }
        let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
        Some(
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&fakes)
                .map_err(RestoreError::from)?,
        )
    };

    let max_hold = entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);

    Ok(RestoreStream {
        inner,
        ac,
        entries,
        session_key,
        buffer: Vec::new(),
        max_hold,
        eof: false,
        pending: VecDeque::new(),
        done: false,
    })
}

impl<S> RestoreStream<S> {
    /// Drain the safe region of `self.buffer` into `self.pending`.
    ///
    /// Delegates to [`process_safe_region`] when entries are present.
    /// When there are no entries (`ac` is `None`), `max_hold` is 0 and all
    /// buffered bytes are immediately safe; they are forwarded as one chunk.
    fn process_buffer(&mut self) {
        let Some(ac) = &self.ac else {
            // No entries: max_hold is 0, so all buffered bytes are safe to emit.
            if !self.buffer.is_empty() {
                self.pending
                    .push_back(Ok(Bytes::copy_from_slice(&self.buffer)));
                self.buffer.clear();
            }
            return;
        };

        let pending = &mut self.pending;
        let result = process_safe_region(
            &mut self.buffer,
            ac,
            &self.entries,
            &self.session_key,
            self.eof,
            self.max_hold,
            &mut |bytes| {
                pending.push_back(Ok(Bytes::copy_from_slice(bytes)));
                Ok::<(), RestoreError>(())
            },
            &mut |entry_idx| RestoreError::AeadTagFailure {
                entry_index: entry_idx,
            },
        );

        if let Err(e) = result {
            pending.push_back(Err(e));
        }
    }
}

impl<S> Stream for RestoreStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    type Item = Result<Bytes, RestoreError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.done {
            return Poll::Ready(None);
        }

        loop {
            // Yield pending output before asking for more input.
            if let Some(item) = this.pending.pop_front() {
                if item.is_err() {
                    this.done = true;
                }
                return Poll::Ready(Some(item));
            }

            // Try to push more items into pending from the current buffer.
            this.process_buffer();
            if !this.pending.is_empty() {
                continue;
            }

            // Nothing left to emit. If inner is exhausted we are done.
            if this.eof {
                this.done = true;
                return Poll::Ready(None);
            }

            // Pull the next chunk from the inner stream.
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    this.buffer.extend_from_slice(&chunk);
                    // Loop to process the newly arrived bytes.
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(RestoreError::Io(e))));
                }
                Poll::Ready(None) => {
                    this.eof = true;
                    // Loop to flush the remaining buffer.
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;
    use crate::swap::swap;
    use futures::StreamExt;

    const ANTHROPIC_SECRET: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";

    /// Drive an RestoreStream to completion, collecting all bytes.
    async fn collect_stream<S>(stream: RestoreStream<S>) -> Result<Vec<u8>, RestoreError>
    where
        S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
    {
        let mut out = Vec::new();
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    /// Build a stream that emits the given bytes in chunks of `chunk_size`.
    fn chunked_stream(
        data: Vec<u8>,
        chunk_size: usize,
    ) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
        let chunks: Vec<Result<Bytes, io::Error>> = data
            .chunks(chunk_size)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        futures::stream::iter(chunks)
    }

    /// Build a stream that emits all bytes in a single chunk.
    fn single_chunk_stream(data: Vec<u8>) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
        chunked_stream(data, usize::MAX)
    }

    struct PendingOnceStream {
        state: u8,
        chunks: std::collections::VecDeque<Bytes>,
    }

    impl PendingOnceStream {
        fn new(data: Vec<u8>, chunk_size: usize) -> Self {
            let chunks = data
                .chunks(chunk_size)
                .map(Bytes::copy_from_slice)
                .collect();
            Self { state: 0, chunks }
        }
    }

    impl Stream for PendingOnceStream {
        type Item = Result<Bytes, io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.state {
                0 => {
                    self.state = 1;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                _ => {
                    if let Some(chunk) = self.chunks.pop_front() {
                        Poll::Ready(Some(Ok(chunk)))
                    } else {
                        Poll::Ready(None)
                    }
                }
            }
        }
    }

    impl Unpin for PendingOnceStream {}

    #[test]
    fn test_async_basic_roundtrip() {
        let payload = [b"Authorization: ".as_slice(), ANTHROPIC_SECRET].concat();
        let sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        let inner = single_chunk_stream(sr.payload);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_async_chunk_boundary() {
        // INV-4: fake split across many 1-byte chunks must still be restored.
        let payload = [b"ctx: ".as_slice(), ANTHROPIC_SECRET, b" end"].concat();
        let sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        let inner = chunked_stream(sr.payload, 1);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "INV-4: single-byte chunks must restore correctly"
        );
    }

    #[test]
    fn test_async_no_fake_in_stream() {
        // INV-7: no fake in response → forward unchanged, no error.
        let sr = swap(b"unrelated", &[patterns::anthropic()]).unwrap();
        let response = b"response with no fakes in it";
        let inner = single_chunk_stream(response.to_vec());
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, response,
            "INV-7: passthrough must be byte-identical"
        );
    }

    #[test]
    fn test_async_empty_entries_passthrough() {
        // No patterns at all: stream passes through unchanged.
        let sr = swap(b"payload", &[]).unwrap();
        assert!(sr.entries.is_empty());
        let response = b"any response bytes";
        let inner = single_chunk_stream(response.to_vec());
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn test_async_tampered_aead_tag_returns_err() {
        // INV-6: tampered AEAD tag → stream yields Err, no secret bytes emitted.
        let payload = [b"Authorization: ".as_slice(), ANTHROPIC_SECRET].concat();
        let mut sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        let last = sr.entries[0].ciphertext.len() - 1;
        sr.entries[0].ciphertext[last] ^= 0xFF;

        let swapped = sr.payload.clone();
        let inner = single_chunk_stream(swapped);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();

        let result = futures::executor::block_on(async {
            let mut out: Vec<u8> = Vec::new();
            futures::pin_mut!(stream);
            loop {
                match stream.next().await {
                    Some(Ok(chunk)) => out.extend_from_slice(&chunk),
                    Some(Err(e)) => return Err((e, out)),
                    None => return Ok(out),
                }
            }
        });

        let (err, out) = result.unwrap_err();
        assert!(
            matches!(err, RestoreError::AeadTagFailure { .. }),
            "INV-6: must yield AeadTagFailure"
        );
        assert!(
            !out.windows(ANTHROPIC_SECRET.len())
                .any(|w| w == ANTHROPIC_SECRET),
            "INV-6: no secret bytes emitted before tag failure"
        );
    }

    #[test]
    fn test_async_multiple_fakes_in_stream() {
        // Two occurrences of the same fake in the response are both restored.
        let payload = [ANTHROPIC_SECRET, b" and again: ", ANTHROPIC_SECRET].concat();
        let sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        // One entry covers both occurrences (INV-14 in swap).
        assert_eq!(sr.entries.len(), 1);
        let inner = single_chunk_stream(sr.payload);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload, "both occurrences must be restored");
    }

    #[test]
    fn test_async_exact_matching_only() {
        // INV-19: a real key in the response (not a fake) must pass through unchanged.
        let real_key = b"sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-BBBBBB";
        let sr = swap(b"unrelated payload", &[patterns::anthropic()]).unwrap();
        let inner = single_chunk_stream(real_key.to_vec());
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, real_key,
            "INV-19: real key must pass through unchanged"
        );
    }

    #[test]
    fn test_async_empty_stream() {
        let sr = swap(b"payload", &[patterns::anthropic()]).unwrap();
        let inner = futures::stream::empty::<Result<Bytes, io::Error>>();
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert!(result.is_empty(), "empty stream must yield no bytes");
    }

    #[test]
    fn test_async_fake_exactly_at_chunk_boundary() {
        // The fake starts at the last byte of one chunk and ends at the start of the next.
        let payload = [b"prefix ".as_slice(), ANTHROPIC_SECRET, b" suffix"].concat();
        let sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        let fake_len = sr.entries[0].fake.len();

        // Split so the chunk boundary falls in the middle of the fake.
        let split_at = 7 + fake_len / 2; // "prefix " + half of fake
        let inner = chunked_stream(sr.payload.clone(), split_at.max(1));
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "fake split exactly at chunk boundary must restore"
        );
    }
    #[test]
    fn test_empty_fake_rejected_stream() {
        use crate::types::{Entry, SessionKey};
        // An Entry with an empty fake must cause the constructor to return Err,
        // not succeed and produce an infinite loop.
        let bad_entry = Entry {
            fake: vec![],
            ciphertext: vec![0u8; 32],
            nonce: vec![0u8; 24],
        };
        let session_key = SessionKey::from_bytes([0u8; 32]);
        let inner = futures::stream::empty::<Result<Bytes, io::Error>>();
        let result = restore_stream(inner, vec![bad_entry], session_key);
        assert!(
            matches!(result, Err(RestoreError::Build { .. })),
            "empty fake must return Err(Build)"
        );
    }

    #[test]
    fn test_async_two_distinct_fakes() {
        // Two different API key types → two entries → validates multi-entry AC indexing.
        // sk-proj- (8) + 58 'A' chars + T3BlbkFJ (8) + 58 'B' chars = 132 chars total.
        let openai_key: Vec<u8> = {
            let mut k = b"sk-proj-".to_vec();
            k.extend(std::iter::repeat_n(b'A', 58));
            k.extend_from_slice(b"T3BlbkFJ");
            k.extend(std::iter::repeat_n(b'B', 58));
            k
        };

        let payload = [
            b"anthropic: ".as_slice(),
            ANTHROPIC_SECRET,
            b" openai: ",
            openai_key.as_slice(),
        ]
        .concat();

        let sr = swap(
            &payload,
            &[patterns::anthropic(), patterns::openai_project()],
        )
        .unwrap();
        assert_eq!(sr.entries.len(), 2, "must detect two distinct secrets");

        let inner = single_chunk_stream(sr.payload);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "both distinct fakes must restore correctly"
        );
    }

    #[test]
    fn test_async_pending_then_ready() {
        // Exercises the waker path: first poll of the inner stream returns Pending.
        let payload = [b"prefix ".as_slice(), ANTHROPIC_SECRET, b" suffix"].concat();
        let sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        let inner = PendingOnceStream::new(sr.payload.clone(), 32);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "Pending → Ready path must restore correctly"
        );
    }

    #[test]
    fn test_async_registered_secret_restoration() {
        // Registered secret: user-registered secret with deterministic fake derivation.
        // Must be long enough to meet the minimum length requirement of register().
        let secret = b"my-custom-tier2-api-token-that-is-long-enough-for-registration-abcd1234";
        let pattern = crate::register(secret).expect("register failed");
        let payload = [b"Bearer ".as_slice(), secret, b" end"].concat();

        let sr = swap(&payload, &[pattern]).unwrap();
        assert_eq!(
            sr.entries.len(),
            1,
            "Registered secret swap must produce one entry"
        );

        let inner = single_chunk_stream(sr.payload);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "registered secret fake must restore correctly"
        );
    }

    #[test]
    fn test_async_empty_entries_multichunk() {
        // ac = None path (no entries) exercised with many small chunks.
        // Verifies the cursor-based None branch drains correctly across multiple
        // process_buffer calls rather than a single eof=true flush.
        let response = b"hello world this is a multi-chunk passthrough test";
        let sr = swap(b"unrelated", &[]).unwrap();
        assert!(sr.entries.is_empty());

        let inner = chunked_stream(response.to_vec(), 4);
        let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, response,
            "multi-chunk passthrough with no entries must be byte-identical"
        );
    }
}
