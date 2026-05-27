use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aho_corasick::{AhoCorasick, MatchKind};
use bytes::Bytes;
use futures_core::Stream;

use crate::crypto::decrypt_entry;
use crate::types::{Entry, SessionKey};
use crate::unscrub::UnscrubError;

/// Async stream adapter that restores scrubbed secrets as bytes flow through.
///
/// Constructed via [`unscrub_stream`]. Applies the same sliding-window
/// algorithm as the synchronous [`unscrub`] function: fakes are replaced
/// with decrypted originals; all other bytes are forwarded unchanged.
///
/// The stream terminates with [`UnscrubError::AeadTagFailure`] if a fake is
/// matched but its AEAD tag does not verify. No plaintext is emitted for a
/// failing entry (INV-5/INV-6).
///
/// [`unscrub`]: crate::unscrub
pub struct UnscrubStream<S> {
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
    pending: VecDeque<Result<Bytes, UnscrubError>>,
    done: bool,
}

/// Wrap `inner` in an async unscrub adapter.
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
/// with entries produced by [`scrub`]).
///
/// [`scrub`]: crate::scrub
pub fn unscrub_stream<S>(
    inner: S,
    entries: Vec<Entry>,
    session_key: SessionKey,
) -> Result<UnscrubStream<S>, UnscrubError>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    let ac = if entries.is_empty() {
        None
    } else {
        let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
        Some(
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&fakes)
                .map_err(|e| UnscrubError::Build { msg: e.to_string() })?,
        )
    };

    let max_hold = entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);

    Ok(UnscrubStream {
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

impl<S> UnscrubStream<S> {
    /// Drain the safe region of `self.buffer` into `self.pending`.
    ///
    /// "Safe" bytes are those that cannot be the start of any fake: at least
    /// `max_hold` bytes trail them (or we are at EOF and all bytes are safe).
    /// Matches within the safe region are decrypted and pushed as individual
    /// items; the loop continues until no more matches fit within safe_end.
    fn process_buffer(&mut self) {
        loop {
            let safe_end = if self.eof {
                self.buffer.len()
            } else if self.buffer.len() > self.max_hold {
                self.buffer.len() - self.max_hold
            } else {
                return;
            };

            if safe_end == 0 {
                return;
            }

            match &self.ac {
                None => {
                    // No entries: forward all safe bytes as one chunk.
                    let chunk = Bytes::copy_from_slice(&self.buffer[..safe_end]);
                    self.buffer.drain(..safe_end);
                    self.pending.push_back(Ok(chunk));
                    // Loop: with max_hold == 0, safe_end == buffer.len() again
                    // until buffer is empty, then safe_end == 0 → return.
                }
                Some(ac) => {
                    match ac.find(&self.buffer) {
                        None => {
                            // No match anywhere in buffer: safe to emit up to safe_end.
                            let chunk = Bytes::copy_from_slice(&self.buffer[..safe_end]);
                            self.buffer.drain(..safe_end);
                            self.pending.push_back(Ok(chunk));
                            return;
                        }
                        Some(m) if m.start() >= safe_end => {
                            // Match falls inside the hold window: emit only up to safe_end.
                            let chunk = Bytes::copy_from_slice(&self.buffer[..safe_end]);
                            self.buffer.drain(..safe_end);
                            self.pending.push_back(Ok(chunk));
                            return;
                        }
                        Some(m) => {
                            // Match starts inside the safe region: emit prefix then plaintext.
                            if m.start() > 0 {
                                let prefix = Bytes::copy_from_slice(&self.buffer[..m.start()]);
                                self.pending.push_back(Ok(prefix));
                            }
                            let entry_idx = m.pattern().as_usize();
                            match decrypt_entry(&self.session_key, &self.entries[entry_idx]) {
                                Ok(plaintext) => {
                                    self.pending.push_back(Ok(Bytes::from(plaintext)));
                                }
                                Err(_) => {
                                    self.pending.push_back(Err(UnscrubError::AeadTagFailure {
                                        entry_index: entry_idx,
                                    }));
                                    self.buffer.drain(..m.end());
                                    return;
                                }
                            }
                            self.buffer.drain(..m.end());
                            // Continue: more matches may follow within the safe region.
                        }
                    }
                }
            }
        }
    }
}

impl<S> Stream for UnscrubStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    type Item = Result<Bytes, UnscrubError>;

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
                    return Poll::Ready(Some(Err(UnscrubError::Io(e))));
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
    use crate::scrub::scrub;
    use crate::tier1::patterns;
    use futures::StreamExt;

    const ANTHROPIC_SECRET: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";

    /// Drive an UnscrubStream to completion, collecting all bytes.
    async fn collect_stream<S>(stream: UnscrubStream<S>) -> Result<Vec<u8>, UnscrubError>
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

    #[test]
    fn test_async_basic_roundtrip() {
        let payload = [b"Authorization: ".as_slice(), ANTHROPIC_SECRET].concat();
        let sr = scrub(&payload, &[patterns::anthropic()]).unwrap();
        let inner = single_chunk_stream(sr.payload);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_async_chunk_boundary() {
        // INV-4: fake split across many 1-byte chunks must still be restored.
        let payload = [b"ctx: ".as_slice(), ANTHROPIC_SECRET, b" end"].concat();
        let sr = scrub(&payload, &[patterns::anthropic()]).unwrap();
        let inner = chunked_stream(sr.payload, 1);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "INV-4: single-byte chunks must restore correctly"
        );
    }

    #[test]
    fn test_async_no_fake_in_stream() {
        // INV-7: no fake in response → forward unchanged, no error.
        let sr = scrub(b"unrelated", &[patterns::anthropic()]).unwrap();
        let response = b"response with no fakes in it";
        let inner = single_chunk_stream(response.to_vec());
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, response,
            "INV-7: passthrough must be byte-identical"
        );
    }

    #[test]
    fn test_async_empty_entries_passthrough() {
        // No patterns at all: stream passes through unchanged.
        let sr = scrub(b"payload", &[]).unwrap();
        assert!(sr.entries.is_empty());
        let response = b"any response bytes";
        let inner = single_chunk_stream(response.to_vec());
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn test_async_tampered_aead_tag_returns_err() {
        // INV-6: tampered AEAD tag → stream yields Err, no secret bytes emitted.
        let payload = [b"Authorization: ".as_slice(), ANTHROPIC_SECRET].concat();
        let mut sr = scrub(&payload, &[patterns::anthropic()]).unwrap();
        let last = sr.entries[0].ciphertext.len() - 1;
        sr.entries[0].ciphertext[last] ^= 0xFF;

        let scrubbed = sr.payload.clone();
        let inner = single_chunk_stream(scrubbed);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();

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
            matches!(err, UnscrubError::AeadTagFailure { .. }),
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
        let sr = scrub(&payload, &[patterns::anthropic()]).unwrap();
        // One entry covers both occurrences (INV-14 in scrub).
        assert_eq!(sr.entries.len(), 1);
        let inner = single_chunk_stream(sr.payload);
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(result, payload, "both occurrences must be restored");
    }

    #[test]
    fn test_async_exact_matching_only() {
        // INV-19: a real key in the response (not a fake) must pass through unchanged.
        let real_key = b"sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-BBBBBB";
        let sr = scrub(b"unrelated payload", &[patterns::anthropic()]).unwrap();
        let inner = single_chunk_stream(real_key.to_vec());
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, real_key,
            "INV-19: real key must pass through unchanged"
        );
    }

    #[test]
    fn test_async_empty_stream() {
        let sr = scrub(b"payload", &[patterns::anthropic()]).unwrap();
        let inner = futures::stream::empty::<Result<Bytes, io::Error>>();
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert!(result.is_empty(), "empty stream must yield no bytes");
    }

    #[test]
    fn test_async_fake_exactly_at_chunk_boundary() {
        // The fake starts at the last byte of one chunk and ends at the start of the next.
        let payload = [b"prefix ".as_slice(), ANTHROPIC_SECRET, b" suffix"].concat();
        let sr = scrub(&payload, &[patterns::anthropic()]).unwrap();
        let fake_len = sr.entries[0].fake.len();

        // Split so the chunk boundary falls in the middle of the fake.
        let split_at = 7 + fake_len / 2; // "prefix " + half of fake
        let inner = chunked_stream(sr.payload.clone(), split_at.max(1));
        let stream = unscrub_stream(inner, sr.entries, sr.session_key).unwrap();
        let result = futures::executor::block_on(collect_stream(stream)).unwrap();
        assert_eq!(
            result, payload,
            "fake split exactly at chunk boundary must restore"
        );
    }
}
