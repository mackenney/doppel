use std::io::{Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};

use crate::restore_core::process_safe_region;
use crate::types::{Entry, SessionKey};

/// Errors returned by [`restore`] and `restore_stream` (async feature).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestoreError {
    /// AEAD tag verification failed for the given entry.
    #[error("AEAD tag verification failed for entry {entry_index}")]
    AeadTagFailure {
        /// Zero-based index of the entry whose tag did not verify.
        entry_index: usize,
    },
    /// An I/O error occurred reading input or writing output.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The Aho-Corasick automaton could not be built from the provided entries.
    #[error("failed to build Aho-Corasick automaton: {msg}")]
    Build {
        /// Description of the build failure.
        msg: String,
    },
}

impl From<aho_corasick::BuildError> for RestoreError {
    fn from(e: aho_corasick::BuildError) -> Self {
        RestoreError::Build { msg: e.to_string() }
    }
}

const CHUNK_SIZE: usize = 4096;

/// Stream `input` to `output` incrementally, replacing any fakes found in `entries`
/// with their original plaintext, decrypted using `session_key`.
///
/// Processes input in fixed-size chunks with a sliding hold window bounded by the
/// longest fake across all entries — output is emitted as soon as bytes are safe to
/// flush, not only at the end. Fakes split across chunk boundaries are handled
/// correctly; partial matches are held in the window until resolved.
///
/// # Examples
///
/// ```
/// use doppel::{swap, restore, patterns};
///
/// let payload = b"safe content";
/// let result = swap(payload, &patterns::all()).unwrap();
/// let mut restored = Vec::new();
/// restore(
///     &mut result.payload.as_slice(),
///     &mut restored,
///     &result.entries,
///     &result.session_key,
/// )
/// .unwrap();
/// assert_eq!(restored, payload);
/// ```
///
/// # Ownership
///
/// Borrows `SessionKey` (unlike async `restore_stream` which takes ownership).
/// The function runs to completion synchronously, so borrowing is sufficient.
pub fn restore<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    entries: &[Entry],
    session_key: &SessionKey,
) -> Result<(), RestoreError> {
    // Empty entries: forward everything immediately (INV-7 edge case)
    if entries.is_empty() {
        let mut buf = [0u8; CHUNK_SIZE];
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            output.write_all(&buf[..n])?;
        }
        return Ok(());
    }

    for (idx, e) in entries.iter().enumerate() {
        if e.fake.is_empty() {
            return Err(RestoreError::Build {
                msg: format!("empty fake in entry at index {idx}"),
            });
        }
    }
    // Build Aho-Corasick automaton from fake byte strings
    let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&fakes)
        .map_err(RestoreError::from)?;

    // max_hold: maximum fake length; we must not emit bytes that could be the start of a fake
    let max_hold: usize = entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);

    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; CHUNK_SIZE];

    loop {
        // Read next chunk
        let n = input.read(&mut chunk)?;
        let eof = n == 0;
        if !eof {
            buffer.extend_from_slice(&chunk[..n]);
        }

        process_safe_region(
            &mut buffer,
            &ac,
            entries,
            session_key,
            eof,
            max_hold,
            &mut |bytes| output.write_all(bytes).map_err(RestoreError::Io),
            &mut |entry_idx| RestoreError::AeadTagFailure {
                entry_index: entry_idx,
            },
        )?;

        if eof {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;
    use crate::swap::swap;

    #[test]
    fn test_restore_basic_roundtrip() {
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"Authorization: ".as_slice(), secret].concat();
        let swap_result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        let mut input = swap_result.payload.as_slice();
        let mut output = Vec::new();
        restore(
            &mut input,
            &mut output,
            &swap_result.entries,
            &swap_result.session_key,
        )
        .unwrap();
        assert_eq!(output, payload, "restore must restore original payload");
    }

    #[test]
    fn test_restore_chunk_boundary() {
        // INV-4: fake split across chunk boundary must still be restored
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"ctx: ".as_slice(), secret, b" end"].concat();
        let swap_result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");

        struct OneByteReader<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl<'a> Read for OneByteReader<'a> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                buf[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }

        let mut reader = OneByteReader {
            data: &swap_result.payload,
            pos: 0,
        };
        let mut output = Vec::new();
        restore(
            &mut reader,
            &mut output,
            &swap_result.entries,
            &swap_result.session_key,
        )
        .unwrap();
        assert_eq!(output, payload, "INV-4: chunk-boundary restoration failed");
    }

    #[test]
    fn test_restore_no_fake_in_stream() {
        // INV-7: no fake → forward unchanged, no error
        let payload = b"no secrets here";
        let swap_result = swap(payload, &[patterns::anthropic()]).expect("swap failed");
        let response = b"response with no fakes in it";
        let mut input = response.as_slice();
        let mut output = Vec::new();
        let result = restore(
            &mut input,
            &mut output,
            &swap_result.entries,
            &swap_result.session_key,
        );
        assert!(result.is_ok(), "INV-7: no error when no fake present");
        assert_eq!(
            output, response,
            "INV-7: output byte-for-byte identical to input"
        );
    }

    #[test]
    fn test_restore_tampered_aead_tag_returns_err() {
        // INV-6: tampered AEAD tag → Err, no partial plaintext emitted
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"Authorization: ".as_slice(), secret].concat();
        let mut swap_result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        let entry = &mut swap_result.entries[0];
        let last = entry.ciphertext.len() - 1;
        entry.ciphertext[last] ^= 0xFF;

        let mut input = swap_result.payload.as_slice();
        let mut output = Vec::new();
        let result = restore(
            &mut input,
            &mut output,
            &swap_result.entries,
            &swap_result.session_key,
        );
        assert!(result.is_err(), "INV-6: tampered tag must return Err");
        assert!(
            !output.windows(secret.len()).any(|w| w == secret),
            "INV-6: no secret bytes in output after tag failure"
        );
    }

    #[test]
    fn test_restore_exact_matching_only() {
        // INV-19: restore must NOT detect secrets by pattern, only exact fake matching
        let real_key_in_response = b"sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-BBBBBB";
        let swap_result =
            swap(b"unrelated payload", &[patterns::anthropic()]).expect("swap failed");
        let mut input = real_key_in_response.as_slice();
        let mut output = Vec::new();
        restore(
            &mut input,
            &mut output,
            &swap_result.entries,
            &swap_result.session_key,
        )
        .unwrap();
        assert_eq!(
            output, real_key_in_response,
            "INV-19: real key in response must pass through unchanged"
        );
    }
    #[test]
    fn test_empty_fake_rejected_sync() {
        use crate::types::{Entry, SessionKey};
        // An Entry with an empty fake must cause restore() to return Err(Build),
        // not succeed and produce an infinite loop.
        let bad_entry = Entry {
            fake: vec![],
            ciphertext: vec![0u8; 32],
            nonce: vec![0u8; 24],
        };
        let session_key = SessionKey::from_bytes([0u8; 32]);
        let mut input = b"some input".as_slice();
        let mut output = Vec::new();
        let result = restore(&mut input, &mut output, &[bad_entry], &session_key);
        assert!(
            matches!(result, Err(RestoreError::Build { .. })),
            "empty fake must return Err(Build)"
        );
        assert!(
            output.is_empty(),
            "guard must fire before any bytes are written"
        );
    }

    #[test]
    fn test_restore_empty_input() {
        // Empty input with entries present must produce empty output with no error.
        // Exercises the eof-on-first-read path through the AhoCorasick inner loop.
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"Authorization: ".as_slice(), secret].concat();
        let sr = swap(&payload, &[patterns::anthropic()]).unwrap();
        assert!(
            !sr.entries.is_empty(),
            "entries must be present for this test to be meaningful"
        );
        let mut input = b"".as_slice();
        let mut output = Vec::new();
        restore(&mut input, &mut output, &sr.entries, &sr.session_key).unwrap();
        assert!(output.is_empty(), "empty input must produce empty output");
    }

    #[test]
    fn test_restore_two_distinct_secrets() {
        // Two different key types → two entries → validates multi-entry AC indexing.
        // sk-proj- (8) + 58×'A' + T3BlbkFJ (8) + 58×'B' = 132 chars total.
        let anthropic_key = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let openai_key: Vec<u8> = {
            let mut k = b"sk-proj-".to_vec();
            k.extend(std::iter::repeat_n(b'A', 58));
            k.extend_from_slice(b"T3BlbkFJ");
            k.extend(std::iter::repeat_n(b'B', 58));
            k
        };

        let payload = [
            b"anthropic: ".as_slice(),
            anthropic_key,
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

        let mut input = sr.payload.as_slice();
        let mut output = Vec::new();
        restore(&mut input, &mut output, &sr.entries, &sr.session_key).unwrap();
        assert_eq!(output, payload, "both distinct secrets must be restored");
    }

    #[test]
    fn test_restore_registered_roundtrip() {
        // Registered secret exercises the HMAC-based fake path.
        let secret = b"my-custom-tier2-api-token-that-is-long-enough-for-registration-abcd1234";
        let pattern = crate::register(secret).expect("register failed");
        let payload = [b"Bearer ".as_slice(), secret, b" end"].concat();

        let sr = swap(&payload, &[pattern]).unwrap();
        assert_eq!(
            sr.entries.len(),
            1,
            "registered swap must produce one entry"
        );

        let mut input = sr.payload.as_slice();
        let mut output = Vec::new();
        restore(&mut input, &mut output, &sr.entries, &sr.session_key).unwrap();
        assert_eq!(
            output, payload,
            "registered secret must be restored correctly"
        );
    }
}
