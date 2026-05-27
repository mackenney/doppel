use std::io::{Read, Write};

use aho_corasick::{AhoCorasick, Input, MatchKind};

use crate::crypto::decrypt_entry;
use crate::types::{Entry, SessionKey};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum UnscrubError {
    #[error("AEAD tag verification failed for entry {entry_index}")]
    AeadTagFailure { entry_index: usize },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to build Aho-Corasick automaton: {msg}")]
    Build { msg: String },
}

impl From<aho_corasick::BuildError> for UnscrubError {
    fn from(e: aho_corasick::BuildError) -> Self {
        UnscrubError::Build { msg: e.to_string() }
    }
}

const CHUNK_SIZE: usize = 4096;

/// Stream `input` to `output`, replacing any fakes found in `entries` with
/// their original plaintext, decrypted using `session_key`.
///
/// # Examples
///
/// ```
/// use its_classified::{scrub, unscrub, tier1::patterns};
///
/// let payload = b"safe content";
/// let result = scrub(payload, &patterns::all()).unwrap();
/// let mut restored = Vec::new();
/// unscrub(
///     &mut result.payload.as_slice(),
///     &mut restored,
///     &result.entries,
///     &result.session_key,
/// )
/// .unwrap();
/// assert_eq!(restored, payload);
/// ```
pub fn unscrub<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    entries: &[Entry],
    session_key: &SessionKey,
) -> Result<(), UnscrubError> {
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
            return Err(UnscrubError::Build {
                msg: format!("empty fake in entry at index {idx}"),
            });
        }
    }
    // Build Aho-Corasick automaton from fake byte strings
    let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&fakes)
        .map_err(UnscrubError::from)?;

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

        // Emit safe bytes (with match handling)
        let mut cursor: usize = 0;
        loop {
            let remaining = buffer.len() - cursor;
            let safe_end = if eof {
                buffer.len()
            } else if remaining > max_hold {
                buffer.len() - max_hold
            } else {
                break;
            };

            if safe_end <= cursor {
                break;
            }

            match ac.find(Input::new(&buffer).range(cursor..)) {
                None => {
                    // No match in unprocessed region: emit cursor..safe_end
                    output.write_all(&buffer[cursor..safe_end])?;
                    cursor = safe_end;
                    break;
                }
                Some(m) if m.start() >= safe_end => {
                    // Match is in the hold region; emit cursor..safe_end, hold the rest
                    output.write_all(&buffer[cursor..safe_end])?;
                    cursor = safe_end;
                    break;
                }
                Some(m) => {
                    // Match starts before safe_end; decrypt and restore
                    output.write_all(&buffer[cursor..m.start()])?;
                    let entry_idx = m.pattern().as_usize();
                    let plaintext = Zeroizing::new(
                        decrypt_entry(session_key, &entries[entry_idx]).map_err(|e| {
                            log::debug!("AEAD decryption failed for entry {entry_idx}: {e}");
                            UnscrubError::AeadTagFailure {
                                entry_index: entry_idx,
                            }
                        })?,
                    );
                    // INV-5: emit plaintext ONLY after successful decryption.
                    // Zeroizing zeroes the decrypt buffer on drop; write_all copies
                    // to the caller's writer without further zeroing.
                    output.write_all(&plaintext)?;
                    cursor = m.end();
                    // Continue inner loop: more matches may exist in the remaining safe region
                }
            }
        }
        if cursor > 0 {
            buffer.drain(..cursor);
        }

        if eof {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::scrub;
    use crate::tier1::patterns;

    #[test]
    fn test_unscrub_basic_roundtrip() {
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"Authorization: ".as_slice(), secret].concat();
        let scrub_result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
        let mut input = scrub_result.payload.as_slice();
        let mut output = Vec::new();
        unscrub(
            &mut input,
            &mut output,
            &scrub_result.entries,
            &scrub_result.session_key,
        )
        .unwrap();
        assert_eq!(output, payload, "unscrub must restore original payload");
    }

    #[test]
    fn test_unscrub_chunk_boundary() {
        // INV-4: fake split across chunk boundary must still be restored
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"ctx: ".as_slice(), secret, b" end"].concat();
        let scrub_result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");

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
            data: &scrub_result.payload,
            pos: 0,
        };
        let mut output = Vec::new();
        unscrub(
            &mut reader,
            &mut output,
            &scrub_result.entries,
            &scrub_result.session_key,
        )
        .unwrap();
        assert_eq!(output, payload, "INV-4: chunk-boundary restoration failed");
    }

    #[test]
    fn test_unscrub_no_fake_in_stream() {
        // INV-7: no fake → forward unchanged, no error
        let payload = b"no secrets here";
        let scrub_result = scrub(payload, &[patterns::anthropic()]).expect("scrub failed");
        let response = b"response with no fakes in it";
        let mut input = response.as_slice();
        let mut output = Vec::new();
        let result = unscrub(
            &mut input,
            &mut output,
            &scrub_result.entries,
            &scrub_result.session_key,
        );
        assert!(result.is_ok(), "INV-7: no error when no fake present");
        assert_eq!(
            output, response,
            "INV-7: output byte-for-byte identical to input"
        );
    }

    #[test]
    fn test_unscrub_tampered_aead_tag_returns_err() {
        // INV-6: tampered AEAD tag → Err, no partial plaintext emitted
        let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
        let payload = [b"Authorization: ".as_slice(), secret].concat();
        let mut scrub_result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
        let entry = &mut scrub_result.entries[0];
        let last = entry.ciphertext.len() - 1;
        entry.ciphertext[last] ^= 0xFF;

        let mut input = scrub_result.payload.as_slice();
        let mut output = Vec::new();
        let result = unscrub(
            &mut input,
            &mut output,
            &scrub_result.entries,
            &scrub_result.session_key,
        );
        assert!(result.is_err(), "INV-6: tampered tag must return Err");
        assert!(
            !output.windows(secret.len()).any(|w| w == secret),
            "INV-6: no secret bytes in output after tag failure"
        );
    }

    #[test]
    fn test_unscrub_exact_matching_only() {
        // INV-19: unscrub must NOT detect secrets by pattern, only exact fake matching
        let real_key_in_response = b"sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-BBBBBB";
        let scrub_result =
            scrub(b"unrelated payload", &[patterns::anthropic()]).expect("scrub failed");
        let mut input = real_key_in_response.as_slice();
        let mut output = Vec::new();
        unscrub(
            &mut input,
            &mut output,
            &scrub_result.entries,
            &scrub_result.session_key,
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
        // An Entry with an empty fake must cause unscrub() to return Err(Build),
        // not succeed and produce an infinite loop.
        let bad_entry = Entry {
            fake: vec![],
            ciphertext: vec![0u8; 32],
            nonce: vec![0u8; 24],
        };
        let session_key = SessionKey::from_bytes([0u8; 32]);
        let mut input = b"some input".as_slice();
        let mut output = Vec::new();
        let result = unscrub(&mut input, &mut output, &[bad_entry], &session_key);
        assert!(
            matches!(result, Err(UnscrubError::Build { .. })),
            "empty fake must return Err(Build)"
        );
        assert!(
            output.is_empty(),
            "guard must fire before any bytes are written"
        );
    }
}
