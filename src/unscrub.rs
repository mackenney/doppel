use std::io::{Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};

use crate::crypto::decrypt_entry;
use crate::types::{Entry, SessionKey};

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
        loop {
            let safe_end = if eof {
                buffer.len()
            } else if buffer.len() > max_hold {
                buffer.len() - max_hold
            } else {
                0
            };
            if safe_end == 0 {
                break;
            }

            match ac.find(&buffer) {
                None => {
                    // No match anywhere: emit up to safe_end
                    output.write_all(&buffer[..safe_end])?;
                    buffer.drain(..safe_end);
                    break;
                }
                Some(m) if m.start() >= safe_end => {
                    // Match is in the hold region; emit up to safe_end, hold the rest
                    output.write_all(&buffer[..safe_end])?;
                    buffer.drain(..safe_end);
                    break;
                }
                Some(m) => {
                    // Match starts before safe_end; decrypt and restore
                    output.write_all(&buffer[..m.start()])?;
                    let entry_idx = m.pattern().as_usize();
                    let plaintext =
                        decrypt_entry(session_key, &entries[entry_idx]).map_err(|_| {
                            UnscrubError::AeadTagFailure {
                                entry_index: entry_idx,
                            }
                        })?;
                    // INV-5: emit plaintext ONLY after successful decryption
                    output.write_all(&plaintext)?;
                    buffer.drain(..m.end());
                    // Continue inner loop: more matches may exist in the remaining safe region
                }
            }
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
}
