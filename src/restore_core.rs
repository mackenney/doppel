//! Shared sliding-window replacement logic for restore operations.
//!
//! This module is internal to the crate. Both sync `restore` and async
//! `RestoreStream` delegate to `process_safe_region` with appropriate
//! emit and error callbacks.

use crate::crypto::decrypt_entry;
use crate::types::{Entry, SessionKey};
use aho_corasick::{AhoCorasick, Input};

/// Process the safe region of the buffer, replacing fakes with originals.
///
/// # Arguments
/// - `buffer`: Mutable buffer containing accumulated input bytes
/// - `ac`: Aho-Corasick automaton built from fake patterns
/// - `entries`: Slice of Entry structs with ciphertext for each fake
/// - `session_key`: Key for AEAD decryption
/// - `eof`: Whether input stream has ended (process all remaining bytes)
/// - `max_hold`: Maximum bytes to hold unemitted (INV-8 bound)
/// - `emit`: Callback to output bytes; called with byte slices to emit
/// - `on_aead_failure`: Callback to produce error value on AEAD tag failure
///
/// # Invariants Preserved
/// - INV-5: Plaintext emitted only after `decrypt_entry` succeeds
/// - INV-6: AEAD failure returns immediately via `on_aead_failure`
/// - INV-8: At most `max_hold` bytes remain in buffer after return (unless error)
/// - INV-19: Uses AhoCorasick with LeftmostFirst for exact matching
///
/// # Returns
/// `Ok(())` on success (all safe bytes emitted), `Err(E)` on AEAD failure.
// Callers: restore and restore_stream modules.
// All parameters are logically distinct parts of the algorithm's context;
// grouping them into a struct would add indirection without improving clarity.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_safe_region<F, G, E>(
    buffer: &mut Vec<u8>,
    ac: &AhoCorasick,
    entries: &[Entry],
    session_key: &SessionKey,
    eof: bool,
    max_hold: usize,
    emit: &mut F,
    on_aead_failure: &mut G,
) -> Result<(), E>
where
    F: FnMut(&[u8]) -> Result<(), E>,
    G: FnMut(usize) -> E,
{
    let mut cursor = 0;

    loop {
        let remaining = buffer.len() - cursor;

        // INV-8: Compute safe_end — how far we can safely process
        let safe_end = if eof {
            buffer.len()
        } else if remaining > max_hold {
            buffer.len() - max_hold
        } else {
            break;
        };

        // Nothing safe to process (e.g. empty buffer with eof=true).
        // Avoids calling emit with an empty slice, which would make async
        // poll_next emit empty Bytes items and never return None.
        if safe_end <= cursor {
            break;
        }

        // Find next fake match in the safe region
        match ac.find(Input::new(&buffer[..]).range(cursor..)) {
            Some(mat) if mat.start() < safe_end => {
                let match_start = mat.start();
                let match_end = mat.end();
                let pattern_idx = mat.pattern().as_usize();

                // Emit bytes before the match
                if match_start > cursor {
                    emit(&buffer[cursor..match_start])?;
                }

                // INV-5/INV-6: Decrypt and emit original, or fail immediately
                let entry = &entries[pattern_idx];
                match decrypt_entry(session_key, entry) {
                    Ok(plaintext) => {
                        let plaintext = zeroize::Zeroizing::new(plaintext);
                        emit(&plaintext)?;
                    }
                    Err(_) => {
                        return Err(on_aead_failure(pattern_idx));
                    }
                }

                cursor = match_end;
                // continue inner loop — more matches may exist in safe region
            }
            // match starts in hold region — emit safe bytes and stop
            Some(_) => {
                emit(&buffer[cursor..safe_end])?;
                cursor = safe_end;
                break;
            }
            None => {
                // No match — emit all safe bytes
                emit(&buffer[cursor..safe_end])?;
                cursor = safe_end;
                break;
            }
        }
    }

    // Remove processed bytes from buffer
    if cursor > 0 {
        buffer.drain(..cursor);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_safe_region_no_matches() {
        let mut buffer = b"hello world".to_vec();
        use aho_corasick::MatchKind;
        let fakes: Vec<&[u8]> = vec![];
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&fakes)
            .unwrap();
        let entries: Vec<Entry> = vec![];
        let session_key = SessionKey::from_bytes([0u8; 32]);

        let mut output = Vec::new();
        let mut emit = |bytes: &[u8]| -> Result<(), ()> {
            output.extend_from_slice(bytes);
            Ok(())
        };
        let mut on_err = |_idx: usize| ();

        process_safe_region(
            &mut buffer,
            &ac,
            &entries,
            &session_key,
            true,
            0,
            &mut emit,
            &mut on_err,
        )
        .unwrap();

        assert_eq!(output, b"hello world");
        assert!(buffer.is_empty());
    }
}
