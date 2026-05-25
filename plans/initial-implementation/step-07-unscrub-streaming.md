# Step 07: Unscrub Streaming Engine

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration.

### Phase Context
Wave 4 (sequential after Wave 3 / step-06). Implements `unscrub()` as a streaming
byte-chunk processor. The scrub engine produces entries; the unscrub engine restores them
from a response stream using exact multi-string matching (Aho-Corasick). This step
enforces INV-4 through INV-8 and INV-19.

### This Step
Implement `src/unscrub.rs`: Aho-Corasick multi-string matching on fake byte strings,
sliding-window buffer with bounded hold (INV-8), AEAD tag verification before emit
(INV-5), hard error on tag failure (INV-6), no-fake pass-through (INV-7), chunk-boundary
restoration (INV-4). Wire up to `src/lib.rs`.

## Prerequisites

- Step 02 complete (Entry, SessionKey, decrypt_entry)
- Step 06 complete (scrub() works — needed to generate valid entries for tests)

## Files to Read Before Starting

- `src/unscrub.rs` — current stub
- `src/crypto.rs` — decrypt_entry, Error type
- `src/types.rs` — Entry, SessionKey
- `SPEC.md §Streaming Invariants` — max_hold formula
- `SPEC.md INV-4, INV-5, INV-6, INV-7, INV-8, INV-19`

## Implementation

### Task 1: Error type

Define a unified error type (or extend the existing crypto::Error):

```rust
#[derive(Debug)]
pub enum UnscrubError {
    AeadTagFailure { entry_index: usize },
    Io(std::io::Error),
}

impl std::fmt::Display for UnscrubError { ... }
impl std::error::Error for UnscrubError {}
impl From<std::io::Error> for UnscrubError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
```

### Task 2: unscrub() function — Aho-Corasick sliding window

```rust
use aho_corasick::{AhoCorasick, MatchKind};
use std::io::{Read, Write};
use crate::types::{Entry, SessionKey};
use crate::crypto::decrypt_entry;

const CHUNK_SIZE: usize = 4096;

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
            if n == 0 { break; }
            output.write_all(&buf[..n])?;
        }
        return Ok(());
    }

    // Build Aho-Corasick automaton from fake byte strings
    let fakes: Vec<&[u8]> = entries.iter().map(|e| e.fake.as_slice()).collect();
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&fakes)
        .expect("AhoCorasick build failed");

    // max_hold: maximum fake length; buffer can hold this many bytes
    // without being safe to emit (a fake may start anywhere in the last max_hold bytes)
    let max_hold: usize = entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);

    let mut buffer: Vec<u8> = Vec::new();

    let mut chunk = vec![0u8; CHUNK_SIZE];
    loop {
        let n = input.read(&mut chunk)?;
        let eof = n == 0;

        if !eof {
            buffer.extend_from_slice(&chunk[..n]);
        }

        // Process buffer: find matches in the "safe region"
        // Safe region = buffer[0..buffer.len()-max_hold+1] (if eof, the whole buffer is safe)
        let safe_end = if eof {
            buffer.len()
        } else if buffer.len() >= max_hold {
            buffer.len() - max_hold + 1
        } else {
            // Buffer is smaller than max_hold; nothing is safe to emit yet
            if eof { buffer.len() } else { 0 }
        };

        if safe_end == 0 && !eof {
            if eof { break; } else { continue; }
        }

        // Find leftmost match in buffer[0..safe_end + max_hold - 1]
        // (We search the full buffer but only commit to emitting up through safe_end)
        let mut cursor = 0usize;
        loop {
            // Search for leftmost match starting at cursor
            let search_end = if eof { buffer.len() } else { buffer.len() };
            let found = ac.find(&buffer[cursor..]);

            match found {
                None => {
                    // No match in buffer[cursor..]. Emit buffer[cursor..safe_end].
                    output.write_all(&buffer[cursor..safe_end])?;
                    cursor = safe_end;
                    break;
                }
                Some(m) => {
                    let abs_start = cursor + m.start();
                    let abs_end = cursor + m.end();

                    if abs_start >= safe_end {
                        // Match is outside the safe region; can't emit yet
                        output.write_all(&buffer[cursor..safe_end])?;
                        cursor = safe_end;
                        break;
                    }

                    // Match is within or straddles safe_end
                    if abs_end > buffer.len() {
                        // Match straddles a not-yet-read chunk; wait for more data
                        output.write_all(&buffer[cursor..abs_start])?;
                        cursor = abs_start;
                        break;
                    }

                    // Emit bytes before the match
                    output.write_all(&buffer[cursor..abs_start])?;

                    // Decrypt and verify (INV-5: decrypt before emitting)
                    let entry_idx = m.pattern();
                    let plaintext = decrypt_entry(session_key, &entries[entry_idx])
                        .map_err(|_| UnscrubError::AeadTagFailure { entry_index: entry_idx })?;
                    // INV-6: on error, stream stops (? propagates, output has partial data
                    // already emitted but no fake bytes or plaintext for this entry)

                    // INV-5: emit plaintext ONLY after successful decryption
                    output.write_all(&plaintext)?;
                    cursor = abs_end;
                }
            }
        }

        // Drain consumed portion of buffer
        buffer.drain(..cursor);

        if eof {
            break;
        }
    }

    Ok(())
}
```

**Important implementation note on INV-8**: The buffer grows by `CHUNK_SIZE` per iteration
but we emit everything up to `safe_end` on each pass. After draining `cursor` bytes:
- The remaining buffer is at most `max_hold - 1` bytes (the tail that couldn't be emitted)
- On the next iteration, `safe_end` advances again
- **At no point is more than `max_hold + CHUNK_SIZE - 1` bytes held** — this exceeds
  the strict INV-8 bound of `max_hold`. Fix: process in a loop until no more safe bytes
  before breaking for the next read. See revised approach below.

**Revised approach** (stricter INV-8 compliance): after draining `cursor`, if `cursor < safe_end`,
loop again before doing another read. The outer `loop` already does this if we `continue`
instead of `break` when there's still safe data to emit. The implementation above uses
`break` after each scan pass — refine to `continue` within the processing loop until
`cursor >= safe_end`.

Simplified correct structure:

```rust
// After building ac and setting max_hold:
let mut buffer: Vec<u8> = Vec::new();
let mut chunk = vec![0u8; CHUNK_SIZE];

loop {
    // Read next chunk
    let n = input.read(&mut chunk)?;
    let eof = n == 0;
    if !eof { buffer.extend_from_slice(&chunk[..n]); }

    // Emit safe bytes (with match handling)
    loop {
        let safe_end = if eof { buffer.len() }
                       else if buffer.len() > max_hold { buffer.len() - max_hold }
                       else { 0 };
        if safe_end == 0 { break; }

        match ac.find(&buffer) {
            None => {
                output.write_all(&buffer[..safe_end])?;
                buffer.drain(..safe_end);
                break;
            }
            Some(m) if m.start() >= safe_end => {
                // Match is in the hold region; emit up to safe_end
                output.write_all(&buffer[..safe_end])?;
                buffer.drain(..safe_end);
                break;
            }
            Some(m) => {
                // Match starts before safe_end
                output.write_all(&buffer[..m.start()])?;
                let entry_idx = m.pattern();
                let plaintext = decrypt_entry(session_key, &entries[entry_idx.as_usize()])
                    .map_err(|_| UnscrubError::AeadTagFailure { entry_index: entry_idx.as_usize() })?;
                output.write_all(&plaintext)?;
                buffer.drain(..m.end());
                // Continue inner loop: there may be more matches in the remaining safe region
            }
        }
    }

    if eof { break; }
}
Ok(())
```

This loop structure ensures:
- After each inner loop iteration, `buffer` drains consumed bytes
- We never hold more than `max_hold` bytes unemitted after each inner loop completes
- Matches are processed greedily; the inner loop continues until no match is in the safe region

### Task 3: Wire up in lib.rs

```rust
pub fn unscrub<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    entries: &[Entry],
    session_key: &SessionKey,
) -> Result<(), crate::unscrub::UnscrubError> {
    crate::unscrub::unscrub(input, output, entries, session_key)
}
```

### Task 4: Unit tests

```rust
#[test]
fn test_unscrub_basic_roundtrip() {
    // Scrub a payload, then unscrub the result
    use crate::scrub::scrub;
    use crate::tier1::patterns;
    let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
    let payload = [b"Authorization: ".as_slice(), secret].concat();
    let scrub_result = scrub(&payload, &[patterns::anthropic()]);
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    unscrub(&mut input, &mut output, &scrub_result.entries, &scrub_result.session_key).unwrap();
    assert_eq!(output, payload, "unscrub must restore original payload");
}

#[test]
fn test_unscrub_chunk_boundary() {
    // INV-4: fake split across chunk boundary must still be restored
    use crate::scrub::scrub;
    use crate::tier1::patterns;
    let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
    let payload = [b"ctx: ".as_slice(), secret, b" end"].concat();
    let scrub_result = scrub(&payload, &[patterns::anthropic()]);

    // Use a 1-byte chunk size to guarantee chunk-boundary splits
    struct OneByteReader<'a> { data: &'a [u8], pos: usize }
    impl<'a> std::io::Read for OneByteReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() { return Ok(0); }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    let mut reader = OneByteReader { data: &scrub_result.payload, pos: 0 };
    let mut output = Vec::new();
    unscrub(&mut reader, &mut output, &scrub_result.entries, &scrub_result.session_key).unwrap();
    assert_eq!(output, payload, "INV-4: chunk-boundary restoration failed");
}

#[test]
fn test_unscrub_no_fake_in_stream() {
    // INV-7: no fake → forward unchanged, no error
    use crate::scrub::scrub;
    use crate::tier1::patterns;
    let payload = b"no secrets here";
    let scrub_result = scrub(payload, &[patterns::anthropic()]);
    // scrub_result.entries is empty; unscrub should pass everything through
    let response = b"response with no fakes in it";
    let mut input = response.as_slice();
    let mut output = Vec::new();
    let result = unscrub(&mut input, &mut output, &scrub_result.entries, &scrub_result.session_key);
    assert!(result.is_ok(), "INV-7: no error when no fake present");
    assert_eq!(output, response, "INV-7: output byte-for-byte identical to input");
}

#[test]
fn test_unscrub_tampered_aead_tag_returns_err() {
    // INV-6: tampered AEAD tag → Err, no partial plaintext emitted
    use crate::scrub::scrub;
    use crate::tier1::patterns;
    let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
    let payload = [b"Authorization: ".as_slice(), secret].concat();
    let mut scrub_result = scrub(&payload, &[patterns::anthropic()]);

    // Tamper with the AEAD tag (last 16 bytes of ciphertext)
    let entry = &mut scrub_result.entries[0];
    let last = entry.ciphertext.len() - 1;
    entry.ciphertext[last] ^= 0xFF;

    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    let result = unscrub(&mut input, &mut output, &scrub_result.entries, &scrub_result.session_key);
    assert!(result.is_err(), "INV-6: tampered tag must return Err");
    // No partial plaintext: output must not contain the original secret
    assert!(
        !output.windows(secret.len()).any(|w| w == secret),
        "INV-6: no secret bytes in output after tag failure"
    );
}

#[test]
fn test_unscrub_exact_matching_only() {
    // INV-19: unscrub must NOT detect secrets by pattern, only exact fake matching
    use crate::scrub::scrub;
    use crate::tier1::patterns;
    // A response stream containing a real API key (not a fake) — unscrub must not touch it
    let real_key_in_response = b"sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-BBBBBB";
    let scrub_result = scrub(b"unrelated payload", &[patterns::anthropic()]);
    // entries may be empty; unscrub does exact matching only
    let mut input = real_key_in_response.as_slice();
    let mut output = Vec::new();
    unscrub(&mut input, &mut output, &scrub_result.entries, &scrub_result.session_key).unwrap();
    assert_eq!(output, real_key_in_response, "INV-19: real key in response must pass through unchanged");
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --lib` exits 0
- [ ] `test_unscrub_basic_roundtrip` passes
- [ ] `test_unscrub_chunk_boundary` passes with chunk_size=1 (INV-4)
- [ ] `test_unscrub_no_fake_in_stream` passes (INV-7)
- [ ] `test_unscrub_tampered_aead_tag_returns_err` passes and output contains no secret bytes (INV-6)
- [ ] `test_unscrub_exact_matching_only` passes (INV-19)
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 07. Verify:

1. Run `cargo nextest run --lib` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Run `cargo nextest run --lib -E 'test(unscrub)'` — all pass
4. Confirm that `decrypt_entry` is called BEFORE `output.write_all(&plaintext)` in `unscrub.rs` (INV-5)
5. Confirm that on `Err` from `decrypt_entry`, the function returns `Err` immediately without writing plaintext (INV-6)
6. Confirm that the safe_end computation ensures buffer hold ≤ max_hold bytes

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-07 commit.
