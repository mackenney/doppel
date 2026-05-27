# Step 05: Zeroize Plaintext + Log AEAD Error in `process_buffer`

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 3 — security hygiene. Depends on step 03. Runs in parallel with steps 06 and 07.
`unscrub_stream.rs` was last touched by step 03 (cursor refactor of `process_buffer`).

### This Step
Two security-hygiene items in `process_buffer`:

**1. Plaintext not zeroized (IMPORTANT)**
`Bytes::from(plaintext)` passes ownership of the `Vec<u8>` to `Bytes`, which wraps it in
`ManuallyDrop`. The allocation is never zeroed. SPEC §Security Properties: session key is
the trust gate; plaintext derived from it inherits the same sensitivity. Fix: wrap in
`Zeroizing<Vec<u8>>` then `Bytes::copy_from_slice`, ensuring the source is zeroed on drop.

**2. AEAD error silently discarded (MEDIUM)**
`Err(_) =>` discards the underlying AEAD error. During development and debugging, this
makes it impossible to distinguish a logic bug from a tampered ciphertext. Fix: bind the
error and emit `log::debug!` before discarding. The AEAD error message does not contain
the session key or plaintext — only a cryptographic tag verification status.

`log` is already a main dependency (`log = "0.4"` in `Cargo.toml`).
`zeroize` is already a main dependency (`zeroize = { version = "1", features = ["derive"] }`).

## Prerequisites
- Step 03 is complete. `process_buffer` in `src/unscrub_stream.rs` uses the cursor-based
  approach and has `Bytes::from(plaintext)` and `Err(_) =>` (unchanged from step 03).

## Files to Read Before Starting
- `src/unscrub_stream.rs` — full file (read AFTER step 03 completes for current line numbers)

## Implementation

### Task 1: Add `Zeroizing` import

At the top of `src/unscrub_stream.rs`, the imports currently include (from step 03):

```rust
use aho_corasick::{AhoCorasick, Input, MatchKind};
use bytes::Bytes;
use futures_core::Stream;
```

Add `use zeroize::Zeroizing;` in the imports block. Place it with the other `use` statements
at the top of the file (Rust import order: std, then external crates, sorted alphabetically
within each group is conventional but not required):

```rust
use zeroize::Zeroizing;
```

### Task 2: Zeroize plaintext in the `Ok(plaintext)` arm

In `process_buffer`, find the `Ok(plaintext) =>` arm (currently contains `Bytes::from(plaintext)`):

**Before:**
```rust
                                Ok(plaintext) => {
                                    self.pending.push_back(Ok(Bytes::from(plaintext)));
                                }
```

**After:**
```rust
                                Ok(plaintext) => {
                                    let plaintext = Zeroizing::new(plaintext);
                                    self.pending.push_back(Ok(Bytes::copy_from_slice(&plaintext)));
                                }
```

`Zeroizing::new(plaintext)` takes ownership of the `Vec<u8>`. `&plaintext` dereferences to
`&[u8]` (via `Deref<Target=[u8]>`). `Bytes::copy_from_slice` allocates a new buffer.
On drop of `plaintext` at the end of the arm, `Zeroizing` zeros the original Vec.

### Task 3: Bind AEAD error and add debug log

In `process_buffer`, find the `Err(_) =>` arm (inside the `decrypt_entry` match):

**Before:**
```rust
                                Err(_) => {
                                    self.pending.push_back(Err(UnscrubError::AeadTagFailure {
                                        entry_index: entry_idx,
                                    }));
                                    cursor = m.end();
                                    break;
                                }
```

**After:**
```rust
                                Err(e) => {
                                    log::debug!(
                                        "AEAD decryption failed for entry {entry_idx}: {e}"
                                    );
                                    self.pending.push_back(Err(UnscrubError::AeadTagFailure {
                                        entry_index: entry_idx,
                                    }));
                                    cursor = m.end();
                                    break;
                                }
```

The only changes are `_` → `e` in the pattern and the `log::debug!` line inserted before
the `push_back`.

## Acceptance Criteria

- [ ] `cargo test --features async 2>&1 | tail -5` exits 0 (all tests pass)
- [ ] `grep -n 'Bytes::from(plaintext)' src/unscrub_stream.rs` prints zero matches
- [ ] `grep -n 'Zeroizing::new' src/unscrub_stream.rs` prints exactly one match
- [ ] `grep -n 'Bytes::copy_from_slice' src/unscrub_stream.rs | grep plaintext` prints one match
- [ ] `grep -n 'log::debug!' src/unscrub_stream.rs` prints exactly one match
- [ ] `grep -n 'AEAD decryption failed' src/unscrub_stream.rs` prints exactly one match
- [ ] `cargo clippy --features async 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm `Zeroizing::new(plaintext)` takes ownership (not a borrow) of the `Vec<u8>`.
2. Confirm `Bytes::copy_from_slice(&plaintext)` — not `Bytes::from(plaintext.to_vec())`.
3. Confirm the error binding is `Err(e)` and the `log::debug!` message includes `{e}`.
4. Confirm `log::debug!` does NOT log the session key, the plaintext, or any key material.
5. Run `RUST_LOG=debug cargo test --features async test_async_tampered_aead_tag_returns_err`
   and confirm the debug message appears.

## Rollback

Revert the three changes: remove the `use zeroize::Zeroizing;` import, restore
`Bytes::from(plaintext)`, and restore `Err(_) =>` without the log line.
