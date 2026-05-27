# Step 03: Cursor Refactor in `process_buffer` (O(n²) → O(n))

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 2 — performance fix. Depends on step 01. Runs in parallel with step 04 (different
file). `unscrub_stream.rs` was last touched by step 01 (constructor area, lines 57–90).
This step only modifies `fn process_buffer` (lines 99–164).

### This Step
`process_buffer` calls `self.buffer.drain(..m.end())` after every match. `Vec::drain` is
O(n) — it shifts all remaining bytes left. With k matches, the total work is O(n·k) where
n is the buffer length. For typical LLM response sizes (tens of kB, multiple secrets)
this is measurably quadratic.

Fix: introduce a `cursor: usize` tracking the first unprocessed byte. Accumulate the
cursor across matches; perform a single `self.buffer.drain(..cursor)` after the loop exits.
`AhoCorasick::find` with `Input::new(&self.buffer).range(cursor..)` returns match positions
relative to the FULL buffer (not relative to `cursor`), so no offset arithmetic is needed.

**No behavioral change.** The bytes emitted, the ordering, and the error semantics are
identical to the pre-refactor code. Existing tests must continue to pass unchanged.

The `Ok(plaintext)` and `Err(_)` arms are left exactly as they are in step 01's output
(steps 05 will improve them).

## Prerequisites
- Step 01 is complete (`unscrub_stream.rs` has the empty-fake guard and `#[must_use]`).

## Files to Read Before Starting
- `src/unscrub_stream.rs` — full file (read AFTER step 01 completes to get current line numbers)

## Implementation

### Task 1: Add `Input` to the `aho_corasick` import

Current import (line 6):

```rust
use aho_corasick::{AhoCorasick, MatchKind};
```

Replace with:

```rust
use aho_corasick::{AhoCorasick, Input, MatchKind};
```

### Task 2: Replace `fn process_buffer` entirely

Locate the `fn process_buffer(&mut self)` method inside `impl<S> UnscrubStream<S>` and
replace the entire function body (from `fn process_buffer` through its closing `}`).

**Before** (current full function, preserving step 01's changes elsewhere in the file):

```rust
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
```

**After** (complete replacement):

```rust
    fn process_buffer(&mut self) {
        let mut cursor: usize = 0;
        loop {
            let remaining = self.buffer.len() - cursor;
            let safe_end = if self.eof {
                self.buffer.len()
            } else if remaining > self.max_hold {
                self.buffer.len() - self.max_hold
            } else {
                break;
            };

            if safe_end <= cursor {
                break;
            }

            match &self.ac {
                None => {
                    // No entries: forward all safe bytes as one chunk.
                    // cursor stays 0 in this branch; drain inline as before.
                    let chunk = Bytes::copy_from_slice(&self.buffer[..safe_end]);
                    self.buffer.drain(..safe_end);
                    self.pending.push_back(Ok(chunk));
                    // Loop: with max_hold == 0, safe_end == buffer.len() each
                    // iteration until buffer is empty, then remaining == 0 → break.
                }
                Some(ac) => {
                    match ac.find(Input::new(&self.buffer).range(cursor..)) {
                        None => {
                            // No match in unprocessed region: emit cursor..safe_end.
                            let chunk = Bytes::copy_from_slice(&self.buffer[cursor..safe_end]);
                            self.pending.push_back(Ok(chunk));
                            cursor = safe_end;
                            break;
                        }
                        Some(m) if m.start() >= safe_end => {
                            // Match is in the hold window: emit cursor..safe_end.
                            let chunk = Bytes::copy_from_slice(&self.buffer[cursor..safe_end]);
                            self.pending.push_back(Ok(chunk));
                            cursor = safe_end;
                            break;
                        }
                        Some(m) => {
                            // Match starts inside the safe region: emit prefix then plaintext.
                            if m.start() > cursor {
                                let prefix =
                                    Bytes::copy_from_slice(&self.buffer[cursor..m.start()]);
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
                                    cursor = m.end();
                                    break;
                                }
                            }
                            cursor = m.end();
                            // Continue: more matches may follow in the safe region.
                        }
                    }
                }
            }
        }
        if cursor > 0 {
            self.buffer.drain(..cursor);
        }
    }
```

**Key differences from the before version:**
1. `cursor: usize = 0` declared before the outer `loop`.
2. `remaining = self.buffer.len() - cursor` drives the hold-window check.
3. All `return` statements inside the `Some(ac)` branch become `break`.
4. All `self.buffer.drain(..X)` inside the `Some(ac)` branch become `cursor = X`.
5. The `None` branch retains its inline drain (cursor stays 0 for that branch).
6. Single `self.buffer.drain(..cursor)` after the loop.
7. `ac.find(&self.buffer)` becomes `ac.find(Input::new(&self.buffer).range(cursor..))`.
8. Prefix slice is `buffer[cursor..m.start()]` (not `buffer[..m.start()]`).
9. "No match" and "match in hold" emit `buffer[cursor..safe_end]` (not `buffer[..safe_end]`).
10. `safe_end == 0` check removed — subsumed by the `remaining > self.max_hold` guard and the `safe_end <= cursor` check.

## Acceptance Criteria

- [ ] `cargo test --features async 2>&1 | tail -5` exits 0 (all pre-existing tests pass unchanged)
- [ ] `grep -n 'Input::new' src/unscrub_stream.rs` prints exactly one match inside `process_buffer`
- [ ] `grep -n 'drain' src/unscrub_stream.rs | grep -v 'cursor > 0'` prints zero matches inside `process_buffer` (only the cursor-guarded drain at the bottom remains; the None-branch drain is the only other one)
- [ ] `cargo clippy --features async 2>&1 | grep -c '^error'` prints `0`

Note on the drain grep: the `None` branch drain (`self.buffer.drain(..safe_end)`) is
intentional and must remain. The acceptance criterion above checks that NO drain inside
`Some(ac)` branches is unguarded — all should have been replaced with `cursor = X`.

## Reviewer Instructions

1. Confirm `cursor` is declared OUTSIDE (before) the `loop {` brace.
2. Confirm `self.buffer.drain` appears exactly twice in `process_buffer`: once in the `None` AC arm, once in the `if cursor > 0` guard after the loop.
3. Confirm the `Input::new(&self.buffer).range(cursor..)` call is inside the `Some(ac)` arm.
4. Confirm the prefix slice uses `cursor..m.start()`, not `0..m.start()`.
5. Confirm existing tests all still pass.

## Rollback

Revert `src/unscrub_stream.rs` to its state after step 01: restore the original
`process_buffer` body and revert the import line to `use aho_corasick::{AhoCorasick, MatchKind};`.
