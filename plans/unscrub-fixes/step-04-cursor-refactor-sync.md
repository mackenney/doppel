# Step 04: Cursor Refactor in `unscrub()` Inner Loop (O(n²) → O(n))

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 2 — performance fix. Depends on step 02. Runs in parallel with step 03 (different
file). `unscrub.rs` was last touched by step 02 (guard inserted before the AC build).

### This Step
The inner `loop` inside `unscrub()` calls `buffer.drain(..m.end())` after every match.
This is O(n) per match (shifts remaining bytes), producing O(n·k) total work for k matches.
The fix is identical in principle to step 03: introduce `cursor: usize` before the inner
loop, accumulate it across matches, drain once after the inner loop.

`AhoCorasick::find` with `Input::new(&buffer).range(cursor..)` returns positions relative
to the FULL buffer, so no offset adjustment is needed.

**No behavioral change.** Bytes written to `output`, ordering, and error semantics are
identical. All existing tests must continue to pass.

The AEAD error handling (`map_err(|_|`)  is left as-is; step 06 will improve it.

## Prerequisites
- Step 02 is complete (`unscrub.rs` has the empty-fake guard before the AC build).

## Files to Read Before Starting
- `src/unscrub.rs` — full file (read AFTER step 02 completes to get current line numbers)

## Implementation

### Task 1: Add `Input` to the `aho_corasick` import

Current import (line 3):

```rust
use aho_corasick::{AhoCorasick, MatchKind};
```

Replace with:

```rust
use aho_corasick::{AhoCorasick, Input, MatchKind};
```

### Task 2: Replace the inner `loop` block inside `unscrub()`

The inner loop processes the safe region on each outer-loop iteration. It currently starts
with `loop {` at line 87 (the `// Emit safe bytes` comment precedes it) and ends at
`}` on line 128.

Locate the inner loop by finding the comment `// Emit safe bytes (with match handling)`
followed by `loop {`. Replace the entire inner loop block — from the opening `loop {`
through its matching `}` — and also add `cursor` initialization before it plus the single
drain after it.

**Before** (the inner loop as it exists after step 02):

```rust
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
```

**After** (replacement — cursor-based, single drain):

```rust
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
                    let plaintext =
                        decrypt_entry(session_key, &entries[entry_idx]).map_err(|_| {
                            UnscrubError::AeadTagFailure {
                                entry_index: entry_idx,
                            }
                        })?;
                    // INV-5: emit plaintext ONLY after successful decryption
                    output.write_all(&plaintext)?;
                    cursor = m.end();
                    // Continue inner loop: more matches may exist in the remaining safe region
                }
            }
        }
        if cursor > 0 {
            buffer.drain(..cursor);
        }
```

**Key differences:**
1. `let mut cursor: usize = 0;` declared BEFORE the `loop {` brace.
2. `remaining = buffer.len() - cursor` drives the hold-window check.
3. `if buffer.len() > max_hold` → `if remaining > max_hold`.
4. `else { 0 }` + `if safe_end == 0 { break; }` replaced by `else { break; }` + `if safe_end <= cursor { break; }`.
5. All `buffer.drain(..X)` inside the loop replaced by `cursor = X`.
6. All `buffer[..X]` slice endpoints updated to start from `cursor` where appropriate.
7. Single `if cursor > 0 { buffer.drain(..cursor); }` after the loop.
8. `ac.find(&buffer)` → `ac.find(Input::new(&buffer).range(cursor..))`.

The `map_err(|_|` in the AEAD branch is **intentionally unchanged** — step 06 will
replace `|_|` with `|e|` and add the `log::debug!` call.

The comment `// INV-5: emit plaintext ONLY after successful decryption` is preserved.

## Acceptance Criteria

- [ ] `cargo test 2>&1 | tail -5` exits 0 (all pre-existing tests pass unchanged)
- [ ] `grep -n 'Input::new' src/unscrub.rs` prints exactly one match inside the inner loop
- [ ] `grep -n 'buffer\.drain' src/unscrub.rs` prints exactly one match (the `if cursor > 0 { buffer.drain(..cursor); }` line after the inner loop)
- [ ] `cargo clippy 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm `cursor` is declared between `// Emit safe bytes` comment and `loop {`.
2. Confirm `buffer.drain` appears exactly once in `unscrub()` body — after the inner loop.
3. Confirm the prefix write uses `buffer[cursor..m.start()]`, not `buffer[..m.start()]`.
4. Confirm the `map_err(|_|` AEAD closure is unchanged (step 06 will fix it).
5. Run `cargo test` and confirm no regressions.

## Rollback

Revert `src/unscrub.rs` to its state after step 02: restore the original inner loop
(removing `cursor` and the single drain) and revert the import to
`use aho_corasick::{AhoCorasick, MatchKind};`.
