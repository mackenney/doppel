# Step 06: Log AEAD Error Before Discarding in `unscrub()`

## Context

### Overall Objective
Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add missing async test coverage.

### Phase Context
Wave 3 — diagnostic improvement. Depends on step 04. Runs in parallel with steps 05 and 07.
`unscrub.rs` was last touched by step 04 (cursor refactor of the inner loop).

### This Step
`unscrub()` has the same AEAD error silencing as `process_buffer` before step 05 fixed it.
The `map_err(|_|` closure discards the error. Binding the error with `|e|` and emitting
`log::debug!` makes tag failures visible during development without cluttering production
logs (`debug` is compile-stripped in release by default and is the conventional diagnostic
level for expected failures on tampered input).

The AEAD error message does not contain the session key or plaintext.

`log` is already a main dependency (`log = "0.4"` in `Cargo.toml`).

## Prerequisites
- Step 04 is complete. `unscrub.rs` uses the cursor-based inner loop with `map_err(|_|`
  unchanged (step 04 intentionally left it for this step).

## Files to Read Before Starting
- `src/unscrub.rs` — full file (read AFTER step 04 completes for current state)

## Implementation

### Task 1: Bind the AEAD error and add debug log

In `unscrub()`, locate the `decrypt_entry` call inside the inner loop. It currently reads
(after step 04):

```rust
                    let plaintext =
                        decrypt_entry(session_key, &entries[entry_idx]).map_err(|_| {
                            UnscrubError::AeadTagFailure {
                                entry_index: entry_idx,
                            }
                        })?;
```

Replace it with:

```rust
                    let plaintext =
                        decrypt_entry(session_key, &entries[entry_idx]).map_err(|e| {
                            log::debug!(
                                "AEAD decryption failed for entry {entry_idx}: {e}"
                            );
                            UnscrubError::AeadTagFailure {
                                entry_index: entry_idx,
                            }
                        })?;
```

The only changes are `|_|` → `|e|` and the `log::debug!` line inserted as the first
statement in the closure body.

## Acceptance Criteria

- [ ] `grep -n 'map_err(|_|' src/unscrub.rs` prints zero matches
- [ ] `grep -n 'log::debug!' src/unscrub.rs` prints exactly one match
- [ ] `grep -n 'AEAD decryption failed' src/unscrub.rs` prints exactly one match
- [ ] `cargo test 2>&1 | tail -5` exits 0 (all tests pass)
- [ ] `cargo clippy 2>&1 | grep -c '^error'` prints `0`

## Reviewer Instructions

1. Confirm `|e|` binds the error (not `|_|`).
2. Confirm `log::debug!` is the first statement in the closure, before constructing the
   `UnscrubError` value.
3. Confirm the message includes `{e}` and `{entry_idx}` but no key material.
4. Confirm the `?` propagation is unchanged.
5. Run `RUST_LOG=debug cargo test test_unscrub_tampered_aead_tag_returns_err` and
   confirm the debug message appears in stderr.

## Rollback

Restore the original `map_err(|_| { ... })` closure by changing `|e|` back to `|_|` and
removing the `log::debug!` line.
