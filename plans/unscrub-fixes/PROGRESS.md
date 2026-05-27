# PROGRESS.md

## Status
In Progress

## Objective

Fix correctness, security, and performance issues in `unscrub_stream.rs` and `unscrub.rs`,
then add the missing test coverage that was never written for the async streaming path.

Eight concrete items, zero architectural changes:

| Severity | Item |
|----------|------|
| BLOCKER | Empty-fake guard missing in `unscrub_stream()` constructor and `unscrub()` — AhoCorasick accepts zero-length patterns and returns `Match{0,0}`, causing an infinite loop in `process_buffer` / the inner emit loop |
| IMPORTANT | O(n²) buffer management in both `process_buffer` and the sync inner loop — `drain(..)` after every match shifts all remaining bytes |
| IMPORTANT | Decrypted plaintext wrapped with `Bytes::from(vec)` which uses `ManuallyDrop`, so the Vec is never zeroed |
| MEDIUM | AEAD decrypt failures discard the underlying error — add `log::debug!` in both files |
| LOW | `bytes = "1"` appears in `[dev-dependencies]` despite being an optional main dep — redundant |
| LOW | `unscrub_stream()` constructor is missing `#[must_use]` |
| TESTS | Two distinct fakes in one response; `Poll::Pending` waker path; Tier 2 pattern restoration |

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 1 | 01, 02 | Yes — different files | — |
| 2 | 03, 04 | Yes — different files | Wave 1 |
| 3 | 05, 06, 07 | Yes — all different files | Wave 2 |
| 4 | 08 | — | Wave 3 |

Steps within the same wave that touch the same file are **prohibited** — the table above
avoids this. `unscrub_stream.rs` is only in steps 01, 03, 05, 08 (each in a different wave).
`unscrub.rs` is only in steps 02, 04, 06 (each in a different wave). `Cargo.toml` is only
in step 07.

## Dependency Table

| Step | Depends On | Why |
|------|-----------|-----|
| 01 | — | First touch of `unscrub_stream.rs` |
| 02 | — | First touch of `unscrub.rs` |
| 03 | 01 | Rewrites `process_buffer`; must be after the guard that prevents the bug |
| 04 | 02 | Rewrites inner loop in `unscrub()`; must be after the guard |
| 05 | 03 | Modifies the refactored `process_buffer` from step 03 |
| 06 | 04 | Modifies the refactored inner loop from step 04 |
| 07 | — | `Cargo.toml` only; no file conflict with any other step |
| 08 | 05 | Tests exercise the `process_buffer` behavior as fixed and refactored in 03+05 |

## Orchestrator Protocol

- Launch steps 01 and 02 in parallel (Wave 1).
- After both complete, launch steps 03 and 04 in parallel (Wave 2).
- After both complete, launch steps 05, 06, and 07 in parallel (Wave 3).
- After all three complete, launch step 08 alone (Wave 4).
- After step 08 completes, run `cargo test --features async` and `cargo clippy --features async` as the final gate.

## Subagent Contract

Each step file is self-contained. A worker receiving only the step file and the files
listed under "Files to Read Before Starting" must be able to implement the step without
asking questions.

Acceptance criteria in each step file use exact runnable commands. Every step's final
state must pass the listed commands before the step is marked complete.

## Steps

- [ ] [step-01-empty-fake-guard-stream](./step-01-empty-fake-guard-stream.md) — Add empty-fake validation + `#[must_use]` in `unscrub_stream()` constructor
- [ ] [step-02-empty-fake-guard-sync](./step-02-empty-fake-guard-sync.md) — Add empty-fake validation in `unscrub()` constructor
- [ ] [step-03-cursor-refactor-stream](./step-03-cursor-refactor-stream.md) — Replace per-match `drain` with cursor in `process_buffer` (O(n) fix)
- [ ] [step-04-cursor-refactor-sync](./step-04-cursor-refactor-sync.md) — Replace per-match `drain` with cursor in `unscrub()` inner loop (O(n) fix)
- [ ] [step-05-zeroize-and-aead-log-stream](./step-05-zeroize-and-aead-log-stream.md) — Zeroize plaintext + log AEAD error in `process_buffer`
- [ ] [step-06-aead-log-sync](./step-06-aead-log-sync.md) — Log AEAD error before discarding in `unscrub()`
- [ ] [step-07-remove-bytes-dep](./step-07-remove-bytes-dep.md) — Remove redundant `bytes` from `[dev-dependencies]`
- [ ] [step-08-tests](./step-08-tests.md) — Add three missing async tests: two distinct fakes, Poll::Pending, Tier 2
