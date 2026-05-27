# PROGRESS.md — unscrub-followup

## Status
In Progress

## Objective
Address five findings from the unscrub-fixes code review + fact-check:

| Severity | Item |
|----------|------|
| IMPORTANT | `unscrub.rs` decrypted plaintext is bare `Vec<u8>` — not zeroized. Add `Zeroizing::new(...)` to match `unscrub_stream.rs`. |
| IMPORTANT | Empty-fake rejection invariant has no external spec test. Add two tests to `tests/spec/inv.rs`. |
| SUGGESTION | `None`-branch in `process_buffer` drains inline, leaves `cursor=0`, epilogue never fires for that path. Structurally fragile. Fix to use cursor uniformly. |
| SUGGESTION | `Zeroizing` comment gap — `Bytes::copy_from_slice` output is not zeroized. Add one-line clarifying comment. |
| SUGGESTION | `ac = None` multi-chunk passthrough never tested. Add one test using `chunked_stream` with empty entries. |

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0 | step-01, step-02 | Yes — different files | — |
| 1 | step-03 | No | Wave 0 |

## Dependency Table

| Step | Files | Depends On | Depended By |
|------|-------|------------|-------------|
| step-01 | `src/unscrub.rs` | — | step-03 |
| step-02 | `src/unscrub_stream.rs` | — | step-03 |
| step-03 | `src/unscrub_stream.rs` (test module), `tests/spec/inv.rs` | step-01, step-02 | — |

## Orchestrator Protocol
1. Read this file to identify current wave
2. Dispatch all steps in current wave in parallel (see wave map)
3. After each step: dispatch reviewer agent (see step file for reviewer instructions)
4. Mark step complete only after reviewer passes
5. Advance to next wave only when all steps in current wave are complete
6. Blockers: stop and report to user with full context

## Subagent Contract
- Workers: Read step file fully before acting. Implement only what the step specifies.
- Workers: Commit with message "step-NN: <name>"
- Workers: Report: "Step NN complete ✅ (commit <hash>)" or "Step NN FAILED: <reason>"
- Reviewers: Run acceptance criteria commands verbatim. Pass or fail with specifics.

## Steps

- [ ] [step-01-zeroize-plaintext-sync](./step-01-zeroize-plaintext-sync.md) — Wrap decrypted plaintext in Zeroizing in unscrub.rs
- [ ] [step-02-none-branch-cursor-and-comment](./step-02-none-branch-cursor-and-comment.md) — Fix None-branch cursor inconsistency + add Zeroizing comment in unscrub_stream.rs
- [ ] [step-03-tests](./step-03-tests.md) — Add spec invariant tests (empty-fake rejection) + multi-chunk None-branch unit test
