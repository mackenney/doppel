# PROGRESS.md — test-cleanup

## Status
In Progress

## Objective
Three small test consistency fixes identified by code review and confirmed by fact-checker:

| # | Severity | File | Fix |
|---|----------|------|-----|
| 1 | MEDIUM | `src/unscrub_stream.rs` | `nonce: vec![0u8; 12]` → `vec![0u8; 24]` in `test_empty_fake_rejected_stream` |
| 2 | MEDIUM | `src/unscrub.rs` | Add `assert!(output.is_empty())` to `test_empty_fake_rejected_sync` |
| 3 | LOW | `src/unscrub_stream.rs` | Add explicit `break` after `cursor = safe_end` in `None` branch of `process_buffer` for symmetry |

All three fixes are in two files. Items 1 and 3 are both in `unscrub_stream.rs` so they must be sequential.

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0 | step-01 | No | — |

One step covers all three changes (two files, coordinated commit).

## Orchestrator Protocol
1. Dispatch step-01 worker
2. Dispatch reviewer after completion
3. Mark complete when reviewer passes

## Subagent Contract
- Worker: Read step file fully. Implement exactly what the step specifies. Commit.
- Reviewer: Run acceptance criteria verbatim.

## Steps

- [ ] [step-01-test-consistency](./step-01-test-consistency.md) — nonce fix, output.is_empty() assertion, None-branch break
