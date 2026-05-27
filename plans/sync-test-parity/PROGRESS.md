# PROGRESS.md — sync-test-parity

## Status
In Progress

## Objective
Close five findings from the final code review + fact-check pass:

| # | Severity | File | Fix |
|---|----------|------|-----|
| 1 | MEDIUM | `src/unscrub_stream.rs` | Add `// INV-5:` reference to async Zeroizing comment |
| 2 | HIGH | `src/unscrub.rs` | Add `test_unscrub_empty_input` — empty byte stream |
| 3 | HIGH | `src/unscrub.rs` | Add `test_unscrub_two_distinct_secrets` — Anthropic + OpenAI round-trip |
| 4 | HIGH | `src/unscrub.rs` | Add `test_unscrub_tier2_roundtrip` — Tier 2 registered secret |
| 5 | LOW | `tests/spec/inv.rs` | Add comment to async spec test explaining no output check |

Items 1 and 5 touch separate files from items 2-4, so Wave 0 can run both in parallel.

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0 | step-01, step-02 | Yes — different files | — |

## Dependency Table

| Step | Files | Depends On | Depended By |
|------|-------|------------|-------------|
| step-01 | `src/unscrub_stream.rs`, `tests/spec/inv.rs` | — | — |
| step-02 | `src/unscrub.rs` | — | — |

## Orchestrator Protocol
1. Dispatch step-01 and step-02 in parallel (Wave 0)
2. After each: dispatch reviewer
3. Mark complete when reviewers pass

## Subagent Contract
- Workers: Read step file fully. Implement only what the step specifies. Commit.
- Reviewers: Run acceptance criteria verbatim.

## Steps

- [ ] [step-01-comment-fixes](./step-01-comment-fixes.md) — INV-5 ref in async unscrub + clarifying comment in async spec test
- [ ] [step-02-sync-test-parity](./step-02-sync-test-parity.md) — Three sync unit tests: empty input, two distinct secrets, Tier 2
