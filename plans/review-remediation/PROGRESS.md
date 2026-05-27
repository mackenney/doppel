# PROGRESS.md

## Status
In Progress

## Objective
Fix INV-12 violations in CLI key handling, add async spec tests for streaming invariants (INV-5/INV-6/INV-8), consolidate duplicated unscrub logic into shared abstraction, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

## Wave Map
| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 1 | 01, 02, 03, 04 | Yes (all 4) | — |
| 2 | 05, 06, 07 | No (sequential) | Wave 1 |
| 3 | 08, 09, 10 | Yes (08-09 parallel, 10 independent) | Wave 2 |
| 4 | 11 | N/A (single step) | Wave 3 (08-09 specifically) |
| 5 | 12 | N/A (optional) | Wave 2 |

## Dependency Table
| Step | File(s) | Depends On | Depended By |
|------|---------|------------|-------------|
| 01 | `src/lib.rs`, `src/unscrub_stream.rs` | — | — |
| 02 | `cli/src/main.rs` | — | — |
| 03 | `tests/spec/inv.rs` | — | — |
| 04 | `src/unscrub.rs`, `src/unscrub_stream.rs` | — | — |
| 05 | `src/unscrub_core.rs` (new) | Wave 1 | 06, 07 |
| 06 | `src/unscrub.rs` | 05 | — |
| 07 | `src/unscrub_stream.rs` | 05 | — |
| 08 | `src/fake.rs` | Wave 2 | 11 |
| 09 | `src/segment.rs`, `src/tier1.rs`, `src/fake.rs` | 08 | 11 |
| 10 | `src/scrub.rs` | Wave 2 | — |
| 11 | `src/tier1.rs`, `src/scrub.rs` | 08, 09 | — |
| 12 | `src/unscrub.rs` or `src/unscrub_core.rs` | 05-07 | — |

## Orchestrator Protocol
1. Read this file to identify current wave
2. Dispatch all steps in current wave in parallel
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
- [ ] [step-01-hygiene-fixes](./step-01-hygiene-fixes.md) — Module visibility `pub(crate)` + AhoCorasick error mapping consistency
- [ ] [step-02-cli-zeroization](./step-02-cli-zeroization.md) — Wrap CLI key intermediates in `Zeroizing<T>` (INV-12)
- [ ] [step-03-async-spec-tests](./step-03-async-spec-tests.md) — Add async spec tests for INV-5, INV-6, INV-8
- [ ] [step-04-sessionkey-docs](./step-04-sessionkey-docs.md) — Document SessionKey ownership asymmetry
- [ ] [step-05-unscrub-core](./step-05-unscrub-core.md) — Create shared `unscrub_core` module with `process_safe_region`
- [ ] [step-06-refactor-sync-unscrub](./step-06-refactor-sync-unscrub.md) — Refactor `unscrub.rs` to use `unscrub_core`
- [ ] [step-07-refactor-async-unscrub](./step-07-refactor-async-unscrub.md) — Refactor `unscrub_stream.rs` to use `unscrub_core`
- [ ] [step-08-charset-bitmap](./step-08-charset-bitmap.md) — Introduce `CharsetBitmap` type with static instances
- [ ] [step-09-charset-migration](./step-09-charset-migration.md) — Migrate `CharsetName::resolve` to return static reference
- [ ] [step-10-scrub-dedup-alloc](./step-10-scrub-dedup-alloc.md) — Fix `to_vec()` allocation before dedup check in scrub
- [ ] [step-11-ac-prefilter](./step-11-ac-prefilter.md) — Build Aho-Corasick pre-filter for Tier 1 prefixes
- [ ] [step-12-unscrub-buffer-opt](./step-12-unscrub-buffer-opt.md) — (Optional) Optimize `buffer.drain` in unscrub with ring-buffer approach
