# PROGRESS.md

## Status
In Progress

## Objective
Update doppel implementation to match the unified Pattern model in SPEC.md: replace 2-tier detection (Structural + Registered) with unified Pattern struct using 3 segment types (`literal`, `opaque`, `variable`), migrate patterns file from v2 to v3, update CLI options, add new built-in patterns, expose `Detector` type with pre-built AC automaton, and update all tests — without regressing any behavioral invariants.

## Wave Map
| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 1 | step-01-segment-types | No | — |
| 2 | step-02-fake-derivation, step-03-pattern-struct-unification | Yes | Wave 1 |
| 3 | step-05-patterns-file-v3 | No | step-03 |
| 4 | step-04-registration-rework | No | step-02, step-03 |
| 5 | step-06-cli-update, step-07-builtin-patterns | Yes | step-04, step-05 |
| 6 | step-08-tests | No | All except step-09 |
| 7 | step-09-detector | No | step-03 |

## Dependency Table
| Step | File(s) | Depends On | Depended By |
|------|---------|------------|-------------|
| step-01-segment-types | segment.rs | — | step-02, step-03 |
| step-02-fake-derivation | fake.rs | step-01 | step-04 |
| step-03-pattern-struct-unification | patterns.rs | step-01 | step-04, step-05 |
| step-04-registration-rework | secrets.rs | step-02, step-03 | step-06 |
| step-05-patterns-file-v3 | secrets_file.rs | step-03 | step-06, step-07 |
| step-06-cli-update | doppel-cli/src/main.rs | step-04, step-05 | step-08 |
| step-07-builtin-patterns | patterns.rs | step-05 | step-08 |
| step-08-tests | tests/**/*.rs | All except step-09 | — |
| step-09-detector | doppel/src/detector.rs | step-03 | step-08 |


## Orchestrator Protocol

1. **Before each step:** Read the step file completely. Verify prerequisites are met.
2. **Execution:** Delegate to a worker with the step file path. Worker reads step file + SPEC.md.
3. **Validation:** Worker runs acceptance criteria commands. All must pass before marking complete.
4. **Progress update:** Check the box in this file. Commit: `complete step-NN: <one-liner>`
5. **Wave completion:** When all steps in a wave are checked, move to next wave.
6. **Plan completion:** When step-09 passes, delete `plans/spec-unified-pattern/`, add one-liner to `MASTER_PROGRESS.md` Completed section.

## Subagent Contract

Each worker receives:
- Path to the step file (e.g., `plans/spec-unified-pattern/step-01-segment-types.md`)
- Instruction to read SPEC.md for authoritative behavior

Worker responsibilities:
- Read the step file completely before writing any code
- Implement exactly what the step file specifies
- Run all acceptance criteria commands
- Report: changed files, validation results, any blockers
- Do NOT proceed to the next step; return to orchestrator

Worker escalates if:
- Acceptance criteria cannot pass without changing the approach
- Step file conflicts with SPEC.md
- A dependency step appears incomplete

## Steps
- [x] [step-01-segment-types](./step-01-segment-types.md) — Add `Opaque` segment variant, `Wide` charset, update `SegmentDef` serde
- [x] [step-02-fake-derivation](./step-02-fake-derivation.md) — Add opaque fake derivation (HMAC-seeded PRNG, never verbatim), defense-in-depth collision check
- [x] [step-03-pattern-struct-unification](./step-03-pattern-struct-unification.md) — Replace `Pattern` enum with unified struct, delete `RegisteredPat`, update AC building
- [x] [step-04-registration-rework](./step-04-registration-rework.md) — New `SecretOptions` (anchor_len, tail_anchor_len, group, force), entropy enforcement (83/131 bits), INV-31 validation
- [x] [step-05-patterns-file-v3](./step-05-patterns-file-v3.md) — Replace SecretsFile v2 with v3 (unified `[[pattern]]` array), update version, add `digests` field
- [x] [step-06-cli-update](./step-06-cli-update.md) — Update CLI: `--identifier`, `--anchor-len`, `--tail-anchor-len`, `--group`, `--force`; remove `--label`/`--preserve-*`
- [ ] [step-07-builtin-patterns](./step-07-builtin-patterns.md) — Add new built-in patterns: OpenRouter, Google OAuth, Slack, Linear, Groq, Perplexity, Cerebras, Stripe, Clerk, Svix, Doppler, Chromatic
- [x] [step-08-tests](./step-08-tests.md) — Update all tests: version assertions (2→3), format changes, new spec-invariant tests (INV-28, INV-31, INV-25, VC-11, INV-39..41), CLI tests
- [ ] [step-09-detector](./step-09-detector.md) — Add `Detector` type with pre-built AC automaton; expose `Detector::new` + `Detector::swap` (INV-39..41)

## Open Decisions
None — all technical decisions resolved from source plans and SPEC.md.

## Notes
- Tests will fail during waves 1-5 (incremental breakage expected). `cargo check` should pass within each step.
- Wave 7 (step-09) can run in parallel with step-08's test writing since it only touches a new file.
- Wave 6 (step-08) is the stabilization step that restores all tests to green; step-08 must include INV-39..41 test cases.
- Built-in count changes from 15 to 27 (or thereabouts depending on final pattern list).
