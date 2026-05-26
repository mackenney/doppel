# PROGRESS.md

## Status
In Progress

## Objective
Make Tier 1 and Tier 2 fakes deterministic across process restarts (fixing INV-13 cross-run), eliminate `Tier2Pat.fake` in favor of match-time derivation, add a JSON patterns file format with serde support, and expose `init`/`register`/`--patterns` CLI surface for Tier 2 registration and stable salt persistence.

## Design Decision (resolved)
**Tier1Def salt storage**: `OnceLock` is dropped entirely. `Tier1Def` becomes a plain `Copy`
struct with `salt: [u8; 32]`. `Pattern::Tier1` holds a by-value `Tier1Def` (no `&'static`
reference). The 8 static instances are pure templates with `salt: [0u8; 32]`; callers supply
the real salt. `patterns::all()` generates an ephemeral random salt per call (stable within
the returned `Vec<Pattern>`, non-persistent across restarts — documented trade-off for
single-session use). `PatternsFile::into_patterns()` is the cross-restart stable path.
The file IS the configuration for the scrubber.


## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0 | step-01, step-02 | Yes | — |
| 1 | step-03, step-04 | Yes | — |
| 2 | step-05 | No | step-02, step-03 |
| 3 | step-06, step-07 | Yes | step-05 |
| 4 | step-08 | No | step-04, step-06, step-07 |
| 5 | step-09 | No | step-08 |
| 6 | step-10 | No | step-09 |

## Dependency Table

| Step | File(s) | Depends On | Depended By |
|------|---------|------------|-------------|
| step-01 | `SPEC.md` | — | step-05 (spec reference) |
| step-02 | `src/fake.rs` | — | step-05 |
| step-03 | `src/tier2.rs` | — | step-05 |
| step-04 | `src/tier1.rs` | — | step-08 |
| step-05 | `src/tier2.rs`, `src/scrub.rs` | step-02, step-03 | step-06 |
| step-06 | `src/tier2.rs`, `src/fake.rs`, `src/scrub.rs` | step-05 | step-08 |
| step-07 | `src/tier1.rs`, tests | step-05 (avoid broken intermediate) | step-08 |
| step-08 | `src/patterns_file.rs`, `src/lib.rs`, `src/types.rs` | step-04, step-06, step-07 | step-09 |
| step-09 | `cli/src/main.rs`, `cli/Cargo.toml` | step-08 | step-10 |
| step-10 | `tests/`, `cli/tests/` | step-09 | — |

## Orchestrator Protocol
1. Read this file to identify current wave
2. Dispatch all steps in current wave in parallel
3. After each step: dispatch reviewer agent (see step file for reviewer instructions)
4. Mark step complete only after reviewer passes
5. Advance to next wave only when all steps in current wave are complete
6. Blockers: stop and report to user with full context

## Subagent Contract
- Workers: Read step file fully before acting. Implement only what the step specifies.
- Workers: Commit changes with message "step-NN: <name>"
- Workers: Report back: "Step NN complete ✅ (commit <hash>)" or "Step NN FAILED: <reason>"
- Reviewers: Run acceptance criteria commands verbatim. Pass or fail with specifics.

## Steps

- [ ] [step-01-spec-update](./step-01-spec-update.md) — Update SPEC.md: Tier 2 fake derivation at match time, patterns file contract, CLI subcommands
- [ ] [step-02-derive-fake-core](./step-02-derive-fake-core.md) — Extract `derive_fake_core` shared helper in `fake.rs`, add `derive_fake_tier2_deterministic`
- [ ] [step-03-tier2pat-derivation-fields](./step-03-tier2pat-derivation-fields.md) — Add `preserve_prefix`, `preserve_suffix`, `charset` fields to `Tier2Pat`
- [ ] [step-04-tier1def-identifier](./step-04-tier1def-identifier.md) — Add `identifier` field to `Tier1Def` and `all_defs()` helper
- [ ] [step-05-try-match-returns-fake](./step-05-try-match-returns-fake.md) — Change `Tier2Pat::try_match` to derive and return fake; update `scrub.rs` callers
- [ ] [step-06-remove-tier2-stored-fake](./step-06-remove-tier2-stored-fake.md) — Remove `Tier2Pat.fake` field and `generate_fake_tier2` function
- [ ] [step-07-tier1-salt-externalize](./step-07-tier1-salt-externalize.md) — Drop `OnceLock` from `Tier1Def`; plain `salt: [u8; 32]`, `Tier1Def: Copy`, `Pattern::Tier1` by value
- [ ] [step-08-patterns-file-serde](./step-08-patterns-file-serde.md) — New `patterns_file` module: serde types, serialize/deserialize, `into_patterns`, `add_tier2_pattern`
- [ ] [step-09-cli-surface](./step-09-cli-surface.md) — Add `init`, `register` subcommands and `--patterns` flag on `scrub`
- [ ] [step-10-tests](./step-10-tests.md) — New integration, spec-invariant, and e2e tests; update existing tests for `--patterns`
