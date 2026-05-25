# PROGRESS.md — initial-implementation

## Status

In Progress

## Objective

Implement the complete `its-classified` Rust library and CLI from the clean-slate
stub. Delivers all 23 behavioral invariants from SPEC.md: Tier 1 built-in secret
detection (6 classes), Tier 2 registered-secret detection with HMAC verification,
leftmost-longest scrub engine, XChaCha20-Poly1305 per-entry AEAD, streaming
unscrub with bounded hold, and a fully-tested CLI binary.

## Open Decisions

_(none — all design choices resolved in planning)_

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0 | step-01-cargo-skeleton | No | — |
| 1 | step-02-types-crypto, step-03-fake-hmac | Yes | Wave 0 |
| 2 | step-04-tier1-patterns, step-05-tier2-register | Yes | Wave 1 |
| 3 | step-06-scrub-engine | No | Wave 2 |
| 4 | step-07-unscrub-streaming | No | Wave 3 |
| 5 | step-08-cli | No | Wave 4 |
| 6 | step-09-spec-tests, step-10-integration-tests | Yes | Wave 5 |
| 7 | step-11-e2e-tests | No | Wave 6 |

## Dependency Table

| Step | File(s) | Depends On | Depended By |
|------|---------|------------|-------------|
| step-01 | Cargo.toml, src/lib.rs, src/main.rs | — | all |
| step-02 | src/types.rs, src/crypto.rs | step-01 | step-03, step-04, step-05, step-06, step-07 |
| step-03 | src/fake.rs | step-02 | step-04, step-05, step-06 |
| step-04 | src/tier1.rs | step-02, step-03 | step-06 |
| step-05 | src/tier2.rs | step-02, step-03 | step-06 |
| step-06 | src/scrub.rs, src/lib.rs | step-03, step-04, step-05 | step-07, step-08, step-09, step-10 |
| step-07 | src/unscrub.rs, src/lib.rs | step-02, step-06 | step-08, step-09, step-10 |
| step-08 | src/main.rs | step-06, step-07 | step-11 |
| step-09 | tests/spec/inv.rs, tests/spec.rs | step-06, step-07 | step-11 |
| step-10 | tests/integration/round_trip.rs, tests/integration.rs | step-06, step-07 | step-11 |
| step-11 | tests/e2e/cli.rs, tests/e2e.rs, .config/nextest.toml | step-08, step-09, step-10 | — |

## Orchestrator Protocol

1. Read this file to identify the current wave.
2. Dispatch all steps in the current wave in parallel (see wave map).
3. After each step: run reviewer checks listed in the step file.
4. Mark step complete only after all acceptance criteria pass.
5. Advance to next wave only when all steps in current wave are complete.
6. Blockers: stop and report to user with full context.

## Subagent Contract

- Workers: Read step file fully before acting. Implement only what the step specifies.
- Workers: Commit changes with message `"step-NN: <name>"`.
- Workers: Report back: `"Step NN complete ✅ (commit <hash>)"` or `"Step NN FAILED: <reason>"`.
- Reviewers: Run acceptance criteria commands verbatim. Pass or fail with specifics.

## Invariant Coverage

Every SPEC.md behavioral invariant is covered by at least one step's acceptance criteria:

| INV | Covered By |
|-----|-----------|
| INV-1 | step-06, step-09 |
| INV-2 | step-06, step-09 |
| INV-3 | step-06, step-09 |
| INV-4 | step-07, step-09, step-10 |
| INV-5 | step-07, step-09 |
| INV-6 | step-07, step-09 |
| INV-7 | step-07, step-09 |
| INV-8 | step-07, step-09 |
| INV-9 | step-06, step-09 |
| INV-10 | step-02, step-08, step-09 |
| INV-11 | step-02 (ZeroizeOnDrop) |
| INV-12 | step-02 (ZeroizeOnDrop) |
| INV-13 | step-03, step-09 |
| INV-14 | step-06, step-09 |
| INV-15 | step-03, step-09 |
| INV-16 | step-05, step-06, step-09 |
| INV-17 | step-05, step-09 |
| INV-18 | step-06, step-09 |
| INV-19 | step-07, step-09 |
| INV-20 | step-08, step-11 |
| INV-21 | step-08, step-11 |
| INV-22 | step-04, step-09 |
| INV-23 | step-06, step-09 |

## Steps

- [ ] [step-01-cargo-skeleton](./step-01-cargo-skeleton.md) — Add all dependencies, module file stubs, binary target
- [ ] [step-02-types-crypto](./step-02-types-crypto.md) — SessionKey, Entry, ScrubResult types; AEAD encrypt/decrypt
- [ ] [step-03-fake-hmac](./step-03-fake-hmac.md) — Fake derivation (keyed, stable, collision-safe); HMAC helpers
- [ ] [step-04-tier1-patterns](./step-04-tier1-patterns.md) — 6 built-in Tier 1 Pattern definitions
- [ ] [step-05-tier2-register](./step-05-tier2-register.md) — Registration, Tier 2 Pattern struct, HMAC token
- [ ] [step-06-scrub-engine](./step-06-scrub-engine.md) — Leftmost-longest scan engine, public `scrub()` function
- [ ] [step-07-unscrub-streaming](./step-07-unscrub-streaming.md) — Aho-Corasick sliding-window streaming unscrub
- [ ] [step-08-cli](./step-08-cli.md) — clap CLI: scrub/unscrub subcommands, 0600 key file, env var
- [ ] [step-09-spec-tests](./step-09-spec-tests.md) — All 23 INV spec-invariant tests in tests/spec/
- [ ] [step-10-integration-tests](./step-10-integration-tests.md) — Full round-trip integration tests
- [ ] [step-11-e2e-tests](./step-11-e2e-tests.md) — CLI E2E tests (feature-gated) + nextest config
