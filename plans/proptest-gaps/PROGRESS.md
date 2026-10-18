# PROGRESS.md

## Status
In Progress

## Objective
Add four proptest property modules under `doppel/tests/property/` covering
SPEC.md gaps: INV-8 restore hold bound under adversarial streams, INV-9/VC-7
entry confidentiality (decoded serialized form, Debug, fake, session key),
registration trailing-run guard end to end (VC-22/23/26/28, INV-49/51), and
`Detector` reuse / cross-thread sharing (INV-39/40). Tests only — no `src/`
changes; a failing property on the unmodified tree is a finding to report,
never a reason to edit `src/` or weaken the property.

## Executor Tier
fast — every step creates exactly one new test file (~200–330 LOC of
near-final code given in the step), one concern, all names and signatures
pre-decided and verified against source with file:line citations.

## Open Decisions
- **Module declarations up front.** The parent adds all four
  `#[path = "property/<m>.rs"] mod <m>;` lines to `doppel/tests/property.rs`
  before step-01. The `property` test binary will not compile until every
  declared file exists, so the parent must also create a placeholder file
  (e.g. a single `// Implemented by a later step.` line) for each of
  `restore_holdback.rs`, `entries_no_leak.rs`, `registration_guard.rs`,
  `detector_reuse.rs` in the same commit. Each step overwrites its own
  placeholder. Alternative: add each `mod` line just before its step.
- **INV-9 window size (step-02).** "No ≥ 8-byte run" is enforced literally on
  every cryptographically random surface (decoded nonce/ciphertext, their
  Debug rendering) and for session-key bytes everywhere. On surfaces that
  legitimately hold charset-derived fake bytes (`Entry::fake`, raw JSON) a
  literal 8-byte rule flakes (8 digits coincide with p = 10^-8 per alignment),
  so those use `max(8, ceil(64 / log2|charset|))` bytes per variable segment
  (digits 20 … wide 10) and exclude opaque anchor bytes, which the generators
  draw from the fixed `abPQ` alphabet and which legitimately reappear as
  another pattern's literal anchor. Confirm this interpretation.
- **Overlap with existing coverage.** `restore_sync.rs` already checks INV-8
  (swapped payload only, chunk sizes 1..=7) and a 16-byte raw-JSON INV-9
  window; `detection.rs` already checks fresh-`Detector` parity on one
  payload. Steps 01/02/04 deliberately widen these (adversarial streams and
  >4096-byte chunks; decoded base64 fields + Debug + key; reuse and threads).
  Keep both, or later retire the narrower checks (not in this plan).
- **Unseeded CSPRNG.** `register_with_options` (salt) and `swap`/`Detector::swap`
  (session key, nonces) use `OsRng` with no public RNG injection, so steps
  02–04 assert only RNG-independent outcomes (as `registration.rs` already
  does). Pattern salts are proptest-generated, so fakes are reproducible.
- **MASTER_PROGRESS.md.** Per AGENTS.md this plan needs a Queued/In Progress
  entry; this planner was restricted to `plans/proptest-gaps/`, so the parent
  must add it in the plan-creation commit.

## Decisions taken

## Pending decisions (human)

<!-- The plan is not complete while any row in the two ledger tables below reads `open` or any ## Steps item is unchecked. Status grammar: step-contract. No model writes `waived`. -->
## Tech debt / deferred gates
| Gate | Class | Owed by | Reason deferred | Status |
|------|-------|---------|-----------------|--------|

## Disabled/softened checks
| Check | Where | Why | Status |
|-------|-------|-----|--------|

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0    | step-01 | No | — (parent's `mod`-line + placeholder commit) |
| 1    | step-02 | No | Wave 0 (single writer in the worktree) |
| 2    | step-03 | No | Wave 1 (single writer in the worktree) |
| 3    | step-04 | No | Wave 2 (single writer; carries plan-level G-integ) |

## Dependency Table

| Step | File(s) | Depends On | Depended By |
|------|---------|------------|-------------|
| step-01 | doppel/tests/property/restore_holdback.rs | parent mod lines | step-02 |
| step-02 | doppel/tests/property/entries_no_leak.rs | step-01 (ordering only) | step-03 |
| step-03 | doppel/tests/property/registration_guard.rs | step-02 (ordering only) | step-04 |
| step-04 | doppel/tests/property/detector_reuse.rs | step-03 (ordering only) | — |

Shared, read-only inputs for every step: `doppel/tests/property/{generators,oracle,support,detection}.rs`.
Mutation scripts (run by `g-unit-2+` gates, each reverts `src/` on exit):
`plans/proptest-gaps/mutations/*.sh`.

## Executor Protocol
1. Read this file to identify current wave
2. Dispatch the single step in the current wave
3. After each step: dispatch reviewer agent (see step file for reviewer instructions)
4. Mark step complete only after reviewer passes
5. Advance to next wave only when the current step is complete
6. Blockers (including any property failing on the unmodified tree): stop and report to user with the shrunk counterexample

## Subagent Contract
Dispatched via `workflows/execute-step.js` / `execute-wave.js`, not ad-hoc task strings — see the `executor` skill. Workers (`wf-structural-worker`, `wf-flash-worker`, or the builtin `worker` with per-run `skill: "step-contract"`) run every sidecar gate, commit `step-NN: <name>`, and return a typed STEP-VERDICT. Reviewers (`wf-step-reviewer`) re-run the gates independently and return a typed REVIEW-VERDICT — never prose PASS/FAIL. `execute-step.js` applies the typed verdict through `ledger-apply`; the parent never edits ledger rows.

## Steps

- [ ] [step-01-restore-holdback](./step-01-restore-holdback.md) — INV-8 hold bound after every chunk + EOF flush, adversarial streams, sync restore
- [ ] [step-02-entries-no-leak](./step-02-entries-no-leak.md) — INV-9/VC-7: no secret run in decoded/Debug/fake surfaces, no session key in entries
- [ ] [step-03-registration-guard](./step-03-registration-guard.md) — VC-22/23/26/28, INV-49/51: registered guard declaration, boundary vs oracle, option errors
- [ ] [step-04-detector-reuse](./step-04-detector-reuse.md) — INV-39/40: reused and thread-shared Detector equals free swap; plan-level integration gate
