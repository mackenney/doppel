# Agent Guidelines — its-classified

## Project

`its-classified` is a Rust library and CLI that intercepts secrets in arbitrary
byte payloads before they reach an external service, replaces them with
structurally-equivalent fakes, and transparently restores the originals in
streaming responses. Implementation is SPEC-driven: every non-trivial module or
behavior must have a corresponding spec document before code is written.

## Workspace layout

```
src/               Library source (single crate for now)
plans/             Active development plans — committed, deleted when complete
artifacts/         Transient working files — git-ignored, never committed
  investigations/  Scanner / librarian output
  fact-checks/     Fact-check sub-artifacts and reports
  progress/        Orchestrator progress files
MASTER_PROGRESS.md Single source of truth for project-wide work status
SPEC.md            Behavioral contract for the full system
TESTING.md         Permanent testing strategy
```

## SPEC-driven development

- Every implementation must be driven by a spec.
- The spec lives at `SPEC.md` (repo root).
- Spec documents use MUST / SHOULD / MAY language (RFC 2119).
- The pipeline is: **investigate → spec → plan → orchestrate**.
- No code is written before a spec exists for the component being built.

## Master Progress

`MASTER_PROGRESS.md` is the single source of truth for project-wide work status.
Every human and agent working on its-classified reads it first to understand
current state.

**What it contains:**
- **In Progress** — active plans with a link to their plan directory
- **Queued** — not-started plans with a link to their plan directory
- **Completed** — one-liner per finished feature/plan, with commit hash
- **Known Gaps** — identified issues with no active plan owner

**Rules:**
- When a plan completes and is deleted → add a one-liner to Completed with the merge commit
- When a new plan is created → add it to Queued
- When work starts on a plan → move it from Queued to In Progress
- Keep entries as one-liners; all detail lives in plan files and git history
- Never let `MASTER_PROGRESS.md` drift: update it in the same commit as the plan change

## Plans

- `plans/` is committed; plans are **deleted** once execution is complete.
- Plans are created by the planner skill; names follow `plans/<feature>/PROGRESS.md`
  and `plans/<feature>/step-NN-*.md`.
- Code comments and docs MUST NOT reference plan files.

## Artifacts

- All transient working files (investigation scans, fact-check reports,
  progress trackers, brainstorm notes) live in `artifacts/` and are git-ignored.
- Never commit files from `artifacts/`.
- Never commit scratch files, session recordings, or API fixture files to the repo root.

## Testing

See `TESTING.md` for the full strategy. Rules for agents:

### Test-first for discovered errors

When a smoke test, sanity check, or investigation surfaces an error or gap,
the fix cycle is:
1. Write a failing test that encodes the incorrect behavior.
2. Verify the test fails as expected.
3. Fix the code until the test passes.
4. Commit both the test and the fix together.
Never fix a discovered defect without a test that would have caught it.

### SPEC-invariant tests vs. auxiliary tests

**SPEC-invariant tests** — directly enforce a MUST/MUST NOT requirement from SPEC.md.
These are the contract.
- Location: `tests/spec/`
- Entry point: `tests/spec.rs`
- Each test MUST have an inline comment citing the invariant number from SPEC.md
  (e.g., `// INV-1: "scrub MUST replace every secret detected..."`).

**Auxiliary tests** — verify correctness of internal mechanics, edge cases, or
intermediate behaviors.
- Location: `#[cfg(test)]` modules in `src/` (unit) or `tests/integration/` (integration)
- Entry point: `tests/integration.rs`

### External tests are contracts

Never weaken an external test to make a refactor pass. A failing external test is
either a bug or a deliberate spec change — update the spec explicitly and record
the decision.

### Test commands

```sh
cargo nextest run                          # all tests
cargo nextest run --test spec              # spec invariants only
cargo nextest run --test integration       # integration only
cargo nextest run --features test-e2e --test e2e  # e2e (requires running service)
```

## Conventions

- Commit messages: imperative mood, 72 chars, no period
- Branch names: `ignacio@<module>/<kebab-description>`
- Format with `cargo fmt`, lint with `cargo clippy` before committing
- No `#[allow(clippy::*)]` without a comment explaining why
- No section-separator comments (`// ---`, `// ===`, etc.)
- Comments explain WHY, not WHAT

## Security conventions

- Session keys MUST NOT appear in logs, error messages, or debug output
- AEAD decryption MUST use constant-time tag verification
- Zeroize key material on drop; use `zeroize` crate
- No `unwrap()` on crypto operations — always propagate errors

## Tooling

- **Shell:** bash; `jq`, `rg`, `fdfind` available
- **Build:** `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`
- **Tests:** `cargo nextest run` (required)
