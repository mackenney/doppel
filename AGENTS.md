# Agent Guidelines — doppel

## Project

`doppel` is a Rust library and CLI that intercepts secrets in arbitrary
byte payloads before they reach an external service, replaces them with
structurally-equivalent fakes, and transparently restores the originals in
streaming responses. Implementation is SPEC-driven: every non-trivial module or
behavior must have a corresponding spec document before code is written.

## Workspace layout

```
src/               Library source (lib crate: doppel)
cli/               CLI crate (doppel-cli)
tests/             Lib spec-invariant and integration tests
  spec/            Spec-invariant test modules (entry: tests/spec.rs)
  integration/     Integration test modules (entry: tests/integration.rs)
cli/tests/         CLI spec and e2e tests
  cli_spec/        CLI spec-invariant modules (entry: cli/tests/cli_spec.rs)
  e2e/             E2e test modules (entry: cli/tests/e2e.rs)
plans/             Active development plans — each plan directory holds step
                   files and PROGRESS.md while work is in progress; the entire
                   directory is deleted when the plan completes
artifacts/         Transient working files — git-ignored, never committed
  investigations/  Scanner / librarian output
  fact-checks/     Fact-check sub-artifacts and reports
  progress/        Orchestrator progress files
MASTER_PROGRESS.md Single source of truth for project-wide work status
SPEC.md            Behavioral contract for the full system
```

## SPEC-driven development

- Every implementation must be driven by a spec.
- The spec lives at `SPEC.md` (repo root).
- Spec documents use MUST / SHOULD / MAY language (RFC 2119).
- The pipeline is: **investigate → spec → plan → orchestrate**.
- No code is written before a spec exists for the component being built.

## Master Progress

`MASTER_PROGRESS.md` is the single source of truth for project-wide work status.
Every human and agent working on doppel reads it first to understand
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

- `plans/` is committed; each plan lives under `plans/<feature>/` with
  `PROGRESS.md` and `step-NN-*.md` files.
- Plans are created by the planner skill; they hold all in-progress work
  context — step files, findings, wave maps — for the duration of execution.
- The entire plan directory is deleted once the plan is complete. No plan
  files survive after completion; their outcomes live in git history and in
  `MASTER_PROGRESS.md`.
- Code comments and docs MUST NOT reference plan files.

## Artifacts

- All transient working files (investigation scans, fact-check reports,
  progress trackers, brainstorm notes) live in `artifacts/` and are git-ignored.
- Never commit files from `artifacts/`.
- Never commit scratch files, session recordings, or API fixture files to the repo root.

## Testing

### Principles

1. **Specs before tests.** `SPEC.md` documents the observable contract. Tests
   assert that spec. When spec and behavior disagree, fix one or the other —
   never silently accept drift.

2. **Test-first for discovered errors.** When a smoke test, sanity check, or
   investigation surfaces a defect:
   1. Write a failing test that encodes the incorrect behavior.
   2. Verify it fails as expected.
   3. Fix the code until the test passes.
   4. Commit test and fix together.
   Never fix a discovered defect without a test that would have caught it.

3. **Security invariants are non-negotiable.** Any test that verifies a security
   property from SPEC.md Behavioral Invariants §1–23 is a spec-invariant test.
   These MUST pass on every commit. Weakening them requires an explicit spec
   change rationale.

4. **No secrets in test output.** Test fixtures MUST NOT contain real API keys,
   tokens, or credentials of any kind. Use synthetic test vectors only.

5. **Deterministic crypto tests.** Tests that involve CSPRNG output MUST use a
   seeded CSPRNG (via the `rand` crate's `SeedableRng`) so they are reproducible.
   The production code uses `OsRng`; tests inject a seeded RNG via dependency
   inversion.

### Test tiers

| Tier | Entry point | Subdirectory | What it covers |
|---|---|---|---|
| **Spec invariants (lib)** | `tests/spec.rs` | `tests/spec/` | Library SPEC.md MUST/MUST NOT invariants |
| **Spec invariants (CLI)** | `cli/tests/cli_spec.rs` | `cli/tests/cli_spec/` | CLI-specific SPEC.md invariants (INV-20, INV-21) |
| **Integration** | `tests/integration.rs` | `tests/integration/` | Public-API behavior: full swap→restore cycles, streaming edge cases |
| **E2E** | `cli/tests/e2e.rs` | `cli/tests/e2e/` | CLI process boundary tests; gated by `--features test-e2e` |

Inline unit tests (`#[cfg(test)]` in `src/`) test implementation internals and
carry no stability guarantee — change freely during refactoring.

### Naming conventions

**Spec-invariant tests** — file header and function naming:

```rust
// Spec: SPEC.md §Behavioral Invariants

#[test]
fn test_inv1_swap_replaces_every_detected_secret() {
    // INV-1: "swap MUST replace every secret detected by the supplied Patterns
    //         with a structurally-equivalent fake."
    ...
}
```

The `invN` number matches the invariant number in SPEC.md Behavioral Invariants.

**Verifiable Condition tests** — map directly to integration tests:

```rust
#[test]
fn test_vc1_swapped_output_contains_no_original_secret() {
    // VC-1 from SPEC.md Verifiable Conditions
    ...
}
```

### External tests are contracts

Never weaken an external test to make a refactor pass. A failing external test is
either a bug or a deliberate spec change — update the spec explicitly and record
the decision. Inline unit tests carry no such guarantee.

### Critical test vectors

Every implementation MUST pass these specific scenarios:

**Swap correctness:**
- Tier 1: Anthropic / OpenAI / AWS IAM / GitHub PAT classic / GitHub PAT fine-grained / GCP API key in payload → fake in output, entry produced
- Tier 2: registered secret in payload → fake in output, entry produced
- No-op: payload with no secrets → returned unchanged, empty entries
- Multiple occurrences of same secret → same fake in all positions, one entry
- Two different secrets → two entries, two distinct fakes
- Overlapping prefix candidates → leftmost-longest match wins
- Tier 2 structural match + HMAC failure → passed through unchanged

**Restore correctness:**
- Fake split across chunk boundary → correctly restored
- Multiple fakes in stream → all restored
- No fake in stream → output byte-for-byte identical to input, no error
- AEAD tag tampered → error returned, no partial output emitted

**Security properties:**
- Fake ≠ original for any detected secret (collision avoidance)
- Same secret + same Pattern → same fake across calls (stability)
- Entries contain no plaintext secret bytes
- Session key not serialized in entries

**CLI:**
- `swap` creates session key file with mode 0600
- `restore` reads key from `DOPPEL_KEY` env var only (no `--key` flag)
- `restore` writes to stdout before stdin reaches EOF (streaming)

### Test commands

```sh
cargo nextest run --workspace                                                  # all tests (lib + cli)
cargo nextest run -p doppel --test spec                               # lib spec invariants
cargo nextest run -p doppel-cli --test cli_spec                       # CLI spec invariants
cargo nextest run -p doppel --test integration                        # integration only
cargo nextest run -p doppel-cli --features test-e2e --test e2e        # e2e
cargo nextest run --lib                                                        # unit tests only
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
