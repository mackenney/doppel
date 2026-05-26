# PROGRESS.md

## Status
Not Started

## Objective
Split the single crate into a Cargo workspace (root = pure library, `cli/` = binary + clap),
clean up the library's public API surface (opaque Pattern, flattened ScrubError), and add
minimal library documentation. Zero behavioral changes; 79 tests must pass throughout.

## Wave Map

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 1 | step-01 (workspace split) | No | baseline (79 tests green) |
| 2 | step-02 (pattern opacity), step-03 (error cleanup) | Yes — independent edits | step-01 complete |
| 3 | step-04 (library docs) | No | steps 02 + 03 complete |

## Dependency Table

| Step | Hard Dependencies | Reads | Writes |
|------|-------------------|-------|--------|
| 01 | none | Cargo.toml, src/main.rs, tests/spec/inv.rs, tests/e2e.rs, tests/e2e/cli.rs, TESTING.md | Cargo.toml, cli/Cargo.toml, cli/src/main.rs, cli/tests/*, tests/spec/inv.rs, TESTING.md |
| 02 | 01 | src/tier1.rs, src/tier2.rs, tests/spec/inv.rs | src/tier1.rs, src/tier2.rs, tests/spec/inv.rs |
| 03 | 01 | src/types.rs, src/fake.rs, src/crypto.rs | src/types.rs, src/fake.rs, src/crypto.rs |
| 04 | 02, 03 | src/lib.rs, src/scrub.rs, src/unscrub.rs, src/tier2.rs, src/tier1.rs, Cargo.toml | src/lib.rs, src/scrub.rs, src/unscrub.rs, src/tier2.rs, src/tier1.rs, Cargo.toml |

## Orchestrator Protocol

1. Run baseline: `cargo nextest run` — must report 79 pass.
2. Execute step-01. Gate: 79 tests pass, `cargo build -p its-classified` has no clap, binary exists.
3. Execute step-02 and step-03 in parallel (no file overlap). Gate each independently: 79 tests pass.
4. Execute step-04. Gate: `cargo doc -p its-classified --no-deps` exits 0 with no warnings.
5. Final: `cargo nextest run` 79 pass, `cargo clippy --workspace` clean, `cargo fmt --all --check` clean.

## Subagent Contract

Each step file is self-contained. The subagent MUST:
- Read the "Files to Read Before Starting" section first.
- Follow the Implementation section task-by-task in order.
- Run every command in the Acceptance Criteria section and verify the expected output.
- If any acceptance criterion fails, stop and report — do not proceed.
- Commit with the exact message specified in the step file.

## Steps
- [x] [step-01-workspace-cargo-split](./step-01-workspace-cargo-split.md) — Cargo workspace split: root = lib, cli/ = binary (commit 662cf67)
- [x] [step-02-pattern-opacity](./step-02-pattern-opacity.md) — Make Pattern opaque: #[non_exhaustive] + pub(crate) fields (commit f681b51)
- [x] [step-03-error-cleanup](./step-03-error-cleanup.md) — Flatten ScrubError: no internal type leakage (commit 8486afd)
- [ ] [step-04-lib-docs](./step-04-lib-docs.md) — Add crate-level docs and function examples
