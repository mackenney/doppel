# doc-fixes — Execution Progress

## Status

| Step | File | Wave | Status | Notes |
|------|------|------|--------|-------|
| 01 | Rust source doc fixes (13 edits across 8 files) | 0 | ✅ done | commit 05ddc99 |
| 02 | `secrets-example.toml` fixes (2 edits) | 0 | ✅ done | commit 05ddc99 |
| 03 | Create `CHANGELOG.md` | 1 | ✅ done | commit 05ddc99 |
| 04 | `README.md` rewrite | 2 | ✅ done | commit 3af6a6d |
| 05 | `docs/for-the-paranoid.md` rewrite | 3 | ✅ done | commit fe70ee7 |

## Wave dependency graph

```
Wave 0 (∥ Wave 1):  step-01  step-02
Wave 1 (∥ Wave 0):  step-03
Wave 2 (after 0):   step-04
Wave 3 (after 2):   step-05
```

Steps 01 and 02 are fully independent (different files); they can run in parallel within
Wave 0. Step 03 is also fully independent. Steps 04 and 05 are sequential and sequential
with 01/02 respectively (README references the fixed TOML format; for-the-paranoid
references README structure).

## Validation commands (run after each wave)

```sh
# After Wave 0 (Rust source + secrets-example.toml):
cargo test --doc --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace

# After Wave 1 (CHANGELOG.md — no Rust):
# No cargo commands needed; just verify Markdown renders.

# After Wave 2 (README.md):
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace

# After Wave 3 (for-the-paranoid.md):
cargo nextest run --workspace
```

## Commit message templates

```
# Wave 0 commit (steps 01 + 02):
doc: fix Rust source comments and secrets-example.toml

# Wave 1 commit (step 03):
doc: add CHANGELOG.md

# Wave 2 commit (step 04):
doc: update README for v3 format and unified Pattern model

# Wave 3 commit (step 05):
doc: rewrite for-the-paranoid.md for v3 registration model
```

## Orchestrator protocol

1. Launch step-01 and step-02 agents in parallel (Wave 0).
2. Launch step-03 agent in parallel with Wave 0.
3. After both Wave 0 agents complete and tests pass, launch step-04 (Wave 2).
4. After step-04 completes and tests pass, launch step-05 (Wave 3).
5. Mark each step ✅ done here after its agent reports success.
6. After all steps done, do a final `cargo nextest run --workspace` sanity check.

## Key source facts (reference)

- `doppel/src/secrets.rs` — registration logic, `SecretOptions`, `SecretError`
- `doppel/src/secrets_file.rs` — TOML v3 serialization, `SecretsFile`, `PatternEntry`
- `doppel/src/segment.rs` — `BuiltinSegment`, `Segment`, `CharsetName`
- `doppel/src/types.rs` — `SessionKey`, `Entry`, `SwapResult`
- `doppel/src/lib.rs` — crate-level docs, re-exports
- `doppel/src/swap.rs` — free `swap` function
- `doppel/src/restore.rs` — free `restore` function
- `doppel/src/restore_stream.rs` — `RestoreStream`, `restore_stream`
- `doppel-cli/src/main.rs` — CLI flags (ground truth for register/inspect/remove)
- `secrets-example.toml` — 15-of-27 built-in patterns, plus commented instance example
- `README.md` (309 lines) — main user doc; large v2 content
- `docs/for-the-paranoid.md` (224 lines) — entirely v2; needs full rewrite
