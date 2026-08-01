# Step 05 — Doc comments, example file, full validation sweep

Depends on: step-04.

## Changes

### Doc comments (WHY-focused, per repo conventions)

- `Pattern` struct doc (patterns.rs:696 region): document the new field's
  contract in one or two lines, referencing SPEC §Trailing Run Guard.
- `gcp()` constructor doc: note it ships guarded by default and why (weakest
  structure in the built-in set against large base64 payloads), and that the
  guard can be removed by editing the patterns file entry.
- `Detector` module doc example unaffected — verify doctests still pass.
- `SecretsFile`/`PatternEntry` docs: describe the optional TOML key, its
  positivity requirement, and the ≥1-variable-segment constraint.
- `swap` / `swap_with_ac` docs: one sentence on guard semantics with a
  SPEC cross-reference (winner-only, no cascade, forward-only probe).
- Check `doppel/src/lib.rs` crate-level docs for any "replaced without
  exception"-style phrasing that needs the same opt-in qualifier SPEC
  §Purpose received. Update if present.
- Cross-check the registration surface landed by step-06: `SecretOptions`
  field doc, `register`/`register_with_options` docs, and the README
  registration example all describe the same contract (positive threshold,
  guard charset = effective variable charset, HMAC-gated semantics). Fix
  drift here rather than re-opening step-06.

### secrets-example.toml

Add `trailing_run_guard = 2048` to the gcp entry (or regenerate the example
if it is generated), plus a one-line TOML comment explaining the field.
Verify the example still deserializes: a unit test already covers
deserialize; if no test reads secrets-example.toml, do a manual
`cargo run -p doppel-cli -- list --patterns secrets-example.toml` sanity
check or equivalent.

### No plan-file references

Grep the diff for `plans/` references in code/docs — none allowed per
AGENTS.md.

## Full validation

```sh
cargo fmt
cargo clippy --workspace --all-targets   # zero new warnings, no new #[allow]
cargo nextest run --workspace
cargo nextest run -p doppel-cli --features test-e2e --test e2e
cargo test --doc -p doppel
```

## Acceptance criteria

- All commands above pass.
- `git grep -n "plans/" doppel/ doppel-cli/` returns nothing new.
- Diff review: no section-separator comments, no TODOs, no dead code.
- Doc comments state the guard is opt-in and cite SPEC §Trailing Run Guard.
