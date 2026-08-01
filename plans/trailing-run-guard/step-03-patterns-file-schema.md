# Step 03 — Patterns file (TOML) field, serde, load-time validation

Depends on: step-01. Parallelizable with step-02.

## Context

- `PatternEntry`: `doppel/src/secrets_file.rs:26` — serde TOML form.
- `SecretsFile::deserialize`: secrets_file.rs:115 — validation gate
  (version, duplicate ids, `validate_segment_defs`, INV-31 min==max).
- `SecretsFile::to_patterns`: secrets_file.rs:173 — builds runtime
  `Pattern`s; re-validates (defense-in-depth for programmatic construction).
- `generate_missing_structural_salts`: secrets_file.rs:333 — builds
  `PatternEntry` from `all_defs()`; with step-01's `StructuralDef` field this
  is where the GCP guard flows into `init`-generated files.

## Changes

### 1. Schema field

```rust
/// Minimum trailing same-charset run length (bytes) that suppresses a match
/// (SPEC §Trailing Run Guard). Absent = no guard, unconditional detection.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub trailing_run_guard: Option<u64>,
```

On-disk type is `u64` per the file's existing convention (`version: u64`);
convert with `usize::try_from` in `to_patterns` (reject on overflow via
`InvalidSegment`-style error — practically unreachable but no `unwrap` per
repo conventions). TOML accepts `trailing_run_guard = 2048` at the
`[[pattern]]` level, matching SPEC §Patterns File exactly.

Reject non-positive values: TOML integers are signed; serde into `u64`
already rejects negatives; explicitly reject `Some(0)` in validation via
`SecretsFileError::InvalidSegment` — the same variant reused by the
no-variable-segment check in §2 below — with
`reason: "trailing_run_guard must be a positive integer".into()`.

### 2. Validation (Behavioral Invariants item 45)

Add a check in **both** `deserialize` (load path) and `to_patterns`
(programmatic path), mirroring the existing INV-31 dual placement:

```rust
if entry.trailing_run_guard.is_some()
    && !entry.segments.iter().any(|s| matches!(s, SegmentDef::Variable { .. }))
{
    return Err(SecretsFileError::InvalidSegment {
        identifier: entry.identifier.clone(),
        reason: "trailing_run_guard requires at least one variable segment".into(),
    });
}
```

(Reuse `InvalidSegment`; a new variant is unnecessary — the message is the
"clear error" the spec requires. Keep the exact message stable: step-04's
VC-21 test asserts on a substring of it.)

### 3. Plumb into runtime Pattern

`to_patterns` sets `trailing_run_guard` on the constructed `Pattern` (with
the `u64→usize` conversion). `add_secret_pattern` and `add_structural_entry`
write `trailing_run_guard: None` into new entries (registration and `define`
have no guard input per current SPEC; users add the key by editing the TOML).
`generate_missing_structural_salts` copies `def.trailing_run_guard` (as
`u64`) into the entry — this is what makes CLI `init` emit a guarded GCP
entry, satisfying the SHOULD in SPEC §Built-in Family Patterns.

## Unit tests (secrets_file.rs `mod tests`)

- Round-trip: entry with `trailing_run_guard: Some(2048)` survives
  serialize → deserialize → `to_patterns`, and the resulting
  `Pattern.trailing_run_guard == Some(2048)`.
- Absent field deserializes to `None` (backward compatibility with existing
  v3 files — no version bump; field is optional and additive).
- Guard on all-literal pattern (TOML fixture) → `deserialize` errors with
  message containing "trailing_run_guard requires at least one variable
  segment".
- `trailing_run_guard = 0` rejected.
- `generate_missing_structural_salts` output: gcp entry has
  `trailing_run_guard == Some(2048)`; anthropic entry has `None`.
- Serialized TOML for an unguarded pattern contains no `trailing_run_guard`
  key (skip_serializing_if — keeps existing files byte-stable modulo salts).

## Acceptance criteria

- All unit tests above pass; existing secrets_file tests green (entry count
  assertions at secrets_file.rs:384/424 unchanged — no new builtins added).
- `cargo nextest run --lib -p doppel` passes.
- `secrets-example.toml` untouched in this step (docs sweep is step-05).
