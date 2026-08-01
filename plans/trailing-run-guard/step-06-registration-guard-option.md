# Step 06 — Registration-path guard option (SecretOptions), API docs, README

Depends on: step-01. Parallelizable with step-02 and step-03.

Covers the specifier addendum that closed the INV-45 registration gap:
SPEC §Registration Options (new **trailing-run-guard** bullet), amended
INV-45, new INV-49, VC-22/VC-23. Tests land in step-04; this step is the
API surface + docs.

## Context

- `SecretOptions`: `doppel/src/secrets.rs:21` — fields `anchor_len`,
  `tail_anchor_len`, `restrict_charset`, `force`; `Default` impl at
  secrets.rs:43. Doc-comment convention: first line is a short contract
  sentence with the default in parens; follow-up lines give validation
  rules and trade-offs (see `anchor_len` at secrets.rs:22-28).
- `SecretError`: secrets.rs:57, `#[non_exhaustive]` — adding a variant is
  non-breaking.
- `register_with_options_rng`: secrets.rs:155 — the funnel for all
  registration entry points. It always emits
  `[Opaque(head), Variable(middle), (optional Opaque tail)]`; the
  `Variable` segment is unconditional (a consumed middle fails earlier with
  `NoVariableBytes`). Therefore the no-variable-segment rejection of
  INV-45 is **structurally unreachable at registration** — per SPEC
  §Registration Options and INV-49, the only registration-time guard
  validation is positivity. Do not add a variable-segment check here.
- `Pattern.trailing_run_guard` field exists after step-01 (step-01 leaves
  registration setting `None`; this step wires the real value).
- README.md lines ~70-86: registration example with a full
  `SecretOptions` struct literal enumerating every field, followed by a
  prose paragraph listing the knobs. Both must stay complete.

## Changes

### 1. `SecretOptions.trailing_run_guard`

Add after `restrict_charset` (secrets.rs:36), mirroring the established
doc style:

```rust
/// Optional trailing run guard threshold in bytes (default `None` — no guard).
///
/// When set, the produced Pattern declares a trailing run guard (SPEC
/// §Trailing Run Guard): a winning match followed by at least this many
/// consecutive guard-charset bytes is suppressed as a likely slice of an
/// encoded blob. The guard charset is the Pattern's single `variable`
/// segment charset — wide by default, or the detected charset when
/// `restrict_charset` is true. Must be positive; zero is rejected with
/// [`SecretError::ZeroTrailingRunGuard`]. Registered patterns are
/// HMAC-gated, so the guard suppresses only genuine occurrences of the
/// secret embedded directly in same-charset runs — leave `None` unless
/// that trade-off is intended.
pub trailing_run_guard: Option<usize>,
```

`Default::default()` sets `trailing_run_guard: None`.

### 2. Positivity validation + error variant

New `SecretError` variant (message prefix kept identical to step-03's
load-path message so both paths read consistently):

```rust
/// `trailing_run_guard` is zero — the guard threshold must be a positive byte count.
#[error("trailing_run_guard must be a positive integer (got 0)")]
ZeroTrailingRunGuard,
```

In `register_with_options_rng`, alongside the existing `anchor_len`
up-front checks (secrets.rs:160-176):

```rust
if opts.trailing_run_guard == Some(0) {
    return Err(SecretError::ZeroTrailingRunGuard);
}
```

No other guard validation: no variable-segment check (unreachable, see
Context) and no threshold-vs-secret-length relation (the probe examines
bytes *after* the match end; the threshold has no structural relationship
to the secret's own length).

### 3. Wire into the produced Pattern

The `Pattern` construction in `register_with_options_rng` sets
`trailing_run_guard: opts.trailing_run_guard` — replacing the `None`
placeholder step-01 put there.

### 4. Doc-comment coherence sweep (registration API)

- `register` doc (secrets.rs:107-125): the pointer sentence "See
  [`register_with_options`] to customise anchor lengths, charset
  restriction, or force." gains the trailing run guard (e.g. "…charset
  restriction, a trailing run guard, or force.").
- `register_with_options` doc (secrets.rs:130-140): add to the `# Errors`
  list: `- [`SecretError::ZeroTrailingRunGuard`] if `trailing_run_guard`
  is `Some(0)`.`
- Neither `secrets.rs` nor `lib.rs` has a module/crate-level enumeration
  of registration options (verified) — no other doc site to update.

### 5. README.md

- Registration example (README.md:75-80): add a field line to the struct
  literal, e.g. `trailing_run_guard: None, // opt-in suppression near
  large same-charset blobs` — keep the field list exhaustive as it is
  today.
- Prose paragraph (README.md:83-86): extend the knob enumeration with the
  optional trailing run guard (one clause; cross-reference the guard
  concept where the README first explains it, if step-05's sweep adds
  such a mention).
- CLI `register` section (README.md:260-277): **no change.** SPEC's CLI
  Contract was deliberately not amended — there is no `--trailing-run-guard`
  flag. Do not invent one or document one.
- No doppel-cli README exists (verified); `docs/for-the-paranoid.md`
  describes stored-entry anatomy and fake derivation only — the guard does
  not alter the stored entry beyond the optional TOML key already covered
  by step-03/step-05; no update needed there.

## Inline unit tests (secrets.rs `mod tests`, seeded RNG per convention)

- `register_with_options_rng` with `trailing_run_guard: Some(0)` →
  `Err(SecretError::ZeroTrailingRunGuard)`.
- `Some(2048)` → `Ok`, and `pattern.trailing_run_guard == Some(2048)`
  (field is `pub(crate)`, visible to inline tests).
- Default options → `pattern.trailing_run_guard == None`.
- `restrict_charset: true` + guard → produced Pattern's
  `last_variable_charset()` equals the detected charset (guard charset
  follows the effective charset per SPEC §Registration Options).

## Acceptance criteria

- `cargo build --workspace` passes; `SecretOptions` literal updates in any
  existing tests/examples compile (struct has no `#[non_exhaustive]`, so
  exhaustive literals in this repo must all gain the field or use
  `..Default::default()` — existing tests already use the latter).
- All four inline tests above pass; `cargo nextest run --lib -p doppel`
  green.
- `cargo test --doc -p doppel` passes (register/register_with_options
  doctests still compile).
- README registration example lists every `SecretOptions` field including
  `trailing_run_guard`; CLI register section diff is empty.
