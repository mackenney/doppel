# Step 02: guard-charset field on Pattern/StructuralDef + swap resolution + GCP default

## Context

### Overall Objective
Explicit guard charset decoupled from the match charset (SPEC item 51), with
GCP shipping `base64_any` so its guard suppresses standard-base64 blobs.

### Phase Context
Wave 1 — the core field and its runtime resolution. Steps 03/04 (schema,
registration) wire external inputs into this field; they block on it.

### This Step
Add `trailing_run_guard_charset: Option<CharsetName>` to `StructuralDef` and
`Pattern` (doppel/src/patterns.rs), resolve it in `swap::guard_fires` with
explicit-wins/fallback-to-inference semantics, and set the GCP built-in's
guard charset to `Base64Any`.

## Prerequisites
- Step 01 complete (`CharsetName::Base64Any` exists).

## Files to Read Before Starting
- `doppel/src/patterns.rs` — `StructuralDef` (~line 21), `Pattern` (~line 766), `last_variable_charset` (~95, ~792), `GCP_DEF` (~284–293), the ~28 `*_DEF` statics and the ~28 `Pattern` build sites (~849–1183), test at ~1420
- `doppel/src/swap.rs` — `guard_fires` (~184–195), tie-break arm (~51), test helpers (~406, ~427)
- `SPEC.md` items 45, 51; §Built-in Family Patterns GCP paragraph

## Implementation

### Task 1: StructuralDef + Pattern fields
Add `pub(crate) trailing_run_guard_charset: Option<CharsetName>` to both
structs, adjacent to `trailing_run_guard`. Every `StructuralDef` literal and
every `Pattern` build site must set it:
- All built-ins except GCP: `trailing_run_guard_charset: None,`
- GCP (`GCP_DEF`): `trailing_run_guard_charset: Some(CharsetName::Base64Any),`
  — threshold stays `Some(GCP_TRAILING_RUN_GUARD)` (1024, unchanged).
- The ~28 `Pattern` constructors copy from their def:
  `trailing_run_guard_charset: X_DEF.trailing_run_guard_charset,`
- Any other `Pattern` construction sites in the crate (swap.rs test helpers
  ~406/~427, secrets.rs ~317, secrets_file.rs ~298 — the latter two get their
  real values in steps 03/04; set `None` here to keep the build green, with
  no comment markers).
- Add a doc comment on the field: explicit guard charset per SPEC item 51;
  `None` = infer from last variable segment.

### Task 2: guard_fires resolution in swap.rs
Current shape:

```rust
let Some(threshold) = pattern.trailing_run_guard else { return false; };
let Some(charset) = pattern.last_variable_charset() else { return false; };
```

Change the charset line to explicit-wins:

```rust
let Some(charset) = pattern
    .trailing_run_guard_charset
    .or_else(|| pattern.last_variable_charset())
else {
    return false;
};
```

Update `guard_fires`' doc comment (and the `last_variable_charset` doc
comment at patterns.rs:95 that says swap calls it directly) to describe the
resolution order. Do not touch the tie-break arm (items 46–48 are orthogonal).

### Task 3: tests
- Update patterns.rs test ~1420 (GCP builtin assertions): also assert
  `p.trailing_run_guard_charset == Some(CharsetName::Base64Any)`.
- New inline swap.rs unit test: pattern with variable charset
  `UrlSafeBase64`, explicit guard charset `Base64Any`, threshold small (e.g.
  32); payload = match + 32 bytes of `+` → suppressed (entry-less). Same
  pattern with explicit charset `None` → same payload NOT suppressed (`+` is
  not url-safe). This is the root-cause reproduction in miniature.

## Acceptance Criteria

- [ ] `cargo nextest run -p doppel --lib` passes, including the new suppression-contrast test
- [ ] `grep -n "trailing_run_guard_charset: Some(CharsetName::Base64Any)" doppel/src/patterns.rs` → exactly 1 hit (GCP def)
- [ ] `cargo nextest run -p doppel --test spec` — all existing guard invariant tests still green (backward compat: `None` field is behaviorally identical)
- [ ] Global gate passes

## Reviewer Instructions

1. Confirm GCP is the only def with an explicit guard charset and its threshold is unchanged (1024).
2. Confirm `guard_fires` resolution is `explicit.or_else(inferred)` — not the reverse.
3. Confirm the contrast unit test proves both directions (suppressed with Base64Any, not suppressed with inferred url-safe).
4. Run `cargo nextest run -p doppel --test spec` and the global gate.

## Rollback
`git revert` the step-02 commit; steps 03/04 must also be reverted if already applied.
