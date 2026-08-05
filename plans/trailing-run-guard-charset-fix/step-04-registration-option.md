# Step 04: SecretOptions.trailing_run_guard_charset (registration parity)

## Context

### Overall Objective
Explicit guard charset per SPEC item 51; registration must accept it for
parity (amended item 49) even though no CLI flag is exposed (deferred per
SPEC §Registration Options).

### Phase Context
Wave 2 (parallel with steps 03/05). This step owns `doppel/src/secrets.rs`
and one additional line-range in `doppel-cli/src/main.rs` (~332–338): the
`SecretOptions` struct literal in the `register` command handler is
exhaustive (no `..Default::default()`), so adding a field to `SecretOptions`
requires a one-line addition there too (fact-check R1). This region is
disjoint from step-05's `main.rs` regions (`charset_size` ~572–582, Define
`long_about`/`long_help` ~103/~117, init template ~162) — no line overlap,
so the two steps remain genuinely parallel, but **both diffs land in the
same file**: the executor/reviewer must apply and merge both patches to
`main.rs` (e.g. sequential `git apply`/rebase of whichever commit lands
second) rather than one clobbering the other.

### This Step
Add the option to `SecretOptions`, validate it (unrecognised name; charset-
without-threshold), and wire it into the produced `Pattern`.

## Prerequisites
- Step 02 complete (`Pattern.trailing_run_guard_charset` exists).

## Files to Read Before Starting
- `doppel/src/secrets.rs` — `SecretOptions` (~26–70), `SecretError` (~77–120), validation block (~200–215), Pattern construction (~317), existing guard tests (~390–436)
- `doppel-cli/src/main.rs` — `SecretOptions` struct-literal construction in the `register` handler (~332–338); confirm it is still an exhaustive field-by-field literal (no `..Default::default()`) before editing
- `SPEC.md` §Registration Options (`trailing-run-guard-charset` bullet), items 49/51, VC 28

## Implementation

### Task 1: option field
`pub trailing_run_guard_charset: Option<String>` on `SecretOptions`
(default `None` in the `Default` impl). Doc comment: explicit guard charset
name per SPEC §Registration Options; requires `trailing_run_guard`; not
CLI-exposed. String-typed because `CharsetName` is `pub(crate)` (locked
decision — do not make `CharsetName` public).

### Task 2: validation in register_with_options (~200 area, alongside the Some(0) check)
1. `trailing_run_guard_charset.is_some() && trailing_run_guard.is_none()` →
   new `SecretError` variant, e.g.
   `GuardCharsetWithoutGuard` — `#[error("trailing_run_guard_charset requires trailing_run_guard")]`.
2. Present → `CharsetName::from_name`; unrecognised → new variant, e.g.
   `UnknownGuardCharset { name: String }` —
   `#[error("unknown trailing_run_guard_charset \"{name}\"")]`.
   (`SecretError` is `#[non_exhaustive]`-style additive; follow the existing
   variant/doc style. Error messages must not echo secret bytes — they don't:
   only the charset name.)
3. Update the `register_with_options` doc-comment error list (~165).

### Task 3: wiring
At the Pattern construction (~317):
`trailing_run_guard_charset: parsed_charset` (the validated
`Option<CharsetName>`; `None` preserves inference — item 49's "unless the
explicit guard-charset option is supplied").

### Task 4: inline tests
- charset without threshold → `GuardCharsetWithoutGuard`.
- `Some("bogus")` + threshold → `UnknownGuardCharset` and the message names `bogus`.
- threshold + `Some("base64_any")` → `pattern.trailing_run_guard_charset == Some(CharsetName::Base64Any)`.
- default options → field `None` on the produced Pattern (extend
  `test_default_options_have_no_trailing_run_guard`).

### Task 5: main.rs struct-literal fix (cross-file, required for this step's own gate)
The `register` command handler in `doppel-cli/src/main.rs` (~332–338)
constructs `SecretOptions` as an exhaustive struct literal:
```rust
let opts = SecretOptions {
    anchor_len,
    tail_anchor_len,
    restrict_charset,
    trailing_run_guard,
    force,
};
```
Adding the 6th field to `SecretOptions` makes this a compile error (E0063)
in `doppel-cli`, which this step's own global gate (`cargo clippy
--workspace`, `cargo nextest run --workspace`) cannot pass without touching
it. Add `trailing_run_guard_charset: None,` as a new line inside the
literal (CLI has no `--trailing-run-guard-charset` flag, so this is always
`None` — deferred per SPEC §Registration Options). Do not switch to
`..SecretOptions::default()` — keep the explicit field-by-field style
already used at this call site; this is a single-line addition, not a
restyle. Do not add a CLI flag, help text, or any other change at this
site — this task is scoped to the one struct-literal field.

## Acceptance Criteria

- [ ] `cargo nextest run -p doppel --lib` passes including the four new/extended tests
- [ ] `grep -n "trailing_run_guard_charset: None," doppel-cli/src/main.rs` → exactly 1 hit, inside the `register` handler's `SecretOptions` literal (~332–338)
- [ ] `grep -c -- '--trailing-run-guard-charset' doppel-cli/src/main.rs` → 0 (confirms the main.rs edit is the struct-literal field only, not a new CLI flag)
- [ ] Global gate passes

## Reviewer Instructions

1. Verify both error paths precede Pattern construction (no partially-built state).
2. Verify the produced Pattern carries the parsed charset and default stays `None`.
3. Verify no CLI flag was added — the only `main.rs` change is the single
   `trailing_run_guard_charset: None,` line in the `register` handler's
   `SecretOptions` literal (~332–338); no help text, no `long`/`short` clap
   attribute, no new match arm.
4. Run the global gate.

## Rollback
`git revert` the step-04 commit; independent of step 03. Shares
`doppel-cli/src/main.rs` with step-05 in disjoint line regions (~332–338 vs
~103/~117/~162/~572–582) — reverting step-04 alone is safe as long as
step-05's separate hunks in the same file are unaffected; if both commits
landed, revert with `git revert` (not `git checkout --`) to avoid clobbering
step-05's hunks.
