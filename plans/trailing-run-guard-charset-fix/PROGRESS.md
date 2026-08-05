# PROGRESS.md — trailing-run-guard-charset-fix

## Status

Queued

## Objective

Fix the trailing-run-guard charset conflation per the amended SPEC.md: add an
explicit, optional guard charset (`trailing_run_guard_charset`) decoupled from
the last-`variable`-segment inference, add the `base64_any` charset (67-char
union of standard + url-safe base64 alphabets plus `=` padding), and set the
built-in GCP pattern's guard charset explicitly to `base64_any` so its guard
actually suppresses the standard-alphabet base64 blobs that motivate it
(HANDOFF.md: 8/3 real-corpus false positives currently suppressed by *zero*
threshold values).

## Binding contract

`SPEC.md` (already amended, uncommitted — commit it with this plan):
- §Trailing Run Guard, Charset resolution (explicit-declaration paragraph + rationale)
- §Built-in Family Patterns (GCP guard charset MUST be `base64_any` when guarded)
- §Registration Options (`trailing-run-guard-charset` bullet; CLI flag deliberately NOT exposed)
- §Patterns File (`trailing_run_guard_charset` field; `base64_any` in valid charset names)
- Behavioral Invariants 45 (amended), 49 (amended), 51 (new)
- Verifiable Conditions 21 (amended), 26, 27, 28 (new)
- Known Limitations (line-wrapped/MIME base64 bullet)

Companion context: `HANDOFF.md` (root cause + empirical proof),
`artifacts/fact-checks/trailing-run-guard-specifier-factcheck.md` (silently-
failing string-keyed surfaces that Rust exhaustiveness will NOT catch).

## Waves

| Wave | Steps | Can Parallelize | Depends On |
|------|-------|-----------------|------------|
| 0 | step-01 (base64_any charset primitive) | — | — |
| 1 | step-02 (guard-charset field: Pattern/StructuralDef/swap + GCP default) | — | Wave 0 |
| 2 | step-03 (patterns-file schema + load validation), step-04 (registration option), step-05 (CLI string surfaces) | Yes — 03 is fully disjoint (`secrets_file.rs`); 04 and 05 both touch `doppel-cli/src/main.rs` but in disjoint line ranges (04: ~332–338 `SecretOptions` literal only; 05: ~103/~117/~162/~572–582 string tables/help) — genuinely parallel, but the executor must apply/merge both `main.rs` diffs without either clobbering the other | Wave 1 (03, 04); Wave 0 only (05) |
| 3 | step-06 (spec-invariant + integration + CLI tests) | — | Wave 2 |
| 4 | step-07 (empirical corpus validation, docs, full gate) | — | Wave 3 |

## Dependency Table

| Step | File(s) | Depends On | Depended By |
|------|---------|------------|-------------|
| step-01 | doppel/src/segment.rs, doppel/src/fake.rs | — | 02, 03, 04, 05 |
| step-02 | doppel/src/patterns.rs, doppel/src/swap.rs | step-01 | 03, 04, 06 |
| step-03 | doppel/src/secrets_file.rs, doppel/src/segment.rs (validate_segment_defs signature) | step-02 | 06 |
| step-04 | doppel/src/secrets.rs, doppel-cli/src/main.rs (~332–338 struct-literal field only) | step-02 | 06 |
| step-05 | doppel-cli/src/main.rs (~103/~117/~162/~572–582 — disjoint from step-04's ~332–338) | step-01 | 06 |
| step-06 | doppel/tests/spec/inv_trailing_run_guard.rs, doppel/tests/integration/guard.rs, doppel-cli/tests/cli_spec/inv_management.rs | 03, 04, 05 | 07 |
| step-07 | secrets-example.toml, CHANGELOG.md, validation only | step-06 | — |

## Key design decisions (locked — do not re-decide)

- **Charset name and shape:** `CharsetName::Base64Any`, serde/string name
  `base64_any` (fact-check confirmed serde `rename_all = "snake_case"` gives
  this for free). Alphabet is exactly 67 bytes in this order:
  `A–Z`, `a–z`, `0–9`, `+`, `/`, `-`, `_`, `=` (alphanumerics first, then
  specials — matches existing `URL_SAFE_BASE64_BYTES` style; order is part of
  fake-derivation determinism, never reorder once committed).
- **General-purpose charset:** `base64_any` is valid wherever a charset name
  is accepted (variable/opaque segments and the guard field) — SPEC §Patterns
  File makes this normative.
- **`detect_charset_name` unchanged:** `Base64Any` is never auto-detected.
  Adding it to the minimal-cover chain would change fake derivation for
  existing `restrict_charset` registrations (bytes with `+` currently map to
  `Wide`), violating item 51's "identical to inferred behavior" MUST. The
  spec is silent on detection; explicit-only is the backward-compatible
  reading.
- **Field shape (flat, per HANDOFF open question 5):**
  - `Pattern` / `StructuralDef` (patterns.rs): `trailing_run_guard_charset: Option<CharsetName>` next to `trailing_run_guard: Option<usize>`.
  - `PatternEntry` (secrets_file.rs, TOML): `trailing_run_guard_charset: Option<String>`, validated at load via `CharsetName::from_name` (same pattern as `SegmentDef` charset strings).
  - `SecretOptions` (secrets.rs, public API): `trailing_run_guard_charset: Option<String>` — `CharsetName` stays `pub(crate)`; string keeps Pattern opacity and matches SPEC's "valid charset name / unrecognised name MUST fail" wording.
- **Guard resolution (swap.rs `guard_fires`):** explicit field wins, inference
  is the fallback: `pattern.trailing_run_guard_charset.or_else(|| pattern.last_variable_charset())`.
- **Validation matrix (load + registration):**
  - charset present, threshold absent → hard error (item 51, VC 28).
  - unrecognised charset name → hard error (SPEC §Registration Options / §Patterns File).
  - guard + no explicit charset + no variable segment → hard error, unchanged (item 45, VC 21 first half).
  - guard + explicit charset + no variable segment → **accepted at load** (item 51, VC 21 second half). `validate_segment_defs` gets an explicit allow flag; only the secrets_file.rs load paths pass `true` when guard+charset are both present. `define` / `add_structural_entry` stay strict (SPEC §define MUST-fail is unchanged; load-vs-define asymmetry is deliberate per fact-check).
- **CLI:** NO new `register`/`define` flag for the guard charset — explicitly
  deferred by SPEC §Registration Options. Only the three silently-failing
  string surfaces change: `charset_size` (`base64_any` → 67), the two `Define`
  help texts, and the `init` template comment. These are NOT compile-checked
  (fact-check claim 5b) and MUST each get a test.
- **GCP built-in:** `trailing_run_guard_charset: Some(CharsetName::Base64Any)`
  with threshold unchanged at `GCP_TRAILING_RUN_GUARD = 1024`. Match charset
  stays `UrlSafeBase64` — detection precision untouched.
- **No `secrets.rs` entropy-table change:** fact-check verified the size is
  derived via `resolve().bytes.len()`; only the `(Wide, 92)` hardcode exists.

## Executor Protocol

1. **On plan start:** move this plan from Queued → In Progress in
   `MASTER_PROGRESS.md`; commit the (currently uncommitted) SPEC.md amendment,
   this plan directory, and the MASTER_PROGRESS.md update together as the
   first commit.
2. Read this file to identify the current wave; dispatch all steps in the
   wave (wave 2 steps are genuinely parallel: 03 is file-disjoint; 04 and 05
   both touch `doppel-cli/src/main.rs` in disjoint line ranges — apply/merge
   both diffs to that file rather than letting one clobber the other).
3. After each step: run the step's acceptance criteria verbatim, then the
   global gate (below). Mark the step complete only when both pass.
4. Advance to the next wave only when all steps in the current wave are done.
5. Blockers: stop and report with full context.
6. **On plan completion:** delete `HANDOFF.md` (it says so itself), delete
   this plan directory, move the MASTER_PROGRESS.md entry to Completed with
   the final commit hash — all in the completion commit.

## Global gate (every step, non-negotiable)

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

## Subagent Contract

- Workers: read the step file fully before acting; implement only what it specifies.
- Workers: commit with message `step-NN: <name>`.
- Workers: report "Step NN complete (commit <hash>)" or "Step NN FAILED: <reason>".
- Reviewers: run acceptance criteria commands verbatim; pass/fail with specifics.

## Steps

- [ ] [step-01-base64-any-charset.md](./step-01-base64-any-charset.md) — `CharsetName::Base64Any` variant + 67-byte alphabet, all four segment.rs surfaces, fake.rs static
- [ ] [step-02-guard-charset-field-core.md](./step-02-guard-charset-field-core.md) — `trailing_run_guard_charset` on StructuralDef/Pattern, guard_fires resolution, GCP default `base64_any`
- [ ] [step-03-patterns-file-schema.md](./step-03-patterns-file-schema.md) — TOML field, load validation matrix, item-51 variable-segment relaxation, builtin-emission wiring
- [ ] [step-04-registration-option.md](./step-04-registration-option.md) — `SecretOptions.trailing_run_guard_charset` + registration validation (item 49/51)
- [ ] [step-05-cli-string-surfaces.md](./step-05-cli-string-surfaces.md) — CLI `charset_size` 67, Define help texts, init template comment (no new flags)
- [ ] [step-06-spec-invariant-tests.md](./step-06-spec-invariant-tests.md) — VC 21 (amended)/26/27/28 tests, backward-compat regression, CLI string-surface tests
- [ ] [step-07-empirical-validation-docs.md](./step-07-empirical-validation-docs.md) — real/synthetic standard-base64 corpus validation at GCP defaults, example file, CHANGELOG, final sweep

## Open Decisions

None. All HANDOFF open questions were resolved by the SPEC amendment
(fact-checked, zero refuted claims); judgment calls above are locked.
