# Step 06: spec-invariant, integration, and CLI tests (VC 21/26/27/28, items 45/49/51)

## Context

### Overall Objective
The amended SPEC contract (items 45/49/51, VC 21/26/27/28) must be encoded in
external spec-invariant tests — these are the non-negotiable gate for the fix.

### Phase Context
Wave 3 — all production surfaces (steps 02–05) exist; this step asserts the
full contract across lib spec, integration, and CLI process boundaries.

### This Step
Update the amended VC 21 test, add its explicit-charset counterpart, add VC
26/27/28 tests, add the backward-compat regression HANDOFF downside 7 demands,
and cover the CLI string surfaces flagged by the fact-check.

## Prerequisites
- Steps 03, 04, 05 complete.

## Files to Read Before Starting
- `doppel/tests/spec/inv_trailing_run_guard.rs` — existing naming/helper style; `test_vc21_guard_without_variable_segment_rejected_at_load` (~189), `test_guard_charset_is_last_variable_segment` (~127), `test_vc23_zero_guard_threshold_rejected_on_both_paths` (~379)
- `doppel/tests/integration/guard.rs` — GCP-context tests (~46, ~72)
- `doppel-cli/tests/cli_spec/inv_management.rs` — `test_define_rejects_unknown_charset` (~139) for CLI test style
- `SPEC.md` VC 21, 26, 27, 28; items 45, 49, 51; §Built-in Family Patterns GCP paragraph

## Implementation

All tests follow repo conventions: `// Spec: SPEC.md §...` file-header
comment style, quoted invariant text in the body, `test_vc{N}_...` names for
VC tests, plain-English names for invariant tests. No real secrets; synthetic
vectors only.

### Task 1: VC 21 (amended) — in inv_trailing_run_guard.rs
- Keep/adjust `test_vc21_guard_without_variable_segment_rejected_at_load`:
  guard + NO explicit charset + no variable segment → load error (unchanged
  semantics; update the quoted spec text to the amended wording).
- New `test_vc21_guard_with_explicit_charset_loads_without_variable_segment`:
  same pattern shape (literal + opaque, zero variable segments) + guard +
  `trailing_run_guard_charset = "base64_any"` → loads successfully. Use an
  `opaque` segment (not all-literal) so the pattern is also swap-viable —
  the all-literal degenerate case is a known pathological config (item 51
  closing sentence), not what this test targets.

### Task 2: VC 26 — explicit charset governs, both directions
`test_vc26_explicit_guard_charset_overrides_segment_charset`, pattern with
last variable segment charset `url_safe_base64`, threshold e.g. 64:
- Direction A (broader-than-segment suppresses): explicit charset
  `base64_any`; trailing run = 64 bytes of `+` (member of declared, NOT of
  segment charset) → suppressed, no entry.
- Direction B (narrower-than-segment leaves standing): explicit charset
  `digits`; trailing run = 64 bytes of `a` (member of segment charset, NOT of
  declared) → match stands, entry produced.
Split into two `#[test]` fns if cleaner; both cite VC 26.

### Task 3: VC 27 — GCP shipped default suppresses standard base64
`test_vc27_gcp_default_suppresses_standard_base64_blob` (integration tier is
also acceptable — put it in `doppel/tests/integration/guard.rs` if it uses
the built-in constructor like the existing GCP tests there; spec tier if
loaded from a generated patterns file — prefer the patterns-file route since
it exercises the full emission+load chain):
- Payload: `AIza` + 35 url-safe chars, followed by ≥1024 bytes of
  deterministic standard-alphabet base64 filler that includes `+` and `/`
  characters well before position 1024 (e.g. repeat `Ab0+Cd1/` 129 times).
- Assert: `swap` returns the region unchanged, zero entries.
- Contrast assertion (root-cause proof): the same payload with fewer than
  1024 trailing bytes → replaced normally (guard still respects threshold).

### Task 4: VC 28 — charset-without-threshold rejected on both paths
`test_vc28_guard_charset_without_threshold_rejected_on_both_paths`, modeled
on `test_vc23_...`: patterns-file load with `trailing_run_guard_charset` but
no `trailing_run_guard` → clear error; `register_with_options` with
`trailing_run_guard_charset: Some("base64_any".into())` and
`trailing_run_guard: None` → clear error.

### Task 5: item 49/51 registration path
`test_inv49_registered_guard_uses_explicit_charset_when_supplied`: register
with threshold + `trailing_run_guard_charset: Some("base64_any".into())`, a
secret whose variable bytes are alphanumeric; `swap` with the secret followed
by ≥threshold bytes of `+/` mix → suppressed; followed by a `"` byte
immediately → replaced. (Counterpart of existing
`test_vc22_registered_guarded_secret_suppressed_and_replaced`.)

### Task 6: backward-compat regression (item 51 closing MUST, HANDOFF downside 7)
`test_guard_without_explicit_charset_behaves_identically_to_inference`:
- A guarded pattern WITHOUT the new field, loaded from TOML that omits
  `trailing_run_guard_charset`, produces byte-for-byte identical `swap`
  output (suppression and non-suppression cases) to the pre-change semantics:
  probe uses last-variable-segment charset. Assert both: url-safe trailing →
  suppressed at threshold; standard-base64 trailing containing `+` before
  threshold → NOT suppressed. (The existing
  `test_guard_charset_is_last_variable_segment` covers half; extend or add
  alongside, do not weaken it.)

### Task 7: CLI string-surface tests — in doppel-cli/tests/cli_spec/inv_management.rs
- `test_define_accepts_base64_any_charset`: `define` with
  `--segment variable:base64_any:35:35` exits 0 (guards `from_name`).
- Extend it (or a sibling test) to run `inspect` on the defined pattern and
  assert the entropy line is NOT `0.0 bits` (guards `charset_size`'s
  `_ => 0`); with min=max=35 and size 67 expect `212.` in the output
  (35 × log2(67) ≈ 212.3 — assert on the `212.` prefix, not exact float).

## Acceptance Criteria

- [ ] `cargo nextest run -p doppel --test spec` passes; lists the new `test_vc26_*`, `test_vc27_*` (if spec-tier), `test_vc28_*`, `test_vc21_guard_with_explicit_charset_*` tests
- [ ] `cargo nextest run -p doppel --test integration` passes
- [ ] `cargo nextest run -p doppel-cli --test cli_spec` passes including `test_define_accepts_base64_any_charset`
- [ ] No existing test weakened: `git diff doppel/tests/spec/inv_trailing_run_guard.rs` shows no deleted assertions except the VC-21 wording update
- [ ] Global gate passes

## Reviewer Instructions

1. For each of VC 21/26/27/28: locate the test, verify its assertions match the spec text verbatim intent (read the VC, read the test).
2. Verify VC 27's filler is standard-alphabet base64 containing `+`/`/` within the first 148 bytes after the match (the measured real-world url-safe run bound) — otherwise the test can't distinguish the fix from the old inferred behavior.
3. Verify the backward-compat test asserts BOTH suppression and non-suppression under inference.
4. Verify the CLI entropy assertion is against `inspect`/`define` output, not internal functions.
5. Run all three test-tier commands and the global gate.

## Rollback
`git revert` the step-06 commit (tests only; no production code).
