# Step 03: patterns-file schema, load validation matrix, item-51 relaxation

## Context

### Overall Objective
Explicit guard charset per SPEC item 51; this step makes it authorable in the
patterns TOML and enforces the full load-time validation matrix.

### Phase Context
Wave 2 (parallel with steps 04/05 — this step owns `secrets_file.rs` plus the
`validate_segment_defs` signature in `segment.rs`; no file overlap with them).

### This Step
Add `trailing_run_guard_charset` to `PatternEntry`, validate it on every load
path (unrecognised name; charset-without-threshold; relaxed variable-segment
requirement when explicit charset is present), and wire it through
load→`Pattern`, `Pattern`→entry save, and builtin emission so GCP's
`base64_any` reaches generated patterns files.

## Prerequisites
- Step 02 complete (`Pattern.trailing_run_guard_charset` exists).

## Files to Read Before Starting
- `doppel/src/secrets_file.rs` — `PatternEntry` (~47), the two load-path validation blocks (~146–181 and ~216–248), entry→Pattern conversion (~283–298), Pattern→entry (~339), `add_structural_entry` (~394), `generate_missing_structural_salts` (~429), guard round-trip test (~632)
- `doppel/src/segment.rs` — `validate_segment_defs` (~295–305, `NoVariableSegment`)
- `SPEC.md` §Patterns File (`trailing_run_guard_charset` bullet), items 45/51, VC 21/28
- Fact-check report §"For the planner" item 1 (three `validate_segment_defs` call sites; keep define strict)

## Implementation

### Task 1: PatternEntry field
`pub trailing_run_guard_charset: Option<String>` with
`#[serde(default, skip_serializing_if = "Option::is_none")]` (match how
`trailing_run_guard: Option<u64>` is declared — keep serialization absent when
`None` so existing files and their hashes/diffs are untouched). Update every
`PatternEntry` literal in the crate (several test fixtures ~406/533/594/621/650:
`None`). This also includes fixtures at ~334 (`add_secret_pattern` path) and
~717-726 (`test_trailing_run_guard_zero_rejected_in_to_patterns`) — not
exhaustively enumerated above, but the compiler catches every miss as an
E0063 missing-field error, so no fixture can be silently skipped.

### Task 2: load validation matrix (both load-path blocks, ~146 and ~216)
In each block, in this order:
1. If `entry.trailing_run_guard_charset.is_some() && entry.trailing_run_guard.is_none()`
   → `InvalidSegment` error, reason
   `"trailing_run_guard_charset requires trailing_run_guard"` (item 51, VC 28).
2. If present, parse with `CharsetName::from_name`; unrecognised →
   `InvalidSegment` error naming the bad value (SPEC: "unrecognised name MUST
   fail with a clear error").
3. The existing "trailing_run_guard requires at least one variable segment"
   rejection now applies **only when `trailing_run_guard_charset` is absent**
   (amended item 45 / item 51 acceptance).

### Task 3: relax validate_segment_defs for the guarded+explicit-charset load case
`validate_segment_defs` unconditionally errors `NoVariableSegment`; it is
called from three sites in secrets_file.rs (~175, ~248, ~394). Change the
signature to take an explicit flag, e.g.
`validate_segment_defs(defs: &[SegmentDef], allow_no_variable: bool)`, which
skips only the `NoVariableSegment` check (all other checks — unknown charset,
empty values, etc. — always run). Call sites:
- the two load paths pass
  `entry.trailing_run_guard.is_some() && entry.trailing_run_guard_charset.is_some()`
- `add_structural_entry` (~394) passes `false` — `define` stays strict per
  SPEC §define (load-vs-define asymmetry is deliberate).
Fix any other callers the compiler surfaces the same way (`false` unless the
spec says otherwise).

### Task 4: conversions
- Load (~283–298): parsed `CharsetName` → `Pattern.trailing_run_guard_charset`.
- Save (~339): `pattern.trailing_run_guard_charset.map(|c| c.as_str().to_string())`.
- `generate_missing_structural_salts` (~429): copy
  `def.trailing_run_guard_charset.map(|c| c.as_str().to_string())` — this is
  what puts `trailing_run_guard_charset = "base64_any"` in GCP's emitted entry.

### Task 5: inline tests (secrets_file.rs `#[cfg(test)]`)
- Round-trip: entry with guard 1024 + charset `"base64_any"` survives
  serialize→deserialize→load and the loaded `Pattern` has
  `Some(CharsetName::Base64Any)`.
- Absent field serializes to TOML with **no** `trailing_run_guard_charset`
  key (assert on the serialized string).
- charset-without-threshold → load error (message contains
  `trailing_run_guard_charset`).
- `trailing_run_guard_charset = "bogus"` → load error naming `bogus`.
- guard + explicit charset + zero variable segments (literal+opaque) → loads OK.
- guard + NO explicit charset + zero variable segments → still rejected.
- Builtin emission: `generate_missing_structural_salts` output's `gcp` entry
  has `trailing_run_guard_charset == Some("base64_any".into())`.

## Acceptance Criteria

- [ ] `cargo nextest run -p doppel --lib` passes including all seven new tests
- [ ] `cargo nextest run -p doppel --test spec` — existing `test_vc21_guard_without_variable_segment_rejected_at_load` still green (no explicit charset ⇒ rejection preserved)
- [ ] `grep -n "allow_no_variable" doppel/src/segment.rs doppel/src/secrets_file.rs` shows the flag threaded to all three call sites, with `add_structural_entry` passing `false`
- [ ] Global gate passes

## Reviewer Instructions

1. Verify the validation order: charset-without-threshold fires even when the charset name is also bogus (threshold-missing error wins or both are clear errors — either is fine, but the VC-28 case must error).
2. Verify only `NoVariableSegment` is gated by the flag — no other check weakened.
3. Verify `add_structural_entry` still rejects no-variable segment lists.
4. Verify absent-field TOML output byte-identical to pre-change output for an unguarded entry.
5. Run the global gate.

## Rollback
`git revert` the step-03 commit; independent of steps 04/05.
