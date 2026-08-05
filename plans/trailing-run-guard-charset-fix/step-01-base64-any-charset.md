# Step 01: base64_any charset primitive

## Context

### Overall Objective
Fix the trailing-run-guard charset conflation: guards need a charset decoupled
from the match charset, and GCP needs a base64-union charset (`base64_any`) so
its guard fires against standard-alphabet base64 blobs (SPEC items 45/49/51).

### Phase Context
Wave 0 — the new charset is a prerequisite for every other step: the guard
field (step-02) stores a `CharsetName`, the TOML/registration paths (03/04)
parse its string name, and the CLI (05) reports its entropy.

### This Step
Add `CharsetName::Base64Any` and its concrete 67-byte charset. Cover all four
`segment.rs` surfaces — two are compile-checked (`resolve`, `as_str`), two are
wildcard-guarded and will fail silently if missed (`from_name`'s `_ => None`;
serde handles itself via `rename_all = "snake_case"`). Do NOT touch
`detect_charset_name` (locked decision: `Base64Any` is never auto-detected —
changing detection would alter fake derivation for existing `restrict_charset`
registrations and violate item 51's backward-compat MUST).

## Prerequisites
None.

## Files to Read Before Starting
- `doppel/src/segment.rs` lines ~160–215 — `CharsetName` enum, `resolve`, `from_name`, `as_str`, and the doc comment listing SPEC charset names
- `doppel/src/fake.rs` lines ~130–200 — existing `*_BYTES` statics, `Charset` statics, `*_ref()` accessors
- `SPEC.md` §Patterns File, "Valid charset names" paragraph — the normative 67-char definition

## Implementation

### Task 1: alphabet static in fake.rs
Add next to the existing byte statics:

```rust
static BASE64_ANY_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=";
```

Exactly 67 bytes, exactly this order (alphanumerics first, then `+ / - _ =`).
Order is part of fake-derivation determinism — never reorder. Add the
corresponding `pub(crate) static BASE64_ANY: LazyLock<Charset>` and
`pub(crate) fn base64_any_ref() -> &'static Charset`, matching the existing
pattern (e.g. `URL_SAFE_BASE64` / `url_safe_base64_ref`).

### Task 2: CharsetName variant + all match arms in segment.rs
- Add `Base64Any,` to the `CharsetName` enum (serde derives `"base64_any"`).
- `resolve()`: `CharsetName::Base64Any => crate::fake::base64_any_ref(),`
- `from_name()`: `"base64_any" => Some(CharsetName::Base64Any),` — this arm is
  NOT compile-enforced (`_ => None`); missing it silently breaks the
  TOML/define path.
- `as_str()`: `CharsetName::Base64Any => "base64_any",`
- Update the doc comment above the enum (lists SPEC charset names) to include
  `base64_any`.
- Leave `detect_charset_name` untouched.

### Task 3: unit tests (inline, segment.rs or fake.rs `#[cfg(test)]`)
- `CharsetName::from_name("base64_any") == Some(CharsetName::Base64Any)` and
  `CharsetName::Base64Any.as_str() == "base64_any"` (round-trip).
- `CharsetName::Base64Any.resolve().bytes.len() == 67`.
- Membership: bitmap contains all of `+ / - _ =` and `A z 0`; does not contain
  `b'\n'`, `b' '`, `b'"'`.

## Acceptance Criteria

- [ ] `cargo nextest run -p doppel --lib` passes, including the three new tests
- [ ] `grep -c base64_any doppel/src/segment.rs` ≥ 3 (from_name, as_str, doc comment)
- [ ] `detect_charset_name` diff is empty: `git diff doppel/src/segment.rs | grep -A5 detect_charset_name` shows no changes to that function
- [ ] Global gate: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo nextest run --workspace`

## Reviewer Instructions

1. Verify `BASE64_ANY_BYTES` is byte-for-byte `A–Za–z0–9+/-_=` and 67 long (count it).
2. Verify all four surfaces: enum variant, `resolve`, `from_name`, `as_str`.
3. Verify `detect_charset_name` is unchanged (`git diff`).
4. Run the global gate. Report PASS/FAIL per criterion.

## Rollback
`git revert` the step-01 commit; no other step depends on anything else yet.
