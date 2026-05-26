# Step 07: Drop `OnceLock` from `Tier1Def` — Plain Salt Field, `Pattern::Tier1` by Value

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose
CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 3 (parallel with step-06). This step makes `Tier1Def` a plain, owned, Copy struct by
replacing the `OnceLock<[u8; 32]>` salt field with a regular `[u8; 32]`. The `Pattern::Tier1`
variant changes from `&'static Tier1Def` (reference into a global) to `Tier1Def` (owned
copy). The 8 static definitions become pure templates with `salt: [0u8; 32]`; callers supply
the real salt when constructing a Pattern. `patterns::all()` and friends are updated to
generate an ephemeral random salt per call (stable within a single `Vec<Pattern>` instance,
but non-persistent across restarts). The persistent, cross-restart path is
`PatternsFile::into_patterns()`, added in step-08.

### This Step
Gut `Tier1Def`'s `OnceLock`, make it `Copy`, change the `Pattern::Tier1` variant to hold a
by-value `Tier1Def`, remove `get_salt()` (callers use `def.salt` directly), update
`patterns::*` convenience functions, and update all callers in `scrub.rs`. External tests
continue to pass because `patterns::all()` still works — it just produces ephemeral salts.
No `init_salt()`, no `init_test_salts()` needed.

## Prerequisites
- Step 05 complete (`scrub.rs` already updated to handle the new `find_best_match` signature
  and `PatternRef` usage — this step changes `def.get_salt()` to `def.salt` in
  `generate_fake_for_match`)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier1.rs` — full file; understand `Tier1Def`, static
  instances, `Pattern` enum, `patterns::*` functions
- `/home/ignacio/pr/its-classified/src/scrub.rs` — `generate_fake_for_match` (line 55–73);
  `PatternRef::Tier1` arm; any other reference to `def.get_salt()`
- `/home/ignacio/pr/its-classified/src/lib.rs` — doc example uses `patterns::all()`; update
  the quick-start example to note the ephemeral-salt caveat

## Implementation

### Task 1: Replace `OnceLock` salt field with plain `[u8; 32]`

In `src/tier1.rs`, make these changes to the `Tier1Def` struct (lines 7–25):

**Remove** the `use std::sync::OnceLock;` import at line 1.

**Change** the struct definition:

```rust
// Before
pub struct Tier1Def {
    pub(crate) prefix: &'static [u8],
    pub(crate) charset: fn() -> Vec<u8>,
    pub(crate) min_len: usize,
    pub(crate) max_len: usize,
    pub(crate) salt: OnceLock<[u8; 32]>,
}

// After
#[derive(Clone, Copy)]
pub struct Tier1Def {
    pub(crate) identifier: &'static str,   // added in step-04
    pub(crate) prefix: &'static [u8],
    pub(crate) charset: fn() -> Vec<u8>,
    pub(crate) min_len: usize,
    pub(crate) max_len: usize,
    pub(crate) salt: [u8; 32],
}
```

Note: `identifier` was added in step-04 (Wave 1). Include it here; if step-04 has not landed
yet due to ordering, add it as part of this step instead.

**Remove** the entire `impl Tier1Def { fn get_salt ... }` block (lines 27–35). Internal
callers access `def.salt` directly.

### Task 2: Update all 8 static `Tier1Def` instances

In `src/tier1.rs` lines 64–127, replace `salt: OnceLock::new()` with `salt: [0u8; 32]` in
every static definition. The zero salt is a sentinel — these statics are used as struct-update
templates only; `PatternsFile::into_patterns()` constructs real `Tier1Def` values with the
caller-supplied salt. Example:

```rust
pub(crate) static ANTHROPIC_DEF: Tier1Def = Tier1Def {
    identifier: "anthropic",
    prefix: b"sk-ant-",
    charset: charsets::url_safe_base64,
    min_len: 80,
    max_len: 120,
    salt: [0u8; 32],
};
```

Apply the same `salt: [0u8; 32]` change to all 8 static instances.

### Task 3: Change `Pattern::Tier1` variant to by-value

In `src/tier1.rs`, locate the `Pattern` enum (line 135):

```rust
// Before
pub enum Pattern {
    Tier1(&'static Tier1Def),
    Tier2(Arc<Tier2Pat>),
}

// After
pub enum Pattern {
    Tier1(Tier1Def),
    Tier2(Arc<Tier2Pat>),
}
```

`Pattern` already derives `Clone`. With `Tier1Def: Copy`, `Pattern::Tier1(Tier1Def)` is
`Clone` (copy semantics for the Tier1 variant). No other derive changes needed.

### Task 4: Update `patterns::*` convenience functions

In `src/tier1.rs`, the `patterns` module (lines 141–186) constructs `Pattern::Tier1` values.
Each function must now supply a real salt. Use `OsRng` to generate a fresh random salt per
call. This preserves the existing behavior (ephemeral, process-local stability) while the
struct no longer holds interior mutability:

```rust
pub mod patterns {
    use rand::RngCore;
    use rand::rngs::OsRng;
    use super::*;

    fn random_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Returns an Anthropic key pattern with an ephemeral salt.
    ///
    /// Fakes are stable for the lifetime of the returned `Pattern` value but differ
    /// across calls and process restarts. For cross-restart stability, use
    /// `PatternsFile::into_patterns()`.
    pub fn anthropic() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..ANTHROPIC_DEF })
    }

    pub fn openai_classic() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..OPENAI_CLASSIC_DEF })
    }

    pub fn openai_project() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..OPENAI_PROJECT_DEF })
    }

    pub fn aws_akia() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..AWS_AKIA_DEF })
    }

    pub fn aws_asia() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..AWS_ASIA_DEF })
    }

    pub fn github_classic() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..GITHUB_CLASSIC_DEF })
    }

    pub fn github_fine_grained() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..GITHUB_FG_DEF })
    }

    pub fn gcp() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..GCP_DEF })
    }

    /// Returns all built-in Tier 1 patterns with ephemeral per-call salts.
    ///
    /// Fakes produced by these patterns are stable within the returned `Vec<Pattern>`
    /// instance but differ across calls to `all()` and across process restarts.
    /// For persistent cross-restart stability, use `PatternsFile::into_patterns()`.
    pub fn all() -> Vec<Pattern> {
        vec![
            anthropic(),
            openai_classic(),
            openai_project(),
            aws_akia(),
            aws_asia(),
            github_classic(),
            github_fine_grained(),
            gcp(),
        ]
    }
}
```

### Task 5: Add `all_defs()` helper (if not added in step-04)

If step-04 has not landed yet, add `all_defs()` here. It is needed by `PatternsFile`
(step-08) to enumerate the 8 templates:

```rust
/// Returns references to all 8 built-in Tier 1 definition templates.
/// Used by the patterns file loader to reconstruct `Pattern::Tier1` values with
/// caller-supplied salts.
pub(crate) fn all_defs() -> &'static [&'static Tier1Def] {
    &[
        &ANTHROPIC_DEF,
        &OPENAI_CLASSIC_DEF,
        &OPENAI_PROJECT_DEF,
        &AWS_AKIA_DEF,
        &AWS_ASIA_DEF,
        &GITHUB_CLASSIC_DEF,
        &GITHUB_FG_DEF,
        &GCP_DEF,
    ]
}
```

### Task 6: Update `scrub.rs` — replace `def.get_salt()` with `def.salt`

In `src/scrub.rs`, `generate_fake_for_match` (line 55), the `PatternRef::Tier1` arm calls
`def.get_salt()`. Change to `&def.salt`:

```rust
// Before
PatternRef::Tier1(def) => {
    derive_fake_tier1(def.get_salt(), def.prefix, &(def.charset)(), def.end - def.start, secret)
}

// After
PatternRef::Tier1(def) => {
    derive_fake_tier1(&def.salt, def.prefix, &(def.charset)(), def.end - def.start, secret)
}
```

Search for any other occurrence of `get_salt()` in the codebase and update similarly:
```sh
grep -rn "get_salt" /home/ignacio/pr/its-classified/src/
```
There should be none remaining after this change.

### Task 7: Update lib.rs doc example

In `src/lib.rs`, the doc example (lines 19–44) calls `patterns::all()`. Add a comment noting
the ephemeral-salt behavior:

```rust
//! // 1. Scrub: detect and replace the key before sending to an external service
//! // Note: `patterns::all()` uses an ephemeral salt — fakes differ across process
//! // restarts. For persistent fake stability, use `PatternsFile::into_patterns()`.
//! let result = scrub(payload, &patterns::all()).unwrap();
```

### Task 8: Update unit tests in `src/tier1.rs`

The existing inline test `test_tier1_all_eight_classes_present` calls `patterns::all()` and
checks the variants. With `Pattern::Tier1(Tier1Def)` by value, the match arm changes from
`Pattern::Tier1(d) if d.prefix == ...` which still works because `Tier1Def` is now an owned
copy and `.prefix` is still accessible.

Any test that constructs `Pattern::Tier1(&SOME_DEF)` directly must change to
`Pattern::Tier1(Tier1Def { salt: [42u8; 32], ..SOME_DEF })`.

Run:
```sh
grep -rn "Pattern::Tier1" /home/ignacio/pr/its-classified/src/
```
and update each match site that passes a reference.

### Task 9: Run the full test suite

```sh
cargo nextest run --workspace
```

All tests must pass. The `patterns::all()` functions still work (they use random salts), so
existing tests that rely on `patterns::all()` within a single test function continue to pass.
The CLI binary panics on `patterns::all()` with a missing `--patterns` argument only after
step-09 removes the `patterns::all()` call in `main.rs` — that regression is expected and
is addressed in step-09.

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run -p its-classified --lib 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test spec 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test integration 2>&1 | tail -3` shows 0 failures
- [ ] `grep -rn "OnceLock" /home/ignacio/pr/its-classified/src/tier1.rs` outputs 0 lines
- [ ] `grep -rn "get_salt" /home/ignacio/pr/its-classified/src/` outputs 0 lines
- [ ] `grep -c "salt: \[0u8; 32\]" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `8`
      (one per static def)
- [ ] `grep -c "derive(Clone, Copy)" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c "Tier1(Tier1Def)" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
      (the enum variant, no longer a reference)
- [ ] `cargo build -p its-classified 2>&1 | grep -c "^error"` outputs `0`
- [ ] `cargo clippy -p its-classified 2>&1 | grep -c "^error"` outputs `0`

## Reviewer Instructions

You are reviewing Step 07. Verify:

1. Run `cargo nextest run -p its-classified --lib` — all tests must pass
2. Run `cargo nextest run -p its-classified --test spec` — all spec tests must pass
3. Run `cargo nextest run -p its-classified --test integration` — all integration tests must pass
4. Check `src/tier1.rs`: no `OnceLock` import, no `OnceLock` field, no `get_salt()` method
5. Check `src/tier1.rs`: `Tier1Def` derives `Clone, Copy`; `salt` field is `[u8; 32]`
6. Check `src/tier1.rs`: all 8 statics have `salt: [0u8; 32]`
7. Check `src/tier1.rs`: `Pattern::Tier1(Tier1Def)` (no `&'static`)
8. Check `src/tier1.rs`: `patterns::random_salt()` private fn exists; each `patterns::*` fn
   calls it
9. Check `src/scrub.rs`: `generate_fake_for_match` uses `&def.salt` not `def.get_salt()`
10. Run `cargo clippy -p its-classified` — no new warnings

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier1.rs src/scrub.rs src/lib.rs
```
