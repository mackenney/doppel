# Step 07: Drop `OnceLock` from `Tier1Def` — Plain Salt Field, `Pattern::Tier1` by Value

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose
CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 3 (parallel with step-06). This step makes `Tier1Def` a plain, owned, Copy struct by
replacing the `OnceLock<[u8; 32]>` salt field with a regular `[u8; 32]`. The `Pattern::Tier1`
variant changes from `&'static Tier1Def` (reference into a global) to `Tier1Def` (owned
copy). The 15 static definitions become pure templates with `salt: [0u8; 32]`; callers supply
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
- Step 04 complete (`Tier1Def` has `identifier: &'static str` and `all_defs()` exists)
- Step 05 complete (`scrub.rs` already updated to handle the new `find_best_match` signature
  and `PatternRef` usage — this step changes `def.get_salt()` to `&def.salt` in
  `generate_fake_for_match`)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier1.rs` — full file; understand `Tier1Def`, static
  instances, `Pattern` enum, `patterns::*` functions
- `/home/ignacio/pr/its-classified/src/scrub.rs` — `generate_fake_for_match` (around line 58);
  `PatternRef::Tier1` arm; any reference to `def.get_salt()`
- `/home/ignacio/pr/its-classified/src/lib.rs` — doc example uses `patterns::all()`; update
  the quick-start example to note the ephemeral-salt caveat

## Implementation

### Task 1: Replace `OnceLock` salt field with plain `[u8; 32]`

In `src/tier1.rs`, make these changes to the `Tier1Def` struct:

**Remove** the `use std::sync::OnceLock;` import at line 1.

**Change** the struct definition. The current shape (after step-04) is:

```rust
// Before (after step-04)
pub struct Tier1Def {
    pub(crate) identifier: &'static str,
    pub(crate) segments: &'static [Segment],
    pub(crate) salt: OnceLock<[u8; 32]>,
}
```

The target shape is:

```rust
// After
#[derive(Clone, Copy)]
pub struct Tier1Def {
    pub(crate) identifier: &'static str,   // added in step-04
    pub(crate) segments: &'static [Segment],
    pub(crate) salt: [u8; 32],
}
```

Note: `Segment` is `#[derive(Clone, Copy)]` (it contains `fn() -> Vec<u8>` and `&'static [u8]`,
both Copy). `Tier1Def: Copy` is therefore valid.

**Remove** the entire `impl Tier1Def { fn get_salt ... }` block. Internal callers access
`def.salt` directly after this step.

### Task 2: Update all 15 static `Tier1Def` instances

Replace `salt: OnceLock::new()` with `salt: [0u8; 32]` in every static definition. The zero
salt is a sentinel — these statics are templates only; `PatternsFile::into_patterns()`
constructs real `Tier1Def` values with the caller-supplied salt. Example:

```rust
pub(crate) static ANTHROPIC_DEF: Tier1Def = Tier1Def {
    identifier: "anthropic",
    segments: &ANTHROPIC_SEGS,
    salt: [0u8; 32],
};
```

Apply the same `salt: [0u8; 32]` change to all 15 static instances:
`ANTHROPIC_DEF`, `ANTHROPIC_ADMIN01_DEF`, `ANTHROPIC_ADMIN03_DEF`, `OPENAI_CLASSIC_DEF`,
`OPENAI_PROJECT_DEF`, `OPENAI_SVCACCT_DEF`, `AWS_AKIA_DEF`, `AWS_ASIA_DEF`,
`GITHUB_CLASSIC_DEF`, `GITHUB_FG_DEF`, `GCP_DEF`, `OPENROUTER_DEF`,
`GOOGLE_OAUTH_SECRET_DEF`, `SLACK_BOT_DEF`, `LINEAR_DEF`.

### Task 3: Change `Pattern::Tier1` variant to by-value

In `src/tier1.rs`, locate the `Pattern` enum:

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

In `src/tier1.rs`, the `patterns` module constructs `Pattern::Tier1` values. Each function
must now supply a real salt. Use `OsRng` to generate a fresh random salt per call. This
preserves the existing behavior (ephemeral, process-local stability) while the struct no
longer holds interior mutability:

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

    pub fn anthropic_admin01() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..ANTHROPIC_ADMIN01_DEF })
    }

    pub fn anthropic_admin03() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..ANTHROPIC_ADMIN03_DEF })
    }

    pub fn openai_classic() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..OPENAI_CLASSIC_DEF })
    }

    pub fn openai_project() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..OPENAI_PROJECT_DEF })
    }

    pub fn openai_svcacct() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..OPENAI_SVCACCT_DEF })
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

    pub fn openrouter() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..OPENROUTER_DEF })
    }

    pub fn google_oauth_secret() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..GOOGLE_OAUTH_SECRET_DEF })
    }

    pub fn slack_bot() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..SLACK_BOT_DEF })
    }

    pub fn linear() -> Pattern {
        Pattern::Tier1(Tier1Def { salt: random_salt(), ..LINEAR_DEF })
    }

    /// Returns all built-in Tier 1 patterns with ephemeral per-call salts.
    ///
    /// Fakes produced by these patterns are stable within the returned `Vec<Pattern>`
    /// instance but differ across calls to `all()` and across process restarts.
    /// For persistent cross-restart stability, use `PatternsFile::into_patterns()`.
    pub fn all() -> Vec<Pattern> {
        vec![
            anthropic(),
            anthropic_admin01(),
            anthropic_admin03(),
            openai_classic(),
            openai_project(),
            openai_svcacct(),
            aws_akia(),
            aws_asia(),
            github_classic(),
            github_fine_grained(),
            gcp(),
            openrouter(),
            google_oauth_secret(),
            slack_bot(),
            linear(),
        ]
    }
}
```

### Task 5: Update `all_defs()` (if not updated in step-04)

If step-04 has not landed yet, add `all_defs()` here. Once it exists (from step-04), confirm
it lists all 15 templates and update it if needed. No signature change — it still returns
`&'static [&'static Tier1Def]` because the statics still exist as templates.

### Task 6: Update `scrub.rs` — replace `def.get_salt()` with `&def.salt`

In `src/scrub.rs`, `generate_fake_for_match`, the `PatternRef::Tier1` arm currently calls
`def.get_salt()`. After this step `Tier1Def` has no `get_salt()` method and `def.salt` is a
plain `[u8; 32]`.

```rust
// Before
PatternRef::Tier1(def) => {
    crate::fake::derive_fake_tier1_segments(
        def.get_salt(),
        def.segments,
        &capture.variable_lengths,
        secret,
    )
}

// After
PatternRef::Tier1(def) => {
    crate::fake::derive_fake_tier1_segments(
        &def.salt,
        def.segments,
        &capture.variable_lengths,
        secret,
    )
}
```

Search for any other occurrence of `get_salt()` in the codebase and update similarly:
```sh
grep -rn "get_salt" /home/ignacio/pr/its-classified/src/
```
There should be none remaining after this change.

Note: `PatternRef::Tier1` in `scrub.rs` currently holds `&'a Tier1Def`. After `Pattern::Tier1`
becomes by-value, `PatternRef::Tier1` must also change — either to `&'a Tier1Def` (borrowing
from the by-value Pattern in the patterns slice, which is valid) or to `Tier1Def` (copying).
The simplest approach is to keep `PatternRef::Tier1(&'a Tier1Def)` and borrow from the
`Pattern::Tier1(ref def)` arm in `find_best_match`. Ensure the match arm reads:

```rust
Pattern::Tier1(def) => def.try_match(payload, pos).map(|capture| Match {
    start: pos,
    end: capture.end,
    is_tier1: true,
    pattern_ref: PatternRef::Tier1(def),   // borrow, not move
    tier1_capture: Some(capture),
}),
```

### Task 7: Update lib.rs doc example

In `src/lib.rs`, the doc example calls `patterns::all()`. Add a comment noting the
ephemeral-salt behavior:

```rust
//! // Note: `patterns::all()` uses ephemeral salts — fakes differ across process restarts.
//! // For persistent fake stability, use `PatternsFile::into_patterns()`.
//! let result = scrub(payload, &patterns::all()).unwrap();
```

### Task 8: Update unit tests in `src/tier1.rs`

The existing inline test `test_tier1_all_classes_present` matches on the first Literal
segment of each `Pattern::Tier1(d)` — this already works with by-value `Tier1Def` because
it only accesses `d.segments`. Do not regress it.

Any test that constructs `Pattern::Tier1(&SOME_DEF)` directly must change to
`Pattern::Tier1(Tier1Def { salt: [42u8; 32], ..SOME_DEF })`.

Run:
```sh
grep -rn "Pattern::Tier1" /home/ignacio/pr/its-classified/src/
```
and update each site that passes a reference.

If any test matches `Pattern::Tier1(d) if d.prefix == ...` — that field no longer exists.
Replace with `Pattern::Tier1(d) if d.identifier == "anthropic"` etc.

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
- [ ] `grep -c "salt: \[0u8; 32\]" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `15`
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
6. Check `src/tier1.rs`: all 15 statics have `salt: [0u8; 32]`
7. Check `src/tier1.rs`: `Pattern::Tier1(Tier1Def)` (no `&'static`)
8. Check `src/tier1.rs`: `patterns::random_salt()` private fn exists; each of the 15
   `patterns::*` fns calls it via struct-update syntax
9. Check `src/scrub.rs`: `generate_fake_for_match` uses `&def.salt` not `def.get_salt()`
10. Run `cargo clippy -p its-classified` — no new warnings

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier1.rs src/scrub.rs src/lib.rs
```
