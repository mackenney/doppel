# Step 04: Add `identifier` Field to `Tier1Def` and `all_defs()` Helper

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 1. The patterns file serializes Tier 1 entries keyed by a string identifier (e.g., `"anthropic"`, `"openai_classic"`). Each `Tier1Def` needs a stable identifier field, and the patterns file loader (step-08) needs a function to iterate all definitions. This step adds both without changing any existing behavior.

### This Step
Add a `pub(crate) identifier: &'static str` field to `Tier1Def` in `src/tier1.rs`. Set the identifier on all 15 static instances. Add a `pub(crate) fn all_defs() -> &'static [&'static Tier1Def]` function. No behavior changes.

## Prerequisites
- None (parallel with step-01, step-02, step-03)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier1.rs` — full file. `Tier1Def` struct at lines 9–21. 15 static defs starting around line 97, spanning to ~351.

## Implementation

### Task 1: Add `identifier` field to `Tier1Def` struct

In `src/tier1.rs`, locate the `Tier1Def` struct (line 9). Add a new field as the **first** field (before `segments`):

```rust
pub struct Tier1Def {
    /// Stable string identifier for this class, used as the key in patterns files.
    pub(crate) identifier: &'static str,
    /// Ordered sequence of structural segments for this secret class.
    pub(crate) segments: &'static [Segment],
    ...
```

The full "after" struct shape is:

```rust
pub struct Tier1Def {
    /// Stable string identifier for this class, used as the key in patterns files.
    pub(crate) identifier: &'static str,
    /// Ordered sequence of structural segments for this secret class.
    /// See SPEC.md §Tier 1.
    pub(crate) segments: &'static [Segment],
    /// Derivation salt for fake generation.
    ///
    /// FIXME: currently initialized lazily with OsRng on first access, which means
    /// the salt (and therefore the fake) differs on every process restart. This
    /// violates INV-13 across process boundaries. The salt must become an explicit,
    /// caller-supplied value loaded from the patterns file so fakes are stable
    /// across runs. See Known Gaps in MASTER_PROGRESS.md.
    pub(crate) salt: OnceLock<[u8; 32]>,
}
```

### Task 2: Set identifier on all 15 static instances

Update each static `Tier1Def` instance to include the `identifier` field as the first field. The complete mapping is:

| Static name              | identifier               |
|--------------------------|--------------------------|
| `ANTHROPIC_DEF`          | `"anthropic"`            |
| `ANTHROPIC_ADMIN01_DEF`  | `"anthropic_admin01"`    |
| `ANTHROPIC_ADMIN03_DEF`  | `"anthropic_admin03"`    |
| `OPENAI_CLASSIC_DEF`     | `"openai_classic"`       |
| `OPENAI_PROJECT_DEF`     | `"openai_project"`       |
| `OPENAI_SVCACCT_DEF`     | `"openai_svcacct"`       |
| `AWS_AKIA_DEF`           | `"aws_akia"`             |
| `AWS_ASIA_DEF`           | `"aws_asia"`             |
| `GITHUB_CLASSIC_DEF`     | `"github_classic"`       |
| `GITHUB_FG_DEF`          | `"github_fine_grained"`  |
| `GCP_DEF`                | `"gcp"`                  |
| `OPENROUTER_DEF`         | `"openrouter"`           |
| `GOOGLE_OAUTH_SECRET_DEF`| `"google_oauth_secret"`  |
| `SLACK_BOT_DEF`          | `"slack_bot"`            |
| `LINEAR_DEF`             | `"linear"`               |

Each static now looks like:

```rust
pub(crate) static ANTHROPIC_DEF: Tier1Def = Tier1Def {
    identifier: "anthropic",
    segments: &ANTHROPIC_SEGS,
    salt: OnceLock::new(),
};
```

Apply identically to all 15 statics; only `identifier` and `segments` (the existing field) vary per instance.

### Task 3: Add `all_defs()` function

In `src/tier1.rs`, add a function after the last static definition (`LINEAR_DEF`) and before the `Pattern` enum:

```rust
/// Returns references to all 15 built-in Tier 1 definitions.
/// Used by patterns file loading to iterate and inject salts.
pub(crate) fn all_defs() -> &'static [&'static Tier1Def] {
    &[
        &ANTHROPIC_DEF,
        &ANTHROPIC_ADMIN01_DEF,
        &ANTHROPIC_ADMIN03_DEF,
        &OPENAI_CLASSIC_DEF,
        &OPENAI_PROJECT_DEF,
        &OPENAI_SVCACCT_DEF,
        &AWS_AKIA_DEF,
        &AWS_ASIA_DEF,
        &GITHUB_CLASSIC_DEF,
        &GITHUB_FG_DEF,
        &GCP_DEF,
        &OPENROUTER_DEF,
        &GOOGLE_OAUTH_SECRET_DEF,
        &SLACK_BOT_DEF,
        &LINEAR_DEF,
    ]
}
```

The order matches `patterns::all()` so that index-aligned iteration works in the patterns file loader.

### Task 4: Add unit tests for identifiers

Add tests to the `#[cfg(test)] mod tests` block in `src/tier1.rs`:

```rust
#[test]
fn test_all_defs_identifiers_unique() {
    let defs = all_defs();
    assert_eq!(defs.len(), 15, "must have 15 built-in Tier 1 defs");
    let mut ids: Vec<&str> = defs.iter().map(|d| d.identifier).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 15, "all identifiers must be unique");
}

#[test]
fn test_all_defs_matches_all_patterns() {
    let defs = all_defs();
    let all = patterns::all();
    assert_eq!(defs.len(), all.len(), "all_defs and patterns::all must have same count");
    for def in defs {
        assert!(
            all.iter().any(|p| matches!(p, Pattern::Tier1(d) if d.identifier == def.identifier)),
            "all_defs entry {} must appear in patterns::all()",
            def.identifier
        );
    }
}
```

Note: the `test_all_defs_matches_all_patterns` test uses identifier-based lookup (not pointer equality) because `Pattern::Tier1` still holds `&'static Tier1Def` at this step but will become by-value in step-07. The identifier check is correct either way.

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run --lib -p its-classified -- tier1::tests 2>&1 | tail -1` shows all tests passing
- [ ] `grep -c 'identifier: &.static str' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c 'identifier: "anthropic"' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c 'identifier: "gcp"' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c 'identifier: "linear"' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c 'identifier: "openrouter"' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c "fn all_defs" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c "&'static Tier1Def" /home/ignacio/pr/its-classified/src/tier1.rs | grep 15` — `all_defs()` slice literal contains 15 entries (count via `grep -c '&ANTHROPIC_DEF\|&OPENAI\|&AWS\|&GITHUB\|&GCP\|&OPENROUTER\|&GOOGLE\|&SLACK\|&LINEAR\|&ANTHROPIC_ADMIN'` ≥ 15)
- [ ] `grep -c "fn test_all_defs_identifiers_unique" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `cargo build -p its-classified 2>&1 | grep -c "error"` outputs `0`

## Reviewer Instructions

You are reviewing Step 04. Verify:
1. Run `cargo nextest run --lib -p its-classified -- tier1::tests` — all tests must pass
2. Check `src/tier1.rs` `Tier1Def` struct: `identifier: &'static str` is present as the first field
3. Check all 15 static instances have an `identifier` field with the correct value (see table above)
4. Check `all_defs()` returns all 15 references in the correct order
5. Check `test_all_defs_matches_all_patterns` uses identifier-based check, not pointer equality
6. Run `cargo nextest run --lib -p its-classified 2>&1 | tail -3` — full lib test suite passes

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier1.rs
```
