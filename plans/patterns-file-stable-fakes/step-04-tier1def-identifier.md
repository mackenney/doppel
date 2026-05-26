# Step 04: Add `identifier` Field to `Tier1Def` and `all_defs()` Helper

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 1. The patterns file serializes Tier 1 entries keyed by a string identifier (e.g., `"anthropic"`, `"openai_classic"`). Each `Tier1Def` needs a stable identifier field, and the patterns file loader (step-08) needs a function to iterate all definitions. This step adds both without changing any existing behavior.

### This Step
Add a `pub(crate) identifier: &'static str` field to `Tier1Def` in `src/tier1.rs`. Set the identifier on all 8 static instances. Add a `pub(crate) fn all_defs() -> &'static [&'static Tier1Def]` function. No behavior changes.

## Prerequisites
- None (parallel with step-01, step-02, step-03)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier1.rs` — full file, 250 lines. `Tier1Def` struct at lines 8–25, 8 static instances at lines 64–127.

## Implementation

### Task 1: Add `identifier` field to `Tier1Def` struct

In `src/tier1.rs`, locate the `Tier1Def` struct (line 8). Add a new field as the **first** field (before `prefix`):

```rust
pub struct Tier1Def {
    /// Stable string identifier for this class, used as the key in patterns files.
    pub(crate) identifier: &'static str,
    /// Fixed literal prefix that a secret of this class starts with.
    pub(crate) prefix: &'static [u8],
    ...
```

### Task 2: Set identifier on all 8 static instances

Update each static `Tier1Def` instance to include the `identifier` field. The exact mappings are:

In `src/tier1.rs`, update each static:

**ANTHROPIC_DEF** (line 64):
```rust
pub(crate) static ANTHROPIC_DEF: Tier1Def = Tier1Def {
    identifier: "anthropic",
    prefix: b"sk-ant-",
    ...
```

**OPENAI_CLASSIC_DEF** (line 72):
```rust
pub(crate) static OPENAI_CLASSIC_DEF: Tier1Def = Tier1Def {
    identifier: "openai_classic",
    prefix: b"sk-",
    ...
```

**OPENAI_PROJECT_DEF** (line 80):
```rust
pub(crate) static OPENAI_PROJECT_DEF: Tier1Def = Tier1Def {
    identifier: "openai_project",
    prefix: b"sk-proj-",
    ...
```

**AWS_AKIA_DEF** (line 88):
```rust
pub(crate) static AWS_AKIA_DEF: Tier1Def = Tier1Def {
    identifier: "aws_akia",
    prefix: b"AKIA",
    ...
```

**AWS_ASIA_DEF** (line 96):
```rust
pub(crate) static AWS_ASIA_DEF: Tier1Def = Tier1Def {
    identifier: "aws_asia",
    prefix: b"ASIA",
    ...
```

**GITHUB_CLASSIC_DEF** (line 104):
```rust
pub(crate) static GITHUB_CLASSIC_DEF: Tier1Def = Tier1Def {
    identifier: "github_classic",
    prefix: b"ghp_",
    ...
```

**GITHUB_FG_DEF** (line 112):
```rust
pub(crate) static GITHUB_FG_DEF: Tier1Def = Tier1Def {
    identifier: "github_fine_grained",
    prefix: b"github_pat_",
    ...
```

**GCP_DEF** (line 120):
```rust
pub(crate) static GCP_DEF: Tier1Def = Tier1Def {
    identifier: "gcp",
    prefix: b"AIza",
    ...
```

### Task 3: Add `all_defs()` function

In `src/tier1.rs`, add a function after the static definitions (after `GCP_DEF`, before the `Pattern` enum):

```rust
/// Returns references to all 8 built-in Tier 1 definitions.
/// Used by patterns file loading to iterate and inject salts.
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

### Task 4: Add unit test for identifiers

Add a test to the `#[cfg(test)] mod tests` block in `src/tier1.rs`:

```rust
#[test]
fn test_all_defs_identifiers_unique() {
    let defs = all_defs();
    assert_eq!(defs.len(), 8, "must have 8 built-in Tier 1 defs");
    let mut ids: Vec<&str> = defs.iter().map(|d| d.identifier).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 8, "all identifiers must be unique");
}

#[test]
fn test_all_defs_matches_all_patterns() {
    let defs = all_defs();
    let all = patterns::all();
    assert_eq!(defs.len(), all.len(), "all_defs and patterns::all must have same count");
    for def in defs {
        assert!(
            all.iter().any(|p| matches!(p, Pattern::Tier1(d) if std::ptr::eq(*d, *def))),
            "all_defs entry {} must appear in patterns::all()",
            def.identifier
        );
    }
}
```

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run --lib -p its-classified -- tier1::tests 2>&1 | tail -1` shows all tests passing
- [ ] `grep -c 'identifier: &.static str' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c 'identifier: "anthropic"' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c 'identifier: "gcp"' /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c "fn all_defs" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `grep -c "fn test_all_defs_identifiers_unique" /home/ignacio/pr/its-classified/src/tier1.rs` outputs `1`
- [ ] `cargo build -p its-classified 2>&1 | grep -c "error"` outputs `0`

## Reviewer Instructions

You are reviewing Step 04. Verify:
1. Run `cargo nextest run --lib -p its-classified -- tier1::tests` — all tests must pass
2. Check `src/tier1.rs` `Tier1Def` struct: `identifier: &'static str` is present
3. Check all 8 static instances have an `identifier` field with the correct value
4. Check `all_defs()` returns all 8 references
5. Run `cargo nextest run --lib -p its-classified 2>&1 | tail -3` — full lib test suite passes
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier1.rs
```
