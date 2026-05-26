# step-02: Make Pattern opaque — non_exhaustive + pub(crate) fields

## Context

**Overall Objective:** Clean up library public API. Pattern should be opaque to external callers.

**Phase Context:** Wave 2 (parallel with step-03). Workspace split is complete.

**This Step:** Add `#[non_exhaustive]` to `Pattern`, make `Tier1Def.prefix` `pub(crate)`,
make all `Tier2Pat` fields `pub(crate)`, and rewrite the one external test that matched on
Pattern variants.

## Prerequisites

- step-01 complete and committed.
- `cargo nextest run` reports 79 passed.

## Files to Read Before Starting

| File | Why |
|------|-----|
| `src/tier1.rs` | `Pattern` enum (line 127), `Tier1Def` struct (line 8), field visibility |
| `src/tier2.rs` | `Tier2Pat` struct (line 87), all fields currently `pub` |
| `tests/spec/inv.rs` | `test_inv22_all_tier1_built_in_classes_present` (line 514) — must be rewritten |
| `src/scrub.rs` | Confirm internal pattern matching is same-crate (unaffected by `#[non_exhaustive]`) |

## Implementation

### Task 1: Add `#[non_exhaustive]` to `Pattern` enum

**File:** `src/tier1.rs`, line 126–130

Change:
```rust
#[derive(Clone)]
pub enum Pattern {
```

To:
```rust
#[derive(Clone)]
#[non_exhaustive]
pub enum Pattern {
```

**Impact:** Internal code (same crate) is unaffected. `match` in `scrub.rs` (line 27, 33) and
`tier1.rs` unit tests continue to compile without a wildcard arm. Only external crates would
need `_ => ..` but no external code matches on Pattern.

### Task 2: Make `Tier1Def.prefix` `pub(crate)`

**File:** `src/tier1.rs`, line 10

Change:
```rust
    pub prefix: &'static [u8],
```

To:
```rust
    pub(crate) prefix: &'static [u8],
```

**Impact:** `prefix` is accessed only in same-crate code: `tier1.rs` (try_match, unit tests)
and `scrub.rs` (generate_fake_for_match). No external code reads `.prefix` after test_inv22 is
rewritten.

### Task 3: Make all `Tier2Pat` fields `pub(crate)`

**File:** `src/tier2.rs`, lines 89–100

Change every `pub` field to `pub(crate)`:

```rust
pub struct Tier2Pat {
    pub(crate) start_fragment: Vec<u8>,
    pub(crate) end_fragment: Vec<u8>,
    pub(crate) exact_length: usize,
    pub(crate) hmac_salt: [u8; 32],
    pub(crate) hmac_digest: [u8; 32],
    pub(crate) fake: Vec<u8>,
}
```

**Impact:** All field access is in `tier2.rs` (construction, try_match, unit tests) and
`scrub.rs` (fake.clone(), pattern matching). All same-crate — no breakage.

### Task 4: Rewrite `test_inv22_all_tier1_built_in_classes_present`

**File:** `tests/spec/inv.rs`, starting at line 514

Delete the current `test_inv22_all_tier1_built_in_classes_present` function (lines 513–549)
and replace with this behavioral version:

```rust
#[test]
fn test_inv22_all_tier1_built_in_classes_present() {
    // INV-22: built-in Tier 1 MUST cover Anthropic, OpenAI (classic + project),
    //         AWS IAM (AKIA + ASIA), GitHub PAT (classic + fine-grained), and GCP API keys.
    //
    // Validates behaviorally: scrub a synthetic key of each class and assert detection.
    let cases: &[(&str, &[u8])] = &[
        // Anthropic: prefix "sk-ant-", min 80, max 120, url_safe_base64
        ("Anthropic", b"sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // OpenAI classic: prefix "sk-", exactly 51, alphanumeric
        ("OpenAI classic", b"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // OpenAI project: prefix "sk-proj-", min 56, max 72, url_safe_base64
        ("OpenAI project", b"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // AWS AKIA: prefix "AKIA", exactly 20, uppercase_alphanumeric
        ("AWS AKIA", b"AKIAAAAAAAAAAAAAAAAA"),
        // AWS ASIA: prefix "ASIA", exactly 20, uppercase_alphanumeric
        ("AWS ASIA", b"ASIAAAAAAAAAAAAAAAAA"),
        // GitHub classic: prefix "ghp_", exactly 40, alphanumeric
        ("GitHub classic", b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // GitHub fine-grained: prefix "github_pat_", min 82, max 100, url_safe_base64
        ("GitHub fine-grained", b"github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // GCP: prefix "AIza", exactly 39, url_safe_base64
        ("GCP", b"AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ];
    let all = patterns::all();
    for (name, secret) in cases {
        let result = scrub(secret, &all).expect("scrub failed");
        assert_eq!(
            result.entries.len(),
            1,
            "INV-22: {name} key must be detected by patterns::all()"
        );
    }
}
```

**Why this is not a weakening:** The original test inspected internal data structure layout
(prefix field values). The new test validates the actual behavioral contract — each key class
is *detected and scrubbed*. It covers all 8 pattern constructors (the same 8 returned by
`patterns::all()`). Each synthetic key has been verified against the Tier1Def length and
charset constraints:

| Class | Prefix | Total Length | Charset | In Range |
|-------|--------|-------------|---------|----------|
| Anthropic | `sk-ant-` (7) | 80 | url_safe_base64 | [80, 120] ✓ |
| OpenAI classic | `sk-` (3) | 51 | alphanumeric | [51, 51] ✓ |
| OpenAI project | `sk-proj-` (8) | 56 | url_safe_base64 | [56, 72] ✓ |
| AWS AKIA | `AKIA` (4) | 20 | uppercase_alphanumeric | [20, 20] ✓ |
| AWS ASIA | `ASIA` (4) | 20 | uppercase_alphanumeric | [20, 20] ✓ |
| GitHub classic | `ghp_` (4) | 40 | alphanumeric | [40, 40] ✓ |
| GitHub FG | `github_pat_` (11) | 82 | url_safe_base64 | [82, 100] ✓ |
| GCP | `AIza` (4) | 39 | url_safe_base64 | [39, 39] ✓ |

### Task 5: Commit

```sh
cargo fmt --all
git add -A
git commit -m "step-02: make Pattern opaque — non_exhaustive + pub(crate) fields"
```

## Acceptance Criteria

1. `cargo nextest run` exits 0, reports exactly 79 tests passed.
2. `cargo nextest run -p its-classified --test spec` passes (including rewritten test_inv22).
3. `cargo nextest run --lib` passes (tier1::tests and tier2::tests still compile — same crate).
4. `cargo clippy --workspace` exits 0 with no warnings.
5. `cargo fmt --all --check` exits 0.
6. Verify `Tier2Pat.start_fragment` is not accessible from external code:
   ```sh
   grep 'pub start_fragment' src/tier2.rs
   # Expected: no output (field is pub(crate), not pub)
   grep 'pub(crate) start_fragment' src/tier2.rs
   # Expected: 1 match
   ```
7. Verify `#[non_exhaustive]` is present on Pattern:
   ```sh
   grep -A1 'non_exhaustive' src/tier1.rs | grep 'pub enum Pattern'
   # Expected: "pub enum Pattern {"
   ```

## Reviewer Instructions

Run these commands in order. All must pass.

```sh
cargo nextest run 2>&1 | tail -3
# Expected: "79 tests run: 79 passed, 0 skipped"

cargo nextest run -p its-classified --test spec 2>&1 | grep test_inv22
# Expected: PASS line containing test_inv22_all_tier1_built_in_classes_present

grep 'pub(crate) prefix' src/tier1.rs
# Expected: 1 match (Tier1Def.prefix)

grep -c 'pub(crate)' src/tier2.rs | head -1
# Expected: at least 6 (all Tier2Pat fields)

grep '#\[non_exhaustive\]' src/tier1.rs
# Expected: 1 match

cargo clippy --workspace 2>&1 | grep -c warning
# Expected: 0
```

## Rollback

```sh
git reset --hard HEAD~1
cargo nextest run   # verify step-01 state restored
```
