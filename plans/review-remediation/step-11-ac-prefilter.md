# Step 11: Aho-Corasick Pre-Filter for Tier 1 Prefixes

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 4 — Final performance optimization for the scrub hot path. When `find_best_match` returns `None`, the current loop advances one byte and retries all P patterns. For a 100KB payload with no secrets and 15 patterns, this is 1.5M pattern match attempts.

### This Step
Build an Aho-Corasick automaton from all Tier 1 literal prefixes. Use it to skip non-candidate positions, reducing worst-case from O(N×P) to O(N + M×P) where M = prefix match positions (typically << N).

## Prerequisites
- Steps 08-09 complete (charset optimizations — the pre-filter benefits from fast charset lookups during candidate verification)

## Files to Read Before Starting
- `src/tier1.rs` — understand Tier 1 pattern definitions and their literal prefixes
- `src/scrub.rs` — locate the main scanning loop
- `SPEC.md` — INV-18: leftmost-longest matching must be preserved

## Implementation
### Task 1: Extract Tier 1 literal prefixes
**File:** `src/tier1.rs`

Create a function that returns all Tier 1 literal prefixes:
```rust
use std::sync::LazyLock;
use aho_corasick::AhoCorasick;

/// Literal prefixes for all Tier 1 patterns.
static TIER1_PREFIXES: &[&[u8]] = &[
    b"sk-ant-api03-",      // Anthropic
    b"sk-",                // OpenAI (also partial match for Anthropic)
    b"AKIA",               // AWS IAM
    b"ghp_",               // GitHub PAT classic
    b"github_pat_",        // GitHub PAT fine-grained
    b"ghu_",               // GitHub user token
    b"ghs_",               // GitHub server token
    b"gho_",               // GitHub OAuth
    b"ghr_",               // GitHub refresh
    b"AIza",               // GCP API key
    // Add all other Tier 1 prefixes
];

/// Pre-built Aho-Corasick automaton for Tier 1 prefix detection.
pub static TIER1_PREFIX_FILTER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .build(TIER1_PREFIXES)
        .expect("failed to build Tier 1 prefix AC")
});

/// Get reference to the pre-built prefix filter.
pub fn prefix_filter() -> &'static AhoCorasick {
    &TIER1_PREFIX_FILTER
}
```

### Task 2: Modify scrub loop to use pre-filter
**File:** `src/scrub.rs`

Change the main loop from:
```rust
let mut pos = 0;
while pos < payload.len() {
    match find_best_match(payload, pos, patterns)? {
        None => {
            output.push(payload[pos]);
            pos += 1;
        }
        Some(m) => { ... }
    }
}
```

To:
```rust
use crate::tier1::prefix_filter;

let tier1_ac = prefix_filter();
let mut pos = 0;

while pos < payload.len() {
    // Find next position that could start a Tier 1 pattern
    let next_candidate = tier1_ac
        .find(&payload[pos..])
        .map(|m| pos + m.start())
        .unwrap_or(payload.len());

    // Copy bytes before the candidate directly to output (no secrets possible)
    if next_candidate > pos {
        output.extend_from_slice(&payload[pos..next_candidate]);
        pos = next_candidate;
    }

    if pos >= payload.len() {
        break;
    }

    // Try all patterns at this candidate position (includes Tier 2)
    match find_best_match(payload, pos, patterns)? {
        None => {
            // AC found a prefix but full pattern didn't match
            output.push(payload[pos]);
            pos += 1;
        }
        Some(m) => {
            // Secret found — process as before
            // ... existing match handling
        }
    }
}
```

### Task 3: Handle Tier 2 patterns
Tier 2 (user-registered) patterns have no fixed prefix. The pre-filter skips positions that can't start Tier 1 patterns, but Tier 2 matching still happens at AC-identified positions.

**Important:** If `patterns` contains ONLY Tier 2 patterns (no Tier 1), the AC will never match and the loop will copy everything to output without checking for Tier 2 secrets.

**Solution:** Check if patterns include any Tier 2:
```rust
let has_tier2 = patterns.iter().any(|p| p.is_tier2());

if has_tier2 {
    // Fall back to byte-by-byte scanning (existing behavior)
    // Tier 2 requires checking every position
} else {
    // Use AC pre-filter optimization
}
```

Or: Build a combined approach where Tier 2 secrets are also added to the AC at runtime.

### Task 4: Add integration test for performance
**File:** `tests/integration/perf.rs` (new file) or in existing integration

```rust
#[test]
fn test_scrub_no_secrets_performance() {
    // Verify large payload with no secrets completes quickly
    let payload = vec![b'x'; 100_000];
    let patterns = &[patterns::anthropic(), patterns::github_classic()];
    
    let start = std::time::Instant::now();
    let result = scrub(&payload, patterns).unwrap();
    let elapsed = start.elapsed();
    
    // Should be well under 100ms for 100KB with AC pre-filter
    assert!(elapsed.as_millis() < 100, "scrub took too long: {:?}", elapsed);
    assert_eq!(result.payload, payload);
}
```

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo nextest run -p its-classified --test spec` passes (INV-18 leftmost-longest preserved)
- [ ] `cargo nextest run -p its-classified --test integration` passes
- [ ] `grep "prefix_filter" src/scrub.rs` returns match showing pre-filter usage
- [ ] Large no-secret payload completes significantly faster than byte-by-byte
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 11. Verify:
1. Run `cargo nextest run -p its-classified` — all tests pass
2. Check `src/tier1.rs` has `TIER1_PREFIX_FILTER` static with all prefixes
3. Check `src/scrub.rs` uses `prefix_filter()` to skip non-candidate positions
4. Verify Tier 2-only patterns still work (either fallback or combined approach)
5. Check INV-18 (leftmost-longest) is preserved in test output
6. Run the performance test (if added) — should complete quickly

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/tier1.rs src/scrub.rs
```
