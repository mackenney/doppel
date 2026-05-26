# Step 05: Change `Tier2Pat::try_match` to Derive and Return Fake

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 2. This step depends on step-02 (`derive_fake_tier2_deterministic` exists in `fake.rs`) and step-03 (`Tier2Pat` has `preserve_prefix`, `preserve_suffix`, `charset` fields). It changes `try_match` to derive the fake at match time and return it alongside the end position, and updates `scrub.rs` to use the returned fake for Tier 2 matches.

### This Step
Change `Tier2Pat::try_match` signature from `Option<usize>` to `Result<Option<(usize, Vec<u8>)>, FakeError>`. After HMAC verification succeeds, derive the fake using `derive_fake_tier2_deterministic`. Update `scrub.rs`: add a `derived_fake: Option<Vec<u8>>` field to `Match`, populate it for Tier 2 matches, use it in `generate_fake_for_match`. The `Tier2Pat.fake` field still exists but is no longer read by scrub (removed in step-06).

## Prerequisites
- Step 02 complete (provides `derive_fake_tier2_deterministic` in `src/fake.rs`)
- Step 03 complete (provides `preserve_prefix`, `preserve_suffix`, `charset` fields on `Tier2Pat`)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier2.rs` — `Tier2Pat::try_match` at lines 269–298
- `/home/ignacio/pr/its-classified/src/scrub.rs` — `Match` struct at lines 10–15, `find_best_match` at lines 22–53, `generate_fake_for_match` at lines 55–73
- `/home/ignacio/pr/its-classified/src/fake.rs` — `FakeError` at lines 5–11, `derive_fake_tier2_deterministic` (added by step-02)

## Implementation

### Task 1: Change `Tier2Pat::try_match` signature and body

In `src/tier2.rs`, update `try_match` (starting at line 269):

**Old signature:**
```rust
pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Option<usize>
```

**New signature:**
```rust
pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Result<Option<(usize, Vec<u8>)>, crate::fake::FakeError>
```

**Updated body** — replace everything from the existing `try_match` opening brace to closing brace with:

```rust
pub(crate) fn try_match(&self, payload: &[u8], pos: usize) -> Result<Option<(usize, Vec<u8>)>, crate::fake::FakeError> {
    use crate::crypto::verify_hmac;
    use crate::fake::derive_fake_tier2_deterministic;

    // 1. Start fragment
    if !payload[pos..].starts_with(&self.start_fragment) {
        return Ok(None);
    }

    // 2. Length check
    let end = pos + self.exact_length;
    if end > payload.len() {
        return Ok(None);
    }

    // 3. End fragment
    if !self.end_fragment.is_empty() {
        let ef_start = end - self.end_fragment.len();
        if &payload[ef_start..end] != self.end_fragment.as_slice() {
            return Ok(None);
        }
    }

    // 4. HMAC verification (INV-16: failure → None, caller passes through)
    let candidate = &payload[pos..end];
    if !verify_hmac(&self.hmac_salt, candidate, &self.hmac_digest) {
        return Ok(None);
    }

    // 5. Derive fake from salt + candidate (deterministic, INV-13)
    let prefix_bytes = &candidate[..self.preserve_prefix];
    let suffix_bytes = if self.preserve_suffix > 0 {
        &candidate[candidate.len() - self.preserve_suffix..]
    } else {
        &[]
    };
    let fake = derive_fake_tier2_deterministic(
        &self.hmac_salt,
        candidate,
        prefix_bytes,
        suffix_bytes,
        &self.charset,
        self.exact_length,
    )?;

    Ok(Some((end, fake)))
}
```

### Task 2: Update `Match` struct in `scrub.rs`

In `src/scrub.rs`, locate the `Match` struct. Add `derived_fake` alongside the existing `tier1_capture` field — **do not remove `tier1_capture`**, it is still read by `generate_fake_for_match` for Tier 1 fakes:

```rust
struct Match<'a> {
    start: usize,
    end: usize,
    is_tier1: bool,
    pattern_ref: PatternRef<'a>,
    tier1_capture: Option<crate::segment::MatchCapture>,
    derived_fake: Option<Vec<u8>>,
}
```

### Task 3: Update `find_best_match` in `scrub.rs`

In `src/scrub.rs`, locate `find_best_match` (line 22). The Tier 2 branch currently reads:

```rust
Pattern::Tier2(arc) => arc.try_match(payload, pos).map(|end| Match {
    start: pos,
    end,
    is_tier1: false,
    pattern_ref: PatternRef::Tier2(arc.as_ref()),
}),
```

Replace with:

```rust
Pattern::Tier2(arc) => match arc.try_match(payload, pos) {
    Ok(Some((end, fake))) => Some(Match {
        start: pos,
        end,
        is_tier1: false,
        pattern_ref: PatternRef::Tier2(arc.as_ref()),
        derived_fake: Some(fake),
    }),
    Ok(None) => None,
    Err(e) => return Some(Err(e)),
},
```

This means `find_best_match` also needs to change its return type. Currently it returns `Option<Match<'a>>`. Change to:

```rust
fn find_best_match<'a>(payload: &[u8], pos: usize, patterns: &'a [Pattern]) -> Option<Result<Match<'a>, FakeError>>
```

Update the Tier 1 branch to retain `tier1_capture` and use `capture.end` (note: `def.try_match()` returns `Option<MatchCapture>`, not `Option<usize>`):

```rust
Pattern::Tier1(def) => def.try_match(payload, pos).map(|capture| Match {
    start: pos,
    end: capture.end,
    is_tier1: true,
    pattern_ref: PatternRef::Tier1(def),
    tier1_capture: Some(capture),
    derived_fake: None,
}),
```

Update the candidate comparison and return logic. The full rewritten function:

```rust
fn find_best_match<'a>(payload: &[u8], pos: usize, patterns: &'a [Pattern]) -> Result<Option<Match<'a>>, FakeError> {
    let mut best: Option<Match<'a>> = None;

    for pattern in patterns {
        let candidate = match pattern {
            Pattern::Tier1(def) => def.try_match(payload, pos).map(|capture| Match {
                start: pos,
                end: capture.end,
                is_tier1: true,
                pattern_ref: PatternRef::Tier1(def),
                tier1_capture: Some(capture),
                derived_fake: None,
            }),
            Pattern::Tier2(arc) => match arc.try_match(payload, pos)? {
                Some((end, fake)) => Some(Match {
                    start: pos,
                    end,
                    is_tier1: false,
                    pattern_ref: PatternRef::Tier2(arc.as_ref()),
                    tier1_capture: None,
                    derived_fake: Some(fake),
                }),
                None => None,
            },
        };

        if let Some(candidate) = candidate {
            best = Some(match best {
                None => candidate,
                Some(b) if candidate.end > b.end => candidate,
                Some(b) if candidate.end == b.end && candidate.is_tier1 && !b.is_tier1 => candidate,
                Some(b) => b,
            });
        }
    }

    Ok(best)
}
```

### Task 4: Update `scrub` function call site

In `src/scrub.rs`, the `scrub` function (line 89) calls `find_best_match` in a match statement (line 97):

```rust
match find_best_match(payload, pos, patterns) {
    None => { ... }
    Some(m) => { ... }
}
```

Change to:

```rust
match find_best_match(payload, pos, patterns)? {
    None => { ... }
    Some(m) => { ... }
}
```

The `?` propagates `FakeError` through `ScrubError` (the `From<FakeError>` impl already exists in `types.rs` line 72).

### Task 5: Update `generate_fake_for_match` Tier 2 branch

In `src/scrub.rs`, `generate_fake_for_match` (line 55), the Tier 2 branch currently reads:

```rust
PatternRef::Tier2(pat) => {
    Ok(pat.fake.clone())
}
```

Change to:

```rust
PatternRef::Tier2(_pat) => {
    Ok(m.derived_fake.clone().expect("Tier 2 match must have derived_fake"))
}
```

### Task 6: Update unit tests in `tier2.rs`

In `src/tier2.rs`, update the two tests that call `try_match`:

**`test_tier2_try_match_correct_secret`** (line 341): Change:
```rust
let result = p.try_match(payload, pos);
assert_eq!(result, Some(pos + secret.len()));
```
to:
```rust
let result = p.try_match(payload, pos).expect("try_match should not error");
assert!(result.is_some(), "should match");
let (end, fake) = result.unwrap();
assert_eq!(end, pos + secret.len());
assert_eq!(fake.len(), secret.len(), "fake must have same length as secret");
assert_ne!(fake.as_slice(), secret, "fake must differ from original");
```

**`test_tier2_try_match_hmac_failure_returns_none`** (line 356): Change:
```rust
let result = p.try_match(&payload, 0);
assert!(result.is_none(), "HMAC failure must return None (INV-16)");
```
to:
```rust
let result = p.try_match(&payload, 0).expect("try_match should not error");
assert!(result.is_none(), "HMAC failure must return None (INV-16)");
```

### Task 7: Run full test suite

```sh
cargo nextest run --lib -p its-classified
```

All tests must pass. The Tier 2 branch now derives fakes at match time but the `fake` field is still populated during registration, so `test_register_*` tests that access `p.fake` still compile and pass.

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run --lib -p its-classified 2>&1 | tail -3` shows 0 failures
- [ ] `grep -c "fn try_match.*Result<Option<(usize, Vec<u8>)>" /home/ignacio/pr/its-classified/src/tier2.rs` outputs `1`
- [ ] `grep -c "derived_fake:" /home/ignacio/pr/its-classified/src/scrub.rs` outputs at least `3` (field def + construction sites)
- [ ] `grep -c "derive_fake_tier2_deterministic" /home/ignacio/pr/its-classified/src/tier2.rs` outputs at least `1`
- [ ] `grep -c "pat.fake.clone()" /home/ignacio/pr/its-classified/src/scrub.rs` outputs `0` (no longer reads stored fake)
- [ ] `cargo build -p its-classified 2>&1 | grep -c "error"` outputs `0`

## Reviewer Instructions

You are reviewing Step 05. Verify:
1. Run `cargo nextest run --lib -p its-classified` — all tests must pass
2. Check `src/tier2.rs`: `try_match` returns `Result<Option<(usize, Vec<u8>)>, FakeError>` and calls `derive_fake_tier2_deterministic` after HMAC success
3. Check `src/scrub.rs`: `Match` has `derived_fake: Option<Vec<u8>>`, `find_best_match` returns `Result<Option<Match>, FakeError>`, `generate_fake_for_match` Tier 2 branch uses `m.derived_fake`
4. Verify `Tier2Pat.fake` field still exists (not removed yet)
5. Run `cargo nextest run -p its-classified --test spec 2>&1 | tail -3` — spec tests pass
6. Run `cargo nextest run -p its-classified --test integration 2>&1 | tail -3` — integration tests pass
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier2.rs src/scrub.rs
```
