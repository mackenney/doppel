# Step 06: Remove `Tier2Pat.fake` Field and `generate_fake_tier2` Function

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 3 (parallel with step-07). After step-05, `scrub.rs` no longer reads `Tier2Pat.fake` — it uses the fake returned by `try_match`. The stored `fake` field and the `generate_fake_tier2` function are now dead code. This step removes both and updates affected tests.

### This Step
Remove the `fake: Vec<u8>` field from `Tier2Pat`. Remove the `generate_fake_tier2` call from `register_with_options_rng`. Remove the `generate_fake_tier2` function from `fake.rs`. Update unit tests that accessed `p.fake` to verify fakes through `try_match` instead.

## Prerequisites
- Step 05 complete (`scrub.rs` uses `derived_fake` from `try_match`, not `pat.fake`)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier2.rs` — `Tier2Pat` struct (the `fake` field), `register_with_options_rng` (the `generate_fake_tier2` call and `fake` in struct construction), and tests
- `/home/ignacio/pr/its-classified/src/fake.rs` — `generate_fake_tier2` function (lines 139–184) and its tests
- `/home/ignacio/pr/its-classified/src/scrub.rs` — verify `pat.fake` is no longer referenced (should already be clean after step-05)

## Implementation

### Task 1: Remove `fake` field from `Tier2Pat`

In `src/tier2.rs`, locate the `Tier2Pat` struct. Remove these lines:

```rust
    /// Pre-generated fake, produced at registration time via OsRng.
    ///
    /// FIXME: should be eliminated. The fake must be derived deterministically
    /// from hmac_salt + candidate at match time (same HMAC-seed-StdRng derivation
    /// as derive_fake_tier1), not stored here. The candidate bytes are available
    /// after HMAC verification in try_match, so derivation is possible there.
    /// Storing the fake couples stability to Pattern lifetime and prevents
    /// patterns file round-trips without a fake field. See Known Gaps in
    /// MASTER_PROGRESS.md.
    pub(crate) fake: Vec<u8>,
```

### Task 2: Remove `generate_fake_tier2` call from `register_with_options_rng`

In `src/tier2.rs`, `register_with_options_rng`, remove:
1. The `use crate::fake::{..., generate_fake_tier2}` import at the top of the file (line 5). Change it to `use crate::fake::FakeError;` (keep only `FakeError` and `charsets` if still used).
2. The local variables `declared_prefix` and `declared_suffix` (lines 232–237) — these were only used by `generate_fake_tier2`. However, check if they're still needed for anything else. They are NOT needed anymore since `preserve_prefix` and `preserve_suffix` usize values are stored directly. Remove them.
3. The `generate_fake_tier2(...)` call and `let fake = ...` (lines 239–246).
4. The `fake` field from the `Tier2Pat` construction.

The end of `register_with_options_rng` should now look like:

```rust
    Ok(Pattern::Tier2(Arc::new(Tier2Pat {
        start_fragment,
        end_fragment,
        exact_length: secret.len(),
        hmac_salt,
        hmac_digest,
        preserve_prefix: pp,
        preserve_suffix: ps,
        charset,
    })))
```

### Task 3: Remove `generate_fake_tier2` function from `fake.rs`

In `src/fake.rs`, remove the entire `generate_fake_tier2` function (lines 139–184) and its doc comment (lines 129–138).

Also remove these tests from `fake.rs` that test the removed function:
- `test_generate_fake_tier2_with_seeded_rng` (line 237)
- `test_generate_fake_tier2_no_secret_bytes_in_variable_region` (line 254)
- `test_generate_fake_tier2_with_preserved_affix` (line 266)

### Task 4: Update `tier2.rs` imports

At the top of `src/tier2.rs`, the import `use crate::fake::{FakeError, charsets, generate_fake_tier2};` should become:

```rust
use crate::fake::{FakeError, charsets};
```

If `charsets` is still used (it is — in the `restrict_charset` logic of `register_with_options_rng`), keep it. If `FakeError` is still used (it is — in `RegistrationError::from`), keep it. Remove `generate_fake_tier2` from the import.

Also check: is `rand::RngCore` still needed at the top of `tier2.rs`? Yes — `register_with_options_rng` still takes `rng: &mut R` for generating `hmac_salt`. Keep it.

### Task 5: Update affected unit tests in `tier2.rs`

**`test_register_discards_secret`** (around line 373): Remove `.chain(&p.fake)` from the field iteration. The test should now read:

```rust
#[test]
fn test_register_discards_secret() {
    let secret = b"super-secret-api-key-value-here!";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(7)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            let middle = &secret[8..secret.len() - 8];
            let all_fields: Vec<u8> = p
                .start_fragment
                .iter()
                .chain(&p.end_fragment)
                .chain(&p.hmac_salt)
                .chain(&p.hmac_digest)
                .copied()
                .collect();
            assert!(
                !all_fields.windows(middle.len()).any(|w| w == middle),
                "middle bytes of secret must not appear verbatim in pattern fields"
            );
        }
        _ => panic!(),
    }
}
```

**`test_register_fake_contains_no_secret_variable_bytes`** (around line 423): Rewrite to derive the fake via `try_match` instead of reading `p.fake`:

```rust
#[test]
fn test_register_fake_contains_no_secret_variable_bytes() {
    let secret = b"deadbeef12345678";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(123)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            let result = p.try_match(secret, 0).expect("try_match error").expect("should match");
            let (_end, fake) = result;
            for window in secret.windows(4) {
                assert!(
                    !fake.windows(4).any(|w| w == window),
                    "fake must not contain secret bytes (variable portion): {:?}",
                    std::str::from_utf8(window).unwrap_or("<binary>")
                );
            }
        }
        _ => panic!(),
    }
}
```

**`test_register_with_preserve_prefix_affix_in_fake`** (around line 448): Rewrite:

```rust
#[test]
fn test_register_with_preserve_prefix_affix_in_fake() {
    let secret = b"MY_ORG_secretbytes1234END";
    let opts = RegistrationOptions {
        preserve_prefix: 7,
        preserve_suffix: 3,
        restrict_charset: false,
    };
    let pat = register_with_options_rng(secret, &opts, &mut StdRng::seed_from_u64(55)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            let result = p.try_match(secret, 0).expect("try_match error").expect("should match");
            let (_end, fake) = result;
            assert!(fake.starts_with(b"MY_ORG_"), "declared prefix must appear in fake");
            assert!(fake.ends_with(b"END"), "declared suffix must appear in fake");
            assert_eq!(fake.len(), secret.len());
        }
        _ => panic!(),
    }
}
```

**`test_register_wide_charset_by_default`** (around line 473): Rewrite:

```rust
#[test]
fn test_register_wide_charset_by_default() {
    let secret = b"my-hex-secret-value-abcd1234";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(77)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            let result = p.try_match(secret, 0).expect("try_match error").expect("should match");
            let (_end, fake) = result;
            let wide = charsets::wide();
            for &b in &fake {
                assert!(wide.contains(&b), "fake byte 0x{b:02x} not in wide charset");
            }
        }
        _ => panic!(),
    }
}
```

**`test_register_restrict_charset_uses_secret_charset`** (around line 489): Rewrite:

```rust
#[test]
fn test_register_restrict_charset_uses_secret_charset() {
    let secret = b"abcdef1234567890abcdef";
    let opts = RegistrationOptions {
        preserve_prefix: 0,
        preserve_suffix: 0,
        restrict_charset: true,
    };
    let pat = register_with_options_rng(secret, &opts, &mut StdRng::seed_from_u64(88)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            let result = p.try_match(secret, 0).expect("try_match error").expect("should match");
            let (_end, fake) = result;
            let allowed: std::collections::BTreeSet<u8> = secret.iter().copied().collect();
            for &b in &fake {
                assert!(
                    allowed.contains(&b),
                    "fake byte 0x{b:02x} not in secret charset under restrict_charset"
                );
            }
        }
        _ => panic!(),
    }
}
```

### Task 6: Verify compilation and tests

```sh
cargo nextest run -p its-classified --lib
cargo nextest run -p its-classified --test spec
cargo nextest run -p its-classified --test integration
```

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run -p its-classified --lib 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test spec 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test integration 2>&1 | tail -3` shows 0 failures
- [ ] `grep -c "pub(crate) fake: Vec<u8>" /home/ignacio/pr/its-classified/src/tier2.rs` outputs `0`
- [ ] `grep -c "generate_fake_tier2" /home/ignacio/pr/its-classified/src/fake.rs` outputs `0`
- [ ] `grep -c "generate_fake_tier2" /home/ignacio/pr/its-classified/src/tier2.rs` outputs `0`
- [ ] `grep -c "p\.fake" /home/ignacio/pr/its-classified/src/tier2.rs` outputs `0`

## Reviewer Instructions

You are reviewing Step 06. Verify:
1. Run `cargo nextest run -p its-classified --lib` — all tests must pass
2. Run `cargo nextest run -p its-classified --test spec` — all spec tests must pass
3. Run `cargo nextest run -p its-classified --test integration` — all integration tests must pass
4. `Tier2Pat` struct has no `fake` field
5. `generate_fake_tier2` function is gone from `fake.rs`
6. No reference to `p.fake` or `pat.fake` in `tier2.rs` or `scrub.rs`
7. All rewritten tests verify fakes through `try_match` instead of stored field
8. Run `cargo clippy -p its-classified --lib 2>&1` — no new warnings
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier2.rs src/fake.rs src/scrub.rs
```
