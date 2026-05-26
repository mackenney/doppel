# Step 03: Add Derivation Parameter Fields to `Tier2Pat`

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 1. `Tier2Pat` needs to store the derivation parameters (`preserve_prefix`, `preserve_suffix`, `charset`) so that `try_match` can derive fakes at match time (step-05) and the patterns file can serialize them (step-08). This step adds the fields without changing any behavior — the existing `fake` field remains.

### This Step
Add three new fields to `Tier2Pat` in `src/tier2.rs`: `preserve_prefix: usize`, `preserve_suffix: usize`, and `charset: Vec<u8>`. Update `register_with_options_rng` to populate them. The `fake` field remains (removed in step-06). All existing tests continue to pass.

## Prerequisites
- None (parallel with step-01, step-02, step-04)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/src/tier2.rs` — full file, 512 lines. `Tier2Pat` struct at lines 87–108, `register_with_options_rng` at lines 153–257.

## Implementation

### Task 1: Add fields to `Tier2Pat` struct

In `src/tier2.rs`, locate the `Tier2Pat` struct (line 87). After the `hmac_digest` field (line 97) and before the `fake` field (line 107), add three new fields:

```rust
    /// Number of prefix bytes declared non-secret, preserved verbatim in the fake.
    pub(crate) preserve_prefix: usize,
    /// Number of suffix bytes declared non-secret, preserved verbatim in the fake.
    pub(crate) preserve_suffix: usize,
    /// Resolved charset for fake variable bytes. Wide charset when restrict_charset is false;
    /// detected charset otherwise.
    pub(crate) charset: Vec<u8>,
```

### Task 2: Populate new fields in `register_with_options_rng`

In `src/tier2.rs`, locate the `Tier2Pat` construction in `register_with_options_rng` (around line 249–257). The current code is:

```rust
    Ok(Pattern::Tier2(Arc::new(Tier2Pat {
        start_fragment,
        end_fragment,
        exact_length: secret.len(),
        hmac_salt,
        hmac_digest,
        fake,
    })))
```

Change to:

```rust
    Ok(Pattern::Tier2(Arc::new(Tier2Pat {
        start_fragment,
        end_fragment,
        exact_length: secret.len(),
        hmac_salt,
        hmac_digest,
        preserve_prefix: pp,
        preserve_suffix: ps,
        charset: charset.clone(),
        fake,
    })))
```

Note: `pp`, `ps`, and `charset` are already local variables in the function (lines 163–230). `charset` is a `Vec<u8>` at that point. The `.clone()` is needed because `charset` is used by `generate_fake_tier2` on the next line before it's moved.

Actually, check the order: `charset` is used in the `generate_fake_tier2` call at line 239, which borrows `&charset`. Since the struct construction happens after that call, we can move `charset` directly:

```rust
    let fake = generate_fake_tier2(
        declared_prefix,
        declared_suffix,
        &charset,
        secret.len(),
        secret,
        rng,
    )?;

    Ok(Pattern::Tier2(Arc::new(Tier2Pat {
        start_fragment,
        end_fragment,
        exact_length: secret.len(),
        hmac_salt,
        hmac_digest,
        preserve_prefix: pp,
        preserve_suffix: ps,
        charset,
        fake,
    })))
```

This works because `charset` is borrowed by `generate_fake_tier2` and then moved into the struct. No clone needed.

### Task 3: Add unit test for stored fields

Add a new test to the `#[cfg(test)] mod tests` block in `src/tier2.rs`:

```rust
#[test]
fn test_register_stores_derivation_params() {
    let secret = b"MY_ORG_secretbytes1234END";
    let opts = RegistrationOptions {
        preserve_prefix: 7,
        preserve_suffix: 3,
        restrict_charset: true,
    };
    let pat = register_with_options_rng(secret, &opts, &mut StdRng::seed_from_u64(42)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            assert_eq!(p.preserve_prefix, 7);
            assert_eq!(p.preserve_suffix, 3);
            let detected = crate::fake::charsets::detect(secret);
            assert_eq!(p.charset, detected, "charset must match detected charset");
        }
        _ => panic!("expected Tier2"),
    }
}

#[test]
fn test_register_default_uses_wide_charset() {
    let secret = b"my-arbitrary-secret-value-12345";
    let pat = register_with_rng(secret, &mut StdRng::seed_from_u64(1)).unwrap();
    match &pat {
        Pattern::Tier2(p) => {
            assert_eq!(p.preserve_prefix, 0);
            assert_eq!(p.preserve_suffix, 0);
            assert_eq!(p.charset, crate::fake::charsets::wide());
        }
        _ => panic!("expected Tier2"),
    }
}
```

### Task 4: Run all existing tests

```sh
cargo nextest run --lib -p its-classified -- tier2::tests
```

All existing tests must still pass since `fake` is still populated and no behavior changed.

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run --lib -p its-classified -- tier2::tests 2>&1 | tail -1` shows all tests passing
- [ ] `grep -c "preserve_prefix: usize" /home/ignacio/pr/its-classified/src/tier2.rs` outputs at least `2` (field def + construction or more)
- [ ] `grep -c "preserve_suffix: usize" /home/ignacio/pr/its-classified/src/tier2.rs` outputs at least `2`
- [ ] `grep -c "charset: Vec<u8>" /home/ignacio/pr/its-classified/src/tier2.rs` outputs at least `1`
- [ ] `grep -c "fn test_register_stores_derivation_params" /home/ignacio/pr/its-classified/src/tier2.rs` outputs `1`
- [ ] `cargo build -p its-classified 2>&1 | grep -c "error"` outputs `0`

## Reviewer Instructions

You are reviewing Step 03. Verify:
1. Run `cargo nextest run --lib -p its-classified -- tier2::tests` — all tests must pass
2. Check `src/tier2.rs` `Tier2Pat` struct: contains `preserve_prefix: usize`, `preserve_suffix: usize`, `charset: Vec<u8>` as `pub(crate)` fields
3. Check `register_with_options_rng`: the `Tier2Pat` construction includes `preserve_prefix: pp, preserve_suffix: ps, charset`
4. Verify `fake` field is still present in `Tier2Pat` (not removed yet)
5. Run `cargo clippy -p its-classified --lib 2>&1 | grep -c "warning"` — 0 new warnings
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- src/tier2.rs
```
