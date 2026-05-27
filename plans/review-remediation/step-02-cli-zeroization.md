# Step 02: CLI Zeroization

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 1 — Security fix for INV-12 violation. The CLI currently leaves session key bytes in unzeroized heap allocations (`String`, `Vec<u8>`) after scope ends.

### This Step
Wrap all intermediate key representations in `Zeroizing<T>` so heap memory is cleared on drop. Three changes: (1) `hex_encode` returns `Zeroizing<String>`, (2) `write_key_file` already works via deref, (3) `run_unscrub` wraps `key_hex` and `key_bytes`.

## Prerequisites
- None — Wave 1 step, independent of other security fixes

## Files to Read Before Starting
- `cli/src/main.rs` — locate `hex_encode` (lines ~625-627), `write_key_file` (lines ~598-623), `run_unscrub` (lines ~636-643)
- Verify `zeroize::Zeroizing` is already imported (used in `run_register` around line 229)

## Implementation
### Task 1: Fix `hex_encode` return type
**File:** `cli/src/main.rs`
**Location:** `hex_encode` function (around line 625)

Change:
```rust
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
```

To:
```rust
fn hex_encode(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}
```

### Task 2: Verify `write_key_file` still works
**File:** `cli/src/main.rs`
**Location:** `write_key_file` function

No code changes needed. The `hex_key.as_bytes()` call works via `Deref` coercion. Verify the function still compiles.

### Task 3: Zeroize intermediates in `run_unscrub`
**File:** `cli/src/main.rs`
**Location:** `run_unscrub` function (around line 636)

Change:
```rust
let key_hex = std::env::var("ITS_CLASSIFIED_KEY")
    .map_err(|_| "ITS_CLASSIFIED_KEY environment variable not set")?;
let key_bytes = hex_decode(&key_hex).map_err(|_| "ITS_CLASSIFIED_KEY is not valid hex")?;
let key_array: [u8; 32] = key_bytes
    .try_into()
    .map_err(|_| "ITS_CLASSIFIED_KEY must be 64 hex characters (32 bytes)")?;
let session_key = SessionKey::from_bytes(key_array);
```

To:
```rust
let key_hex = Zeroizing::new(
    std::env::var("ITS_CLASSIFIED_KEY")
        .map_err(|_| "ITS_CLASSIFIED_KEY environment variable not set")?
);
let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
    hex_decode(&key_hex).map_err(|_| "ITS_CLASSIFIED_KEY is not valid hex")?
);
let key_array: [u8; 32] = key_bytes
    .as_slice()
    .try_into()
    .map_err(|_| "ITS_CLASSIFIED_KEY must be 64 hex characters (32 bytes)")?;
let session_key = SessionKey::from_bytes(key_array);
```

Note: `key_array` is a stack-allocated `[u8; 32]` consumed immediately by `from_bytes()`. Stack memory is not a persistent leak vector; zeroizing heap-allocated `String` and `Vec<u8>` is the priority.

## Acceptance Criteria
- [ ] `cargo build -p its-classified-cli` exits 0
- [ ] `cargo nextest run -p its-classified-cli` passes
- [ ] `cargo nextest run -p its-classified-cli --features test-e2e --test e2e` passes
- [ ] `grep -n "Zeroizing<String>" cli/src/main.rs` shows hex_encode return type
- [ ] `grep -n "Zeroizing<Vec<u8>>" cli/src/main.rs` shows key_bytes type annotation
- [ ] `cargo clippy -p its-classified-cli -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 02. Verify:
1. Run `cargo build -p its-classified-cli` — must exit 0
2. Check `cli/src/main.rs` `hex_encode` returns `Zeroizing<String>`
3. Check `cli/src/main.rs` `run_unscrub` has `key_hex: Zeroizing<_>` and `key_bytes: Zeroizing<Vec<u8>>`
4. Run `cargo nextest run -p its-classified-cli --features test-e2e --test e2e` — must pass
5. Verify no plaintext key material passes through unzeroized heap types

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout cli/src/main.rs
```
