# Step 08: Introduce CharsetBitmap Type

## Context
### Overall Objective
Fix INV-12 violations, add async spec tests, consolidate duplicated unscrub logic, and optimize scrub hot-path with static charsets and Aho-Corasick pre-filtering.

### Phase Context
Wave 3 — First charset optimization step. Currently `CharsetName::resolve()` allocates a fresh `Vec<u8>` on every call. This step introduces a `CharsetBitmap` type with O(1) membership lookup and static instances initialized via `LazyLock`.

### This Step
Create `CharsetBitmap` struct with `[bool; 256]` array for O(1) `contains(b: u8)` lookup. Create `Charset` struct combining bitmap with `&'static [u8]` slice for iteration. Initialize static instances for all built-in charsets.

## Prerequisites
- Wave 2 complete (shared abstraction in place)

## Files to Read Before Starting
- `src/fake.rs` — locate `charsets` module with `alphanumeric()`, `url_safe_base64()`, etc.
- `src/segment.rs` — see how `CharsetName::resolve()` is called

## Implementation
### Task 1: Define CharsetBitmap and Charset types
**File:** `src/fake.rs` (in `charsets` module or new `charset` submodule)

```rust
use std::sync::LazyLock;

/// A 256-element bitmap for O(1) charset membership tests.
#[derive(Clone)]
pub struct CharsetBitmap([bool; 256]);

impl CharsetBitmap {
    /// Create from an iterator of bytes.
    pub const fn empty() -> Self {
        Self([false; 256])
    }

    /// Check if byte is in the charset. O(1).
    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.0[b as usize]
    }
}

/// A charset with both bitmap (for membership) and byte slice (for iteration).
pub struct Charset {
    pub bitmap: CharsetBitmap,
    pub bytes: &'static [u8],
}

impl Charset {
    /// Check if byte is in the charset. O(1).
    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.bitmap.contains(b)
    }

    /// Get the bytes for iteration (e.g., fake generation).
    #[inline]
    pub fn bytes(&self) -> &'static [u8] {
        self.bytes
    }

    /// Number of bytes in charset.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}
```

### Task 2: Create static byte arrays for each charset
**File:** `src/fake.rs`

```rust
// Static byte arrays for iteration (computed at compile time where possible)
static ALPHANUMERIC_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static URL_SAFE_BASE64_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static UPPERCASE_ALPHANUMERIC_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static DIGITS_BYTES: &[u8] = b"0123456789";
static HEX_LOWER_BYTES: &[u8] = b"0123456789abcdef";
```

### Task 3: Create static Charset instances with LazyLock
**File:** `src/fake.rs`

```rust
fn build_bitmap(bytes: &[u8]) -> CharsetBitmap {
    let mut bits = [false; 256];
    for &b in bytes {
        bits[b as usize] = true;
    }
    CharsetBitmap(bits)
}

pub static ALPHANUMERIC: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(ALPHANUMERIC_BYTES),
    bytes: ALPHANUMERIC_BYTES,
});

pub static URL_SAFE_BASE64: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(URL_SAFE_BASE64_BYTES),
    bytes: URL_SAFE_BASE64_BYTES,
});

pub static UPPERCASE_ALPHANUMERIC: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(UPPERCASE_ALPHANUMERIC_BYTES),
    bytes: UPPERCASE_ALPHANUMERIC_BYTES,
});

pub static DIGITS: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(DIGITS_BYTES),
    bytes: DIGITS_BYTES,
});

pub static HEX_LOWER: LazyLock<Charset> = LazyLock::new(|| Charset {
    bitmap: build_bitmap(HEX_LOWER_BYTES),
    bytes: HEX_LOWER_BYTES,
});
```

### Task 4: Add accessor functions
**File:** `src/fake.rs`

Keep existing functions for backward compatibility during migration:
```rust
// Existing (keep for now, will be removed in step-09)
pub fn alphanumeric() -> Vec<u8> { ... }

// New static accessors
pub fn alphanumeric_ref() -> &'static Charset {
    &ALPHANUMERIC
}

pub fn url_safe_base64_ref() -> &'static Charset {
    &URL_SAFE_BASE64
}

pub fn uppercase_alphanumeric_ref() -> &'static Charset {
    &UPPERCASE_ALPHANUMERIC
}

pub fn digits_ref() -> &'static Charset {
    &DIGITS
}

pub fn hex_lower_ref() -> &'static Charset {
    &HEX_LOWER
}
```

### Task 5: Add unit tests
**File:** `src/fake.rs`

```rust
#[cfg(test)]
mod bitmap_tests {
    use super::*;

    #[test]
    fn test_bitmap_matches_vec() {
        // Verify bitmap membership matches the original Vec for all 256 bytes
        let vec_alphanum = alphanumeric();
        for b in 0u8..=255 {
            assert_eq!(
                ALPHANUMERIC.contains(b),
                vec_alphanum.contains(&b),
                "mismatch at byte {}", b
            );
        }
    }

    #[test]
    fn test_charset_bytes_iteration() {
        assert_eq!(ALPHANUMERIC.bytes().len(), 62);
        assert_eq!(DIGITS.bytes().len(), 10);
        assert_eq!(HEX_LOWER.bytes().len(), 16);
    }
}
```

## Acceptance Criteria
- [ ] `cargo build -p its-classified` exits 0
- [ ] `cargo test -p its-classified bitmap_tests` passes
- [ ] `grep "CharsetBitmap" src/fake.rs` returns matches
- [ ] `grep "LazyLock<Charset>" src/fake.rs` returns at least 5 matches
- [ ] `cargo nextest run --workspace` passes (no regressions)
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions
You are reviewing Step 08. Verify:
1. Run `cargo build -p its-classified` — must exit 0
2. Check `CharsetBitmap` has `[bool; 256]` internal representation
3. Check `Charset` has both `bitmap` and `bytes` fields
4. Verify all 5 charsets have static instances: ALPHANUMERIC, URL_SAFE_BASE64, UPPERCASE_ALPHANUMERIC, DIGITS, HEX_LOWER
5. Run `cargo test -p its-classified bitmap` — bitmap tests pass
6. Verify `contains()` is O(1) array lookup

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <reason>"

## Rollback
```
git checkout src/fake.rs
```
