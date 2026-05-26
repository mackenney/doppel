# step-04: Add library docs and crate-level documentation

## Context

**Overall Objective:** Add minimal library documentation so consumers understand the scrub→unscrub workflow.

**Phase Context:** Wave 3. Pattern opacity and error cleanup are complete.

**This Step:** Add a crate-level `//!` doc block to `src/lib.rs`, add `/// # Examples` to
the key public functions (`scrub`, `unscrub`, `register`), and improve the `patterns::all()`
doc comment.

## Prerequisites

- step-02 and step-03 complete and committed.
- `cargo nextest run` reports 79 passed.

## Files to Read Before Starting

| File | Why |
|------|-----|
| `src/lib.rs` | Add crate-level `//!` doc block at top |
| `src/scrub.rs` | Add `/// # Examples` to `pub fn scrub` |
| `src/unscrub.rs` | Add `/// # Examples` to `pub fn unscrub` |
| `src/tier2.rs` | Add `/// # Examples` to `pub fn register` |
| `src/tier1.rs` | Improve `patterns::all()` doc comment |
| `Cargo.toml` | Verify `[lib]` section exists or add it |

## Implementation

### Task 1: Add `[lib]` section to root `Cargo.toml` (if missing)

Check whether root `Cargo.toml` has a `[lib]` section. If not, add after `[package]`:

```toml
[lib]
name = "its_classified"
```

This makes the crate name explicit for `cargo doc`.

### Task 2: Add crate-level doc block to `src/lib.rs`

Replace the first two lines of `src/lib.rs`:
```rust
// its-classified: secret scrubbing and streaming restoration.
// See SPEC.md for the complete behavioral contract.
```

With a `//!` doc block:

```rust
//! Secret scrubbing and streaming restoration for arbitrary byte payloads.
//!
//! `its-classified` intercepts secrets in outbound payloads, replaces them with
//! structurally-equivalent fakes, and restores the originals in streaming responses.
//!
//! Three operations form the core workflow:
//!
//! 1. **[`scrub`]** — scan a payload for secrets matching the supplied [`Pattern`]s,
//!    replace each with a fake, and return the scrubbed payload, encrypted entries,
//!    and a session key.
//! 2. **Transmit** — send the scrubbed payload to the external service. Hold the
//!    entries and session key locally.
//! 3. **[`unscrub`]** — stream the response through the unscrub function, which
//!    replaces fakes with originals using the session key and entries.
//!
//! # Quick start
//!
//! ```rust
//! use its_classified::{scrub, unscrub, tier1::patterns};
//!
//! // 1. Scrub: detect and replace secrets
//! let payload = b"safe payload with no secrets";
//! let result = scrub(payload, &patterns::all()).unwrap();
//!
//! // result.payload  — scrubbed bytes (send to external service)
//! // result.entries  — encrypted metadata (keep locally)
//! // result.session_key — decryption key (keep locally, zeroized on drop)
//!
//! // 2. Unscrub: restore originals in the response stream
//! let mut response = result.payload.as_slice();
//! let mut restored = Vec::new();
//! unscrub(
//!     &mut response,
//!     &mut restored,
//!     &result.entries,
//!     &result.session_key,
//! )
//! .unwrap();
//! assert_eq!(restored, payload);
//! ```
```

Keep the blank line after the doc block, then the module declarations as before.

### Task 3: Add doc example to `scrub`

**File:** `src/scrub.rs`, immediately before `pub fn scrub(...)` (line 75)

Add:

```rust
/// Scan `payload` for secrets matching `patterns`, replace each with a
/// structurally-equivalent fake, and return the scrubbed payload, encrypted
/// entries, and a fresh session key.
///
/// # Examples
///
/// ```
/// use its_classified::{scrub, tier1::patterns};
///
/// let payload = b"key: sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let result = scrub(payload, &patterns::all()).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// assert_ne!(result.payload, payload.to_vec());
/// ```
```

### Task 4: Add doc example to `unscrub`

**File:** `src/unscrub.rs`, immediately before `pub fn unscrub<R: Read, W: Write>(...)` (line 20)

Add (replace any existing bare doc comment):

```rust
/// Stream `input` to `output`, replacing any fakes found in `entries` with
/// their original plaintext, decrypted using `session_key`.
///
/// # Examples
///
/// ```
/// use its_classified::{scrub, unscrub, tier1::patterns};
///
/// let payload = b"safe content";
/// let result = scrub(payload, &patterns::all()).unwrap();
/// let mut restored = Vec::new();
/// unscrub(
///     &mut result.payload.as_slice(),
///     &mut restored,
///     &result.entries,
///     &result.session_key,
/// )
/// .unwrap();
/// assert_eq!(restored, payload);
/// ```
```

### Task 5: Add doc example to `register`

**File:** `src/tier2.rs`, before `pub fn register(...)` (line 111)

The function already has a doc comment (lines 106–110). Append an `# Examples` section
after the existing text:

```rust
/// Register an arbitrary secret with default options and produce a Tier 2 Pattern.
///
/// Returns `Err` instead of panicking on invalid input. See [`RegistrationError`]
/// for the error conditions. See [`register_with_options`] to customise prefix/suffix
/// preservation or charset restriction.
///
/// # Examples
///
/// ```
/// use its_classified::{register, scrub};
///
/// let secret = b"my-custom-api-token-that-is-long-enough-for-tier2";
/// let pattern = register(secret).unwrap();
/// let result = scrub(secret, &[pattern]).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// ```
```

### Task 6: Improve `patterns::all()` doc comment

**File:** `src/tier1.rs`, line 161

Replace:
```rust
    /// All built-in patterns. Convenient for "scrub everything known".
```

With:
```rust
    /// All built-in Tier 1 patterns.
    ///
    /// Covers: Anthropic (`sk-ant-`), OpenAI classic (`sk-`), OpenAI project
    /// (`sk-proj-`), AWS AKIA, AWS ASIA, GitHub classic (`ghp_`), GitHub
    /// fine-grained (`github_pat_`), and GCP (`AIza`).
```

### Task 7: Verify docs build

```sh
cargo doc -p its-classified --no-deps 2>&1
```

Must exit 0 with no warnings. Fix any broken intra-doc links.

### Task 8: Commit

```sh
cargo fmt --all
git add -A
git commit -m "step-04: add library docs and crate-level documentation"
```

## Acceptance Criteria

1. `cargo nextest run` exits 0, reports exactly 79 tests passed.
2. `cargo doc -p its-classified --no-deps` exits 0, no warnings in output.
3. `cargo clippy --workspace` exits 0 with no warnings.
4. `cargo fmt --all --check` exits 0.
5. `src/lib.rs` starts with `//!` doc block (not plain `//` comments).
6. `cargo test --doc -p its-classified` exits 0 (doc examples compile and pass).

## Reviewer Instructions

Run these commands in order. All must pass.

```sh
cargo nextest run 2>&1 | tail -3
# Expected: "79 tests run: 79 passed, 0 skipped"

cargo doc -p its-classified --no-deps 2>&1 | grep -i warning
# Expected: no output

cargo test --doc -p its-classified 2>&1 | tail -5
# Expected: all doc tests pass

head -1 src/lib.rs
# Expected: "//! Secret scrubbing..."

cargo clippy --workspace 2>&1 | grep -c warning
# Expected: 0
```

## Rollback

```sh
git reset --hard HEAD~1
cargo nextest run   # verify step-02/03 state restored
```
