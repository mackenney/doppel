# Step 01 — Rust source doc fixes

**Wave:** 0 (parallel with step-02 and step-03)
**Status:** ⬜ pending

## Context

The `spec-unified-pattern` branch introduced a unified Pattern model, v3 file format, 27
built-ins, `Detector` type, and new registration API. Rust source doc comments were not
updated to reflect these changes. This step corrects 13 targeted edits across 8 files.

## Prerequisites

- Working directory: `/home/ignacio/pr/doppel/.wt/spec-unified-pattern`
- No prior steps required

## Files to read before editing

Read each file to get current `LINE#HASH` anchors before making edits:

1. `doppel/src/secrets.rs` — lines 50–56 (TooShort variant)
2. `doppel/src/secrets_file.rs` — lines 22–24, 94–114, 162–168
3. `doppel/src/segment.rs` — lines 27–34, 157–161
4. `doppel/src/types.rs` — lines 6–10, 22–24, 77–80
5. `doppel/src/lib.rs` — lines 7–16
6. `doppel/src/swap.rs` — lines 49–64
7. `doppel/src/restore.rs` — lines 36–62
8. `doppel/src/restore_stream.rs` — lines 14–24, 40–54

## Implementation tasks

### 1 — `doppel/src/secrets.rs`: TooShort error message

**Current** (around line 55):
```rust
/// Secret is empty or shorter than `anchor_len`.
#[error("secret is empty; registration requires at least 1 byte")]
TooShort,
```

**Problem:** The message only describes the empty-secret path. The variant is also returned
when `secret.len() < opts.anchor_len` (default 3), which is not "requires at least 1 byte".

**Fix — replace the `#[error]` attribute text:**
```rust
/// Secret is empty or shorter than `anchor_len`.
#[error("secret too short for the given anchor_len")]
TooShort,
```

Leave the `///` doc comment line unchanged; only the `#[error(...)]` string changes.

### 2 — `doppel/src/secrets_file.rs`: `PatternEntry` struct doc

**Current** (around line 23):
```rust
/// A pattern entry: identifier, salt, optional digests, and segment list.
```

**Fix — replace that single doc line with two lines:**
```rust
/// On-disk TOML (version 3) serialization form for a single pattern entry.
/// Holds an identifier, 32-byte salt, optional HMAC digests, and ordered segment definitions.
```

### 3 — `doppel/src/secrets_file.rs`: `serialize` method description

**Current** (around line 95):
```rust
/// Serialize to TOML bytes.
```

**Fix:**
```rust
/// Serialize to TOML version 3 bytes.
```

### 4 — `doppel/src/secrets_file.rs`: `deserialize` method description

**Current** (around line 105):
```rust
/// Deserialize from TOML bytes with validation.
```

**Fix:**
```rust
/// Deserialize from TOML version 3 bytes with validation.
```

### 5 — `doppel/src/secrets_file.rs`: `to_patterns` method doc

**Current** (around lines 163–167):
```rust
/// Convert to runtime [`Pattern`] values.
///
/// # Errors
///
/// Returns [`SecretsFileError::InvalidSegment`] if a segment definition is malformed.
```

**Fix — append one sentence after the first line** (before the blank line preceding `# Errors`):
```rust
/// Convert to runtime [`Pattern`] values.
///
/// Salts are read from the file entries and remain stable across process restarts.
/// This differs from [`patterns::all`] which generates a fresh ephemeral salt each
/// time — important when you need the same secret to produce the same fake across runs.
///
/// # Errors
///
/// Returns [`SecretsFileError::InvalidSegment`] if a segment definition is malformed.
```

### 6 — `doppel/src/segment.rs`: `BuiltinSegment::Opaque` dead_code comment

**Current** (around line 29):
```rust
    #[allow(dead_code)]
    Opaque {
```

**Fix — add an inline comment on the `#[allow]` line explaining why:**
```rust
    // Built-in patterns currently use only Literal and Variable; Opaque is reserved for completeness.
    #[allow(dead_code)]
    Opaque {
```

### 7 — `doppel/src/segment.rs`: `CharsetName` doc — add `wide`

**Current** (around lines 158–160):
```rust
/// Named character set for Variable segments.
///
/// Maps 1:1 to the charset names in SPEC.md §Patterns File line 90:
/// `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`, `digits`, `hex_lower`.
```

**Fix — add `wide` to the list:**
```rust
/// Named character set for Variable segments.
///
/// Maps 1:1 to the charset names in SPEC.md §Patterns File:
/// `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`, `digits`, `hex_lower`, `wide`.
```

(`wide` = 92 printable ASCII bytes: 0x21–0x7E excluding `"` and `\`; used as default for
registered-secret variable segments.)

### 8 — `doppel/src/types.rs`: `SessionKey` — move source comment to doc comment

**Current** (around lines 6–10 and 22–24):
```rust
/// Session key: 32-byte random value, destroyed on drop.
/// Never serialized, never logged. See SPEC.md INV-10, INV-12.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey(Box<[u8; 32]>);
...
// No Clone, no Debug, no Display — prevents accidental logging or copying.
```

**Fix — move the comment to a `///` doc line appended after the existing struct doc:**
1. Replace `// No Clone, no Debug, no Display — prevents accidental logging or copying.`
   with a blank line (just remove the comment line, it becomes a blank line between the
   `SessionKey` impl block and the `Entry` struct).
2. Add the text as a `///` line on the struct:

```rust
/// Session key: 32-byte random value, destroyed on drop.
/// Never serialized, never logged. See SPEC.md INV-10, INV-12.
///
/// `Clone`, `Debug`, and `Display` are intentionally not derived — prevents accidental
/// logging or copying of the key material.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey(Box<[u8; 32]>);
```

And remove (or blank) the old `// No Clone...` line.

### 9 — `doppel/src/types.rs`: `SwapResult` doc — note `#[non_exhaustive]`

**Current** (around line 78–79):
```rust
/// Result of a swap() call.
#[non_exhaustive]
pub struct SwapResult {
```

**Fix — expand the doc to mention non-exhaustive:**
```rust
/// Result of a [`swap`] call.
///
/// Marked `#[non_exhaustive]`: struct-update syntax (`SwapResult { .., ..other }`) will not
/// compile; construct via `swap()` only.
///
/// [`swap`]: crate::swap
#[non_exhaustive]
pub struct SwapResult {
```

### 10 — `doppel/src/lib.rs`: crate-level prose — add `Detector` mention

**Current** (crate-level module doc, around lines 7–16):
```
//! Three operations form the core workflow:
//!
//! 1. **[`swap`]** — scan a payload for secrets matching the supplied [`Pattern`]s, ...
//! 2. **Transmit** — ...
//! 3. **[`restore`]** — ...
```

**Fix — add a paragraph after the numbered list** (before `//! # Quick start`):
```
//! For repeated swap calls against the same fixed pattern set, use [`Detector`] to
//! pre-build the Aho-Corasick automaton once and reuse it across calls; this avoids
//! rebuilding the automaton on every request.
```

Locate the blank `//!` line after item 3 and insert this paragraph there (keep one blank
line before `# Quick start`).

### 11 — `doppel/src/swap.rs`: free `swap` doc — add `Detector` link

**Current** (around lines 50–53):
```rust
/// Scan `payload` for secrets matching `patterns`, replace each with a
/// structurally-equivalent fake, and return the swapped payload, encrypted
/// entries, and a fresh session key.
```

**Fix — append a sentence after the opening description** (before the `# Examples` section):
```rust
/// Scan `payload` for secrets matching `patterns`, replace each with a
/// structurally-equivalent fake, and return the swapped payload, encrypted
/// entries, and a fresh session key.
///
/// For repeated calls with a fixed pattern set, prefer [`Detector`] to avoid
/// rebuilding the Aho-Corasick automaton on every call.
///
/// [`Detector`]: crate::Detector
```

### 12 — `doppel/src/restore.rs`: `restore` doc — add streaming and split-fake notes

**Current** (around lines 37–38):
```rust
/// Stream `input` to `output`, replacing any fakes found in `entries` with
/// their original plaintext, decrypted using `session_key`.
```

**Fix — expand the description paragraph:**
```rust
/// Stream `input` to `output` incrementally, replacing any fakes found in `entries`
/// with their original plaintext, decrypted using `session_key`.
///
/// Processes input in fixed-size chunks with a sliding hold window bounded by the
/// longest fake across all entries — output is emitted as soon as bytes are safe to
/// flush, not only at the end. Fakes split across chunk boundaries are handled
/// correctly; partial matches are held in the window until resolved.
```

### 13 — `doppel/src/restore_stream.rs`: `RestoreStream` and `restore_stream` docs

**`RestoreStream` doc** (around lines 14–24): Add `Send` note and split-fake note.

**Current:**
```rust
/// Async stream adapter that restores swapped secrets as bytes flow through.
///
/// Constructed via [`restore_stream`]. Applies the same sliding-window
/// algorithm as the synchronous [`restore`] function: fakes are replaced
/// with decrypted originals; all other bytes are forwarded unchanged.
///
/// The stream terminates with [`RestoreError::AeadTagFailure`] if a fake is
/// matched but its AEAD tag does not verify. No plaintext is emitted for a
/// failing entry (INV-5/INV-6).
///
/// [`restore`]: crate::restore
```

**Fix — insert two additional notes:**
```rust
/// Async stream adapter that restores swapped secrets as bytes flow through.
///
/// Constructed via [`restore_stream`]. Applies the same sliding-window
/// algorithm as the synchronous [`restore`] function: fakes are replaced
/// with decrypted originals; all other bytes are forwarded unchanged.
/// Fakes split across [`Bytes`] chunk boundaries are handled correctly.
///
/// The stream terminates with [`RestoreError::AeadTagFailure`] if a fake is
/// matched but its AEAD tag does not verify. No plaintext is emitted for a
/// failing entry (INV-5/INV-6).
///
/// `RestoreStream<S>` is `Send` when `S: Send`.
///
/// [`restore`]: crate::restore
```

**`restore_stream` function doc** (around lines 42–63): Add split-fake note near the
algorithm description.

**Current:**
```
/// Each [`Bytes`] chunk from `inner` is processed through a sliding-window
/// algorithm: fakes present in `entries` are replaced with their decrypted
/// originals using `session_key`; all other bytes are forwarded unchanged.
```

**Fix — add "Fakes split across chunk boundaries are handled correctly." after the second
sentence in that paragraph:**
```
/// Each [`Bytes`] chunk from `inner` is processed through a sliding-window
/// algorithm: fakes present in `entries` are replaced with their decrypted
/// originals using `session_key`; all other bytes are forwarded unchanged.
/// Fakes split across chunk boundaries are handled correctly.
```

## Acceptance criteria

```sh
cd /home/ignacio/pr/doppel/.wt/spec-unified-pattern

# All doc tests pass (includes crate-level example in lib.rs):
cargo test --doc --workspace

# No clippy warnings:
cargo clippy --workspace --all-targets -- -D warnings

# Full test suite passes:
cargo nextest run --workspace
```

All three commands must exit 0.

## Reviewer instructions

After the worker completes, verify:

1. `SecretError::TooShort` `#[error]` text is `"secret too short for the given anchor_len"`.
2. `PatternEntry` doc starts with "On-disk TOML (version 3) serialization form".
3. `serialize` doc says "TOML version 3 bytes".
4. `deserialize` doc says "TOML version 3 bytes with validation".
5. `to_patterns` doc mentions stable salts vs `patterns::all()` ephemeral salts.
6. `BuiltinSegment::Opaque` has an inline comment before `#[allow(dead_code)]`.
7. `CharsetName` doc includes `wide` in the charset list.
8. `SessionKey` struct has a `///` doc comment about no Clone/Debug/Display; the old `//` comment is gone.
9. `SwapResult` doc mentions `#[non_exhaustive]` and struct-update syntax.
10. `lib.rs` crate doc mentions `Detector` for high-throughput use.
11. `swap` function doc has a "prefer `Detector`" note.
12. `restore` function doc mentions incremental processing and split-fake handling.
13. `RestoreStream` doc mentions split-fake handling and `Send`.
14. `restore_stream` function doc mentions split-fake handling.
15. No section-separator comments introduced (`// ---`, `// ===`, etc.).
