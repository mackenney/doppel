# Step 01: Cargo Skeleton

## Context

### Overall Objective
Build `its-classified`: a Rust library + CLI for scrubbing secrets from byte payloads
and restoring them in streaming responses. SPEC.md defines the complete behavioral contract.

### Phase Context
Wave 0 — foundation. Every subsequent step depends on having the correct crate
structure, dependencies, and module stubs in place before any implementation begins.

### This Step
Add all Cargo dependencies, create the `[[bin]]` target, create all source module
stub files, and verify the project compiles clean. No logic is implemented here —
only the skeleton that subsequent steps fill in.

## Prerequisites

None (first step).

## Files to Read Before Starting

- `Cargo.toml` — current state (package only, no deps)
- `src/lib.rs` — current stub (2-line comment)
- `SPEC.md` — understand the full scope
- `AGENTS.md` — coding conventions (no section-separator comments, etc.)

## Implementation

### Task 1: Update Cargo.toml

Replace the `[dependencies]` section with all required dependencies and add the
binary target. Final `Cargo.toml`:

```toml
[package]
name = "its-classified"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "its-classified"
path = "src/main.rs"

[dependencies]
chacha20poly1305 = "0.10"
hmac = "0.12"
sha2 = "0.10"
rand = { version = "0.8", features = ["std", "std_rng"] }
zeroize = { version = "1", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
subtle = "2"
aho-corasick = "1"
clap = { version = "4", features = ["derive"] }

[dev-dependencies]
# rand 0.8 SeedableRng is in the main dep; no extra dev dep needed

[features]
test-e2e = []
```

**Why these crates:**
- `chacha20poly1305 = "0.10"` — provides `XChaCha20Poly1305` (192-bit nonce, no birthday risk)
- `hmac + sha2` — HMAC-SHA256 for Tier 2 verification tokens and fake derivation keying
- `rand 0.8` — `OsRng` for production, `StdRng::seed_from_u64` for deterministic tests
- `zeroize` — `ZeroizeOnDrop` derive for `SessionKey` (INV-12)
- `serde + serde_json` — entries file serialization; JSON for human inspectability
- `base64` — encode binary fields (nonce, ciphertext) in JSON entries
- `subtle` — constant-time byte comparison for HMAC verification (prevents timing attacks)
- `aho-corasick` — multi-string exact matching for `unscrub` streaming engine
- `clap` — CLI arg parsing with derive macros

### Task 2: Create source module stubs

Create each file with a minimal valid Rust comment (no `//` section separators):

**`src/types.rs`** — stub:
```rust
// Core data types: SessionKey, Entry, ScrubResult, Pattern.
```

**`src/crypto.rs`** — stub:
```rust
// Session key generation and per-entry AEAD encrypt/decrypt.
```

**`src/fake.rs`** — stub:
```rust
// Fake generation: keyed derivation for Tier 1 stability, collision avoidance.
```

**`src/tier1.rs`** — stub:
```rust
// Built-in Tier 1 pattern definitions (6 secret classes, INV-22).
```

**`src/tier2.rs`** — stub:
```rust
// Tier 2 registration: HMAC token construction, pattern creation.
```

**`src/scrub.rs`** — stub:
```rust
// Leftmost-longest scrub engine (INV-18) and public scrub() function.
```

**`src/unscrub.rs`** — stub:
```rust
// Aho-Corasick streaming unscrub with bounded hold (INV-8).
```

**`src/main.rs`** — stub:
```rust
fn main() {}
```

### Task 3: Update src/lib.rs to declare modules

```rust
// its-classified: secret scrubbing and streaming restoration.
// See SPEC.md for the complete behavioral contract.

pub mod types;
pub(crate) mod crypto;
pub(crate) mod fake;
pub mod tier1;
pub(crate) mod tier2;
pub(crate) mod scrub;
pub(crate) mod unscrub;

pub use types::{Entry, Pattern, ScrubResult, SessionKey};
```

(These re-exports will fail to compile until the types are defined in subsequent steps.
For now, comment out the `pub use` lines and leave only the `mod` declarations with empty stub files.)

Practical approach: stub `lib.rs` as:
```rust
// its-classified: secret scrubbing and streaming restoration.
// See SPEC.md for the complete behavioral contract.

mod types;
mod crypto;
mod fake;
mod tier1;
mod tier2;
mod scrub;
mod unscrub;
```

### Task 4: Verify Cargo.lock is updated

Run `cargo fetch` to ensure all dependencies resolve and lock file is updated.

## Acceptance Criteria

- [ ] `cargo build` exits 0 (stub files compile clean)
- [ ] `cargo clippy -- -D warnings` exits 0
- [ ] `cargo fetch` exits 0 (all deps downloaded)
- [ ] `ls src/` shows: `lib.rs types.rs crypto.rs fake.rs tier1.rs tier2.rs scrub.rs unscrub.rs main.rs`
- [ ] `grep 'chacha20poly1305' Cargo.toml` finds the dependency line
- [ ] `grep 'aho-corasick' Cargo.toml` finds the dependency line
- [ ] `grep 'test-e2e' Cargo.toml` finds the feature definition

## Reviewer Instructions

You are reviewing Step 01 implementation. Verify:

1. Run `cargo build` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Run `ls src/` — must show all 9 source files
4. Run `grep 'chacha20poly1305\|aho-corasick\|clap\|zeroize\|subtle' Cargo.toml` — must find all 5
5. Run `grep 'test-e2e' Cargo.toml` — must find the feature
6. Run `grep '\[\[bin\]\]' Cargo.toml` — must find the binary target

Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback

`git revert` the step-01 commit. The project reverts to the 2-line stub state.
