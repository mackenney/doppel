# Step 02: Core Types and AEAD Crypto

## Context

### Overall Objective
Build `its-classified`: a Rust library + CLI for scrubbing secrets from byte payloads
and restoring them in streaming responses. Full contract in SPEC.md.

### Phase Context
Wave 1 (parallel with step-03). Establishes the data types that ALL other modules
depend on, plus the AEAD primitive that `scrub` uses to encrypt entries and `unscrub`
uses to decrypt them. INV-5, INV-6, INV-10, INV-11, INV-12 are primarily enforced here.

### This Step
Implement `SessionKey`, `Entry`, `ScrubResult`, and the `Pattern` enum (opaque at
this layer), plus AEAD encryption/decryption using XChaCha20-Poly1305. Implement
`ZeroizeOnDrop` for `SessionKey`. Implement entries serialization to/from JSON
(base64-encoded binary fields).

## Prerequisites

- Step 01 complete (`Cargo.toml` has all deps, stub modules exist)

## Files to Read Before Starting

- `src/types.rs` — current stub
- `src/crypto.rs` — current stub
- `SPEC.md §Security Properties` — AEAD requirements
- `SPEC.md §Behavioral Invariants` INV-5, 6, 9, 10, 11, 12

## Implementation

### Task 1: src/types.rs — Core data types

```rust
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Session key: 32-byte random value, destroyed on drop.
/// Never serialized, never logged. See SPEC.md INV-10, INV-12.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey(Box<[u8; 32]>);

impl SessionKey {
    /// Construct from raw bytes. Used by crypto::generate_session_key() only.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// No Clone, no Debug, no Display — prevents accidental logging or copying.

/// One substitution record produced by a single scrub call.
/// Contains the fake bytes (not secret) and the AEAD-encrypted original secret.
/// See SPEC.md §Entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// The fake bytes that replaced the original secret in the scrubbed payload.
    #[serde(with = "base64_serde")]
    pub fake: Vec<u8>,
    /// Random 24-byte nonce used for this entry's AEAD encryption.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,  // 24 bytes; Vec for serde convenience
    /// AEAD ciphertext: encrypted original secret + 16-byte tag.
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
}

/// Result of a scrub() call.
pub struct ScrubResult {
    pub payload: Vec<u8>,
    pub entries: Vec<Entry>,
    pub session_key: SessionKey,
}

/// Pattern enum is defined here as opaque; variants are in tier1/tier2 modules.
/// Defined as a re-export target; the actual enum variants live in those modules.
// (Pattern enum is declared in tier1.rs/tier2.rs and re-exported from lib.rs
//  once those modules are implemented in steps 04 and 05.)
```

**Base64 serde module** (in `src/types.rs` or a helper `src/serde_helpers.rs`):
```rust
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
```

### Task 2: src/crypto.rs — Session key and AEAD

```rust
use chacha20poly1305::{
    XChaCha20Poly1305, KeyInit, AeadInPlace,
    aead::OsRng,
};
use rand::RngCore;
use crate::types::{Entry, SessionKey};

pub fn generate_session_key() -> SessionKey {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    SessionKey::from_bytes(key.into())
}

/// Encrypt `plaintext` under `session_key`. Returns an Entry with a fresh nonce.
/// The plaintext MUST be the original secret bytes.
pub(crate) fn encrypt_secret(session_key: &SessionKey, fake: Vec<u8>, plaintext: &[u8]) -> Entry {
    use chacha20poly1305::XNonce;
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(session_key.as_bytes()).unwrap();
    let mut buffer = plaintext.to_vec();
    cipher.encrypt_in_place(&nonce, b"", &mut buffer).expect("encrypt failed");
    Entry {
        fake,
        nonce: nonce_bytes.to_vec(),
        ciphertext: buffer,
    }
}

/// Decrypt an entry's ciphertext. Returns Err if AEAD tag verification fails.
/// Plaintext is NOT returned on tag failure (INV-6).
pub(crate) fn decrypt_entry(session_key: &SessionKey, entry: &Entry) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::XNonce;
    let nonce_arr: [u8; 24] = entry.nonce.as_slice().try_into()
        .map_err(|_| Error::InvalidNonce)?;
    let nonce = XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new_from_slice(session_key.as_bytes()).unwrap();
    let mut buffer = entry.ciphertext.clone();
    cipher.decrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|_| Error::AeadTagFailure)?;
    Ok(buffer)
}

#[derive(Debug, thiserror::Error)]   // or a manual Display impl — avoid thiserror dep
pub enum Error {
    #[error("AEAD tag verification failed")]
    AeadTagFailure,
    #[error("invalid nonce length")]
    InvalidNonce,
}
```

**Note on `thiserror`**: If adding `thiserror` dep, add it to Cargo.toml. Alternatively,
define `Error` with a manual `impl std::fmt::Display`. Keep it simple — add `thiserror`
only if already in the dep list. If not, use manual impl.

Actually, update Cargo.toml to add `thiserror = "1"` to avoid verbose manual error impls.
Add to step-01 if missed, or add here as an addendum to Cargo.toml.

### Task 3: Entries serialization helpers

In `src/types.rs`, add:

```rust
impl Entry {
    /// Serialize a slice of entries to JSON bytes.
    pub fn serialize_entries(entries: &[Entry]) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(entries)
    }

    /// Deserialize entries from JSON bytes.
    pub fn deserialize_entries(data: &[u8]) -> Result<Vec<Entry>, serde_json::Error> {
        serde_json::from_slice(data)
    }
}
```

### Task 4: Unit tests for AEAD

In `src/crypto.rs` `#[cfg(test)]`:
```rust
#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = generate_session_key();
    let plaintext = b"my-secret-api-key-value";
    let fake = b"sk-fake-aaabbbccc".to_vec();
    let entry = encrypt_secret(&key, fake.clone(), plaintext);
    assert_eq!(entry.fake, fake);
    assert_eq!(entry.nonce.len(), 24);
    let recovered = decrypt_entry(&key, &entry).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn test_tampered_tag_returns_err() {
    let key = generate_session_key();
    let plaintext = b"secret";
    let fake = b"fake".to_vec();
    let mut entry = encrypt_secret(&key, fake, plaintext);
    // Flip a byte in the ciphertext (tag is appended at the end)
    let last = entry.ciphertext.len() - 1;
    entry.ciphertext[last] ^= 0xFF;
    let result = decrypt_entry(&key, &entry);
    assert!(result.is_err(), "tampered tag must return Err");
}

#[test]
fn test_session_key_not_in_entry_serialization() {
    let key = generate_session_key();
    let plaintext = b"secret";
    let fake = b"fake".to_vec();
    let entry = encrypt_secret(&key, fake, plaintext);
    let json = Entry::serialize_entries(&[entry]).unwrap();
    // Session key bytes must not appear in JSON
    let key_hex = hex::encode(key.as_bytes());  // if hex dep added; else manual check
    // At minimum, the raw key bytes are not present in the JSON
    assert!(!json.windows(32).any(|w| w == key.as_bytes().as_slice()));
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --lib` exits 0
- [ ] Roundtrip test: `encrypt_secret` followed by `decrypt_entry` returns original plaintext
- [ ] Tampered tag test: `decrypt_entry` returns `Err` (not `Ok`), NOT a panic
- [ ] `cargo clippy -- -D warnings` exits 0
- [ ] `SessionKey` has no `Clone` or `Debug` impl (verify: `grep -n 'derive.*Clone' src/types.rs` shows no line for `SessionKey`)
- [ ] Entry serialization produces valid JSON with base64 fields (no raw binary in JSON)

## Reviewer Instructions

You are reviewing Step 02. Verify:

1. Run `cargo nextest run --lib` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Confirm `SessionKey` has `ZeroizeOnDrop` but NOT `Clone` or `Debug` in `src/types.rs`
4. Confirm `decrypt_entry` with tampered ciphertext returns `Err`, not panics (test name: `test_tampered_tag_returns_err`)
5. Run `cargo nextest run --lib -E 'test(tampered)'` — must pass

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` the step-02 commit. Module stubs from step-01 remain.
