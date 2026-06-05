//! Core types: [`SessionKey`], [`Entry`], [`SwapResult`], and error enums.

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Session key: 32-byte random value, destroyed on drop.
/// Never serialized, never logged. See SPEC.md INV-10, INV-12.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey(Box<[u8; 32]>);

impl SessionKey {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Return the raw 32-byte key. For use in crypto operations only; do not log or serialize.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// No Clone, no Debug, no Display — prevents accidental logging or copying.

/// One substitution record produced by a single swap call.
/// Contains the fake bytes (not secret) and the AEAD-encrypted original secret.
/// See SPEC.md §Entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// The fake bytes that replaced the original secret in the swapped payload.
    #[serde(with = "base64_serde")]
    pub fake: Vec<u8>,
    /// Random 24-byte nonce used for this entry's AEAD encryption.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// AEAD ciphertext: encrypted original secret + 16-byte tag.
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
}

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

/// Result of a swap() call.
pub struct SwapResult {
    /// The input payload with every detected secret replaced by a structurally-equivalent fake.
    pub payload: Vec<u8>,
    /// One entry per distinct secret detected; each entry holds the encrypted original and the fake bytes used.
    pub entries: Vec<Entry>,
    /// Session key needed to decrypt entries during restore. Keep locally; never transmit.
    pub session_key: SessionKey,
}

/// Errors returned by [`swap`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SwapError {
    /// AEAD encryption of a detected secret failed.
    #[error("encryption failed: {msg}")]
    Crypto {
        /// Description of the encryption failure.
        msg: String,
    },
    /// Fake generation for a detected secret failed.
    #[error("fake generation failed: {msg}")]
    Fake {
        /// Description of the generation failure.
        msg: String,
    },
}

impl From<crate::crypto::Error> for SwapError {
    fn from(e: crate::crypto::Error) -> Self {
        SwapError::Crypto { msg: e.to_string() }
    }
}

impl From<crate::fake::FakeError> for SwapError {
    fn from(e: crate::fake::FakeError) -> Self {
        SwapError::Fake { msg: e.to_string() }
    }
}

/// Re-export Pattern from patterns module so callers can reach it via doppel::types::Pattern.
pub use crate::patterns::Pattern;

use crate::serde_helpers::base64_vec as base64_serde;
