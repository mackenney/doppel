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

    pub fn as_bytes(&self) -> &[u8; 32] {
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

/// Result of a scrub() call.
pub struct ScrubResult {
    pub payload: Vec<u8>,
    pub entries: Vec<Entry>,
    pub session_key: SessionKey,
}

/// Re-export Pattern from tier1 so callers can reach it via its_classified::types::Pattern.
pub use crate::tier1::Pattern;

mod base64_serde {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
