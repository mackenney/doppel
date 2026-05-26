use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::types::{Entry, SessionKey};

pub fn generate_session_key() -> SessionKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    SessionKey::from_bytes(key)
}

/// Encrypt `plaintext` under `session_key`. Returns an Entry with a fresh nonce.
/// The plaintext MUST be the original secret bytes.
pub(crate) fn encrypt_secret(
    session_key: &SessionKey,
    fake: Vec<u8>,
    plaintext: &[u8],
) -> Result<Entry, Error> {
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    // Key is always exactly 32 bytes; new_from_slice cannot fail here.
    let cipher = XChaCha20Poly1305::new_from_slice(session_key.as_bytes())
        .expect("32-byte key is always valid for XChaCha20Poly1305");
    let mut buffer = plaintext.to_vec();
    // AAD = fake bytes: binds the fake field to the ciphertext tag.
    // Tampering fake after encrypt causes AeadTagFailure at decrypt time.
    cipher
        .encrypt_in_place(&nonce, &fake, &mut buffer)
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(Entry {
        fake,
        nonce: nonce_bytes.to_vec(),
        ciphertext: buffer,
    })
}

/// Decrypt an entry's ciphertext. Returns Err if AEAD tag verification fails.
/// Plaintext is NOT returned on tag failure (INV-6).
pub(crate) fn decrypt_entry(session_key: &SessionKey, entry: &Entry) -> Result<Vec<u8>, Error> {
    let nonce_arr: [u8; 24] = entry
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidNonce)?;
    let nonce = XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new_from_slice(session_key.as_bytes())
        .expect("32-byte key is always valid for XChaCha20Poly1305");
    let mut buffer = entry.ciphertext.clone();
    // AAD must match the fake used at encrypt time; any tamper breaks the tag.
    cipher
        .decrypt_in_place(&nonce, &entry.fake, &mut buffer)
        .map_err(|_| Error::AeadTagFailure)?;
    Ok(buffer)
}

/// Compute HMAC-SHA256(salt, data). Returns 32-byte digest.
pub(crate) fn hmac_sha256(salt: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify HMAC-SHA256(salt, data) == expected in constant time.
/// Returns true if match, false if not. Never leaks timing information.
pub(crate) fn verify_hmac(salt: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = hmac_sha256(salt, data);
    computed.ct_eq(expected).into()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("AEAD tag verification failed")]
    AeadTagFailure,
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("AEAD encryption failed")]
    EncryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Entry;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_session_key();
        let plaintext = b"my-secret-api-key-value";
        let fake = b"sk-fake-aaabbbccc".to_vec();
        let entry = encrypt_secret(&key, fake.clone(), plaintext).unwrap();
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
        let mut entry = encrypt_secret(&key, fake, plaintext).unwrap();
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
        let entry = encrypt_secret(&key, fake, plaintext).unwrap();
        let json = Entry::serialize_entries(&[entry]).unwrap();
        assert!(!json.windows(32).any(|w| w == key.as_bytes().as_slice()));
    }

    #[test]
    fn test_tampered_fake_returns_err() {
        // Fake is bound to the ciphertext via AAD. Replacing fake after
        // encrypt must break the AEAD tag and return Err — no plaintext out.
        let key = generate_session_key();
        let plaintext = b"secret";
        let fake = b"original-fake".to_vec();
        let mut entry = encrypt_secret(&key, fake, plaintext).unwrap();
        entry.fake = b"attacker-trigger".to_vec();
        let result = decrypt_entry(&key, &entry);
        assert!(result.is_err(), "tampered fake must return Err");
    }
}
