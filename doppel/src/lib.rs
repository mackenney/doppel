#![warn(missing_docs)]
//! Secret swapping and streaming restoration for arbitrary byte payloads.
//!
//! `doppel` intercepts secrets in outbound payloads, replaces them with
//! structurally-equivalent fakes, and restores the originals in streaming responses.
//!
//! Three operations form the core workflow:
//!
//! 1. **[`swap`]** — scan a payload for secrets matching the supplied [`Pattern`]s,
//!    replace each with a fake, and return the swapped payload, encrypted entries,
//!    and a session key.
//! 2. **Transmit** — send the swapped payload to the external service. Hold the
//!    entries and session key locally.
//! 3. **[`restore`]** — stream the response through the restore function, which
//!    replaces fakes with originals using the session key and entries.
//!
//! # Quick start
//!
//! ```rust
//! use doppel::{swap, restore, patterns};
//!
//! // NOT real credentials — synthetic key matching the Anthropic structural pattern
//! let payload = b"Authorization: sk-ant-api03-w8bVJRHra9S96i3ios_XhbLgzEBjS6qjPUEgiPrWjN2OeICCY1lwhK3Z35Z_jM89STjqSOxHh6GWGkG2R7uv-AohQLmK9AA";
//!
//! // 1. Swap: detect and replace the key before sending to an external service
//! // Note: `patterns::all()` uses ephemeral salts — fakes differ across process restarts.
//! // For persistent fake stability, use `SecretsFile::to_patterns()`.
//! let result = swap(payload, &patterns::all()).unwrap();
//! assert_eq!(result.entries.len(), 1); // one secret detected
//! assert_ne!(result.payload.as_slice(), payload as &[u8]); // key replaced with a fake
//!
//! // result.payload     — send to external service (key replaced with a fake)
//! // result.entries     — keep locally; needed to restore secrets in the response
//! // result.session_key — keep locally; zeroized on drop
//!
//! // 2. Restore: recover the original secret from the response stream
//! let mut response = result.payload.as_slice();
//! let mut restored = Vec::new();
//! restore(
//!     &mut response,
//!     &mut restored,
//!     &result.entries,
//!     &result.session_key,
//! )
//! .unwrap();
//! assert_eq!(restored, payload.as_slice());
//! ```

pub(crate) mod crypto;
pub(crate) mod fake;
pub mod patterns;
pub(crate) mod restore;
pub(crate) mod restore_core;
#[cfg(feature = "async")]
pub(crate) mod restore_stream;
pub(crate) mod secrets;
pub mod secrets_file;
pub mod segment;
pub(crate) mod serde_helpers;
pub(crate) mod swap;
pub mod types;

pub use patterns::Pattern;
pub use restore::{RestoreError, restore};
#[cfg(feature = "async")]
pub use restore_stream::{RestoreStream, restore_stream};
pub use secrets::{SecretError, SecretOptions, register, register_with_options};
pub use secrets_file::{PatternEntry, SecretEntry, SecretsFile, SecretsFileError};
pub use swap::swap;
pub use types::{Entry, SessionKey, SwapError, SwapResult};
