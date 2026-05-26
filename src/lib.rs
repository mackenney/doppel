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
//! // A synthetic Anthropic key embedded in a payload
//! let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
//!
//! // 1. Scrub: detect and replace the key before sending to an external service
//! // Note: `patterns::all()` uses ephemeral salts — fakes differ across process restarts.
//! // For persistent fake stability, use `PatternsFile::into_patterns()`.
//! let result = scrub(payload, &patterns::all()).unwrap();
//! assert_eq!(result.entries.len(), 1); // one secret detected
//! assert_ne!(result.payload.as_slice(), payload as &[u8]); // key replaced with a fake
//!
//! // result.payload     — send to external service (key replaced with a fake)
//! // result.entries     — keep locally; needed to restore secrets in the response
//! // result.session_key — keep locally; zeroized on drop
//!
//! // 2. Unscrub: restore the original secret in the response stream
//! let mut response = result.payload.as_slice();
//! let mut restored = Vec::new();
//! unscrub(
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
pub(crate) mod scrub;
pub(crate) mod segment;
pub mod tier1;
pub(crate) mod tier2;
pub mod types;
pub(crate) mod unscrub;

pub use scrub::scrub;
pub use tier1::patterns;
pub use tier2::{RegistrationError, RegistrationOptions, register, register_with_options};
pub use types::{Entry, Pattern, ScrubError, ScrubResult, SessionKey};
pub use unscrub::{UnscrubError, unscrub};
