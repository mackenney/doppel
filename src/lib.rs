// its-classified: secret scrubbing and streaming restoration.
// See SPEC.md for the complete behavioral contract.

pub(crate) mod crypto;
pub(crate) mod fake;
pub(crate) mod scrub;
pub mod tier1;
pub(crate) mod tier2;
pub mod types;
pub(crate) mod unscrub;

pub use scrub::scrub;
pub use tier1::patterns;
pub use tier2::register;
pub use types::{Entry, Pattern, ScrubError, ScrubResult, SessionKey};
pub use unscrub::{UnscrubError, unscrub};
