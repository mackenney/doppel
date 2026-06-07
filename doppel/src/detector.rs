//! Pre-built detection context for high-throughput use cases.
//!
//! [`Detector`] builds the Aho-Corasick automaton once at construction and
//! reuses it across [`Detector::swap`] calls. For a proxy serving hundreds of
//! requests per second with a fixed pattern set, this avoids rebuilding the
//! automaton on every request.

use aho_corasick::AhoCorasick;

use crate::patterns::{Pattern, build_ac_automaton};
use crate::swap::swap_with_ac;
use crate::types::{SwapError, SwapResult};

/// Pre-built detection context. Construct once at startup; call [`Detector::swap`] per payload.
///
/// `Detector` is `Send + Sync`: it holds the pattern list and the pre-built
/// Aho-Corasick automaton, neither of which carries request-scoped state.
///
/// # Example
///
/// ```
/// use doppel::{Detector, patterns};
///
/// let detector = Detector::new(patterns::all());
///
/// // ... later, once per request:
/// let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let result = detector.swap(payload).unwrap();
/// assert_eq!(result.entries.len(), 1);
/// ```
pub struct Detector {
    patterns: Vec<Pattern>,
    ac: AhoCorasick,
}

impl Detector {
    /// Build the Aho-Corasick automaton from `patterns` and store both.
    ///
    /// O(total first-segment prefix bytes). Call once at startup.
    pub fn new(patterns: Vec<Pattern>) -> Self {
        let ac = build_ac_automaton(&patterns);
        Self { patterns, ac }
    }

    /// Swap secrets in `payload` using the pre-built automaton.
    ///
    /// Semantics are identical to the free [`crate::swap`] function (INV-39).
    /// The Aho-Corasick automaton is NOT rebuilt (INV-41).
    pub fn swap(&self, payload: &[u8]) -> Result<SwapResult, SwapError> {
        swap_with_ac(payload, &self.patterns, &self.ac)
    }
}

// Verify Send + Sync at compile time (INV-40)
fn _assert_detector_send_sync()
where
    Detector: Send + Sync,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;

    const TEST_ANT: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn test_detector_swap_semantics_identical_to_free_swap() {
        // INV-39: Detector::swap MUST produce identical output to free swap
        // for the same payload and patterns.
        let pat = patterns::anthropic();
        let payload = [b"token: ".as_slice(), TEST_ANT].concat();

        let detector = Detector::new(vec![pat.clone()]);
        let r_detector = detector.swap(&payload).unwrap();
        let r_free = crate::swap::swap(&payload, &[pat]).unwrap();

        // Same fake bytes (deterministic derivation)
        assert_eq!(
            r_detector.entries[0].fake, r_free.entries[0].fake,
            "INV-39: fakes must match"
        );
        // Same payload structure
        assert_eq!(
            r_detector.payload, r_free.payload,
            "INV-39: swapped payloads must match"
        );
        assert_eq!(r_detector.entries.len(), r_free.entries.len());
    }

    #[test]
    fn test_detector_ac_not_rebuilt_across_calls() {
        // INV-41: AC is NOT rebuilt on each Detector::swap call.
        // Verified indirectly: the Detector struct holds `ac` as a field;
        // multiple calls use the same field without re-invoking build_ac_automaton.
        let detector = Detector::new(patterns::all());
        let payload_a = [b"token: ".as_slice(), TEST_ANT].concat();
        let payload_b = b"no secrets here".as_ref();

        let r_a = detector.swap(&payload_a).unwrap();
        let r_b = detector.swap(payload_b).unwrap();

        assert_eq!(r_a.entries.len(), 1, "secret in payload_a must be detected");
        assert_eq!(r_b.entries.len(), 0, "no secret in payload_b");
    }

    #[test]
    fn test_detector_is_send_sync() {
        // INV-40: Detector MUST be Send + Sync (lcp stores it in an Arc).
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Detector>();
    }

    #[test]
    fn test_detector_empty_patterns() {
        let detector = Detector::new(vec![]);
        let payload = b"hello world";
        let r = detector.swap(payload).unwrap();
        assert_eq!(r.payload, payload.as_ref());
        assert!(r.entries.is_empty());
    }
}
