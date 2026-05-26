/// A single structural element of a Tier 1 pattern.
///
/// Patterns are sequences of segments matched left-to-right against the payload.
/// Detection records how many bytes each Variable segment consumed; that per-segment
/// length drives fake generation (SPEC.md §Tier 1).
#[derive(Clone, Copy)]
pub(crate) enum Segment {
    /// Fixed bytes that must appear verbatim at the current position.
    /// Reproduced verbatim in every fake (INV-28).
    Literal(&'static [u8]),
    /// A run of bytes all belonging to `charset`, with length in `[min, max]`.
    /// Filled with CSPRNG bytes from `charset` in every fake (INV-29).
    Variable {
        charset: fn() -> Vec<u8>,
        min: usize,
        max: usize,
    },
}

/// Result of a successful Tier 1 pattern match.
pub(crate) struct MatchCapture {
    /// Exclusive end position of the match in the payload.
    pub(crate) end: usize,
    /// Number of bytes consumed by each Variable segment, in segment order.
    /// Length equals the number of Variable segments in the matched pattern.
    pub(crate) variable_lengths: Vec<usize>,
}
