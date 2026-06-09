# Follow-up request: Detector type (post spec-unified-pattern)

**To be actioned after `spec-unified-pattern` plan completes.**

## What is needed

`lcp` (llm-cache-proxy) needs a `Detector` type in doppel so it can pre-build the
Aho-Corasick automaton once at startup rather than rebuilding it on every proxied
request.

Currently `swap(payload, &patterns)` rebuilds the AC automaton from patterns on
every call. For a proxy that handles hundreds of requests per second with a fixed
pattern set loaded at startup, this is wasted work.

## Proposed API

```rust
/// Pre-built detection context. Construct once; call swap per payload.
pub struct Detector {
    patterns: Vec<Pattern>,  // the unified Pattern type from spec-unified-pattern
    ac: AhoCorasick,         // built once in Detector::new
}

impl Detector {
    /// Build the AC automaton from pattern first-segment bytes. O(prefix bytes), once.
    pub fn new(patterns: Vec<Pattern>) -> Self { ... }

    /// Swap secrets using the pre-built automaton. Identical semantics to free `swap`.
    pub fn swap(&self, payload: &[u8]) -> Result<SwapResult, SwapError> { ... }
}
```

`Detector` MUST be `Send + Sync` (lcp stores it in an `Arc` shared across async handlers).

## Implementation sketch

1. Create `doppel/src/detector.rs`.
2. In `lib.rs`, extract the AC-using inner swap logic into `pub(crate) fn swap_with_ac(payload, patterns, ac)`.
3. `swap` free function builds AC then calls `swap_with_ac`.
4. `Detector::swap` reuses the pre-built AC by calling `swap_with_ac` directly.
5. Re-export `Detector` from `lib.rs`.

## SPEC additions needed

In `SPEC.md §Core Mental Model`:
- Mention `Detector` as a fourth abstraction alongside Pattern, swap, restore.

Add `§Detector` section before `§Behavioral Invariants` with:
- `Detector::new` builds AC once (O(total prefix bytes)).
- `Detector::swap` semantics identical to free `swap` (new INV-39).
- `Detector` is `Send + Sync` (new INV-40).
- AC is NOT rebuilt on `Detector::swap` calls (new INV-41).

## Why this depends on spec-unified-pattern

`Detector::new` calls `pattern.first_segment_bytes()` which requires the unified
`Pattern` struct (added in step-03 of spec-unified-pattern). It cannot be built
on top of the old `Pattern` enum.

## Requester

lcp (llm-cache-proxy) at `/home/ignacio/pr/llm-cache-proxy` — see
`crates/lcp-server/src/ext/doppel.rs` `DoppelExt::new` and lcp's root `SPEC.md`
`[extensions.doppel]` section for context.
