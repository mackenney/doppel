# Progress

## Status
In Progress

## Tasks
- [x] Fact-check claims about error types and test counts → /tmp/fc-errors-testcount.md
- [x] Fact-check claims about Cargo/test structure (binary move, deps, CARGO_BIN_EXE) → /tmp/fc-cargo-tests.md
- [x] Fact-check Pattern type claims (step-02 pre-implementation) → /tmp/fc-pattern-types.md
- [x] Fact-check claims about Cargo/test structure (binary move, deps, CARGO_BIN_EXE) → /tmp/fc-cargo-tests.md

## Files Changed
- /tmp/fc-errors-testcount.md (written)
- /tmp/fc-cargo-tests.md (written)
- /tmp/fc-pattern-types.md (written)
- /tmp/fc-cargo-tests.md (written)

## Notes
All 8 claims CONFIRMED. 79 tests pass (26 spec / 13 integration / 40 unit). FakeError is pub inside pub(crate) mod fake. crypto::Error is pub inside pub(crate) mod crypto. ScrubError has #[from] at types.rs:60,62 with no #[non_exhaustive]. ? on scrub.rs:97-98 survives manual From impls. tier2.rs:72 From<FakeError> impl survives pub(crate) change. 3 CLI spec tests confirmed at inv.rs:411,430,469. UnscrubError is pub-exported and leaks aho_corasick::BuildError.

Cargo/test structure fact-check (2nd batch): Claim 1 PARTIAL (main.rs also has top-level `use clap::` and `use std::path::` — not only its_classified — but zero content changes still confirmed). Claims 2,3,5,6,7 CONFIRMED. Claim 4 PARTIAL (only 2 of 3 CLI spec functions use tempfile::tempdir; test_inv20 does not). Claim 8 PARTIAL (rand+zeroize in [dev-dependencies] are redundant — both already in [dependencies] — but harmless to keep; no integration test uses rand directly).

step-02 Pattern-type fact-check (7 claims, all CONFIRMED): Pattern enum at tier1.rs:127 with #[derive(Clone)] only (no #[non_exhaustive]). Tier1Def.prefix is sole pub field. All 6 Tier2Pat fields are pub. #[non_exhaustive] is safe for same-crate code (scrub.rs match unaffected). test_inv22 at inv.rs:514 is the only external test accessing d.prefix. All 8 synthetic test vectors structurally valid (correct prefix, length in [min,max], charset A is valid in all three charsets).
