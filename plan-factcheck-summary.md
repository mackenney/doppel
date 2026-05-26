# Plan Fact-Check Summary — initial-implementation

**Full report:** `artifacts/fact-checks/plan-factcheck.md`
**Claims checked:** 34 — **29 confirmed, 1 refuted, 3 partial, 1 unverifiable**

---

## REFUTED (1)

**Step-09 acceptance criterion claims 23 `test_invN_*` functions; only 22 are defined.**

- Step-09 Task 2 implements tests for INV-1 through INV-20, INV-22, INV-23 — exactly 22 functions.
- No `test_inv21` is defined anywhere in `tests/spec/inv.rs`.
- Both the acceptance criterion ("All 23 test_invN_* functions present") and the reviewer check (`grep -c "fn test_inv" tests/spec/inv.rs` — must return 23) would **fail**.
- INV-21 (0600 key file mode) is correctly covered by step-08 and step-11 per the PROGRESS.md table, but the spec-test gap remains. A `test_inv21_cli_key_file_mode_0600` test should be added to `tests/spec/inv.rs`, or the acceptance criterion should be corrected to "≥22 (INV-21 is CLI-only, covered by e2e tests)".

---

## PARTIAL (3)

**P1 — Step-07 Task 2 initial code: `entries[entry_idx]` won't compile (aho-corasick 1.x)**
- `m.pattern()` returns `PatternID`, not `usize`; `Vec<Entry>` can't be indexed by `PatternID`.
- The "Simplified correct structure" at the end of Task 2 **is correct** (`entry_idx.as_usize()`).
- Risk: a worker stopping at the first code block gets a compile error. The revised approach must be used.

**P2 — Step-04 / step-05 circular source dependency within Wave 2**
- Step-04 imports `Tier2Pat` from `tier2.rs` (step-05's output). Both are Wave 2 and declared parallelizable.
- The dependency is acknowledged in step-05's prerequisites but no explicit resolution (e.g., stub `Tier2Pat` in step-04) is provided.
- Risk: if implemented strictly in parallel as specified, the first to compile will fail until the other's type is present.

**P3 — `thiserror` missing from step-01 Cargo.toml**
- Step-02's `crypto::Error` uses `#[derive(Debug, thiserror::Error)]` but `thiserror = "1"` is not in the step-01 Cargo.toml listing.
- Step-02 notes "update Cargo.toml to add `thiserror = '1'`" but the step-01 acceptance criteria don't check for it.
- Risk: a worker following step-01 verbatim produces a Cargo.toml that causes a step-02 compile error.

---

## All Other Claims: CONFIRMED

- All 11 crate version constraints resolve on crates.io: `chacha20poly1305 0.10.1`, `hmac 0.12.1`, `sha2 0.10.9`, `rand 0.8.6`, `zeroize 1.8.x`, `serde 1.x`, `serde_json 1.x`, `base64 0.22.1`, `subtle 2.6.1`, `aho-corasick 1.1.4`, `clap 4.x` — all confirmed by `cargo fetch`.
- XChaCha20-Poly1305 nonce: 192-bit = 24 bytes confirmed (`XNonce = GenericArray<u8, U24>` in lib.rs).
- aho-corasick 1.x: `builder()`, `MatchKind::LeftmostFirst`, `m.pattern().as_usize()`, `ac.find(&buffer)` all confirmed from source.
- `rand 0.8` `StdRng::seed_from_u64` confirmed as a default `SeedableRng` method in rand_core 0.6.4.
- `zeroize::ZeroizeOnDrop` derive confirmed in zeroize_derive 1.4.3.
- `base64::engine::general_purpose::STANDARD` and `Engine` trait confirmed in base64 0.22.1.
- All 23 SPEC.md invariants are covered by at least one step (per PROGRESS.md table).
- All acceptance criteria use runnable, observable commands.
- Wave dependency ordering is internally consistent.
