# Code Review Summary — its-classified
**Date:** 2026-05-25
**Baseline:** 65/65 tests pass, 0 clippy warnings
**Full review:** `artifacts/fact-checks/code-review.md`

---

## Counts

| Severity | Count |
|---|---|
| BLOCKER | 1 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 6 |

---

## BLOCKER (1)

**Missing `test_inv21` in spec-invariant suite** (`tests/spec/inv.rs`)

INV-21 ("CLI `scrub` MUST create the session key file with mode 0600") has no `test_inv21_*` in the mandatory spec suite. The only test for this invariant is in `tests/e2e/cli.rs::test_e2e_key_file_mode_0600`, which is behind `--features test-e2e` and never runs in the default `cargo nextest run`. A regression in `write_key_file` would be invisible to mandatory CI. Per AGENTS.md, every MUST clause requires a spec-invariant test at `tests/spec/`.

Fix: Add `test_inv21_cli_scrub_key_file_mode_0600` to `tests/spec/inv.rs` (see full review for implementation).

---

## HIGH (2)

**1. `expect()` on `encrypt_in_place` in `crypto.rs:30`**

`encrypt_secret` returns `Entry` (not `Result`), forcing `cipher.encrypt_in_place(...).expect("encryption failed")`. AGENTS.md: "No `unwrap()` on crypto operations — always propagate errors." While XChaCha20Poly1305 encrypt is practically infallible for in-memory data, the design violates the convention and the panic cannot be recovered by callers.

Fix: `encrypt_secret -> Result<Entry, Error>`, add `Error::EncryptionFailed`, propagate through `scrub -> Result<ScrubResult, _>`.

**2. `unwrap()` in `main.rs::hex_decode`**

`std::str::from_utf8(pair).unwrap()` at `main.rs:123` — unwrap in production (non-test) code. If the env var value contains multi-byte UTF-8, a chunk split at byte boundaries can produce invalid UTF-8 pairs.

Fix: Replace with direct byte nibble parsing (no `str::from_utf8` needed at all).

---

## MEDIUM (5)

**3. `InvalidNonce` mapped to `AeadTagFailure` in `unscrub.rs:89-93`**

`decrypt_entry` errors `InvalidNonce` and `AeadTagFailure` are both mapped to `UnscrubError::AeadTagFailure`. Behavior is correct (stream stops, no plaintext emitted) but the error message is wrong for the nonce-corruption case, complicating incident diagnosis.

Fix: Add `UnscrubError::InvalidEntry` variant or map errors distinctly.

**4. `panic!` in fake generation library functions (`fake.rs:96`, `fake.rs:128`)**

`derive_fake_tier1` and `generate_fake_tier2` panic after `MAX_ATTEMPTS = 1000` collision-avoidance retries. Probability is astronomically small, but libraries must not panic — panics cannot be recovered by callers and cross FFI boundaries unsafely.

Fix: Return `Result<Vec<u8>, FakeError>` and propagate.

**5. `AhoCorasick::build().expect()` in `unscrub.rs:42`**

`unscrub` already returns `Result<(), UnscrubError>`. The `expect` on automaton construction converts a recoverable failure to a panic in a library function.

Fix: Add `UnscrubError::BuildFailed` and propagate with `map_err`.

**6. INV-8 buffer bound transiently exceeded**

`unscrub` reads up to `CHUNK_SIZE = 4096` bytes before the inner drain loop. Between the read and the drain, `buffer.len()` can reach `old_hold + 4096`, exceeding `max_hold` momentarily. INV-8 says "at any point during processing." The practical streaming behavior is correct (CHUNK_SIZE is small), but the strict invariant is violated between read and drain.

The `test_inv8_unscrub_bounded_hold` is a proxy test (round-trip success with 1-byte chunks) that doesn't verify the buffer size bound directly.

Fix option: Document the per-chunk transience in the spec, or verify the bound in the test via instrumentation.

**7. Modulo bias in charset sampling (`fake.rs:86`, `fake.rs:120`)**

`(rng.next_u32() as usize) % charset.len()` — non-uniform sampling for charset sizes that don't divide 2^32. Bias is ~0.0015% for alphanumeric (62 chars). Fakes are not secret, so practical impact is zero, but correctness is easily achieved.

Fix: `rng.gen_range(0..charset.len())` from the `rand` crate.

---

## LOW (6)

**8.** `Tier1Def` is `pub` (leaks implementation internals). Should be `pub(crate)` + public accessor.

**9.** `test_inv12_key_material_destroyed_on_drop` is a no-op (`std::mem::size_of::<SessionKey>()`). Doesn't verify absence of `Clone`/`Debug`. Fix: `static_assertions::assert_not_impl_any!(SessionKey: Clone, std::fmt::Debug)`.

**10.** `test_inv17` spec test verifies detection works for two patterns but doesn't verify salt uniqueness (internal field; verified in unit test only). Document the limitation.

**11.** `test_tier1_all_six_classes_present` — `patterns::all()` returns 8 patterns, not 6. Rename to avoid confusion.

**12.** `charset` field in `Tier2Pat` has `#[allow(dead_code)]` without a comment explaining why it's retained after registration. Either document the reason or remove the field.

**13.** INV-18 Tier1-vs-Tier2 tie-break (`is_tier1 && !b.is_tier1`) exists in `scrub.rs` but is not exercised by any test. Add a test case registering an Anthropic-format secret as Tier 2 and verifying Tier 1 wins.

---

## What's Working Well

- `SessionKey` with `ZeroizeOnDrop`, no `Clone`/`Debug` — correct key management (INV-11/12).
- 192-bit XChaCha20Poly1305 random nonces via `OsRng` — correct choice for this protocol.
- `verify_hmac` uses `subtle::ConstantTimeEq` — correct constant-time comparison (INV-16 timing safety).
- `OnceLock` for Tier 1 fake-derivation salts — thread-safe, one-time initialization, enables INV-13 stability.
- Aho-Corasick `LeftmostFirst` for unscrub — exact matching only, no pattern detection (INV-19 by construction).
- Leftmost-longest scrub logic with Tier1-wins-tie correctly implemented (INV-18).
- No key material in `UnscrubError` messages. CLI reads key from env only (INV-20).
- E2E tests cover VC-8, VC-9, and missing-env-var failure. Test vectors are all synthetic.
