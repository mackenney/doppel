# Code Review Fact-Check Summary

**Full report:** `artifacts/fact-checks/code-review-factcheck.md`
**Claims checked:** 14 — **14 CONFIRMED, 0 REFUTED, 0 UNVERIFIABLE**

The code review is fully accurate. Every finding is real and every cited file:line is correct.

---

## CONFIRMED Issues with Fix Locations

### BLOCKER (1)

| # | Finding | File:Line | Fix |
|---|---------|-----------|-----|
| 1 | `test_inv21` missing from spec suite | `tests/spec/inv.rs` after line 399 | Add test spawning the binary and asserting 0600 mode on the key file |

### HIGH (2)

| # | Finding | File:Line | Fix |
|---|---------|-----------|-----|
| 2 | `.expect("encryption failed")` on `encrypt_in_place` | `src/crypto.rs:30` | Change `encrypt_secret` → `Result<Entry, Error>`, add `EncryptionFailed` variant, propagate at `scrub.rs:96` |
| 3 | `from_utf8(pair).unwrap()` in `hex_decode` | `src/main.rs:123` | Replace with direct byte nibble parsing (`hex_nibble` helper) |

### MEDIUM (5)

| # | Finding | File:Line | Fix |
|---|---------|-----------|-----|
| 4 | `InvalidNonce` erased to `AeadTagFailure` | `src/unscrub.rs:89-93` | Match on error variant; add `UnscrubError::InvalidEntry` |
| 5 | `panic!` in fake derivation/generation | `src/fake.rs:96-98, 128` | Return `Result<Vec<u8>, FakeError>` from both functions |
| 6 | `.expect()` on `AhoCorasick::build` | `src/unscrub.rs:42` | `map_err` into new `UnscrubError::BuildFailed` variant |
| 7 | INV-8 transient buffer bound (spec wording) | `src/unscrub.rs:52-66` | Update spec wording or add clarifying comment; no behavioral change needed |
| 8 | Modulo bias in charset sampling | `src/fake.rs:86, 120` | Replace `% charset.len()` with `rng.gen_range(0..charset.len())` |

### LOW (6)

| # | Finding | File:Line | Fix |
|---|---------|-----------|-----|
| 9 | `Tier1Def` is `pub` instead of `pub(crate)` | `src/tier1.rs:8` | Make `pub(crate)`, add `pub fn prefix()` accessor |
| 10 | `test_inv12` is a no-op (`size_of` call) | `tests/spec/inv.rs:237-243` | Use `static_assertions::assert_not_impl_any!(SessionKey: Clone, Debug, Display)` |
| 11 | `test_inv17` doesn't verify salt uniqueness | `tests/spec/inv.rs:325-337` | Compare salts via `Tier2Pat::hmac_salt` or document the unit-test coverage |
| 12 | Test name says "six", 8 patterns exist | `src/tier1.rs:181` | Rename `test_tier1_all_six_classes_present` → `test_tier1_all_required_classes_present` |
| 13 | `#[allow(dead_code)]` on `charset` field | `src/tier2.rs:18-19` | Remove field (fake already generated) or justify retention in comment |
| 14 | INV-18 Tier1-vs-Tier2 tie-break untested | `tests/spec/inv.rs` | Add test registering a Tier2 pattern for a Tier1-matchable string; assert Tier1 wins |

---

## Priority Order for Implementation

1. **test_inv21** (BLOCKER — spec compliance gap)
2. **encrypt_secret → Result** (HIGH — AGENTS.md crypto convention)
3. **hex_decode unwrap** (HIGH — AGENTS.md no-unwrap convention)
4. **InvalidNonce/AeadTagFailure distinction** (MEDIUM — diagnostic correctness)
5. **fake.rs panic → Result** (MEDIUM — library API hygiene)
6. **AhoCorasick expect → propagate** (MEDIUM — same as above)
7. **LOW batch**: test name, dead charset field, Tier1Def visibility, test_inv12, test_inv17, INV-18 test
8. **Spec wording** for INV-8 (editorial only, no code change)
