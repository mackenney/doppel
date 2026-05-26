# Security Round 2 — Protocol & Data Flow Findings

**Date:** 2026-05-25  
**Scope:** scrub/unscrub protocol, fake derivation, HMAC matching, streaming invariants, serialization.

Full detail at `artifacts/investigations/security-round-2-protocol.md`.

---

## Findings by Severity

### Medium

**F1 — INV-10 vs CLI Contract (SPEC inconsistency)**  
`src/main.rs:54-80` | INV-10

INV-10 states: "The session key MUST NOT be written to disk." The CLI contract (INV-21, §CLI) explicitly writes the session key to a caller-specified file with mode 0600. These are contradictory within the same specification. The code correctly implements the CLI contract, but INV-10 as written is violated and carries no carve-out for the CLI path. If the 0600 key file is not deleted after `unscrub` completes (caller's responsibility, per §Known Limitations), the key persists on disk. Coverage tests asserting INV-10 would incorrectly fail against the CLI.

**F2 — INV-9 Gray Area: Tier 2 `fake` exposes start_fragment in Entry JSON**  
`src/tier2.rs:75`, `src/types.rs:28-35` | INV-9

`generate_fake_tier2` is called with `prefix = start_fragment` (first 8 bytes of the registered secret). The resulting fake — stored in `Entry.fake` and serialized as base64 in the entries JSON — begins with those 8 bytes verbatim. Since entries are described as "not sensitive" and can be stored in untrusted locations, any observer of the entries file can decode the `fake` field and recover the first 8 bytes of every Tier 2 registered secret.

The SPEC resolves this intentionally ("Tier 2 fragment exposure is bounded and deliberate") and calls the start_fragment the "prefix" that is visible by design. However, INV-9 ("entries MUST NOT contain plaintext secret bytes in any field or serialized form") provides no such exception. The invariant and the design are contradictory for the Tier 2 case.

**Test gap:** `test_inv9_entries_contain_no_plaintext_secret` checks only that the FULL secret does not appear in the JSON (using `windows(full_len)`). It does not check for the 8-byte fragment and would incorrectly pass for a Tier 2 entry.

---

### Low

**F3 — INV-4 Potential Miss: `MatchKind::LeftmostFirst` skips longer fake when shorter fake is a byte-prefix of it**  
`src/unscrub.rs:41-44` | INV-4

```rust
.match_kind(MatchKind::LeftmostFirst)
```

If `entries[i].fake` (length L1) is a byte-prefix of `entries[j].fake` (length L2, L2 > L1), and the response stream contains the L2-byte string of fake[j] at some position P, Aho-Corasick finds fake[i] at P (lower index wins on same-start-position tie), decrypts the wrong entry, advances past P+L1, and never matches fake[j]. Entry[j]'s original secret is not restored — INV-4 violated.

Fakes for secrets of different lengths can have this prefix relationship. The probability is `(1/|charset|)^L1` — negligible for any realistic key length with CSPRNG fakes. The fix is `MatchKind::LeftmostLongest`, which correctly picks the longest match at each start position.

**F4 — INV-8 Momentary Violation: buffer transiently exceeds max_hold after each read**  
`src/unscrub.rs:54-58` | INV-8

After `buffer.extend_from_slice(&chunk[..n])`, the buffer holds up to `max_hold + CHUNK_SIZE` bytes (max_hold + 4096). The inner loop immediately reduces it back to ≤ max_hold. INV-8 ("MUST NOT hold more than max_hold bytes unemitted at any point") is momentarily exceeded — by up to 4096 bytes — between the `extend_from_slice` call and the first emit. The spirit of the invariant (bounded streaming, no full-response buffering) is satisfied; only the strict letter is not.

**F5 — Plaintext secrets in `seen` HashMap not zeroized on drop**  
`src/scrub.rs:79`, `src/unscrub.rs:91-93` | INV-12 (spirit)

`scrub`'s `seen: HashMap<Vec<u8>, usize>` holds plaintext copies of every distinct detected secret. When `scrub` returns, the HashMap is dropped normally — no zeroization. Similarly, the `Vec<u8>` returned by `decrypt_entry` in `unscrub` is written to output but not zeroized before drop. INV-12 covers "key material" (the session key, which IS correctly zeroized via `ZeroizeOnDrop`), not payload secrets. No strict invariant violation, but secrets linger in heap memory longer than necessary.

---

### Informational

**F6 — Tier 1 fake salt is per-process, not cross-process stable**  
`src/tier1.rs:22-29` | INV-13

The `OnceLock` salt is initialized with a fresh random value on first access in each process. Two separate process invocations (e.g., two CLI `scrub` runs) with the same Tier 1 Pattern and the same secret produce different fakes. Within a single process, INV-13 holds exactly. The SPEC's "within any context where the same Pattern and the same secret appear" covers this, but callers expecting cross-invocation stability will be surprised.

**F7 — Tier 2 charset = exact observed bytes; small charsets yield low-entropy fakes**  
`src/fake.rs:55-58`

`charsets::detect(secret)` returns exactly the set of distinct bytes in the secret. For all-hex, all-lowercase, or UUID-format secrets, the charset is 16-26 characters. A 20-byte fake over 16 chars has ~4 bits/byte of diversity. The code handles `charset.len() <= 1` (fallback to alphanumeric) but not small-charset secrets. No security violation given HMAC-salt uniqueness, but fakes over small charsets are easily enumerable.

**F8 — INV-9 test coverage gap: partial-secret leakage from Tier 2 fake not checked**  
`tests/spec/inv.rs:201-213`

`test_inv9_entries_contain_no_plaintext_secret` only checks whether the FULL secret appears in the JSON. It passes even when the first 8 bytes of a Tier 2 secret appear in base64 in the `fake` field (as documented in F2). A correct Tier 2 INV-9 test would verify that no 8-byte window of the registered secret appears in the serialized JSON.

---

## Non-Findings (explicitly verified)

- **INV-1 leftmost-position semantics**: `scrub` outer loop correctly advances by match length; no in-scope secret can be skipped because of how `find_best_match` is called only at the current `pos`.
- **INV-18 same-position tie-breaking**: `find_best_match` correctly selects longest match with Tier1-wins-on-tie. Logic verified against `candidate.end > b.end` and equal-end Tier1 precedence conditions.
- **INV-14 deduplication key**: `HashMap<Vec<u8>, usize>` uses byte equality; two `Vec<u8>` slices with identical bytes produce the same key.
- **INV-16 HMAC bypass**: `verify_hmac` uses `subtle::ConstantTimeEq`; HMAC covers the entire candidate slice; no bypass path. Structural matches that fail HMAC correctly return `None` from `try_match`.
- **INV-9 session key in serialized entries**: Session key is used only as the XChaCha20Poly1305 cipher key — never stored as a field in `Entry`. Test `test_session_key_not_in_entry_serialization` confirms raw key bytes absent from JSON.
- **INV-19 unscrub exact matching**: Aho-Corasick is built solely from `entries[i].fake` byte slices. No pattern detection, charset scanning, or regex is used.
- **INV-4 chunk boundary (nominal, no prefix collision)**: Sliding window with `safe_end = buffer.len() - max_hold` correctly holds the last `max_hold` bytes and finds fakes straddling any boundary. EOF handling sets `safe_end = buffer.len()` for full flush.
- **INV-17 salt uniqueness**: Each `register_with_rng` call fills 32 fresh bytes; no reuse mechanism.
- **Tier 2 short-secret fragments**: For secrets of length 8-15, start and end fragments together cover all bytes without overlap; HMAC provides final confirmation regardless of fragment coverage.
- **HMAC derivation unambiguity (Tier 1)**: `HMAC(salt, original || attempt_le)` — HMAC is not length-extension-vulnerable; fixed 4-byte `attempt` appended to variable `original` produces no collisions.
