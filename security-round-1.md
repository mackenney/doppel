# Security Round 1 — Key Material & Cryptography: Findings

Date: 2026-05-25  
Full artifact: `artifacts/investigations/security-round-1-crypto.md`

---

## Finding Summary

| ID | Severity | INV | Location | Title |
|----|----------|-----|----------|-------|
| F1 | **HIGH** | INV-12 | `crypto.rs:13-15`, `main.rs:94-100`, `types.rs:11-13` | Unzeroized session key copies on generation and load paths |
| F2 | **MEDIUM** | — | `crypto.rs:33`, `crypto.rs:55` | `fake` field excluded from AEAD AAD — entry integrity not bound |
| F3 | **MEDIUM** | INV-12 (spirit) | `scrub.rs:79-101` | `seen` HashMap holds plaintext secrets unzeroized |
| F4 | LOW | INV-12 (spirit) | `tier2.rs:10-24` | `Tier2Pat` secret fragments not zeroized on drop |
| F5 | LOW | — | `tier2.rs:26-28` | Tier 2 fully exposes secrets ≤ 16 bytes; no minimum enforced |
| F6 | LOW | — | `fake.rs:2`, `fake.rs:89` | `StdRng` algorithm not CSPRNG-stable across `rand` versions |
| F7 | INFO | — | various | Additional unzeroized `key_hex` String in `write_key_file` |
| F8 | INFO | — | `unscrub.rs:11-12` | Error message leaks `entry_index` on AEAD failure |

---

## F1 — HIGH: Unzeroized session key copies (INV-12)

**SPEC INV-12**: "All key material MUST be destroyed (overwritten with zeros or equivalent) when the session key's response cycle ends."

### Generation path (`crypto.rs:12-16`)
```rust
let mut key = [0u8; 32];      // stack frame; holds key material
OsRng.fill_bytes(&mut key);
SessionKey::from_bytes(key)   // moves key; stack NOT zeroed afterward
```
`SessionKey::from_bytes` does `Box::new(bytes)` — copies 32 bytes from stack to heap. Rust moves don't zero source memory. The dead stack frames of both `generate_session_key` and `from_bytes` contain the key after the call returns. Only the `Box`-allocated heap copy is zeroed by `ZeroizeOnDrop`.

### Load path (`main.rs:94-100`)
```rust
let key_hex   = std::env::var("ITS_CLASSIFIED_KEY")?;  // String on heap, NEVER zeroized
let key_bytes = hex_decode(&key_hex)?;                  // Vec<u8> on heap, NEVER zeroized
let key_array: [u8; 32] = key_bytes.try_into()?;       // stack array, NOT zeroized after move
let session_key = SessionKey::from_bytes(key_array);    // another stack copy in from_bytes
```
Four live copies: `key_hex` (heap), `key_bytes` backing allocation (heap), `key_array` (stack), `from_bytes`' `bytes` parameter (stack). None are zeroed.

**Attack scenario**: Core dump, OOM report, or `/proc/<pid>/mem` snapshot taken any time after key loading captures the 32-byte key in at least 2-4 heap/stack locations even after `SessionKey` is dropped and the `Box` is properly zeroed.

**Note**: `test_inv11_session_key_zeroized_on_drop` only verifies the `ZeroizeOnDrop` trait bound — it does NOT verify these intermediate copies. The test passes today despite the violation.

**Fix**: Use `zeroize::Zeroizing<Vec<u8>>` for `key_bytes`; `Zeroizing<String>` for `key_hex`; zeroize `key_array` explicitly with `key_array.zeroize()` after `from_bytes`. For `generate_session_key`, write directly into the `Box` heap allocation to eliminate the stack-copy transfer.

---

## F2 — MEDIUM: `fake` field excluded from AEAD AAD

**File**: `crypto.rs:33`, `crypto.rs:55`

Both `encrypt_in_place` and `decrypt_in_place` use empty AAD (`b""`). The AEAD tag authenticates `(nonce, ciphertext)` only — NOT the `fake` field in the same `Entry`.

**Active attacker scenario** (no session key required, only write access to `entries.json`):

1. `scrub` writes `entries.json` via `std::fs::write()` — default umask, typically `0644`. The SPEC calls entries "not sensitive", so callers may store them with relaxed permissions.
2. Attacker with write access to `entries.json` replaces `entries[0].fake` with a string known to appear in the upcoming LLM response (the attacker can predict or influence this).
3. `unscrub` builds its Aho-Corasick automaton from the tampered `fake`. It finds the planted string in the response, calls `decrypt_entry` (AEAD tag still valid — ciphertext was not modified), and writes the original secret to stdout.

The SPEC claim "Entries are not sensitive on their own: without the session key, the ciphertext is opaque" is true for passive observation but false under active `fake`-field modification. An attacker can extract the secret without the session key.

**Fix**: Include `fake` bytes in the AEAD AAD:
```rust
cipher.encrypt_in_place(&nonce, &fake, &mut buffer)
// and symmetrically:
cipher.decrypt_in_place(&nonce, &entry.fake, &mut buffer)
```
This binds the `fake` routing field to the AEAD tag; any tampering invalidates decryption.

---

## F3 — MEDIUM: `seen` HashMap retains plaintext secrets (INV-12 spirit)

**File**: `scrub.rs:79`, `scrub.rs:101`

```rust
let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
let secret = payload[m.start..m.end].to_vec();   // plaintext bytes
seen.insert(secret, idx);                          // lives in HashMap until scrub() returns
```

Every distinct detected secret is stored as a `Vec<u8>` key in `seen`. `HashMap::drop` frees backing allocations without zeroing. In a long-running process with many scrub calls, these allocations may be reused slowly, leaving a window where plaintext secrets are recoverable from heap.

**Fix**: Replace `Vec<u8>` keys with `zeroize::Zeroizing<Vec<u8>>`, which implements `Drop` via `zeroize()`.

---

## F4 — LOW: `Tier2Pat` secret fragments not zeroized on drop

**File**: `tier2.rs:10-24`

`Tier2Pat` has no `ZeroizeOnDrop`. Its `start_fragment` (first ≤8 bytes of registered secret) and `end_fragment` (last ≤8 bytes) are freed by the allocator without zeroing when the `Arc`'s reference count reaches zero.

**Fix**: Add `#[derive(ZeroizeOnDrop)]` to `Tier2Pat`. All fields (`Vec<u8>` and `[u8; 32]`) implement `Zeroize`.

---

## F5 — LOW: Tier 2 exposes full secret for ≤ 16-byte registrations

**File**: `tier2.rs:52-65`

With `START_FRAGMENT_LEN = END_FRAGMENT_LEN = 8`:

| Secret length | Bytes in `start_fragment` | Bytes in `end_fragment` | Hidden bytes |
|---|---|---|---|
| 8 | 8 (all) | 0 | 0 |
| 12 | 8 | 4 | 0 |
| 16 | 8 | 8 | 0 |
| 17 | 8 | 8 | **1** |

For secrets ≤ 16 bytes, the entire secret is stored across `start_fragment + end_fragment`. The Tier 2 security model (store fragments, not full secret) provides zero protection here. The only assertion is `secret.len() >= 2`.

Additionally, the Tier 2 fake prefix is generated from `start_fragment` (first 8 bytes of the secret), so an observer of the scrubbed payload learns the first 8 bytes of any Tier 2-registered secret by design.

**Fix**: Document the boundary; assert `secret.len() >= START_FRAGMENT_LEN + END_FRAGMENT_LEN + 1` (i.e., `>= 17`), or clearly warn callers registering short secrets.

---

## F6 — LOW: `StdRng` algorithm not guaranteed CSPRNG across `rand` versions

**File**: `fake.rs:89`

```rust
let mut rng = StdRng::from_seed(seed_bytes);
```

`StdRng` is currently ChaCha12 in rand 0.8, but the `rand` crate documents it as subject to algorithm changes without semver break. If it changes to a non-cryptographic PRNG, an attacker who knows the HMAC salt (obtainable if the process-global `OnceLock` salt leaks via a memory disclosure like F1) could enumerate fakes for a given charset/prefix.

**Fix**: Use `rand_chacha::ChaCha20Rng::from_seed(seed_bytes)` explicitly.

---

## Items Correctly Implemented (Checked)

- **Nonce uniqueness**: 192-bit random nonces; birthday bound P ≈ n²/2¹⁹³ is negligible for any practical n. SPEC claim accurate. ✓
- **`SessionKey` type safety**: No `Clone`, no `Debug`, no `Display`. Prevents accidental logging or duplication. ✓
- **Constant-time HMAC verification** (`subtle::ConstantTimeEq`). ✓
- **AEAD tag failure stops stream** (INV-5/6): `decrypt_entry` returns `Err` on tag failure; `unscrub` propagates the error and emits nothing. ✓
- **AAD consistency**: Encrypt and decrypt both use `b""` — consistent (though see F2 on why empty is wrong). ✓
- **Tier 1 salt stability** (`OnceLock`): Initialized once per process, persists across `scrub` calls. Enables INV-13. ✓
- **HMAC key size**: `new_from_slice` on a `&[u8; 32]` — the `.expect("HMAC accepts any key size")` can only panic on empty input. 32-byte salt never triggers this. ✓
- **INV-18 leftmost-longest**: `find_best_match` scans all patterns at each position, picks longest, Tier1-wins-on-tie. ✓
- **INV-20/21**: No `--key` flag; key file created with `mode(0o600)`. ✓
- **Fake derivation soundness** (when using current `StdRng`): HMAC-SHA256 output seeded into ChaCha12 is cryptographically sound for fake generation. ✓

---

## Recommended Remediation Priority

1. **F1** (HIGH, INV-12): Eliminate unzeroized copies on key generation and load paths. This is a hard MUST violation.
2. **F2** (MEDIUM): Add `fake` to AEAD AAD. One-line change per encrypt/decrypt call.
3. **F3** (MEDIUM): Wrap `seen` keys in `Zeroizing<Vec<u8>>`.
4. **F4** (LOW): `#[derive(ZeroizeOnDrop)]` on `Tier2Pat`.
5. **F5** (LOW): Raise minimum secret length assertion for Tier 2 or document the exposure boundary.
6. **F6** (LOW): Pin `ChaCha20Rng` explicitly.
