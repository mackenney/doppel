# Testing Strategy — its-classified

## Principles

1. **Specs before tests.** `SPEC.md` documents the observable contract. Tests
   assert that spec. When spec and behavior disagree, fix one or the other —
   never silently accept drift.

2. **Test-first for discovered errors.** When a smoke test, sanity check, or
   investigation surfaces a defect:
   1. Write a failing test that encodes the incorrect behavior.
   2. Verify it fails as expected.
   3. Fix the code until the test passes.
   4. Commit test and fix together.
   Never fix a discovered defect without a test that would have caught it.

3. **Security invariants are non-negotiable.** Any test that verifies a security
   property from SPEC.md Behavioral Invariants §1–23 is a spec-invariant test.
   These MUST pass on every commit. Weakening them requires an explicit spec
   change rationale.

4. **No secrets in test output.** Test fixtures MUST NOT contain real API keys,
   tokens, or credentials of any kind. Use synthetic test vectors only.

5. **Deterministic crypto tests.** Tests that involve CSPRNG output MUST use a
   seeded CSPRNG (via the `rand` crate's `SeedableRng`) so they are reproducible.
   The production code uses `OsRng`; tests inject a seeded RNG via dependency
   inversion.

---

## Test Tiers

**Inline unit tests** — `#[cfg(test)]` modules inside `src/` files
- Test implementation internals: private functions, algorithms, data-structure
  edge cases.
- Coupled to implementation — change freely during refactoring.
- No external obligation.

**External tests** — binaries in `tests/`
- Test observable behavior at public API boundaries.
- Coupled to the spec — a failing external test is a bug or a deliberate spec
  change, never a refactor casualty.

| Tier | Entry point | Subdirectory | What it covers |
|---|---|---|---|
| **Spec invariants** | `tests/spec.rs` | `tests/spec/` | Direct assertions of SPEC.md MUST/MUST NOT invariants; must pass on every commit |
| **Integration** | `tests/integration.rs` | `tests/integration/` | Public-API behavior: full scrub→unscrub cycles, streaming edge cases |
| **E2E** | `tests/e2e.rs` | `tests/e2e/` | CLI process boundary tests; gated by `--features test-e2e` |

---

## Naming Conventions

### Spec-invariant tests

File header:
```rust
// Spec: SPEC.md §Behavioral Invariants
```

Test function:
```rust
#[test]
fn test_inv1_scrub_replaces_every_detected_secret() {
    // INV-1: "scrub MUST replace every secret detected by the supplied Patterns
    //         with a structurally-equivalent fake."
    ...
}
```

The `invN` number matches the invariant number in SPEC.md Behavioral Invariants.

### Verifiable Condition tests

Verifiable Conditions from SPEC.md map directly to integration tests:
```rust
#[test]
fn test_vc1_scrubbed_output_contains_no_original_secret() {
    // VC-1 from SPEC.md Verifiable Conditions
    ...
}
```

---

## Critical Test Vectors

Every implementation MUST pass these specific scenarios:

### Scrub correctness
- Tier 1: anthropic key in payload → fake in output, entry produced
- Tier 1: openai key in payload → fake in output, entry produced
- Tier 1: AWS IAM key in payload → fake in output, entry produced
- Tier 1: GitHub PAT (classic) in payload → fake in output, entry produced
- Tier 1: GitHub PAT (fine-grained) in payload → fake in output, entry produced
- Tier 1: GCP API key in payload → fake in output, entry produced
- Tier 2: registered secret in payload → fake in output, entry produced
- No-op: payload with no secrets → returned unchanged, empty entries
- Multiple occurrences of same secret → same fake in all positions, one entry
- Two different secrets → two entries, two distinct fakes
- Overlapping prefix candidates → leftmost-longest match wins
- Tier 2 structural match + HMAC failure → passed through unchanged

### Unscrub correctness
- Fake split across chunk boundary → correctly restored
- Multiple fakes in stream → all restored
- No fake in stream → output byte-for-byte identical to input, no error
- AEAD tag tampered → error returned, no partial output emitted

### Security properties
- Fake != original for any detected secret (collision avoidance)
- Same secret + same Pattern → same fake across calls (stability)
- Entries contain no plaintext secret bytes
- Session key not serialized in entries

### CLI
- `scrub` creates session key file with mode 0600
- `unscrub` reads key from `ITS_CLASSIFIED_KEY` env var only (no `--key` flag)
- `unscrub` writes to stdout before stdin reaches EOF (streaming)

---

## Run Commands

```sh
cargo nextest run                                    # all tests (no e2e)
cargo nextest run --test spec                        # spec invariants only
cargo nextest run --test integration                 # integration only
cargo nextest run --features test-e2e --test e2e    # e2e
cargo nextest run --lib                              # unit tests only
```

---

## Stability Contract

Inline unit tests carry no stability guarantee — they live and die with the
implementation.

External tests are contracts: a failing external test is either a bug or a
deliberate spec change. Never weaken an external test to make a refactor pass.
Either the implementation is wrong or the spec changed — update the spec
explicitly and record the decision.
