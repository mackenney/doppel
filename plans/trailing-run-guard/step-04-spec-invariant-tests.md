# Step 04 — Spec-invariant and integration tests (items 18, 44–49, VC 18–25)

Depends on: step-02, step-03, step-06, and step-07.

## Context

- Spec-invariant entry point: `doppel/tests/spec.rs` with
  `#[path = "spec/inv.rs"] mod inv;`. Add a sibling module file
  `doppel/tests/spec/inv_trailing_run_guard.rs` and wire it:
  `#[path = "spec/inv_trailing_run_guard.rs"] mod inv_trailing_run_guard;`.
- Integration entry point: `doppel/tests/integration.rs` (modules
  `integration/round_trip.rs`, `integration/detector.rs`).
- Naming per AGENTS.md: file header `// Spec: SPEC.md §Behavioral
  Invariants` / `§Trailing Run Guard`; plain-English function names; VC
  tests named `test_vcNN_...`.
- Test vectors: synthetic only. GCP-shaped key = `AIza` + 35 url-safe-base64
  chars (see patterns.rs:1208 for an existing synthetic vector). Base64
  filler: repeat a 64-char base64 alphabet slice — deterministic, no RNG
  needed (guard logic is charset-membership only; no crypto in the probe).
- For the no-cascade test you need two overlapping patterns where the longer
  one is guarded. Built-ins can't express this (no built-in pair overlaps
  GCP). Construct via `SecretsFile`/TOML fixture with two family patterns
  sharing prefix, e.g. guarded `[literal "tok_", variable(alphanumeric,
  30,30)]` with `trailing_run_guard = 64`, and unguarded `[literal "tok_",
  variable(alphanumeric, 20, 20)]`. At a position with 30+64 alphanumeric
  trailing bytes: longer pattern wins by longest-match (not a tie-break —
  guard fires, and the
  20-char pattern MUST NOT produce a replacement (item 46).
- For the VC-24/25 tie-break tests, reuse the same TOML-fixture approach
  with **equal** shapes: two patterns both `[literal "tok_",
  variable(alphanumeric, 30, 30)]`, distinct identifiers and salts (same
  shape with distinct salts is legal — item 17 prohibits salt reuse, not
  shape reuse). Equal length + both literal-first ⇒ the persistent tie
  that item 18's new sub-clauses govern. Which pattern won is observed
  through the public API via fake stability (INV-13): swap the same
  payload against each pattern alone to obtain `fake_g` / `fake_u`, then
  assert the combined-set swap emits the expected one. Run the combined
  swap with **both pattern-set orders** — set order is the unspecified
  final fallback, so order-independence is exactly what proves the
  tie-break arm fired.

## Tests — `doppel/tests/spec/inv_trailing_run_guard.rs`

Header: `// Spec: SPEC.md §Trailing Run Guard, §Registration Options, §Behavioral Invariants item 18 (tie-break clauses) and items 44-49`

1. `test_guard_suppresses_match_at_exact_threshold` (item 44, VC-18)
   — GCP key + exactly 2048 base64 bytes → payload unchanged, zero entries.
2. `test_guard_does_not_fire_one_byte_under_threshold` (item 44, VC-19)
   — GCP key + 2047 base64 bytes + `b'"'` → replaced, one entry.
3. `test_match_stands_when_eof_reached_before_threshold` (item 44, VC-19)
   — GCP key + 2047 base64 bytes, EOF → replaced.
4. `test_guard_charset_is_last_variable_segment` (item 45)
   — two-variable pattern (last charset `digits`, guard 16) via TOML:
   match followed by 16 digits → suppressed; followed by 16 base64
   non-digit bytes → stands. Proves the probe uses the LAST variable
   charset, not the first.
5. `test_vc21_guard_without_variable_segment_rejected_at_load` (item 45)
   — TOML with guard on all-literal pattern → `deserialize` error, message
   contains "trailing_run_guard".
6. `test_suppressed_winner_does_not_cascade_to_shorter_pattern` (item 46)
   — the two-overlapping-pattern fixture above; assert zero entries and
   payload unchanged. Include a comment citing SPEC §Trailing Run Guard
   "Selection order": uneven guard config across overlapping patterns is
   the pattern author's responsibility — this test pins the documented
   no-fallback behavior so it cannot regress silently.
7. `test_vc20_genuine_secret_inside_probe_window_still_detected` (item 47)
   — payload: GCP key + 100 base64 bytes + full synthetic Anthropic key +
   enough base64 filler after it that the GCP guard fires (total trailing
   run ≥ 2048; the Anthropic key's own bytes are url-safe-base64-charset
   except `-`, so place filler accordingly: simplest is GCP key + 2048
   base64 bytes + `" "` + Anthropic key). Assert: GCP region unchanged,
   Anthropic key replaced with one entry.
8. `test_unguarded_pattern_never_suppressed_by_trailing_context` (item 48)
   — synthetic Anthropic key followed by 4096 base64 bytes → replaced
   normally (anthropic has no guard).
9. `test_probe_is_forward_only` (item 47)
   — 4096 base64 bytes + `" "` + GCP key at end of payload → replaced
   (huge preceding run is irrelevant; forward window is empty).
10. `test_inv49_registration_default_has_no_guard` (items 48, 49)
    — `register(secret)` (default options), payload: secret + 4096
    wide-charset filler bytes → replaced normally, one entry. Pins that the
    option is opt-in: absent threshold means unconditional detection.
11. `test_vc22_registered_guarded_secret_suppressed_and_replaced` (item 49,
    VC-22) — `register_with_options` with `trailing_run_guard: Some(64)`.
    Payload A: secret + 64 wide-charset bytes → payload unchanged, zero
    entries. Payload B: secret + `b'"'` (outside the wide charset) →
    replaced, one entry. Filler bytes MUST be drawn from the wide charset
    (0x21–0x7E excluding `"` and `\`) since the default effective charset
    is wide; `b'"'` and `b' '` are valid terminators.
12. `test_vc23_zero_guard_threshold_rejected_on_both_paths` (item 45,
    VC-23) — `register_with_options` with `trailing_run_guard: Some(0)` →
    `Err`, message contains "trailing_run_guard must be a positive
    integer"; TOML fixture with `trailing_run_guard = 0` → `deserialize`
    error, message contains the same substring (shared positivity contract
    across load and registration).
13. `test_vc24_guarded_pattern_wins_persistent_tie_over_unguarded` (item 18,
    VC-24) — equal-shape fixture above, one pattern guarded
    (`trailing_run_guard = 64`). Payload: `tok_` + 30 alphanumeric chars +
    `b'"'` (terminator, so the guard cannot fire and the win is observable
    as a replacement). Assert: combined swap output contains `fake_g` (the
    guarded pattern's fake), not `fake_u`, in both set orders; one entry.
14. `test_vc25_larger_threshold_wins_tie_and_match_stands_between_thresholds`
    (item 18, VC-25) — equal-shape fixture, both guarded: thresholds 8 and
    64. Payload A: secret + `b'"'` → replaced with the threshold-64
    pattern's fake, both set orders. Payload B: secret + 32 alphanumeric
    bytes + `b'"'` (satisfies 8, not 64) → the threshold-64 pattern is
    still the winner and its guard does NOT fire: match stands, replaced
    with the threshold-64 fake — replaced, not suppressed (VC-25 second
    half; also proves selection happened before suppression, since a
    threshold-8 winner would have been suppressed here). Payload C: secret
    + 64 alphanumeric bytes → suppressed, payload unchanged, zero entries.

RNG note for tests 10–14: they assert observable swap behavior and error
surfaces, never specific fake bytes, so the public `register` /
`register_with_options` entry points (OsRng-backed) are fine — no seeded
RNG needed; the AGENTS.md seeded-CSPRNG rule applies only to assertions on
CSPRNG output.

## Tests — integration

In `doppel/tests/integration/detector.rs` (or a new `guard.rs` module wired
into integration.rs, executor's choice by file size):

- `test_detector_swap_guard_parity_with_free_swap` — INV-39 holds for a
  guard-suppressing payload: `Detector::swap` and free `swap` both return
  the payload unchanged.
- `test_gcp_key_in_realistic_json_context_still_detected` — GCP key inside
  a small JSON body (`{"api_key": "AIza..."}`) with `patterns::all()` →
  replaced. Guards must not regress the motivating real-world use.
- `test_large_base64_blob_with_embedded_prefix_roundtrip` — a ~64KB
  synthetic base64 payload containing `AIza` at several interior offsets,
  swap with `patterns::all()` → byte-identical payload, zero entries
  (the original false-positive scenario, now defended).

## Acceptance criteria

- `cargo nextest run -p doppel --test spec` and `--test integration` pass.
- Every test asserts on observable `swap` output (payload bytes + entries),
  not on internals.
- No test fixture contains a real credential; all vectors synthetic.
- Existing spec/integration tests untouched.
- **Equal-length tie gap explicitly closed** (earlier fact-check open
  question): test 6 (no-cascade) covers only unequal-length overlapping
  patterns (30 vs 20 chars), so before this amendment no test exercised
  the item-18 persistent-tie path at all. Tests 13–14 use equal-length,
  equal-first-segment-kind pattern pairs — verify by inspection that both
  fixture patterns produce the same `capture.end` and are both
  literal-first, i.e. the tie is genuine and only the new guard tie-break
  arms can decide the winner.
