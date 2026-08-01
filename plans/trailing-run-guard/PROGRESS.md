# PROGRESS.md — trailing-run-guard

## Status

Queued

## Objective

Implement the trailing run guard per SPEC.md §Trailing Run Guard: an opt-in,
per-Pattern forward-probe that suppresses a winning structural match when at
least `threshold` consecutive bytes after the match end all belong to the
pattern's last-variable-segment charset. Includes the registration-path
option (`SecretOptions.trailing_run_guard`) per SPEC §Registration Options,
and the item-18 tie-break extension (guarded beats unguarded on persistent
tie; larger threshold beats smaller among guarded ties) in match selection.
Covers Behavioral Invariants 44–49 plus item 18's guard tie-break
sub-clauses, and Verifiable Conditions 18–25. The built-in GCP pattern
ships guarded (threshold 2048 — user-ratified default, rationale in
step-01).

## Binding contract

`SPEC.md` — specifically:
- §Purpose (opt-in exception clause)
- §Detection Algorithm in `swap`, steps 5–6 (selection tie-break order incl.
  the two guard tie-breaks; winner-only suppression, no cascade)
- §Trailing Run Guard (charset resolution, suppression rule, selection order, tie-breaking, independence, opt-in)
- §Registration → Registration Options (trailing-run-guard bullet)
- §Built-in Family Patterns (GCP SHOULD be guarded)
- §Patterns File → `trailing_run_guard` field
- Behavioral Invariants 44–49 and item 18 (amended: two guard tie-break
  sub-clauses); Verifiable Conditions 18–25
- Known Limitations (bounded false-negative class; forward-only; filler-vs-secret)

## Waves

| Wave | Steps | Depends on |
|---|---|---|
| 1 | step-01 (core types + probe) | — |
| 2 | step-02 (swap wiring), step-03 (patterns file), step-06 (registration option + docs) — parallelizable | step-01 |
| 3 | step-07 (guard tie-break arms in find_best_match) | step-01, step-02 |
| 4 | step-04 (spec-invariant + integration tests) | step-02, step-03, step-06, step-07 |
| 5 | step-05 (docs, lint, full validation) | step-04 |

## Steps

- [ ] [step-01-core-pattern-guard-field.md](./step-01-core-pattern-guard-field.md)
- [ ] [step-02-swap-suppression-wiring.md](./step-02-swap-suppression-wiring.md)
- [ ] [step-03-patterns-file-schema.md](./step-03-patterns-file-schema.md)
- [ ] [step-04-spec-invariant-tests.md](./step-04-spec-invariant-tests.md)
- [ ] [step-05-docs-and-validation.md](./step-05-docs-and-validation.md)
- [ ] [step-06-registration-guard-option.md](./step-06-registration-guard-option.md) *(wave 2; appended to keep existing numbering stable)*
- [ ] [step-07-tiebreak-selection.md](./step-07-tiebreak-selection.md) *(wave 3; appended for the SPEC item-18 tie-break addendum)*

## Key design decisions (locked by spec or explicit user ratification — do not re-decide)

- **Design B / no cascade:** guard *suppression* runs once, on the single
  winner returned by `find_best_match`, inside `swap_with_ac`. Suppression
  never re-enters the comparison loop; it falls through to the existing
  copy-one-byte no-match path (`output.push(payload[pos]); pos += 1`).
- **Guard tie-break is selection, not suppression (step-07):** one new arm
  in `find_best_match`, between the literal-first arm and the
  keep-incumbent fallback, firing only on persistent tie (same
  `capture.end`, same first-segment-literal-ness). `Option<usize>`'s
  derived ordering (`None < Some(t)`; `Some(a) < Some(b)` iff `a < b`)
  encodes both item-18 sub-clauses in a single comparison. Does not touch
  the Design-B post-fold suppression check.
- **Forward-only bounded probe:** never scans backward; early-exits the moment
  the threshold count is reached (O(threshold) worst case per candidate, never
  O(run length)).
- **Charset inferred, not declared:** guard charset = last `Segment::Variable`
  charset. Guard + zero variable segments = construction/load error.
- **Opt-in:** `Option<usize>`; `None` preserves the unconditional detection
  contract for every existing pattern (INV-48).
- **GCP builtin threshold: 2048 bytes — user-ratified default.** Explicit
  product-owner decision: 2048 is a deliberately semi-arbitrary point in the
  wide gap between real-key trailing contexts (tens of bytes) and observed
  real-world base64 screenshot payloads (15–400 KB). Not an automated design
  review output. Full rationale in step-01.
- **Registration guard validation is positivity-only.** The
  no-variable-segment rejection (INV-45) is structurally unreachable via
  registration — every registered Pattern has exactly one `variable` segment
  by construction (SPEC §Registration Options, INV-49). Only `Some(0)` is
  rejected; no threshold-vs-secret-length check exists or is wanted.

## Validation commands

```sh
cargo nextest run --workspace
cargo nextest run -p doppel --test spec
cargo nextest run -p doppel --test integration
cargo clippy --workspace --all-targets
cargo fmt --check
```

## Open Decisions

None. Spec is complete for this scope; CLI `define` and `register` get no
guard flag in this plan (SPEC's CLI Contract was not amended — patterns file
editing and the library-level `SecretOptions` option cover declaration; CLI
flags would be a separate spec change).
