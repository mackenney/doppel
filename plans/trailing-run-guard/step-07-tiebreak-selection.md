# Step 07 — Guard tie-break arms in find_best_match (INV-18 extension)

Depends on: step-01 (needs `Pattern.trailing_run_guard`) and step-02
(serializes swap.rs edits — step-02's acceptance criterion asserts its own
diff leaves `find_best_match` untouched, so this step must run after it).

Covers the SPEC tie-break addendum: Behavioral Invariants item 18 (two new
MUST sub-clauses), §Pattern Detection → Detection Algorithm step 5 (extended
prose), §Trailing Run Guard → "Tie-breaking." paragraph, VC 24/25 (tests in
step-04).

## Context

- `find_best_match`: `doppel/src/swap.rs:9-35`. The candidate fold currently
  has exactly two comparison arms plus a keep-incumbent fallback:

  ```rust
  best = Some(match best {
      None => (pattern, capture),
      Some((_bp, bc)) if capture.end > bc.end => (pattern, capture),
      // INV-18: literal-first wins on length tie
      Some((bp, bc))
          if capture.end == bc.end
              && pattern.first_segment_is_literal()
              && !bp.first_segment_is_literal() =>
      {
          (pattern, capture)
      }
      Some(b) => b,
  });
  ```

- SPEC item 18 (amended): on persistent tie (same match-end position, same
  first-segment kind), a guarded Pattern MUST beat an unguarded one; between
  two guarded Patterns the larger threshold MUST win. Both sub-clauses
  "apply strictly after, and MUST NOT override, the longest-match and
  literal-first rules."
- Rationale (SPEC §Trailing Run Guard "Tie-breaking."): a larger threshold
  is harder to satisfy, so preferring it on tie biases ambiguous ties toward
  the configuration least likely to ever suppress a detection —
  security-first.
- **Scope boundary:** this is *selection* only — which single pattern
  becomes `best`, exactly as the existing two arms already decide. The
  Design-B post-fold suppression check in `swap_with_ac`
  (`guard_fires` / no-cascade, step-02) is a separate, unaffected mechanism
  and MUST NOT be touched by this step.

## Changes

Insert one new arm between the literal-first arm and the `Some(b) => b`
fallback:

```rust
// INV-18: on persistent tie (same end, same first-segment kind), a
// guarded pattern beats an unguarded one, and between guarded patterns
// the larger threshold wins. Option<usize>'s derived ordering encodes
// both sub-clauses in one comparison: None < Some(t) covers
// guarded-beats-unguarded, Some(a) < Some(b) covers the threshold rule.
// Equal guards (including None vs None) fall through to the incumbent.
Some((bp, bc))
    if capture.end == bc.end
        && pattern.first_segment_is_literal() == bp.first_segment_is_literal()
        && pattern.trailing_run_guard > bp.trailing_run_guard =>
{
    (pattern, capture)
}
```

Notes:

- The `first_segment_is_literal() == ...` equality (not the existing arm's
  asymmetric form) is what enforces "MUST NOT override literal-first": when
  the incumbent is literal-first and the challenger is opaque-first, this
  arm must not fire even if the challenger is guarded. Same-end is likewise
  required so the arm never overrides longest-match.
- `Some(b) => b` stays the final fallback: full ties beyond all four rules
  still resolve by pattern-set order, which SPEC continues to leave
  unspecified.
- Add a doc comment on `find_best_match` enumerating the full selection
  chain — longest match → literal-first → guarded-over-unguarded → larger
  threshold → incumbent kept — citing SPEC §Pattern Detection step 5 and
  Behavioral Invariants item 18. (step-05's doc sweep covers `swap` /
  `swap_with_ac`; the `find_best_match` doc is owned here, at the code
  change, to avoid a duplicate step.)

## Inline unit tests (swap.rs `mod tests`)

Construct tied pattern pairs directly (struct literal; fields are
`pub(crate)`), call `find_best_match`, assert on the returned pattern's
`identifier`. All pairs: `[Literal(b"tok_"), Variable(Alphanumeric, 30, 30)]`
shape with distinct salts unless stated.

1. Guarded (`Some(64)`) vs unguarded, tied → guarded wins, in **both**
   pattern-set orders (proves the arm, not set-order luck).
2. `Some(64)` vs `Some(8)`, tied → larger threshold wins, both orders.
3. Longer unguarded match (`Variable 34,34`) vs shorter guarded (`30,30`)
   → longer wins (non-override of longest-match).
4. Literal-first unguarded vs opaque-first guarded (`Opaque(4)` head, same
   total length) → literal-first wins (non-override of literal-first).
5. Both `None`, tied → first-in-set kept (fallback unchanged).

## Acceptance criteria

- New arm sits between the literal-first arm and the `Some(b) => b`
  fallback; diff shows no change to `guard_fires`, `trailing_run_reaches`,
  or the `swap_with_ac` suppression wiring from step-02.
- All five inline tests above pass; existing swap tests untouched and green.
- `find_best_match` has a doc comment covering all four selection rules
  with SPEC citations.
- `cargo nextest run --lib -p doppel` passes.
