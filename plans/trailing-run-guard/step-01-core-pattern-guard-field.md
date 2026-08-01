# Step 01 — Core Pattern guard field, GCP default, bounded probe

## Context

- `Pattern` struct: `doppel/src/patterns.rs:696` — fields `identifier`,
  `segments`, `salt`, `digests`, all `pub(crate)`. Constructed via struct
  literal in ~27 built-in constructor fns (`anthropic()` … `chromatic()`),
  in `SecretsFile::to_patterns` (`doppel/src/secrets_file.rs:214`), and in
  registration (`doppel/src/secrets.rs`, `register_with_options_rng`).
- `StructuralDef`: `doppel/src/patterns.rs:13` — static template
  (identifier + segments) behind each built-in; `all_defs()` feeds
  `SecretsFile::generate_missing_structural_salts`
  (`doppel/src/secrets_file.rs:333`), which is what `init` uses to write the
  patterns file. The GCP guard MUST live here too, or `init`-generated files
  won't carry it.
- `GCP_DEF` / `GCP_SEGS`: `doppel/src/patterns.rs:240-256` —
  `Literal(b"AIza") + Variable{UrlSafeBase64, 35, 35}`.
- `CharsetName::resolve()`: `doppel/src/segment.rs` — returns
  `&'static Charset`; `Charset::contains(u8)` is O(1) (bitmap, per
  review-remediation commit 36f8099).

## Changes

### 1. `Pattern.trailing_run_guard`

Add to `Pattern` (patterns.rs:696):

```rust
/// Optional trailing run guard threshold in bytes (SPEC §Trailing Run Guard).
/// `None` = unconditional detection (Behavioral Invariants item 48).
pub(crate) trailing_run_guard: Option<usize>,
```

Add `trailing_run_guard: Option<usize>` to `StructuralDef` as well.

Update every construction site. All built-in constructor fns and
`StructuralDef` statics get `trailing_run_guard: None` **except GCP** (see
below). `register_with_options_rng` (secrets.rs) sets `None` in this step as
a placeholder; step-06 replaces it with `opts.trailing_run_guard` when the
registration option lands. `to_patterns` is handled in step-03.

### 2. GCP default guard

Threshold provenance: **2048 is an explicit user-ratified default** (product-
owner decision, acknowledged as semi-arbitrary), supported by real-world
observation — base64 screenshot uploads in the motivating false-positive
scenario measured 15–400 KB. It is not the output of an automated design
review gate. Do not re-derive or "optimize" it during execution.

```rust
/// GCP guard threshold: a genuine standalone key is delimited by structural
/// context (quote, whitespace, punctuation) within tens of bytes of its end;
/// base64-encoded binary blobs (the false-positive source) run uninterrupted
/// for far longer — real-world screenshot uploads observed at 15–400 KB.
/// 2048 is a deliberately coarse point in the wide gap between those two
/// regimes: ~2 orders of magnitude above real-key trailing contexts, well
/// below observed blob sizes, and it bounds probe cost at 2KB per candidate
/// (candidates occur ~once per 16.7MB of uniform base64).
pub(crate) const GCP_TRAILING_RUN_GUARD: usize = 2048;
```

### 3. Guard charset helper

On `Pattern` (and reachable from `StructuralDef` segments — takes
`&[Segment]`):

```rust
/// Charset of the last Variable segment — the guard charset per
/// Behavioral Invariants item 45. None if no Variable segment exists.
pub(crate) fn last_variable_charset(&self) -> Option<CharsetName>
```

Implementation: `self.segments.iter().rev().find_map(|s| match s { Segment::Variable { charset, .. } => Some(*charset), _ => None })`.

### 4. Bounded forward probe

Free function in `swap.rs` (it is a detection-time concern, colocated with
its only caller):

```rust
/// Returns true when at least `threshold` consecutive bytes starting at
/// `start` all belong to `charset`. Early-exits at the first non-charset
/// byte, at end of payload, or as soon as `threshold` bytes are confirmed —
/// never reads past `start + threshold` (SPEC §Trailing Run Guard:
/// "MAY stop reading as soon as the threshold is reached").
fn trailing_run_reaches(payload: &[u8], start: usize, charset: &Charset, threshold: usize) -> bool {
    let end = start.saturating_add(threshold);
    if end > payload.len() {
        return false; // EOF before threshold → match stands (item 44)
    }
    payload[start..end].iter().all(|&b| charset.contains(b))
}
```

Note the EOF short-circuit: if fewer than `threshold` bytes remain, the run
cannot reach the threshold — return false without scanning. This makes the
probe O(min(threshold, remaining)) with zero allocation and no decoding.

### 5. Construction-time validation (library-internal invariant)

`Pattern` fields are `pub(crate)`, so external callers cannot construct an
invalid guard+no-variable Pattern; load-time validation lives in step-03.
Still, add a debug assertion helper used by both step-03 validation and a
unit test over `all_defs()`:

```rust
#[cfg(test)]
fn assert_builtin_guards_valid() // every def with a guard has ≥1 Variable segment
```

(Plain `#[test]` in patterns.rs `mod tests` iterating `all_defs()` is
sufficient; no runtime machinery needed.)

## Acceptance criteria

- `cargo build --workspace` passes with the new field on `Pattern` and
  `StructuralDef`; all 27+ construction sites updated, no `Default` shortcut
  that could silently leave a builtin unguarded.
- `patterns::gcp().trailing_run_guard == Some(2048)`; every other builtin is
  `None` (unit test iterating `patterns::all()`).
- Unit tests for `trailing_run_reaches`: exact-threshold true; threshold-1
  charset bytes then non-charset byte false; EOF before threshold false;
  threshold 1 with one charset byte true; does not panic at `start ==
  payload.len()`.
- Unit test: last-variable-charset helper on a multi-variable pattern
  (construct one with two Variables of different charsets) returns the last
  one's charset.
- `cargo nextest run --lib -p doppel` passes.
