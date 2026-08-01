# Step 02 — Suppression wiring in swap_with_ac (Design B, no cascade)

Depends on: step-01.

## Context

- `swap_with_ac`: `doppel/src/swap.rs:80` — scan loop; the match arm
  `Some((pattern, capture))` (around swap.rs:111) replaces; the `None` arm
  copies one byte and advances (`output.push(payload[pos]); pos += 1;`).
- `find_best_match`: `doppel/src/swap.rs:9-35`. **MUST NOT be modified by
  this step.** SPEC §Trailing Run Guard "Selection order" / Behavioral
  Invariants item 46: the guard applies only to the single winner already
  selected; losing candidates are never reconsidered — suppression never
  re-enters the comparison loop. (The INV-18 guard *tie-break* arms are a
  separate selection-time concern and land in step-07, after this step.)

## Changes

In `swap_with_ac`, restructure the `Some((pattern, capture))` arm so a fired
guard takes exactly the `None` path:

```rust
match find_best_match(payload, pos, patterns) {
    Some((pattern, capture)) if !guard_fires(pattern, payload, &capture) => {
        // existing replacement body, unchanged
    }
    _ => {
        // existing None body: copy one byte, advance by one.
        // Item 46: suppression yields no detection at this position;
        // no cascade to a losing candidate. Scanning resumes at pos+1,
        // so any secret inside the probe window is still detected
        // independently at its own position (item 47 / VC-20).
    }
}
```

with:

```rust
fn guard_fires(pattern: &Pattern, payload: &[u8], capture: &MatchCapture) -> bool {
    let Some(threshold) = pattern.trailing_run_guard else { return false };
    let Some(charset) = pattern.last_variable_charset() else {
        // Unreachable for validated patterns (item 45 enforced at load);
        // fail open to "no suppression" rather than panic.
        return false;
    };
    trailing_run_reaches(payload, capture.end, charset.resolve(), threshold)
}
```

Notes:
- The guard-fired path advances `pos` by **one byte**, not by `capture.end`.
  This is deliberate and spec-relevant: an AC candidate for another pattern
  starting inside the suppressed span must still be evaluated (independence,
  item 47). The next loop iteration's `ac.find` re-locates from `pos`,
  bulk-copying as usual — no O(n²) behavior since AC search resumes forward.
- Zero behavior change for `pattern.trailing_run_guard == None` (item 48):
  `guard_fires` returns false without touching the payload.
- `Detector::swap` needs no changes — it delegates to `swap_with_ac`
  (INV-39 parity is automatic; step-04 adds a test anyway).

## Inline unit tests (swap.rs `mod tests`)

Use `patterns::gcp()` and a synthetic 39-byte GCP-shaped key
(`AIza` + 35 url-safe-base64 chars — reuse the vector from
patterns.rs:1208).

- Suppression: key immediately followed by 2048 base64 bytes → payload
  unchanged, entries empty.
- Match stands: key followed by 2047 base64 bytes then `"` → replaced,
  one entry.
- Match stands at EOF: key followed by 100 base64 bytes then EOF → replaced.
- Key at very end of payload (0 trailing bytes) → replaced.

## Acceptance criteria

- No hunk from this step touches `find_best_match` (`git diff
  doppel/src/swap.rs` at step completion shows none; the step-07 tie-break
  arms land later and are out of scope here).
- All four inline tests above pass; existing swap tests untouched and green.
- `cargo nextest run --lib -p doppel` passes.
