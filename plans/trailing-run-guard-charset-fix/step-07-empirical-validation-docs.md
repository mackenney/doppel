# Step 07: empirical corpus re-validation, docs, final sweep

## Context

### Overall Objective
The fix isn't done until the guard demonstrably suppresses the payload class
that motivated it: GCP-shaped candidates inside unwrapped standard-alphabet
base64 blobs, at the shipped default (threshold 1024 + `base64_any`).

### Phase Context
Wave 4, final. Unit/spec tests (step-06) prove the contract; this step proves
the real-world outcome HANDOFF.md measured (8/3 false positives, zero
suppressed) is actually fixed end-to-end through `doppel swap`.

### This Step
Re-run HANDOFF.md's empirical validation, update user-facing docs/examples,
and run the full validation sweep.

## Prerequisites
- Step 06 complete (all spec tests green).

## Files to Read Before Starting
- `HANDOFF.md` §Empirical proof (the exact corpora and method)
- `secrets-example.toml` — `trailing_run_guard = 1024` line (~195) and surrounding comments
- `CHANGELOG.md` — `[Unreleased]` section
- `doppel-cli/src/main.rs` — `swap` command usage (for the corpus run)

## Implementation

### Task 1: empirical corpus validation (acceptance evidence, not committed code)
Preferred (real corpora, if available in this environment):
1. Check for `~/Pictures/Screenshots/*.png` and `~/.ffxec/screenshot-*.png`.
2. For each corpus: base64-encode every image with the STANDARD alphabet
   (e.g. `base64 -w0` — GNU coreutils uses standard alphabet, unwrapped),
   concatenate or process per-file into payloads.
3. Run `doppel swap` (init a scratch patterns dir first; GCP ships guarded
   1024/`base64_any` by default) over each payload; count GCP entries
   produced.
4. Acceptance: the GCP-shaped false positives previously measured (8 in
   Screenshots, 3 in ffxec per HANDOFF.md) are now suppressed — zero GCP
   entries from pure image-blob payloads.

Fallback (no real corpora available): synthetic substitute is acceptable —
generate ≥10 payloads of several hundred KB of deterministic
standard-alphabet base64 (must include `+`/`/` at natural ~1/32 frequency,
unwrapped), embed a GCP-shaped candidate (`AIza` + 35 url-safe chars) at
varied offsets including mid-blob and near-tail, run `doppel swap`.
Acceptance criterion is the same either way: **the GCP default
threshold+charset suppresses standard-base64-embedded noise** (mid-blob
candidates produce zero entries; only a candidate within <1024 bytes of blob
end may still match — that is the documented end-of-blob limitation, not a
failure).

Also re-confirm the 1024-default sanity per HANDOFF next-step 4: spot-check
that threshold 1024 suppresses where 65536 would not for a near-tail case
(one payload with ~2KB of trailing blob suffices). No code change expected;
record results.

Write the run log/results to
`artifacts/investigations/trailing-run-guard-charset-fix-validation.md`
(git-ignored; summarize the outcome in the completion report and commit
message body, not in committed files).

### Task 2: docs
- `secrets-example.toml`: add `trailing_run_guard_charset = "base64_any"` to
  the GCP example entry (regenerate via `doppel init` if that's how the file
  is produced — check its header) and a brief comment: explicit guard charset,
  models the noise (standard-base64 blobs), match charset unchanged.
- `CHANGELOG.md` `[Unreleased]`: entry for the new `trailing_run_guard_charset`
  field, the `base64_any` charset, and the GCP default fix (guard previously
  ineffective against standard-alphabet base64 — cite the behavior, not
  HANDOFF/plan files).
- Doc comments sweep: `cargo doc -p doppel --no-deps` builds without warnings;
  ensure `SecretOptions` and patterns-file docs mention the new field where
  the old guard field is documented.
- Do NOT delete `HANDOFF.md` in this step — that happens in the plan
  completion commit per PROGRESS.md Executor Protocol.

### Task 3: final sweep

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo test --doc -p doppel
cargo nextest run -p doppel-cli --features test-e2e --test e2e
```

## Acceptance Criteria

- [ ] Corpus validation performed (real or synthetic fallback) and results recorded in `artifacts/investigations/trailing-run-guard-charset-fix-validation.md`; outcome: GCP default suppresses standard-base64-embedded candidates (zero entries mid-blob)
- [ ] `grep -n trailing_run_guard_charset secrets-example.toml` → ≥1 hit on the GCP entry
- [ ] `grep -n base64_any CHANGELOG.md` → ≥1 hit under `[Unreleased]`
- [ ] All five sweep commands exit 0
- [ ] No committed file references `HANDOFF.md`, `plans/`, or `artifacts/` paths

## Reviewer Instructions

1. Read the validation artifact: confirm the method (standard alphabet, unwrapped), the corpus used, and zero mid-blob GCP entries.
2. If synthetic fallback was used: confirm filler contains `+`/`/` within the first ~150 bytes after the embedded candidate.
3. Run the five sweep commands verbatim.
4. Confirm `secrets-example.toml` and `CHANGELOG.md` changes carry no plan/handoff references.

## Rollback
`git revert` the step-07 commit (docs only; validation artifact is git-ignored).
