# Handoff: Trailing Run Guard — Charset Correctness

## Status of this document

Tracked in git (not in `artifacts/`) so it survives clone, worktree, and
session boundaries — unlike a prior handoff for this same feature area that
was git-ignored and nearly lost. Delete this file once the work it describes
is complete and captured in `MASTER_PROGRESS.md` / git history; do not leave
it to rot as permanent documentation.

**Expected pipeline for the next agent:** `specifier → planner → executor`.
This document is investigation output, not a spec and not a plan. Read it,
write a proper `SPEC.md` amendment, plan the implementation, then execute.

## Branch state

Branch `ignacio@patterns/trailing-run-guard`, 12 commits ahead of `main`
(`main` = `origin/main`, unpushed, unmerged). Working tree clean. All tests
green (`cargo nextest run --workspace`, `cargo test --doc -p doppel`, `cargo
fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`) as of
the last commit below.

Relevant commits on this branch, most recent first:

| Commit | What |
|---|---|
| `e8add4c` | GCP guard default lowered 2048 → 1024; new advisory warning when a `trailing_run_guard` threshold exceeds 20,000 (SPEC item 50), on both the registration path and patterns-file load path |
| `6db2b02` | `--trailing-run-guard <n>` CLI flag added to `register`, full parity with other `SecretOptions` fields |
| `cf60c0f` | Stale `#[allow(dead_code)]`/comment cleanup on `last_variable_charset` |
| `239d3b4` and earlier | Original trailing-run-guard feature implementation (spec, core field, suppression wiring, tie-break, tests) — see `SPEC.md` §Trailing Run Guard for the full behavioral contract already in place |

None of the above three most recent commits are the subject of this handoff
— they're already correct, reviewed (competitive 3-reviewer pass, fact-checked,
zero blockers), and tested. This handoff is about a **newly discovered,
separate, more serious problem** found while empirically validating the
1024/20000 threshold choice.

## The problem: guard charset is wrong for its own motivating use case

### What the guard currently does

Per `SPEC.md` §Trailing Run Guard and Behavioral Invariant item 45: **the
guard's charset is not declared separately — it is inferred as the charset
of the pattern's last `variable` segment.** For the built-in GCP pattern,
that segment's charset is `url_safe_base64` (Google's real API keys never
contain `+` or `/`, only `A-Za-z0-9-_`). The guard probes bytes immediately
following a winning match and suppresses the match if at least `threshold`
consecutive bytes all belong to that same charset.

### Why that's the wrong charset for the guard's own use case

The guard exists specifically to suppress false positives caused by base64
image data embedded in request bodies (SPEC's own stated rationale — "image
data embedded in a request body"). But **real-world base64 encoders
overwhelmingly use the standard alphabet** (`+`, `/`, `=` padding), not
url-safe. Confirmed first-party, in this exact repo's own tooling: pi's
`read` tool (the coding agent this investigation was performed in) encodes
every image it sends to Claude via `Buffer.from(bytes).toString("base64")`
— Node's standard base64, verified at:

```
dist/utils/image-process.js:78        Buffer.from(normalized.bytes).toString("base64")
dist/utils/image-resize-core.js:12,51 Buffer.from(...).toString("base64")
dist/utils/image-convert.js:41        Buffer.from(pngBytes).toString("base64")
```

Node has a distinctly-named `"base64url"` encoding for the url-safe variant;
none of this code path ever calls it. This is not a contrived edge case —
url-safe base64 exists specifically for contexts where `+`/`/` would break
URL syntax (query strings, file paths); request **bodies** essentially never
need it, so standard base64 is the near-universal real-world choice for
embedded image data in JSON/data-URI payloads — exactly the payload class
this feature targets.

### Empirical proof

Tested against two real screenshot corpora (2792 files from
`~/Pictures/Screenshots`, 417 from `~/.ffxec/screenshot-*.png`; sizes 0.5KB
to 5.5MB, median ~110KB — matches SPEC's own "15-400KB" assumption).

**With images base64-encoded the real way (standard alphabet, what pi and
virtually every other tool actually produces):** 8 false-positive GCP-shaped
candidates found in the Screenshots corpus, 3 in ffxec. Guard threshold
tested from 256 through 65,536 bytes — **the false-positive count was 8 and
3 respectively at every single threshold value, including `none`.** The
guard suppressed *zero* of them, regardless of threshold magnitude.

Root cause confirmed by direct measurement of trailing-run length in each
charset, for all 8 real Screenshots false positives:

```
match at byte 27791444: url_safe trailing run=0,   std_b64 trailing run=1,015,555
match at byte 92796069: url_safe trailing run=108, std_b64 trailing run=6,332
match at byte 159277073: url_safe trailing run=9,  std_b64 trailing run=55,464
match at byte 234633401: url_safe trailing run=148,std_b64 trailing run=3,848,943
match at byte 247572388: url_safe trailing run=27, std_b64 trailing run=1,094,443
match at byte 471243494: url_safe trailing run=37, std_b64 trailing run=160,853
match at byte 518913505: url_safe trailing run=10, std_b64 trailing run=1,307,934
match at byte 676667021: url_safe trailing run=36, std_b64 trailing run=98,807
```

Every single one sits inside a standard-base64 run of thousands to over a
million bytes (exactly what the guard is supposed to catch), but the
url-safe-charset run the guard actually measures terminates within 0-150
bytes (the first `+` or `/` character breaks it) — far below even the
smallest threshold tested. **No threshold value fixes this; the mechanism
cannot fire at all against this payload class as currently configured.**

Isolated confirmation, same fake GCP candidate, guard=2048, only the trailing
data's alphabet varied:

```
standard-base64 trailing data → entries=1  (NOT suppressed)
url-safe-base64 trailing data → entries=0  (suppressed)
```

**Conclusion: the shipped GCP guard currently provides ~zero protection
against its own primary stated motivating case.** The 1024/20000 threshold
tuning already committed (`e8add4c`) is sound *conditional on this charset
bug being fixed* — with matching charsets, the same corpora showed complete
suppression at threshold 1024 and *worsening* suppression above ~8192 (see
`SPEC.md`'s "A larger threshold is not uniformly better" limitation, added
in `e8add4c` — that finding remains valid and doesn't need to be redone).

## Root cause, precisely stated

The guard's charset resolution conflates two distinct concepts that happen
to coincide for most patterns but diverge for GCP:

1. **Match charset** — what a genuine secret's variable region looks like.
   For GCP, correctly `url_safe_base64` (real keys never contain `+`/`/`).
2. **Noise charset** — what the surrounding blob that causes false positives
   actually looks like. For GCP's real-world false-positive source (base64
   image data), that's the standard alphabet, a strict superset.

Today's design (item 45) only has one charset slot and infers it from (1),
so (2) is wrong whenever they diverge.

## Analysis: three options considered

| # | Approach | Verdict |
|---|---|---|
| 1 | Implicit "charset family" widening (e.g. auto-map `url_safe_base64` → a wider base64 superset for guard-probing purposes only, silently) | **Rejected.** No general rule exists for widening arbitrary charsets (what's the "wider family" of `digits`? of `wide`, which is already maximal?). Only base64-like charsets have an obvious superset — ad hoc special-casing with no principled stopping point. Also silently makes the guard check something other than what SPEC item 45 documents, breaking an already-tested, spec'd invariant implicitly rather than through an explicit, auditable spec change. |
| 2 | Widen the *match* charset itself (make GCP's segment accept `+`/`/` too) | **Rejected.** This also widens what counts as a real GCP key candidate for the primary detection itself — trading match precision for guard effectiveness. Wrong direction; would increase false positives elsewhere to fix false positives here. |
| 3 | **Explicit, decoupled guard-charset field**, separate from the segment's match charset | **Recommended.** New optional field (e.g. `trailing_run_guard_charset: Option<CharsetName>`) on `Pattern`/`PatternEntry`/`SecretOptions`, alongside the existing `trailing_run_guard: Option<usize>`. Defaults to `None` = today's inferred-from-last-Variable-segment behavior (fully backward compatible for every pattern that doesn't opt in). GCP's built-in definition would set it explicitly to a new charset value covering the *union* of standard and url-safe base64 alphabets (`A-Za-z0-9+/\-_=`), while its segment charset stays exactly `url_safe_base64` — match precision untouched, guard now checks the right thing. |

## Downsides of the recommended approach (option 3) — read before speccing

1. **Real API surface growth.** New field across `Pattern`, `PatternEntry`
   (TOML schema), `SecretOptions` (registration), possibly a CLI flag for
   parity (open question — recommend deferring, see below), plus SPEC prose
   and new tests. Bigger diff than the mechanical 1024/20000 change.
2. **New `CharsetName` variant needed** for the base64-union charset. Every
   exhaustive `match` over `CharsetName` needs a new arm: charset membership
   bitmap (`segment.rs` or wherever charset tables live), fake-derivation
   tables (`fake.rs`), entropy-size table (`secrets.rs`), and the CLI's
   duplicate `charset_size()` table in `doppel-cli/src/main.rs`. Rust's
   exhaustiveness check catches every miss at compile time — safe, but
   touches several files.
3. **Amends a previously-locked, tested Behavioral Invariant (item 45).**
   Currently: "a pattern that declares a trailing run guard but contains no
   `variable` segment MUST be rejected at patterns-file load time" — this
   rule exists purely because there's no charset to infer without a Variable
   segment. With an explicit override, that restriction becomes unnecessary
   — a positive side effect (guards become usable on all-literal/opaque
   patterns too) but it is scope beyond the immediate charset-correctness
   fix. Existing tests tied to that rejection
   (`test_vc21_guard_without_variable_segment_rejected_at_load` in
   `doppel/tests/spec/inv_trailing_run_guard.rs`) need re-validation to
   confirm they still hold when the charset is *inferred* (no explicit
   override), and a new counterpart test is needed proving the explicit-
   charset path skips that rejection correctly.
4. **New footgun, more exposed than before.** An author can now pick a guard
   charset structurally disconnected from reality — too narrow (false
   negatives on suppression, the status quo bug) or too *broad* (e.g. `wide`,
   which would count almost any subsequent printable byte toward the run,
   over-suppressing genuine secrets followed by ordinary prose/JSON — a
   worse version of the already-accepted "bounded false-negative class"
   limitation in SPEC). Needs explicit doc guidance: choose the guard
   charset to model the actual noise being defended against, not the widest
   available option.
5. **Conceptual load increase.** Two charsets to reason about per guarded
   pattern (match charset vs. guard charset) instead of one, for anyone
   reading a patterns TOML or the SPEC. Mitigated by optionality — the
   common case (no override) stays exactly as simple as today.
6. **Line-wrapped/MIME base64 remains an accepted gap regardless of this
   fix.** Some base64 embeddings insert `\r\n` every 76 chars (classic MIME
   encoding), which would break *any* charset-membership run test well
   before reaching even a 1024 threshold. Not relevant to the case actually
   measured here (pi's own encoder and virtually all JSON/data-URI
   embeddings are unwrapped, continuous strings), but should be stated as an
   explicit accepted limitation in SPEC rather than left implicit.
7. **Backward-compat correctness burden.** The default-`None`-falls-back-to-
   inferred path must be airtight — needs an explicit regression test
   proving every existing built-in and hand-authored pattern's suppression
   behavior is byte-for-byte unchanged when the new field is absent, not
   just a type-level "defaults to None" claim.

## What does NOT change (no downside, for the record)

- Match/detection precision for GCP keys themselves — untouched, still
  exactly `AIza` + 35 url-safe-base64 chars.
- Every other built-in pattern — none currently declare a guard, so none
  are affected by this change.
- The zero-guard/tie-break/independence invariants (items 44, 46-49) —
  orthogonal to charset resolution, no interaction with this fix.
- The already-committed 1024 default / 20,000 warning-threshold decision
  from `e8add4c` — those numbers were validated on a charset-matched
  synthetic test explicitly to isolate them from this bug, and remain valid
  once the charset is fixed.

## Open design questions for the specifier/planner to resolve

These were flagged during analysis but intentionally left undecided —
they're specification decisions, not something to infer:

1. **Exact charset value/name** for the new base64-union guard charset.
   Proposed alphabet: `A-Za-z0-9+/-_=` (union of RFC 4648 §4 standard and
   §5 url-safe alphabets, plus `=` padding for completeness). Needs a name
   consistent with existing `CharsetName` conventions (e.g.
   `url_safe_base64`, `hex_lower`) — something like `base64_any` or
   `base64_union`.
2. **Whether to allow the new charset as an actual segment-matching charset**
   (for `variable` segments generally), or restrict it to
   guard-charset-only use. Recommend: allow generally for consistency
   (simpler mental model, and Rust's exhaustive matching means there's no
   extra cost to supporting it everywhere), but this needs an explicit
   decision.
3. **Whether to relax item 45's Variable-segment requirement** when an
   explicit guard charset is declared (see downside 3 above). Recommend yes,
   but it's additional scope — confirm before including it in the plan, or
   explicitly defer it to a follow-up if the planner wants a narrower first
   pass.
4. **Whether to expose the new field via `doppel-cli register`** for
   parity with `--trailing-run-guard` (added in `6db2b02`). Recommend
   deferring — SPEC's CLI Contract already treats `register`'s option list
   as closed by explicit enumeration; this would be the second registration-
   path option not CLI-exposed (trailing_run_guard's own threshold already
   IS CLI-exposed, so this would be an inconsistency worth a deliberate
   choice, not a default one).
5. **Field naming and shape**: flat second `Option<CharsetName>` field
   alongside `trailing_run_guard: Option<usize>` (matches existing flat
   style, smaller diff) vs. restructuring into a single
   `TrailingRunGuard { threshold: usize, charset: Option<CharsetName> }`
   struct (cleaner API, but a breaking change to `Pattern`'s public shape —
   larger migration). Recommend the flat field for minimal footprint unless
   the specifier judges otherwise.
6. **Should the GCP built-in's guard-charset default become the new
   base64-union charset immediately** (as part of this fix), or should this
   land as infrastructure first with GCP's own default updated in a
   follow-up? Recommend doing both together — the whole point of this fix
   is to make GCP's guard actually work, landing the field without updating
   GCP's own definition leaves the shipped bug exactly as broken as today.

## Suggested next steps for the continuing agent

1. `specifier`: write the `SPEC.md` amendment. Needs to touch: §Trailing Run
   Guard (charset resolution paragraph), Behavioral Invariant item 45
   (amend), a new Behavioral Invariant for the explicit-charset-declaration
   path, §Registration Options (parity question above), §Valid charset
   names list (new charset value), and a new Known Limitations bullet for
   line-wrapped/MIME base64 (see downside 6).
2. `planner`: plan the implementation — expect it to span
   `doppel/src/patterns.rs` (GCP definition + new charset), `doppel/src/segment.rs`
   or wherever `CharsetName` and its membership/size tables live,
   `doppel/src/swap.rs` (`guard_fires`, resolve charset from the new field
   with fallback to today's inference), `doppel/src/secrets.rs`
   (`SecretOptions`), `doppel/src/secrets_file.rs` (TOML schema + validation,
   including the item-45 relaxation if in scope), tests in
   `doppel/tests/spec/inv_trailing_run_guard.rs`, and `secrets-example.toml`.
3. `executor`: implement per the plan. Re-run the same empirical validation
   done in this investigation (real screenshot corpora, standard-base64
   encoding) as part of acceptance — the fix isn't done until the 8/3 real
   false positives found in this investigation are actually suppressed by
   `doppel swap` at the shipped GCP default threshold.
4. After implementation: re-verify the 1024-default / 20,000-warn threshold
   choice still holds once the charset is correct (it should — the earlier
   corpus test already validated it under a charset-matched synthetic
   condition — but a real end-to-end confirmation on the actual GCP pattern
   is worth the few minutes it costs).
5. Resume the originally-planned chain after this: `code-reviewer →
   fact-checker → fixer` on the whole branch diff, then `e2e-tester`, then
   push/PR. None of that has been run against the 1024/20000/CLI-flag
   commits either — see "Branch state" above.

## Key file locations

- Spec: `SPEC.md` §Trailing Run Guard (search for that heading), §Registration
  Options (the `trailing-run-guard` bullet), Behavioral Invariant item 45,
  new item 50 (already added in `e8add4c`), Known Limitations (the "A larger
  threshold is not uniformly better" bullet, already added).
- Core code: `doppel/src/patterns.rs` (`GCP_TRAILING_RUN_GUARD` constant,
  GCP definition), `doppel/src/swap.rs` (`guard_fires`, `trailing_run_reaches`,
  `find_best_match`), `doppel/src/secrets.rs` (`SecretOptions`, the new
  `TRAILING_RUN_GUARD_WARN_THRESHOLD`), `doppel/src/secrets_file.rs`
  (TOML schema, load-time validation, its own copy of the warn threshold).
- Tests: `doppel/tests/spec/inv_trailing_run_guard.rs` (14+ spec-invariant
  tests, including the two new item-50 tests from `e8add4c`),
  `doppel/tests/integration/guard.rs`.
- CLI: `doppel-cli/src/main.rs` (`Commands::Register`, `run_register`) —
  already has `--trailing-run-guard`, added in `6db2b02`.
- This handoff: `HANDOFF.md` (repo root, tracked in git — delete once
  consumed and reflected in `MASTER_PROGRESS.md`).
