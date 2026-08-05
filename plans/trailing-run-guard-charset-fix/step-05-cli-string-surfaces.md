# Step 05: CLI string surfaces for base64_any (no new flags)

## Context

### Overall Objective
`base64_any` is a general-purpose charset (SPEC §Patterns File); the CLI has
three string-keyed surfaces that Rust exhaustiveness does NOT check
(fact-check claim 5b) and would fail silently.

### Phase Context
Wave 2 (parallel with steps 03/04). This step owns `doppel-cli/src/main.rs`
at `charset_size` (~572–582), Define `long_about`/`long_help` (~103/~117),
and the init template comment (~162). Depends only on step 01 (`from_name`
accepts `base64_any`, so `define` already works end-to-end once these
surfaces are updated). Step-04 also lands one line in this same file
(~332–338, `SecretOptions` struct-literal fix) but that region does not
overlap any of the four regions this step touches — genuinely disjoint line
ranges in the same file. The executor/reviewer must apply both steps'
`main.rs` diffs without one clobbering the other (e.g. rebase/merge rather
than blind overwrite if commit order interleaves).

### This Step
Enumerate the three silently-failing surfaces: `charset_size` (`_ => 0` →
silent 0-bit entropy), the two `Define` help texts, and the `init` template
comment. Explicitly NOT in scope: any `--trailing-run-guard-charset` flag
(deferred per SPEC §Registration Options).

## Prerequisites
- Step 01 complete.

## Files to Read Before Starting
- `doppel-cli/src/main.rs` — `charset_size` (~572–582), `entropy_estimate` (~584), Define `long_about` (~103) and `long_help` (~117), init template comment (~162)
- `SPEC.md` §Patterns File "Valid charset names" (67-char definition)

## Implementation

### Task 1: charset_size
Add `"base64_any" => 67,` (before the `_ => 0` arm). 67 = resolved alphabet
length, consistent with how the other arms mirror `resolve().bytes.len()`.

### Task 2: help texts and template
- `long_about` (~103) and `long_help` (~117): extend the
  `Charsets: alphanumeric, uppercase_alphanumeric, digits, hex_lower, url_safe_base64, wide`
  lists with `base64_any` (insert after `url_safe_base64` to keep related
  names adjacent; keep the rest of the text unchanged).
- Init template comment (~162, `# Valid charset names: ...`): add
  `base64_any` to the list, matching SPEC's valid-names line.

### Task 3: guard against regressions
CLI tests land in step-06 (cli_spec); this step only needs the lib/CLI build
green. Add one inline sanity: if `main.rs` has no test module, skip inline
tests — step-06's process-boundary tests cover these surfaces.

## Acceptance Criteria

- [ ] `grep -n '"base64_any" => 67' doppel-cli/src/main.rs` → 1 hit
- [ ] `grep -c base64_any doppel-cli/src/main.rs` ≥ 4 (charset_size + two help texts + template comment)
- [ ] `cargo run -p doppel-cli -- define --help 2>&1 | grep -c base64_any` ≥ 1
- [ ] No new clap flags: `git diff doppel-cli/src/main.rs | grep -E '^\+.*(long|short)\s*='` shows no added flag definitions
- [ ] Global gate passes

## Reviewer Instructions

1. Verify all four text sites (573-area match arm, 103, 117, 162) include `base64_any`.
2. Verify no `Register`/`Define` flag additions anywhere in the diff.
3. Run `cargo run -p doppel-cli -- define --help` and confirm the charset list renders with `base64_any`.
4. Run the global gate.

## Rollback
`git revert` the step-05 commit; independent of step 03. Shares
`doppel-cli/src/main.rs` with step-04 in disjoint line regions
(~103/~117/~162/~572–582 vs ~332–338) — reverting step-05 alone is safe as
long as step-04's separate hunk in the same file is unaffected; if both
commits landed, revert with `git revert` (not `git checkout --`) to avoid
clobbering step-04's hunk.
