# Step 03 — Create `CHANGELOG.md`

**Wave:** 1 (independent; can run in parallel with Wave 0)
**Status:** ⬜ pending

## Context

`CHANGELOG.md` was created on an orphaned branch chain and never reached the current HEAD
(`554c12e`). It must be created from scratch using the actual current state of the
codebase. Do NOT copy text from any orphaned commit; derive entries from the code and git
log.

The file must follow the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format
and include `cargo-release` anchors.

## Prerequisites

- Working directory: `/home/ignacio/pr/doppel/.wt/spec-unified-pattern`
- No prior steps required; independent of Wave 0

## Files to read before writing

```sh
# Understand what changed between [0.0.1] boundary and HEAD:
git log --oneline f16bf3c..HEAD

# Understand what was in [0.0.1]:
git log --oneline 643788e..f16bf3c   # from scaffold to last 0.0.1 commit

# Check current Cargo.toml for the crate version:
grep '^version' Cargo.toml doppel/Cargo.toml doppel-cli/Cargo.toml
```

Read `SPEC.md` briefly for the invariant numbers referenced in the log.

## Key facts

**Release boundary:**
- `[0.0.1]` = everything through commit `f16bf3c` (inclusive)
- `[Unreleased]` = commits `ccc303e` (review-det-r1) through `554c12e` (review-det-r7)

**What [0.0.1] contains** (initial release, derive from code):
- Core `swap` / `restore` / `restore_stream` operations
- Unified `Pattern` model (no structural/registered split at runtime)
- TOML version 3 patterns file (`SecretsFile`, `PatternEntry`)
- 27 built-in structural patterns (`patterns::all()`, `patterns::anthropic()`, etc.)
- `register` / `register_with_options` with `anchor_len`, `tail_anchor_len`, entropy guard
- Group patterns (`add_secret_to_group`)
- `Detector` type for pre-built Aho-Corasick automaton (INV-39/40/41)
- CLI: `init`, `swap`, `restore`, `register` (`--identifier`, `--anchor-len`,
  `--tail-anchor-len`, `--group`, `--force`), `define`, `list`, `inspect`, `remove`
- `#[non_exhaustive]` on `SwapResult`, `SwapError`, `RestoreError`, `SecretsFileError`,
  `SecretError`
- Async feature: `RestoreStream` / `restore_stream`

**What [Unreleased] contains** (derive from commits ccc303e..554c12e):
- CT fold fix: HMAC comparison used non-constant-time equality; corrected to constant-time
- Wide charset cardinality fix: was 72, corrected to 92 (0x21–0x7E excluding `"` and `\`)
- Additional spec-tier tests: INV-39/40/41 (Detector round-trips), INV-37 (distinct fakes),
  VC-14/VC-16/VC-17 coverage, group round-trip, empty-payload, inv2-gap, utf8-error path
- `Detector` refinements from review feedback
- `try_to_def` UTF-8 error path
- `validate_segment_defs` called inside `to_patterns` (defense-in-depth, INV-31)
- Fixed entry-ordering invariant (entries before stdout in CLI)
- Group HMAC gate, in-place group update (INV-37)

Verify against `git log --oneline ccc303e..554c12e` and adjust if the summary above
differs from what you see.

## Required file structure

```markdown
<!-- next-header -->
## [Unreleased]

### Fixed

- ...

## [0.0.1] — YYYY-MM-DD

### Added

- ...

<!-- next-url -->
[Unreleased]: https://github.com/mackenney/doppel/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/mackenney/doppel/tree/v0.0.1
```

Rules:
- `<!-- next-header -->` must be the first line of the file (no blank line before it).
- `<!-- next-url -->` must appear before the footer link lines with no blank line between
  the anchor and the first link.
- Each section uses `### Added`, `### Fixed`, `### Changed` subsections as appropriate.
- Bullet style: plain `-` bullets, no sub-bullets.
- Dates: use the commit date of the last commit in that range. For [0.0.1] check
  `git log -1 --format="%ad" --date=short f16bf3c`. For [Unreleased] no date.

## Implementation

Write the complete file as `/home/ignacio/pr/doppel/.wt/spec-unified-pattern/CHANGELOG.md`.

Use `git log --oneline` output to write accurate, concise bullet points. Do not use vague
phrases like "various improvements"; be specific about what changed and why it matters to
users.

Suggested bullets for `[Unreleased] ### Fixed` (verify against code):
- `Constant-time HMAC comparison: replaced `==` with `ct_eq` for HMAC verification to
  eliminate timing side-channel (CT fold).`
- `Wide charset cardinality corrected from 72 to 92 (all printable ASCII 0x21–0x7E
  except `"` and `\`); fakes generated with the previous value are incompatible.`

Suggested bullets for `[0.0.1] ### Added` (verify against code — these are the main
user-visible features):
- `swap`, `restore`, `restore_stream` core operations.
- Unified `Pattern` model with `Literal`, `Variable`, and `Opaque` segment kinds.
- TOML v3 patterns file (`SecretsFile`, `PatternEntry`) with `version = 3` enforcement.
- 27 built-in structural patterns (Anthropic, OpenAI, AWS, GitHub, GCP, Stripe, Clerk,
  …); available via `patterns::all()`.
- `register` / `register_with_options`: register an arbitrary secret by value; stores
  only a detection anchor (opaque segment) and HMAC digest, never the plaintext.
- `anchor_len` / `tail_anchor_len` options; `force` flag to bypass entropy guard.
- Group patterns: multiple secrets sharing one `[[pattern]]` entry with multiple digests.
- `Detector` type: pre-built Aho-Corasick automaton for high-throughput repeated swaps
  (INV-39/40/41).
- CLI commands: `init`, `swap`, `restore`, `register`, `define`, `list`, `inspect`,
  `remove`.
- `async` feature: `RestoreStream` / `restore_stream` for async streaming restore.
- Entropy enforcement: registration rejects secrets with less than 83 bits of variable
  entropy unless `--force` is used.

## Acceptance criteria

```sh
cd /home/ignacio/pr/doppel/.wt/spec-unified-pattern

# File exists and is non-empty:
test -s CHANGELOG.md && echo "exists"

# Contains required anchors:
grep -F '<!-- next-header -->' CHANGELOG.md
grep -F '<!-- next-url -->' CHANGELOG.md
grep -F '[Unreleased]' CHANGELOG.md
grep -F '[0.0.1]' CHANGELOG.md

# Footer links present:
grep 'mackenney/doppel' CHANGELOG.md

# No trailing whitespace (common mistake):
grep -P '\s+$' CHANGELOG.md && echo "TRAILING WHITESPACE FOUND" || echo "clean"
```

## Reviewer instructions

After the worker completes, verify:

1. File begins with `<!-- next-header -->` on line 1 (no blank line before it).
2. `## [Unreleased]` section exists and is non-empty.
3. `## [0.0.1]` section exists with a date in `YYYY-MM-DD` format.
4. `<!-- next-url -->` appears before the footer links.
5. Footer links reference `mackenney/doppel` and use correct tag format.
6. All bullets are accurate (spot-check: wide charset = 92, CT fold fix, 27 built-ins,
   Detector type).
7. No placeholder text like "TODO" or "..." left in.
8. No section-separator comments introduced.
