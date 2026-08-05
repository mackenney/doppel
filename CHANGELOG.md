<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

- `trailing_run_guard_charset` field on `Pattern`/`PatternEntry`/`SecretOptions`: an explicit, optional guard-probe charset for the trailing run guard, decoupled from the pattern's match charset. Defaults to `None` (guard infers the charset from the pattern's last `variable` segment, unchanged behavior). A new `base64_any` charset (union of standard and url-safe base64 alphabets) is available for patterns whose match charset is narrower than the base64 noise it needs to guard against.
- Built-in GCP pattern now sets `trailing_run_guard_charset = "base64_any"` explicitly. Previously the guard inferred its probe charset from GCP's match charset (`url_safe_base64`), which does not include `+`/`/` — the exact bytes that terminate a probe run within the first few dozen bytes of a standard-alphabet base64 blob (the near-universal real-world encoding for embedded image data). The guard was measured to suppress zero real-world false positives against standard-base64 payloads at any threshold. With the explicit `base64_any` guard charset, the shipped 1024-byte default threshold suppresses these false positives while the match charset (and therefore real-key detection precision) is unchanged.

### Fixed

- `register --group` combined with `--trailing-run-guard` is now rejected at parse time instead of silently ignoring the guard flag.

### Changed

- New `doppel::segment::charset_cardinality(name)` public accessor replaces the CLI's hand-maintained charset-size table (`doppel-cli`'s `inspect` entropy estimate); the CLI now delegates to the library so the two cannot drift.

## [0.0.2] - 2026-06-09

### Breaking Changes

**Unified `Pattern` model — replaces the v2 structural/registered split.**

`Pattern` was an enum with two mutually-exclusive variants; this distinction is removed:

```rust
// v2 — removed
pub enum Pattern {
    Structural(StructuralDef),      // any key matching a known format
    Registered(Arc<RegisteredPat>), // one specific known key value
}
```

`Pattern` is now a struct. Family vs instance is expressed through the `digests` field:

```rust
// v3 — current
pub struct Pattern {
    segments: Arc<[Segment]>, // ordered detection structure
    salt:     [u8; 32],       // drives deterministic fake derivation
    digests:  Vec<[u8; 32]>,  // empty = family pattern; non-empty = instance/group pattern
}
```

- `digests` empty → **family pattern** (formerly `Structural`): matches any candidate satisfying the segment structure. Used for well-known formats (Anthropic keys, GitHub PATs, etc.).
- `digests` non-empty → **instance/group pattern** (formerly `Registered`): matches only when `HMAC(salt, candidate)` equals one of the stored digests. Used for protecting specific known values.

`swap` receives a `&[Pattern]` slice and is unaware of which kind produced each entry.

**Patterns file format v2 → v3 (incompatible).** The separate `[[structural]]` and `[[registered]]` TOML arrays are replaced by a single `[[pattern]]` array. The `SecretEntry` struct and its fields (`start_fragment`, `end_fragment`, `exact_length`, `preserve_prefix`, `preserve_suffix`) are removed. Recreate existing patterns files with `doppel init` and re-register instance secrets with `doppel register`.

**`SecretOptions` fields removed.** `preserve_prefix`, `preserve_suffix`, `start_fragment_len`, and `end_fragment_len` no longer exist. The new knobs are `anchor_len` (leading opaque anchor bytes, default 3), `tail_anchor_len` (trailing opaque anchor bytes, default 0), and `restrict_charset` (draw fake variable bytes from detected charset instead of wide, default false).

**CLI registration flags changed.** `--label` is renamed to `--identifier`. `--preserve-prefix`, `--preserve-suffix`, and `--start-fragment-len` are removed. New flags: `--anchor-len`, `--tail-anchor-len`, `--restrict-charset`, `--group`.

### Added

**`opaque` segment kind.** The mechanism that makes the unification possible. Unlike `literal` (verbatim in fake), an `opaque` segment matches exact bytes for detection but derives its fake bytes from a HMAC-seeded ChaCha12 PRNG rather than reproducing the anchor. Registered secrets use an `opaque` first segment to anchor Aho-Corasick detection on the leading bytes of the secret without exposing those bytes verbatim in the output. This replaces the old `start_fragment`/`end_fragment` fragment-matching approach entirely.

- `wide` charset: 92 printable ASCII bytes (0x21–0x7E, excluding `"` and `\`); default for variable segments in registered secrets. Replacing the previous 72-byte charset (incompatible — fakes derived under v2 charset do not match v3).
- 14 new built-in family patterns: OpenRouter, Groq, Perplexity, Cerebras, Google OAuth client secrets, Slack bot tokens, Linear, Stripe (live/test), Clerk, Svix, Doppler, Chromatic, GitHub OAuth, GitHub app (server/user/refresh tokens). Total built-in count: 28.
- Registration reworked: `register` / `register_with_options` now produce a Pattern with an `opaque` anchor segment and a `variable` middle segment. The plaintext secret is never stored. `anchor_len` controls how many leading bytes become the detection anchor.
- Entropy enforcement: registration hard-fails below 83 bits of variable entropy; warns below 131 bits. Override with `--force`.
- Group patterns: multiple secrets sharing one `[[pattern]]` entry, each contributing a digest. All digests verified against a shared salt via `add_secret_to_group`.
- `Detector` type: pre-built Aho-Corasick automaton for high-throughput repeated `swap` calls without per-call AC construction. Implements `Send + Sync` (INV-39/40/41).
- `define` CLI command: add user-defined family patterns by supplying a segment list directly.
- `SecretError::AnchorTooShort`: `register` hard-fails when `anchor_len` is 0 or 1; warns at 2 (INV-42).
- `SegmentDefError::FirstSegmentTooShort`: `define` hard-fails when the first segment value is shorter than 2 bytes; warns below 4 bytes (INV-43).

### Fixed

- Constant-time HMAC comparison: replaced `==` with `ct_eq` for HMAC verification to eliminate timing side-channel (CT fold).
- Wide charset cardinality corrected from 72 to 92 (all printable ASCII 0x21–0x7E except `"` and `\`); fakes generated with the previous value are incompatible.
- Entry ordering: CLI now writes entries JSON before stdout output (INV ordering fix).
- Group HMAC gate enforced; in-place group update preserves distinct fakes per digest (INV-37).
- `try_to_def` UTF-8 error path now propagates correctly instead of panicking.
- `validate_segment_defs` called inside `to_patterns` for defense-in-depth (INV-31).

## [0.0.1] — 2026-06-07

### Added

- `swap`, `restore`, `restore_stream` core operations.
- Unified `Pattern` model with `Literal`, `Variable`, and `Opaque` segment kinds; no separate structural/registered split at runtime.
- TOML v3 patterns file (`SecretsFile`, `PatternEntry`) with `version = 3` enforcement.
- 27 built-in structural patterns (Anthropic, OpenAI, AWS, GitHub, GCP, Stripe, Clerk, and more); available via `patterns::all()`.
- `register` / `register_with_options`: register an arbitrary secret by value; stores only a detection anchor (opaque segment) and HMAC digest, never the plaintext.
- `anchor_len` / `tail_anchor_len` options; `force` flag to bypass entropy guard.
- Entropy enforcement: registration rejects secrets with less than 83 bits of variable entropy unless `--force` is used.
- Group patterns: multiple secrets sharing one `[[pattern]]` entry with multiple digests (`add_secret_to_group`).
- `Detector` type: pre-built Aho-Corasick automaton for high-throughput repeated swaps (INV-39/40/41).
- `#[non_exhaustive]` on `SwapResult`, `SwapError`, `RestoreError`, `SecretsFileError`, and `SecretError`.
- `async` feature: `RestoreStream` / `restore_stream` for async streaming restore.
- CLI commands: `init`, `swap`, `restore`, `register` (`--identifier`, `--anchor-len`, `--tail-anchor-len`, `--group`, `--force`), `define`, `list`, `inspect`, `remove`.

<!-- next-url -->
[Unreleased]: https://github.com/mackenney/doppel/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/mackenney/doppel/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/mackenney/doppel/tree/v0.0.1
