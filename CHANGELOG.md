<!-- next-header -->
## [Unreleased]

### Added

- `SecretError::AnchorTooShort`: `register` now hard-fails when `anchor_len` is 0 or 1; emits a warning at 2 (INV-42).
- `SegmentDefError::FirstSegmentTooShort`: `define` now hard-fails when the first segment value is shorter than 2 bytes; emits a warning below 4 bytes (INV-43).

### Fixed

- Constant-time HMAC comparison: replaced `==` with `ct_eq` for HMAC verification to eliminate timing side-channel (CT fold).
- Wide charset cardinality corrected from 72 to 92 (all printable ASCII 0x21–0x7E except `"` and `\`); fakes generated with the previous value are incompatible.
- Entry ordering: CLI now writes entries JSON before stdout output (INV ordering fix).
- Group HMAC gate enforced; in-place group update preserves distinct fakes per digest (INV-37).
- `try_to_def` UTF-8 error path now propagates correctly instead of panicking.
- `validate_segment_defs` called inside `to_patterns` for defense-in-depth (INV-31).

## [0.0.1] — 2026-06-07

### Changed

**Unified Pattern model** (breaking — replaces the v2 structural/registered split).

The previous architecture represented the two detection strategies as separate `Pattern` enum variants:

```rust
// v2 — removed
pub enum Pattern {
    Structural(StructuralDef),     // any key of a given format
    Registered(Arc<RegisteredPat>), // one specific known key
}
```

Each variant had its own detection path: structural patterns walked a segment list; registered
patterns used `start_fragment`/`end_fragment` anchor bytes plus `exact_length` and an HMAC digest.
The on-disk representation mirrored this split with separate `[[structural]]` and `[[registered]]`
TOML tables and a `SecretEntry` struct carrying `start_fragment`, `end_fragment`, `exact_length`,
`preserve_prefix`, and `preserve_suffix`.

Both concepts are now expressed as a single `Pattern` struct:

```rust
// v3 — current
pub struct Pattern {
    segments: Arc<[Segment]>, // ordered detection structure
    salt:     [u8; 32],        // drives deterministic fake derivation
    digests:  Vec<[u8; 32]>,  // empty = family; non-empty = instance/group
}
```

The unifying insight is that a registered secret is a family pattern with an HMAC gate:
- `digests` empty → **family pattern** (formerly `Structural`): matches any candidate satisfying
  the segment structure. Used for well-known formats (Anthropic keys, GitHub PATs, etc.).
- `digests` non-empty → **instance/group pattern** (formerly `Registered`): matches only when
  `HMAC(salt, candidate)` equals one of the stored digests. Used for specific known values.

`swap` receives a `&[Pattern]` slice and treats all entries uniformly; it has no concept of
"structural" vs "registered".

**`opaque` segment type** is the mechanism that makes this unification possible. Unlike `literal`
(verbatim in fake), an `opaque` segment matches exact bytes for detection but derives its fake
bytes from a HMAC-seeded ChaCha12 PRNG rather than reproducing the anchor. Registered secrets use
an `opaque` first segment to anchor Aho-Corasick detection on the leading bytes of the secret
without exposing those bytes verbatim in the output. This replaces the old
`start_fragment`/`end_fragment`/`preserve_prefix`/`preserve_suffix` fragment model entirely.

**Patterns file format v3** (breaking — v2 files are incompatible). The unified `[[pattern]]` array
replaces the separate `[[structural]]` and `[[registered]]` sections. The presence of the `digests`
field distinguishes family from instance patterns. Recreate patterns files with `doppel init` and
re-register any instance secrets with `doppel register`.

**`SecretOptions` API** (breaking). Fields removed: `preserve_prefix`, `preserve_suffix`,
`start_fragment_len`, `end_fragment_len`. Replaced by: `anchor_len` (leading opaque anchor bytes,
default 3), `tail_anchor_len` (trailing opaque anchor bytes, default 0), `restrict_charset`
(draw fake variable bytes from detected charset rather than wide, default false).

**CLI registration** (breaking). `--label` renamed to `--identifier`. Flags
`--preserve-prefix`, `--preserve-suffix`, `--start-fragment-len` removed.
New: `--anchor-len`, `--tail-anchor-len`, `--restrict-charset`, `--group`.

### Added

- `swap`, `restore`, `restore_stream` core operations.
- `opaque` segment kind: exact detection anchor with HMAC-seeded (ChaCha12) fake derivation; replaces the fragment-based registration model.
- `wide` charset: 92 printable ASCII bytes (0x21–0x7E, excluding `"` and `\`); default for variable segments in registered secrets.
- TOML v3 patterns file (`SecretsFile`, `PatternEntry`) with `version = 3` enforcement.
- 28 built-in family patterns: Anthropic, OpenAI (classic/project/service-account), AWS IAM (AKIA/ASIA), GitHub PATs (classic/fine-grained/OAuth/app-server/app-user/refresh), GCP API keys, OpenRouter, Groq, Perplexity, Cerebras, Google OAuth client secrets, Slack bot tokens, Linear, Stripe (live/test), Clerk, Svix, Doppler, Chromatic. Available via `patterns::all()`.
- `register` / `register_with_options`: produces an instance Pattern storing only an opaque detection anchor and HMAC digest — never the plaintext secret.
- Entropy enforcement: registration hard-fails below 83 bits of variable entropy; warns below 131 bits. Override with `--force`.
- Group patterns: multiple secrets sharing one `[[pattern]]` entry via `add_secret_to_group`; digests verified against a shared salt.
- `Detector` type: pre-built Aho-Corasick automaton for high-throughput repeated `swap` calls without per-call AC construction (INV-39/40/41). Implements `Send + Sync`.
- `#[non_exhaustive]` on `SwapResult`, `SwapError`, `RestoreError`, `SecretsFileError`, and `SecretError`.
- `async` feature: `RestoreStream` / `restore_stream` for async streaming restore.
- CLI commands: `init`, `swap`, `restore`, `register` (`--identifier`, `--anchor-len`, `--tail-anchor-len`, `--group`, `--force`), `define` (user-defined family patterns), `list`, `inspect`, `remove`.

<!-- next-url -->
[Unreleased]: https://github.com/mackenney/doppel/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/mackenney/doppel/tree/v0.0.1
