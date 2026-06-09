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
[Unreleased]: https://github.com/mackenney/doppel/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/mackenney/doppel/tree/v0.0.1
