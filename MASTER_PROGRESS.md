# MASTER_PROGRESS.md

## Status

Active

## Objective

Implement `doppel`: a Rust library and CLI for secret swapping and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

- `trailing-run-guard-charset-fix` — explicit guard charset (`trailing_run_guard_charset`) + `base64_any` charset; GCP guard currently suppresses zero standard-base64 false positives (see `HANDOFF.md`) — [plan](plans/trailing-run-guard-charset-fix/PROGRESS.md)

## Queued

*(none)*

## Completed

- `trailing-run-guard` — opt-in trailing same-charset run guard suppressing base64-blob false positives (SPEC items 44-49 + item 18 guard tie-breaks, VC 18-25, GCP guarded by default 2048 bytes, registration option); commit 7bff46b

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex unzeroized; commit 650ae57
- `exploit-filesystem-race` — key file 0644 mode race confirmed + /proc/environ leak confirmed; chained PoC decrypts entries.json; commit 3c0560b
- `exploit-aad-tampering` — 6 PoC tests: fake-swap, stealth Unicode trigger, prefix-shadow DoS+redirect, batch exfil, e2e; 72/72 pass; commit 7005d46
- `workspace-lib-split` — workspace split, Pattern opacity, SwapError cleanup, lib docs, review fixes; commit 4b47145
- `exploit-tier2-leakage` — start_fragment leakage PoC confirmed; fix: wide-charset default, opt-in prefix/suffix; commit 662fca8
- `tier1-segments` — segment-list model for Tier 1 detection (INV-28, INV-29, VC-13); fixes Anthropic AA suffix, OpenAI T3BlbkFJ, GitHub FG `_` separator, Slack digit structure; commit 895e596
- `patterns-file-stable-fakes` — deterministic fakes across restarts (INV-13), Tier 2 at-match derivation, SecretsFile JSON serde, CLI init/register/--patterns, 102 tests; merge commit 6904209
- `toml-patterns-user-tier1` — TOML+hex patterns file (v2), user-defined Tier 1 patterns, CLI define/list/inspect/remove, register --label, CollisionLimit fix; commit 7e4b9a8
- `sync-test-parity` — parity async/sync restore tests: empty input, two distinct secrets, Tier 2; INV-5 ref in async Zeroizing; commit 0922dd4
- `review-remediation` — INV-12 CLI zeroization, async spec tests (INV-5/6/8), shared restore abstraction (process_safe_region), charset O(1) bitmap+static, AC pre-filter, dedup alloc fix; commit 36f8099
- `restore-followup` — zeroize decrypted plaintext in sync restore, AEAD log in sync; commit 3bb4f97
- `test-cleanup` — nonce consistency (24-byte), output.is_empty() assertion, explicit break in None branch; commit 54201f0
- `restore-fixes` — empty-fake guard, cursor O(n) refactor, zeroize plaintext, AEAD log, #[must_use], async tests; commit 35dfb76
- `spec-unified-pattern` — unified Pattern model (literal/opaque/variable segments), v3 patterns file, anchor_len registration, entropy enforcement, 28 built-ins, 130 tests; commit 38168b3
- `doc-fixes` — Rust source doc fixes, secrets-example.toml, CHANGELOG.md, README v3 rewrite, for-the-paranoid v3 rewrite, INV-42/43 anchor enforcement; commit 7b37fd6
## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
- INV-26 and INV-27 `log::warn` diagnostics have no test assertions; tests verify registration succeeds but cannot capture log output without a test logger harness. Future fix: wire a test logger via `testing_logger` or equivalent.
