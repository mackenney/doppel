# MASTER_PROGRESS.md

## Status

Complete

## Objective

Implement `its-classified`: a Rust library and CLI for secret scrubbing and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

_(none)_
## Queued


## Completed

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex unzeroized; commit 650ae57
- `exploit-filesystem-race` — key file 0644 mode race confirmed + /proc/environ leak confirmed; chained PoC decrypts entries.json; commit 3c0560b
- `exploit-aad-tampering` — 6 PoC tests: fake-swap, stealth Unicode trigger, prefix-shadow DoS+redirect, batch exfil, e2e; 72/72 pass; commit 7005d46
- `workspace-lib-split` — workspace split, Pattern opacity, ScrubError cleanup, lib docs, review fixes; commit 4b47145
- `exploit-tier2-leakage` — start_fragment leakage PoC confirmed; fix: wide-charset default, opt-in prefix/suffix; commit 662fca8
- `tier1-segments` — segment-list model for Tier 1 detection (INV-28, INV-29, VC-13); fixes Anthropic AA suffix, OpenAI T3BlbkFJ, GitHub FG `_` separator, Slack digit structure; commit 895e596
- `patterns-file-stable-fakes` — deterministic fakes across restarts (INV-13), Tier 2 at-match derivation, PatternsFile JSON serde, CLI init/register/--patterns, 102 tests; merge commit 6904209
## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
- _(All other gaps resolved by the `patterns-file-stable-fakes` plan)_
- **Built-in Tier 1 patterns are exemplary, not authoritative.** The 15 compiled-in definitions (`anthropic`, `openai_classic`, etc.) exist for testing and as a template starting point. Long-term, the library should ship a canonical `patterns.json` template that users copy and maintain; the compiled-in set should not be treated as the production list. Making pattern management fully user-driven (no compiled-in defaults, library provides only the segment/salt machinery) is a future design decision.
- `RegistrationError::CollisionLimit` is unreachable after the fake-derivation-at-match-time refactor; collision detection moved to `ScrubError::Fake` at scrub time. Future fix: trial derivation at registration time to preserve INV-25 CollisionLimit contract.
- INV-26 and INV-27 `log::warn` diagnostics have no test assertions; tests verify registration succeeds but cannot capture log output without a test logger harness. Future fix: wire a test logger via `testing_logger` or equivalent.
