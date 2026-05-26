# MASTER_PROGRESS.md

## Status

In Progress

## Objective

Implement `its-classified`: a Rust library and CLI for secret scrubbing and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

- `patterns-file-stable-fakes` — deterministic fakes across process restarts (INV-13 fix), patterns file serde, CLI init/register; plan at `plans/patterns-file-stable-fakes/`

## Queued


## Completed

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex unzeroized; commit 650ae57
- `exploit-filesystem-race` — key file 0644 mode race confirmed + /proc/environ leak confirmed; chained PoC decrypts entries.json; commit 3c0560b
- `exploit-aad-tampering` — 6 PoC tests: fake-swap, stealth Unicode trigger, prefix-shadow DoS+redirect, batch exfil, e2e; 72/72 pass; commit 7005d46
- `workspace-lib-split` — workspace split, Pattern opacity, ScrubError cleanup, lib docs, review fixes; commit 4b47145
- `exploit-tier2-leakage` — start_fragment leakage PoC confirmed; fix: wide-charset default, opt-in prefix/suffix; commit 662fca8
- `tier1-segments` — segment-list model for Tier 1 detection (INV-28, INV-29, VC-13); fixes Anthropic AA suffix, OpenAI T3BlbkFJ, GitHub FG `_` separator, Slack digit structure; commit 895e596

## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
- _(All other gaps — Tier 1/2 salt stability, Tier 2 fake derivation, CLI pattern registration, patterns file — are addressed by the `patterns-file-stable-fakes` plan)_
