# MASTER_PROGRESS.md

## Status

In Progress

## Objective

Implement `its-classified`: a Rust library and CLI for secret scrubbing and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

- `workspace-lib-split` — Cargo workspace split (lib + CLI), Pattern opacity, error cleanup, docs → [plans/workspace-lib-split/](plans/workspace-lib-split/PROGRESS.md)

## Queued

- `exploit-tier2-leakage` — recover secret bytes from fake prefix in entries.json; MEDIUM → [plans/exploit-tier2-leakage/](plans/exploit-tier2-leakage/PROGRESS.md)
## Completed

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex unzeroized; commit 650ae57
- `exploit-filesystem-race` — key file 0644 mode race confirmed + /proc/environ leak confirmed; chained PoC decrypts entries.json; commit 3c0560b
- `exploit-aad-tampering` — 6 PoC tests: fake-swap, stealth Unicode trigger, prefix-shadow DoS+redirect, batch exfil, e2e; 72/72 pass; commit 7005d46

## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
- `UnscrubError::Build(aho_corasick::BuildError)` exposes a third-party type in the public API — no active plan
