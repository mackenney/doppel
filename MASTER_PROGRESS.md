# MASTER_PROGRESS.md

## Status

All planned work complete — no active or queued plans

## Objective

Implement `its-classified`: a Rust library and CLI for secret scrubbing and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

_(none)_

## Queued

_(none)_

## Completed

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex unzeroized; commit 650ae57
- `exploit-filesystem-race` — key file 0644 mode race confirmed + /proc/environ leak confirmed; chained PoC decrypts entries.json; commit 3c0560b
- `exploit-aad-tampering` — 6 PoC tests: fake-swap, stealth Unicode trigger, prefix-shadow DoS+redirect, batch exfil, e2e; 72/72 pass; commit 7005d46
- `workspace-lib-split` — workspace split, Pattern opacity, ScrubError cleanup, lib docs, review fixes; commit 4b47145
- `exploit-tier2-leakage` — start_fragment leakage PoC confirmed; fix: wide-charset default, opt-in prefix/suffix; commit 662fca8

## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
- No CLI pattern registration surface — no `--patterns` file, no Tier 2 secret input; CLI hardcodes `patterns::all()` with no user control
- Tier 1 salt is ephemeral (`OnceLock` + `OsRng` on first access): same secret produces a different fake on every process restart, violating INV-13 across process boundaries; salt must be explicit and stable (stored in patterns file)
