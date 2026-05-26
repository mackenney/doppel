# MASTER_PROGRESS.md

## Status

Complete

## Objective

Implement `its-classified`: a Rust library and CLI for secret scrubbing and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

_(none)_

## Queued

- `exploit-filesystem-race` — key file 0644 pre-create race + /proc/environ env leak; MEDIUM → [plans/exploit-filesystem-race/](plans/exploit-filesystem-race/PROGRESS.md)
- `exploit-tier2-leakage` — recover secret bytes from fake prefix in entries.json; MEDIUM → [plans/exploit-tier2-leakage/](plans/exploit-tier2-leakage/PROGRESS.md)
## Completed

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex String unzeroized throughout stdin.read() window; /proc/pid/mem bypasses ptrace_scope; commit 650ae57
- `exploit-aad-tampering` — 6 PoC tests: fake-swap, stealth Unicode trigger, prefix-shadow DoS+redirect, batch exfil, e2e; 72/72 pass; commit 7005d46 (branch ignacio@exploit/aad-tampering-attack)

## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
