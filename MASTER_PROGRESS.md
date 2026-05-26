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
- `exploit-aad-tampering` — entries.json fake-field swap without session key + LeftmostFirst prefix-shadow; MEDIUM → [plans/exploit-aad-tampering/](plans/exploit-aad-tampering/PROGRESS.md)
- `exploit-tier2-leakage` — recover secret bytes from fake prefix in entries.json; MEDIUM → [plans/exploit-tier2-leakage/](plans/exploit-tier2-leakage/PROGRESS.md)
## Completed

- `initial-implementation` — full library + CLI (11 steps, 65 tests, all 23 INV invariants) commit 63672b1
- `exploit-memory-forensics` — session key recoverable via /proc/pid/mem in 0.25s; key_hex String unzeroized throughout stdin.read() window; /proc/pid/mem bypasses ptrace_scope; commit 650ae57

## Known Gaps

- No CI configuration (out of scope for initial-implementation plan)
