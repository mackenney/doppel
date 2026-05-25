# MASTER_PROGRESS.md

## Status

In Progress

## Objective

Implement `its-classified`: a Rust library and CLI for secret scrubbing and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

_(none yet)_

## Queued

- `plans/initial-implementation/` — full library + CLI implementation (Wave 0: types + core crypto; Wave 1: scrub engine; Wave 2: unscrub streaming; Wave 3: CLI)

## Completed

_(none yet)_

## Known Gaps

- No dependencies specified in Cargo.toml yet — needs crypto crates (aead, chacha20poly1305, zeroize, hmac, sha2, rand)
- No workspace crate split yet — SPEC may warrant separating library from CLI binary
- No test infrastructure yet — needs nextest, tests/ directory scaffold
- No CI configuration
