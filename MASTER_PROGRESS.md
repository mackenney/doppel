# MASTER_PROGRESS.md

## Status

Active

## Objective

Implement `doppel`: a Rust library and CLI for secret swapping and
restoration in arbitrary byte payloads. Full behavioral contract in `SPEC.md`.

## In Progress

*(none)*

## Queued

*(none)*

## Completed

Core milestones only; per-change detail lives in `CHANGELOG.md` and git history.

- Initial implementation: library + CLI, swap/restore with AEAD-bound fakes, streaming restore (63672b1)
- Workspace split (`doppel` lib, `doppel-cli`) and opaque `Pattern` API (4b47145)
- Unified pattern model: literal/opaque/variable segments, v3 TOML patterns file, 28 built-ins (38168b3)
- Stable fakes across restarts, user-defined patterns, CLI define/register/list/inspect/remove (6904209, 7e4b9a8)
- Security hardening from exploit rounds: key zeroization, key-file permissions, AAD fake binding, Tier 2 leakage (650ae57, 3c0560b, 7005d46, 662fca8)
- Trailing-run guard against base64-blob false positives, default for GCP and AWS AKIA/ASIA (7bff46b, b48fd08, 69094f0)
- Property-test tier with independent oracles; swap/restore/registration bugs fixed (6738b73..4a113ad)
- Release discipline: `just` gates, hooks, tag policy, `RELEASING.md`; v0.1.0 released (5ff3156)

## Known Gaps

- Property tier built and validated on Rust 1.86 only; exact 1.85 (declared MSRV) not tested because the toolchain is not installed.
- Intermittent `BrokenPipe` in `doppel-cli/tests/e2e/cli.rs` `test_e2e_register_missing_patterns_file` (test writes stdin after the child may already have exited); not fixed.
- No CI configuration (out of scope for initial-implementation plan)
- INV-26 and INV-27 `log::warn` diagnostics have no test assertions; tests verify registration succeeds but cannot capture log output without a test logger harness. Future fix: wire a test logger via `testing_logger` or equivalent.
