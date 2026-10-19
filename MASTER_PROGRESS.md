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

## Known Gaps

- Property tier built and validated on Rust 1.86 only; exact 1.85 (declared MSRV) not tested because the toolchain is not installed.
- Intermittent `BrokenPipe` in `doppel-cli/tests/e2e/cli.rs` `test_e2e_register_missing_patterns_file` (test writes stdin after the child may already have exited); not fixed.
- No CI configuration (out of scope for initial-implementation plan)
- INV-26 and INV-27 `log::warn` diagnostics have no test assertions; tests verify registration succeeds but cannot capture log output without a test logger harness. Future fix: wire a test logger via `testing_logger` or equivalent.
