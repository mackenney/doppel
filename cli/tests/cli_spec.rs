// CLI spec invariant tests — SPEC.md §Behavioral Invariants
// These tests exercise CLI binary behavior via CARGO_BIN_EXE.
// See also: tests/spec/ in the root library crate for non-CLI invariants.

#[path = "cli_spec/inv_cli.rs"]
mod inv_cli;
