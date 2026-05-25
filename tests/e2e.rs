// E2E tests — CLI process boundary.
// Gated by: cargo nextest run --features test-e2e --test e2e
#![cfg(feature = "test-e2e")]

#[path = "e2e/cli.rs"]
mod cli;
