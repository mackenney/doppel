// Spec invariant tests — SPEC.md §Behavioral Invariants
// Each test directly asserts a MUST/MUST NOT clause.
// Failing any test here is a bug or a deliberate spec change.

#[path = "spec/inv.rs"]
mod inv;

#[path = "spec/inv_trailing_run_guard.rs"]
mod inv_trailing_run_guard;

#[path = "spec/inv_candidate_positions.rs"]
mod inv_candidate_positions;

#[path = "spec/inv_restore_prefix_fakes.rs"]
mod inv_restore_prefix_fakes;
