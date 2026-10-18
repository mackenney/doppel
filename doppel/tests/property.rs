// Property-based tests (proptest) for SPEC.md Behavioral Invariants and
// Verifiable Conditions, each checked against an independent oracle.
// Failing seeds persist to `property/<module>.proptest-regressions`.

#[path = "property/detection.rs"]
mod detection;

#[path = "property/detection_multi.rs"]
mod detection_multi;

#[path = "property/generators.rs"]
mod generators;

#[path = "property/guard.rs"]
mod guard;

#[path = "property/oracle.rs"]
mod oracle;

#[path = "property/patterns_file.rs"]
mod patterns_file;

#[path = "property/registration.rs"]
mod registration;

#[cfg(feature = "async")]
#[path = "property/restore_async.rs"]
mod restore_async;

#[path = "property/restore_sync.rs"]
mod restore_sync;

#[path = "property/tamper.rs"]
mod tamper;

#[path = "property/support.rs"]
mod support;

#[path = "property/smoke.rs"]
mod smoke;
