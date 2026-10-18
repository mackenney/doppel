use proptest::test_runner::{Config, FileFailurePersistence};

/// Routine configuration: `routine_cases` cases and 2048 shrink iterations,
/// unless PROPTEST_CASES / PROPTEST_MAX_SHRINK_ITERS are set. An explicit
/// `cases` field would otherwise silently override the env var, which is what
/// exploratory runs rely on.
pub fn config(routine_cases: u32) -> Config {
    let base = Config::default();
    let env_set = |k: &str| std::env::var_os(k).is_some();
    Config {
        cases: if env_set("PROPTEST_CASES") {
            base.cases
        } else {
            routine_cases
        },
        max_shrink_iters: if env_set("PROPTEST_MAX_SHRINK_ITERS") {
            base.max_shrink_iters
        } else {
            2048
        },
        failure_persistence: if env_set("PROPTEST_DISABLE_FAILURE_PERSISTENCE") {
            None
        } else {
            Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            )))
        },
        ..base
    }
}
