// Spec: SPEC.md Verifiable Condition 12, Behavioral Invariant 23
use proptest::prelude::*;

proptest! {
    #![proptest_config(crate::support::config(64))]

    #[test]
    fn prop_swap_with_no_patterns_is_identity(payload in proptest::collection::vec(any::<u8>(), 0..512)) {
        let r = doppel::swap(&payload, &[]).unwrap();
        prop_assert_eq!(&r.payload, &payload);
        prop_assert!(r.entries.is_empty());
    }
}
