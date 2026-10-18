// P-PF: patterns-file round trip and load-time validation properties.
// A SecretsFile built through the public API is serialized to TOML and reloaded;
// the two files MUST describe the same patterns and derive identical fakes from a
// fixed payload. Required-set mutations MUST be rejected at load time; mutations
// the spec leaves unspecified MUST only avoid panicking. Never read the session
// key, nonce, or ciphertext.

use crate::generators;
use doppel::segment::SegmentDef;
use doppel::{PatternEntry, SecretsFile};
use proptest::prelude::*;

/// One valid generated family entry, built through `generators::build` so it has
/// already passed `to_patterns`.
fn valid_entry() -> impl Strategy<Value = PatternEntry> {
    generators::arb_family_spec().prop_map(|spec| {
        let (file, _, _) = generators::build(std::slice::from_ref(&spec));
        file.pattern.into_iter().next().expect("one entry")
    })
}

fn first_too_short(segs: &[SegmentDef]) -> bool {
    match segs.first() {
        None => true,
        Some(SegmentDef::Literal { value }) | Some(SegmentDef::Opaque { value, .. }) => {
            value.len() < 2
        }
        Some(SegmentDef::Variable { .. }) => true,
    }
}

fn singleton(entry: PatternEntry) -> SecretsFile {
    SecretsFile {
        version: 3,
        pattern: vec![entry],
    }
}

#[derive(Debug)]
struct RequiredCase {
    file: SecretsFile,
    to_patterns_must_err: bool,
}

/// Exactly one mutation from the SPEC-required load-rejection set, layered on a
/// valid generated entry. Every branch genuinely violates its rule, so
/// `deserialize` MUST return `Err`; `to_patterns` re-validates every rule the
/// version check does not cover.
fn required_case() -> impl Strategy<Value = RequiredCase> {
    valid_entry().prop_flat_map(|base| {
        let version_base = base.clone();
        let first_variable = base.clone();
        let zero_guard = base.clone();
        let charset_without_guard = base.clone();
        let no_variable_guard = base.clone();
        let bad_instance = base.clone();

        prop_oneof![
            (0u64..=9).prop_map(move |v| {
                let version = if v >= 3 { v + 1 } else { v };
                RequiredCase {
                    file: SecretsFile {
                        version,
                        pattern: vec![version_base.clone()],
                    },
                    to_patterns_must_err: false,
                }
            }),
            Just(()).prop_map(move |()| {
                let mut entry = first_variable.clone();
                entry.segments[0] = SegmentDef::Variable {
                    charset: "alphanumeric".into(),
                    min: 1,
                    max: 1,
                };
                RequiredCase {
                    file: singleton(entry),
                    to_patterns_must_err: true,
                }
            }),
            Just(()).prop_map(move |()| {
                let mut entry = zero_guard.clone();
                entry.trailing_run_guard = Some(0);
                RequiredCase {
                    file: singleton(entry),
                    to_patterns_must_err: true,
                }
            }),
            Just(()).prop_map(move |()| {
                let mut entry = charset_without_guard.clone();
                entry.trailing_run_guard = None;
                entry.trailing_run_guard_charset = Some("alphanumeric".into());
                RequiredCase {
                    file: singleton(entry),
                    to_patterns_must_err: true,
                }
            }),
            (1u64..=1000).prop_map(move |t| {
                let mut entry = no_variable_guard.clone();
                entry
                    .segments
                    .retain(|s| !matches!(s, SegmentDef::Variable { .. }));
                entry.trailing_run_guard = Some(t);
                entry.trailing_run_guard_charset = None;
                if first_too_short(&entry.segments) {
                    entry
                        .segments
                        .insert(0, SegmentDef::Literal { value: "ab".into() });
                }
                RequiredCase {
                    file: singleton(entry),
                    to_patterns_must_err: true,
                }
            }),
            Just(()).prop_map(move |()| {
                let mut entry = bad_instance.clone();
                entry.digests = vec![[1u8; 32]];
                for seg in entry.segments.iter_mut() {
                    if let SegmentDef::Variable { min, max, .. } = seg {
                        *min = 1;
                        *max = 2;
                        break;
                    }
                }
                RequiredCase {
                    file: singleton(entry),
                    to_patterns_must_err: true,
                }
            }),
        ]
        .boxed()
    })
}

/// Exactly one mutation the spec leaves unspecified: either `Err` or `Ok` is
/// acceptable, but it MUST NOT panic.
fn unspecified_case() -> impl Strategy<Value = SecretsFile> {
    valid_entry().prop_flat_map(|base| {
        let min_gt_max = base.clone();
        let short_first = base.clone();
        let zero_min = base.clone();
        let unknown_charset = base.clone();
        let duplicate = base.clone();

        prop_oneof![
            Just(()).prop_map(move |()| {
                let mut entry = min_gt_max.clone();
                for seg in entry.segments.iter_mut() {
                    if let SegmentDef::Variable { min, max, .. } = seg {
                        *min = *max + 1;
                        break;
                    }
                }
                singleton(entry)
            }),
            (0usize..=1).prop_map(move |n| {
                let mut entry = short_first.clone();
                let value = "a".repeat(n);
                match entry.segments.first_mut() {
                    Some(SegmentDef::Literal { value: v })
                    | Some(SegmentDef::Opaque { value: v, .. }) => *v = value,
                    _ => {}
                }
                singleton(entry)
            }),
            Just(()).prop_map(move |()| {
                let mut entry = zero_min.clone();
                for seg in entry.segments.iter_mut() {
                    if let SegmentDef::Variable { min, .. } = seg {
                        *min = 0;
                        break;
                    }
                }
                singleton(entry)
            }),
            Just(()).prop_map(move |()| {
                let mut entry = unknown_charset.clone();
                for seg in entry.segments.iter_mut() {
                    if let SegmentDef::Variable { charset, .. } = seg {
                        *charset = "bogus_charset".into();
                        break;
                    }
                }
                singleton(entry)
            }),
            Just(()).prop_map(move |()| SecretsFile {
                version: 3,
                pattern: vec![duplicate.clone(), duplicate.clone()],
            }),
        ]
        .boxed()
    })
}

fn arb_valid_file_bytes() -> impl Strategy<Value = Vec<u8>> {
    generators::arb_case(3).prop_map(|(specs, _payload)| {
        let (file, _, _) = generators::build(&specs);
        file.serialize().expect("generated file serializes")
    })
}

/// Arbitrary bytes, plus a valid serialized file with one byte replaced or cut
/// short. Any `Result` is acceptable; the property only forbids a panic.
fn arb_deserialize_input() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..512),
        arb_valid_file_bytes().prop_flat_map(|bytes| {
            if bytes.is_empty() {
                return Just(bytes).boxed();
            }
            let n = bytes.len();
            let replaced = (0..n, any::<u8>()).prop_map({
                let bytes = bytes.clone();
                move |(i, b)| {
                    let mut v = bytes.clone();
                    v[i] = b;
                    v
                }
            });
            let cut = (1..n).prop_map({
                let bytes = bytes.clone();
                move |k| bytes[..k].to_vec()
            });
            prop_oneof![replaced, cut].boxed()
        }),
    ]
    .boxed()
}

proptest! {
    #![proptest_config(crate::support::config(64))]

    #[test]
    fn prop_patterns_file_round_trip_preserves_entries_and_fakes(
        (specs, payload) in generators::arb_case(3),
    ) {
        let (original, _, _) = generators::build(&specs);
        let bytes = original.serialize().expect("generated file serializes");
        let round_tripped = SecretsFile::deserialize(&bytes).expect("generated file loads");

        prop_assert_eq!(original.version, round_tripped.version);
        prop_assert_eq!(original.pattern.len(), round_tripped.pattern.len());
        for (a, b) in original.pattern.iter().zip(round_tripped.pattern.iter()) {
            prop_assert_eq!(&a.identifier, &b.identifier);
            prop_assert_eq!(a.salt, b.salt);
            prop_assert_eq!(&a.digests, &b.digests);
            prop_assert_eq!(&a.segments, &b.segments);
            prop_assert_eq!(a.trailing_run_guard, b.trailing_run_guard);
            prop_assert_eq!(
                &a.trailing_run_guard_charset,
                &b.trailing_run_guard_charset
            );
        }

        // INV-13 across serialization: salts come from the file, so the same
        // payload must swap to byte-identical fakes through both pattern sets.
        let original_patterns = original.to_patterns().expect("original builds patterns");
        let round_tripped_patterns = round_tripped
            .to_patterns()
            .expect("round-tripped builds patterns");
        let original_swap =
            doppel::swap(&payload, &original_patterns).expect("generated swap must succeed");
        let round_tripped_swap = doppel::swap(&payload, &round_tripped_patterns)
            .expect("generated swap must succeed");
        prop_assert_eq!(
            &original_swap.payload,
            &round_tripped_swap.payload,
            "round trip changed the swapped payload"
        );
        let mut original_fakes: Vec<Vec<u8>> =
            original_swap.entries.iter().map(|e| e.fake.clone()).collect();
        let mut round_tripped_fakes: Vec<Vec<u8>> =
            round_tripped_swap.entries.iter().map(|e| e.fake.clone()).collect();
        original_fakes.sort();
        round_tripped_fakes.sort();
        prop_assert_eq!(
            original_fakes,
            round_tripped_fakes,
            "round trip changed the entry fakes"
        );
    }

    #[test]
    fn prop_spec_required_load_rejections(case in required_case()) {
        let bytes = toml::to_string(&case.file).expect("mutated file serializes to TOML");
        let loaded = SecretsFile::deserialize(bytes.as_bytes());
        prop_assert!(
            loaded.is_err(),
            "required-set mutation loaded Ok: {:?}",
            case.file
        );
        if case.to_patterns_must_err {
            prop_assert!(
                case.file.to_patterns().is_err(),
                "required-set mutation built patterns Ok: {:?}",
                case.file
            );
        }
    }

    #[test]
    fn prop_unspecified_load_rejections_never_panic(file in unspecified_case()) {
        let bytes = toml::to_string(&file).expect("mutated file serializes to TOML");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = SecretsFile::deserialize(bytes.as_bytes());
        }));
        prop_assert!(
            outcome.is_ok(),
            "deserialize panicked on unspecified mutation: {:?}",
            file
        );
    }
}

proptest! {
    #![proptest_config(crate::support::config(256))]

    #[test]
    fn prop_deserialize_arbitrary_input_never_panics(input in arb_deserialize_input()) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = SecretsFile::deserialize(&input);
        }));
        prop_assert!(
            outcome.is_ok(),
            "deserialize panicked on {}-byte input",
            input.len()
        );
    }
}
