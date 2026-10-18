// Constructive pattern and payload generators over the public SecretsFile API.
// Candidates are built segment by segment from the spec, so every planted payload
// matches structurally by construction; no filtering or assumption combinators are used.

use crate::oracle::{Cs, OPattern, Seg};
use doppel::segment::SegmentDef;
use doppel::{Pattern, PatternEntry, SecretsFile};
use proptest::prelude::*;

/// Bytes that belong to no charset and no generator alphabet, so a fake can never
/// straddle them. Kept disjoint from every charset emitted by `arb_cs`/`arb_small_cs`.
pub const FILLER: &[u8] = b" \n\"\\\x00\x80\xff";

const ANCHOR_BYTES: &[u8] = b"abPQ";
const LITERAL_TAIL_BYTES: &[u8] = b"ab1_-";
const OPAQUE_TAIL_BYTES: &[u8] = b"ab";
const NEAR_MISS_BYTES: &[u8] = b"abPQ1_-+/=Z9";

// Small charsets containing every anchor byte (a, b, P, Q), so an opaque anchor is
// always reproducible from its own charset. No Wide: smaller alphabets force collisions.
const ANCHOR_CS: [Cs; 3] = [Cs::Alphanumeric, Cs::UrlSafeBase64, Cs::Base64Any];
const SMALL_CS: [Cs; 6] = [
    Cs::Alphanumeric,
    Cs::UrlSafeBase64,
    Cs::Base64Any,
    Cs::UppercaseAlphanumeric,
    Cs::Digits,
    Cs::HexLower,
];

/// A generated pattern: the oracle-shaped structure plus the caller-chosen salt and,
/// for instance patterns, the accepted candidate set.
#[derive(Clone, Debug)]
pub struct PatternSpec {
    pub segs: Vec<Seg>,
    pub guard: Option<usize>,
    pub guard_cs: Option<Cs>,
    pub salt: [u8; 32],
    /// Some(secrets) = instance pattern; secrets are full candidates.
    pub accepted: Option<Vec<Vec<u8>>>,
}

impl PatternSpec {
    pub fn to_oracle(&self) -> OPattern {
        OPattern {
            segs: self.segs.clone(),
            guard: self.guard,
            guard_cs: self.guard_cs,
            accepted: self.accepted.clone(),
        }
    }

    fn seg_def(seg: &Seg) -> SegmentDef {
        match seg {
            Seg::Lit(bytes) => SegmentDef::Literal {
                value: String::from_utf8(bytes.clone()).expect("generated literal is UTF-8"),
            },
            Seg::Opq(value, cs) => SegmentDef::Opaque {
                value: String::from_utf8(value.clone()).expect("generated opaque value is UTF-8"),
                charset: Some(cs.name().to_string()),
            },
            Seg::Var(cs, min, max) => SegmentDef::Variable {
                charset: cs.name().to_string(),
                min: *min,
                max: *max,
            },
        }
    }
}

/// Builds the `SecretsFile` (ids "p0","p1",…), the doppel `Pattern`s (via `to_patterns`)
/// and the oracle patterns, all in the same order.
pub fn build(specs: &[PatternSpec]) -> (SecretsFile, Vec<Pattern>, Vec<OPattern>) {
    let mut file = SecretsFile::new();
    for (i, spec) in specs.iter().enumerate() {
        let id = format!("p{i}");
        let segments: Vec<SegmentDef> = spec.segs.iter().map(PatternSpec::seg_def).collect();
        let guard = spec.guard.map(|g| g as u64);
        let guard_cs = spec.guard_cs.map(|c| c.name().to_string());

        let mut entry = PatternEntry {
            identifier: id.clone(),
            salt: spec.salt,
            digests: Vec::new(),
            segments,
            trailing_run_guard: guard,
            trailing_run_guard_charset: guard_cs,
        };
        if spec.accepted.is_some() {
            // Placeholder digest makes this an instance entry; it matches nothing in practice.
            entry.digests.push([0u8; 32]);
        }
        file.pattern.push(entry);
        if let Some(secrets) = &spec.accepted {
            for secret in secrets {
                file.add_secret_to_group(&id, secret)
                    .expect("instance entry was just inserted");
            }
        }
    }

    let patterns = file
        .to_patterns()
        .expect("generated specs must load through SecretsFile");
    let oracles = specs.iter().map(PatternSpec::to_oracle).collect();
    (file, patterns, oracles)
}

pub fn arb_cs() -> impl Strategy<Value = Cs> {
    prop::sample::select(crate::oracle::ALL_CS.to_vec())
}

pub fn arb_small_cs() -> impl Strategy<Value = Cs> {
    prop::sample::select(SMALL_CS.to_vec())
}

/// Fake-format capacity floor, in bits, that every generated property-tier pattern
/// must meet. It matches registration's `InsufficientEntropy` floor (SPEC.md
/// §Entropy Requirements); under it a collision is a finding, not a skip (D5 = A).
pub const FAKE_CAPACITY_FLOOR_BITS: f64 = 83.0;

/// Conservative fake-format capacity: the sum over variable segments of
/// `min × log2 |charset|`. Literal and opaque segments contribute 0, mirroring
/// registration, which counts only the variable portion. The minimum length is
/// used because fakes only collide at equal length.
pub fn fake_capacity_bits(segs: &[Seg]) -> f64 {
    segs.iter()
        .map(|seg| match seg {
            Seg::Var(cs, min, _) => crate::oracle::entropy_bits(*min, cs.bytes().len()),
            _ => 0.0,
        })
        .sum()
}

/// The smallest variable length whose charset draw meets `FAKE_CAPACITY_FLOOR_BITS`.
pub fn floor_len(cs: Cs) -> usize {
    let size = cs.bytes().len();
    let mut len = 1;
    while crate::oracle::entropy_bits(len, size) < FAKE_CAPACITY_FLOOR_BITS {
        len += 1;
    }
    len
}

/// A variable segment whose minimum length already meets the capacity floor. It is
/// constructive (no filter, no `prop_assume`), and its lower bound is the floor, so
/// shrinking cannot drop the fake capacity below it.
fn capacity_var() -> BoxedStrategy<Seg> {
    arb_small_cs()
        .prop_flat_map(|cs| {
            let m = floor_len(cs);
            (m..=m + 3).prop_map(move |max| Seg::Var(cs, m, max))
        })
        .boxed()
}

fn bytes_from(len: std::ops::RangeInclusive<usize>, alphabet: &[u8]) -> BoxedStrategy<Vec<u8>> {
    prop::collection::vec(prop::sample::select(alphabet.to_vec()), len).boxed()
}

fn anchor_charset() -> BoxedStrategy<Cs> {
    prop::sample::select(ANCHOR_CS.to_vec()).boxed()
}

/// Family pattern with a literal or opaque anchor followed by 1..=3 mixed segments,
/// always containing at least one Variable segment and an optional trailing-run guard.
pub fn arb_family_spec() -> impl Strategy<Value = PatternSpec> {
    let first = prop_oneof![
        6 => bytes_from(2..=4, ANCHOR_BYTES).prop_map(Seg::Lit),
        4 => (bytes_from(2..=4, ANCHOR_BYTES), anchor_charset())
            .prop_map(|(bytes, cs)| Seg::Opq(bytes, cs)),
    ];
    let tail = prop_oneof![
        3 => (arb_small_cs(), 1usize..=4).prop_flat_map(|(cs, min)| {
            (Just(cs), Just(min), min..=min + 3).prop_map(|(cs, min, max)| Seg::Var(cs, min, max))
        }),
        1 => bytes_from(1..=2, LITERAL_TAIL_BYTES).prop_map(Seg::Lit),
        1 => bytes_from(1..=2, OPAQUE_TAIL_BYTES).prop_map(|b| Seg::Opq(b, Cs::Alphanumeric)),
    ];
    let segs = (
        first,
        prop::collection::vec(tail, 1..=3),
        capacity_var(),
        any::<prop::sample::Index>(),
    )
        .prop_map(|(first, mut rest, capacity, index)| {
            rest.insert(index.index(rest.len() + 1), capacity);
            let mut segs = Vec::with_capacity(rest.len() + 1);
            segs.push(first);
            segs.append(&mut rest);
            segs
        });
    let guard = prop_oneof![
        3 => Just((None::<usize>, None::<Cs>)),
        1 => (1usize..=12, prop::option::of(arb_cs())).prop_map(|(t, cs)| (Some(t), cs)),
    ];
    (segs, guard, any::<[u8; 32]>()).prop_map(|(segs, (guard, guard_cs), salt)| PatternSpec {
        segs,
        guard,
        guard_cs,
        salt,
        accepted: None,
    })
}

/// Instance pattern: an opaque anchor plus a fixed-length Variable segment (min == max,
/// INV-31) and 1..=3 constructively generated accepted secrets.
pub fn arb_instance_spec() -> impl Strategy<Value = PatternSpec> {
    (
        bytes_from(2..=4, ANCHOR_BYTES),
        arb_small_cs(),
        any::<[u8; 32]>(),
    )
        .prop_flat_map(|(anchor, cs, salt)| {
            let m = floor_len(cs);
            (m..=m + 3).prop_flat_map(move |n| {
                let segs = vec![
                    Seg::Opq(anchor.clone(), Cs::Alphanumeric),
                    Seg::Var(cs, n, n),
                ];
                let secrets = prop::collection::vec(candidate_strategy(&segs), 1..=3);
                (Just(segs), secrets).prop_map(move |(segs, secrets)| PatternSpec {
                    segs,
                    guard: None,
                    guard_cs: None,
                    salt,
                    accepted: Some(secrets),
                })
            })
        })
}

/// Strategy for one structurally valid candidate of `segs`: the concatenation of
/// literal/opaque bytes and, per Variable segment, a length in `min..=max` and that
/// many bytes from the charset.
pub fn candidate_strategy(segs: &[Seg]) -> BoxedStrategy<Vec<u8>> {
    segs.iter()
        .map(seg_bytes)
        .fold(Just(Vec::new()).boxed(), |acc, part| {
            (acc, part)
                .prop_map(|(mut prefix, bytes)| {
                    prefix.extend_from_slice(&bytes);
                    prefix
                })
                .boxed()
        })
}

fn seg_bytes(seg: &Seg) -> BoxedStrategy<Vec<u8>> {
    match seg {
        Seg::Lit(bytes) | Seg::Opq(bytes, _) => Just(bytes.clone()).boxed(),
        Seg::Var(cs, min, max) => {
            let alphabet = cs.bytes();
            (*min..=*max)
                .prop_flat_map(move |len| {
                    prop::collection::vec(prop::sample::select(alphabet.clone()), len..=len)
                })
                .boxed()
        }
    }
}

#[derive(Clone, Debug)]
pub enum Piece {
    Planted(Vec<u8>),
    NearMiss(Vec<u8>),
    Filler(Vec<u8>),
}

/// Payload for a fixed pattern set: 0..=8 pieces, concatenated. Adjacent Planted
/// pieces (no Filler between) deliberately exercise adjacency.
pub fn arb_payload(specs: &[PatternSpec]) -> BoxedStrategy<Vec<u8>> {
    prop::collection::vec(arb_piece(specs), 0..=8)
        .prop_map(|pieces| {
            let mut out = Vec::new();
            for piece in pieces {
                match piece {
                    Piece::Planted(b) | Piece::NearMiss(b) | Piece::Filler(b) => {
                        out.extend_from_slice(&b)
                    }
                }
            }
            out
        })
        .boxed()
}

fn arb_piece(specs: &[PatternSpec]) -> BoxedStrategy<Piece> {
    let planted = planted_bytes(specs).prop_map(Piece::Planted);
    let near = near_miss(planted_bytes(specs)).prop_map(Piece::NearMiss);
    let filler =
        prop::collection::vec(prop::sample::select(FILLER.to_vec()), 1..=4).prop_map(Piece::Filler);
    prop_oneof![
        4 => planted,
        2 => near,
        2 => filler,
    ]
    .boxed()
}

fn planted_bytes(specs: &[PatternSpec]) -> BoxedStrategy<Vec<u8>> {
    let specs = specs.to_vec();
    if specs.is_empty() {
        return Just(Vec::new()).boxed();
    }
    (0..specs.len())
        .prop_flat_map(move |i| {
            let spec = &specs[i];
            match &spec.accepted {
                None => candidate_strategy(&spec.segs),
                Some(accepted) => prop_oneof![
                    7 => prop::sample::select(accepted.clone()),
                    3 => candidate_strategy(&spec.segs),
                ]
                .boxed(),
            }
        })
        .boxed()
}

fn near_miss(candidate: BoxedStrategy<Vec<u8>>) -> BoxedStrategy<Vec<u8>> {
    candidate
        .prop_flat_map(|c| {
            if c.is_empty() {
                return Just(Vec::new()).boxed();
            }
            let n = c.len();
            let replace = (0..n, prop::sample::select(NEAR_MISS_BYTES.to_vec())).prop_map({
                let base = c.clone();
                move |(i, b): (usize, u8)| {
                    let mut v = base.clone();
                    v[i] = b;
                    v
                }
            });
            let truncate = (1usize..=2.min(n)).prop_map({
                let base = c.clone();
                move |k: usize| {
                    let mut v = base.clone();
                    v.truncate(n - k);
                    v
                }
            });
            prop_oneof![replace, truncate,].boxed()
        })
        .boxed()
}

/// A case: 1..=max_patterns family specs (plus an instance spec with p=0.25), and a
/// payload built for exactly those specs.
pub fn arb_case(max_patterns: usize) -> impl Strategy<Value = (Vec<PatternSpec>, Vec<u8>)> {
    let specs = (
        prop::collection::vec(arb_family_spec(), 1..=max_patterns),
        prop::bool::weighted(0.25),
    )
        .prop_flat_map(|(families, add_instance)| {
            if add_instance {
                arb_instance_spec()
                    .prop_map({
                        let families = families.clone();
                        move |inst| {
                            let mut out = families.clone();
                            out.push(inst);
                            out
                        }
                    })
                    .boxed()
            } else {
                Just(families.clone()).boxed()
            }
        });
    specs.prop_flat_map(|specs| {
        let payload = arb_payload(&specs);
        (Just(specs), payload)
    })
}

/// Rest segments for an overlapping-pair pattern: 1..=2 segments drawn from the same
/// alternatives as `arb_family_spec`, always containing at least one Variable.
fn pair_rest_segments() -> BoxedStrategy<Vec<Seg>> {
    let seg = prop_oneof![
        3 => (arb_small_cs(), 1usize..=4).prop_flat_map(|(cs, min)| {
            (Just(cs), Just(min), min..=min + 3).prop_map(|(cs, min, max)| Seg::Var(cs, min, max))
        }),
        1 => bytes_from(1..=2, LITERAL_TAIL_BYTES).prop_map(Seg::Lit),
        1 => bytes_from(1..=2, OPAQUE_TAIL_BYTES).prop_map(|b| Seg::Opq(b, Cs::Alphanumeric)),
    ];
    (
        prop::collection::vec(seg, 1..=2),
        capacity_var(),
        any::<prop::sample::Index>(),
    )
        .prop_map(|(mut segs, capacity, index)| {
            segs.insert(index.index(segs.len() + 1), capacity);
            segs
        })
        .boxed()
}

/// Two family specs whose first-segment anchors overlap: the inner anchor is
/// `outer_anchor[k..k + m]` with `k >= 1`, `m >= 2` and `k + m < outer_anchor.len()`,
/// so the inner anchor starts later and ends earlier than the outer. The outer anchor is
/// 4..=6 bytes from `b"abPQ"`, literal or opaque; each pattern's remaining 1..=2 segments
/// contain at least one Variable. Guards are `None`. Returns `[outer, inner]` in random
/// order, so identify the outer spec by its strictly longer first-segment anchor.
pub fn arb_overlapping_pair() -> BoxedStrategy<Vec<PatternSpec>> {
    (bytes_from(4..=6, ANCHOR_BYTES), prop::bool::weighted(0.5))
        .prop_flat_map(|(outer_anchor, outer_literal)| {
            let len = outer_anchor.len();
            (1usize..=(len - 3)).prop_flat_map(move |k| {
                let outer_anchor = outer_anchor.clone();
                (2usize..=(len - 1 - k)).prop_flat_map(move |m| {
                    let inner_anchor = outer_anchor[k..k + m].to_vec();
                    let outer_first = if outer_literal {
                        Seg::Lit(outer_anchor.clone())
                    } else {
                        Seg::Opq(outer_anchor.clone(), Cs::Alphanumeric)
                    };
                    (
                        Just(inner_anchor),
                        Just(outer_first),
                        pair_rest_segments(),
                        pair_rest_segments(),
                        prop::bool::weighted(0.5),
                        any::<[u8; 32]>(),
                        any::<[u8; 32]>(),
                        prop::bool::weighted(0.5),
                    )
                        .prop_map(
                            |(
                                inner_anchor,
                                outer_first,
                                outer_rest,
                                inner_rest,
                                inner_literal,
                                outer_salt,
                                inner_salt,
                                reverse,
                            )| {
                                let inner_first = if inner_literal {
                                    Seg::Lit(inner_anchor)
                                } else {
                                    Seg::Opq(inner_anchor, Cs::Alphanumeric)
                                };
                                let mut outer_segs = vec![outer_first];
                                outer_segs.extend(outer_rest);
                                let mut inner_segs = vec![inner_first];
                                inner_segs.extend(inner_rest);
                                let mut pair = vec![
                                    PatternSpec {
                                        segs: outer_segs,
                                        guard: None,
                                        guard_cs: None,
                                        salt: outer_salt,
                                        accepted: None,
                                    },
                                    PatternSpec {
                                        segs: inner_segs,
                                        guard: None,
                                        guard_cs: None,
                                        salt: inner_salt,
                                        accepted: None,
                                    },
                                ];
                                if reverse {
                                    pair.reverse();
                                }
                                pair
                            },
                        )
                })
            })
        })
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    fn first_anchor(segs: &[Seg]) -> Vec<u8> {
        match segs.first() {
            Some(Seg::Lit(bytes)) | Some(Seg::Opq(bytes, _)) => bytes.clone(),
            other => panic!("expected literal or opaque first segment, got {other:?}"),
        }
    }

    fn assert_capacity_floor(specs: &[PatternSpec], context: &str) {
        for spec in specs {
            let capacity = fake_capacity_bits(&spec.segs);
            assert!(
                capacity >= FAKE_CAPACITY_FLOOR_BITS,
                "{context}: fake capacity {capacity} below floor for {:?}",
                spec.segs
            );
        }
    }

    #[test]
    fn test_floor_len_matches_registration_floor() {
        let expected = [
            (Cs::Wide, 13),
            (Cs::Alphanumeric, 14),
            (Cs::UrlSafeBase64, 14),
            (Cs::Base64Any, 14),
            (Cs::UppercaseAlphanumeric, 17),
            (Cs::HexLower, 21),
            (Cs::Digits, 25),
        ];
        for (cs, want) in expected {
            assert_eq!(floor_len(cs), want, "floor_len({})", cs.name());
        }
        for &cs in crate::oracle::ALL_CS.iter() {
            let size = cs.bytes().len();
            assert!(
                crate::oracle::entropy_bits(floor_len(cs), size) >= FAKE_CAPACITY_FLOOR_BITS,
                "floor_len({}) does not meet the floor",
                cs.name()
            );
            assert!(
                crate::oracle::entropy_bits(floor_len(cs) - 1, size) < FAKE_CAPACITY_FLOOR_BITS,
                "floor_len({}) is not minimal",
                cs.name()
            );
        }
    }

    proptest! {
        #![proptest_config(crate::support::config(64))]

        #[test]
        fn prop_generated_specs_meet_fake_capacity_floor(
            (is_overlap, specs) in prop_oneof![
                (Just(false), arb_family_spec().prop_map(|s| vec![s])),
                (Just(false), arb_instance_spec().prop_map(|s| vec![s])),
                (Just(false), arb_case(3).prop_map(|(specs, _)| specs)),
                (Just(true), arb_overlapping_pair()),
            ],
        ) {
            assert_capacity_floor(&specs, "generated spec");
            if is_overlap {
                prop_assert_eq!(specs.len(), 2);
                let a = first_anchor(&specs[0].segs);
                let b = first_anchor(&specs[1].segs);
                let (outer, inner) = if a.len() >= b.len() { (&a, &b) } else { (&b, &a) };
                prop_assert!(
                    inner.len() + 2 <= outer.len(),
                    "inner anchor {inner:?} is not strictly shorter than outer {outer:?}"
                );
                let interior = (1..=outer.len() - inner.len() - 1)
                    .any(|k| outer[k..k + inner.len()] == inner[..]);
                prop_assert!(
                    interior,
                    "inner anchor {inner:?} is not a strict interior substring of outer {outer:?}"
                );
            }
        }
    }

    #[test]
    fn generated_specs_keep_capacity_floor_while_shrinking() {
        let strategies: Vec<BoxedStrategy<Vec<PatternSpec>>> = vec![
            arb_family_spec().prop_map(|s| vec![s]).boxed(),
            arb_instance_spec().prop_map(|s| vec![s]).boxed(),
            arb_overlapping_pair().boxed(),
            arb_case(3).prop_map(|(specs, _)| specs).boxed(),
        ];
        let mut runner = TestRunner::deterministic();
        for strategy in &strategies {
            for _ in 0..64 {
                let mut tree = strategy.new_tree(&mut runner).expect("new_tree");
                assert_capacity_floor(&tree.current(), "initial");
                for _ in 0..512 {
                    if !tree.simplify() {
                        break;
                    }
                    assert_capacity_floor(&tree.current(), "after simplify");
                }
                let _ = tree.complicate();
                assert_capacity_floor(&tree.current(), "after complicate");
            }
        }
    }

    proptest! {
        #![proptest_config(crate::support::config(64))]

        #[test]
        fn prop_generated_specs_load_through_secrets_file(
            (mut specs, instance) in (
                prop::collection::vec(arb_family_spec(), 1..=3),
                prop::option::of(arb_instance_spec()),
            ),
        ) {
            if let Some(instance) = instance {
                specs.push(instance);
            }
            let (file, patterns, oracles) = build(&specs);
            prop_assert_eq!(patterns.len(), specs.len());
            prop_assert_eq!(oracles.len(), specs.len());

            let bytes = file.serialize().expect("generated file must serialize");
            let reloaded = SecretsFile::deserialize(&bytes).expect("generated file must deserialize");
            let reloaded_patterns = reloaded.to_patterns().expect("reloaded file must load");
            prop_assert_eq!(reloaded_patterns.len(), specs.len());
        }

        #[test]
        fn prop_planted_candidates_match_their_spec_in_oracle(
            (spec, candidate) in prop_oneof![arb_family_spec(), arb_instance_spec()]
                .prop_flat_map(|spec| {
                    let candidate = candidate_strategy(&spec.segs);
                    (Just(spec), candidate)
                }),
        ) {
            let ends: Vec<usize> = crate::oracle::segmentations(&spec.segs, &candidate, 0)
                .into_iter()
                .map(|(end, _)| end)
                .collect();
            prop_assert!(
                ends.contains(&candidate.len()),
                "no full segmentation of {:?} under {:?}",
                candidate,
                spec.segs
            );
        }

        #[test]
        fn prop_generated_cases_build_and_payload_stays_in_known_alphabets(
            (specs, payload) in arb_case(4),
        ) {
            prop_assert!(!specs.is_empty());
            let (_file, patterns, oracles) = build(&specs);
            prop_assert_eq!(patterns.len(), specs.len());
            prop_assert_eq!(oracles.len(), specs.len());
            // Filler bytes are disjoint from every charset, and every generated
            // planted/near-miss byte comes from some charset, so this must hold.
            let all_known = payload
                .iter()
                .all(|&b| FILLER.contains(&b) || crate::oracle::ALL_CS.iter().any(|cs| cs.contains(b)));
            prop_assert!(all_known);
        }
    }

    #[test]
    fn prop_filler_bytes_are_outside_every_charset() {
        for &b in FILLER {
            for &cs in crate::oracle::ALL_CS.iter() {
                assert!(
                    !cs.contains(b),
                    "filler byte {b:#04x} unexpectedly in {}",
                    cs.name()
                );
            }
        }
    }
}
