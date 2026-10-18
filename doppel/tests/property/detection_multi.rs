// P-DET-2: multi-pattern detection with constructed anchor overlaps, the
// literal-first tie (INV-18), the HMAC gate (INV-16, VC-11) and group patterns
// (VC-17), all checked against the independent oracle. The spans `swap`
// replaced cannot be recovered from its output (fakes are random), so the
// oracle predicts them first. Never read the session key, nonce, or ciphertext.

use crate::generators::{self, PatternSpec};
use crate::oracle::{Cs, Seg};
use proptest::prelude::*;

const ANCHOR: &[u8] = b"abPQ";

/// Length of a spec's fixed first-segment anchor. Overlapping-pair specs always
/// start with a literal or opaque anchor, so this is the anchor byte length.
fn anchor_len(spec: &PatternSpec) -> usize {
    match spec.segs.first() {
        Some(Seg::Lit(bytes)) | Some(Seg::Opq(bytes, _)) => bytes.len(),
        _ => 0,
    }
}

/// Overlapping pair plus 0..=1 unrelated family spec. The payload prepends one
/// planted candidate of the outer (strictly longer-anchor) spec followed by a filler
/// run, so the outer candidate always begins at byte 0 — the topology D-1 missed.
fn overlapping_case() -> BoxedStrategy<(Vec<PatternSpec>, Vec<u8>)> {
    (
        generators::arb_overlapping_pair(),
        prop::collection::vec(generators::arb_family_spec(), 0..=1),
    )
        .prop_flat_map(|(pair, extra)| {
            let outer_pos = if anchor_len(&pair[0]) >= anchor_len(&pair[1]) {
                0
            } else {
                1
            };
            let outer_candidate = generators::candidate_strategy(&pair[outer_pos].segs);
            let mut specs = pair;
            specs.extend(extra);
            let base = generators::arb_payload(&specs);
            let filler =
                prop::collection::vec(prop::sample::select(generators::FILLER.to_vec()), 1..=4);
            let specs_ret = specs.clone();
            (outer_candidate, filler, base).prop_map(move |(candidate, filler, payload)| {
                let mut out = candidate;
                out.extend_from_slice(&filler);
                out.extend_from_slice(&payload);
                (specs_ret.clone(), out)
            })
        })
        .boxed()
}

/// A family-spec list (1..=2) plus exactly one instance spec, with a payload built for
/// the whole list. The instance spec appears with probability 1.0.
fn multi_instance_case() -> BoxedStrategy<(Vec<PatternSpec>, Vec<u8>)> {
    (
        prop::collection::vec(generators::arb_family_spec(), 1..=2),
        generators::arb_instance_spec(),
    )
        .prop_flat_map(|(mut families, instance)| {
            families.push(instance);
            let payload = generators::arb_payload(&families);
            (Just(families), payload)
        })
        .boxed()
}

/// One group pattern with 2..=3 distinct accepted secrets. The secrets differ in the
/// first byte of the floor-length Variable segment, chosen constructively as distinct
/// charset elements, so distinctness holds without filtering. The anchor is 3..=4 bytes
/// and the Variable segment's minimum meets the 83-bit fake-capacity floor, so the
/// HMAC-seeded fakes have ample entropy and pairwise collisions are negligible (VC-17).
fn group_case() -> BoxedStrategy<(PatternSpec, Vec<Vec<u8>>)> {
    (
        prop::collection::vec(prop::sample::select(ANCHOR.to_vec()), 3..=4),
        generators::arb_small_cs(),
        2usize..=3,
        any::<[u8; 32]>(),
    )
        .prop_flat_map(|(anchor, cs, count, salt)| {
            let floor = generators::floor_len(cs);
            (floor..=floor + 4).prop_flat_map(move |n| {
                let alphabet = cs.bytes();
                let tags = (0usize..alphabet.len()).prop_map({
                    let alphabet = alphabet.clone();
                    move |start| {
                        (0..count)
                            .map(|i| alphabet[(start + i) % alphabet.len()])
                            .collect::<Vec<u8>>()
                    }
                });
                let tail =
                    prop::collection::vec(prop::sample::select(alphabet.clone()), (n - 1)..=n - 1);
                let tails = prop::collection::vec(tail, count..=count);
                let anchor_seg = anchor.clone();
                let anchor_secret = anchor.clone();
                let segs = vec![Seg::Opq(anchor_seg, Cs::Alphanumeric), Seg::Var(cs, n, n)];
                (tags, tails).prop_map(move |(tags, tails)| {
                    let secrets: Vec<Vec<u8>> = tags
                        .iter()
                        .zip(tails.iter())
                        .map(|(&tag, tail)| {
                            let mut secret = anchor_secret.clone();
                            secret.push(tag);
                            secret.extend_from_slice(tail);
                            secret
                        })
                        .collect();
                    let spec = PatternSpec {
                        segs: segs.clone(),
                        guard: None,
                        guard_cs: None,
                        salt,
                        accepted: Some(secrets.clone()),
                    };
                    (spec, secrets)
                })
            })
        })
        .boxed()
}

proptest! {
    #![proptest_config(crate::support::config(64))]

    #[test]
    fn prop_overlapping_anchors_swap_matches_oracle(
        (specs, payload) in overlapping_case(),
    ) {
        let (_file, patterns, oracles) = generators::build(&specs);
        prop_assert_eq!(patterns.len(), oracles.len());
        crate::detection::check_swap_against_oracle(&patterns, &oracles, &payload)?;
    }

    #[test]
    fn prop_multi_pattern_with_instance_swap_matches_oracle(
        (specs, payload) in multi_instance_case(),
    ) {
        let (_file, patterns, oracles) = generators::build(&specs);
        prop_assert_eq!(patterns.len(), oracles.len());
        crate::detection::check_swap_against_oracle(&patterns, &oracles, &payload)?;
    }

    #[test]
    fn prop_group_pattern_detects_every_member_with_distinct_fakes(
        (spec, secrets) in group_case(),
    ) {
        let mut payload: Vec<u8> = Vec::new();
        for (i, secret) in secrets.iter().enumerate() {
            if i > 0 {
                payload.push(b' ');
            }
            payload.extend_from_slice(secret);
        }

        let (_file, patterns, oracles) = generators::build(std::slice::from_ref(&spec));
        crate::detection::check_swap_against_oracle(&patterns, &oracles, &payload)?;

        let result = doppel::swap(&payload, &patterns).expect("group swap must succeed");
        prop_assert_eq!(
            result.entries.len(),
            secrets.len(),
            "one entry per accepted secret"
        );

        // INV-14: distinct secrets share no fake; VC-17 requires distinct fakes.
        let fakes: Vec<Vec<u8>> = result.entries.iter().map(|e| e.fake.clone()).collect();
        for i in 0..fakes.len() {
            for j in (i + 1)..fakes.len() {
                prop_assert_ne!(&fakes[i], &fakes[j], "group fakes must be pairwise distinct");
            }
        }

        // INV-1: every accepted secret is replaced, so none survives in the output.
        for secret in &secrets {
            prop_assert!(
                !result
                    .payload
                    .windows(secret.len())
                    .any(|w| w == secret.as_slice()),
                "accepted secret must be absent from the swapped payload"
            );
        }
    }

    #[test]
    fn prop_local_specs_meet_fake_capacity_floor((spec, _secrets) in group_case()) {
        prop_assert!(
            generators::fake_capacity_bits(&spec.segs) >= generators::FAKE_CAPACITY_FLOOR_BITS,
            "group spec below the fake-capacity floor: {:?}",
            spec.segs
        );
    }
}
