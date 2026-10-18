// Spec: SPEC.md Behavioral Invariant 4, Verifiable Condition 2

use doppel::segment::SegmentDef;
use doppel::{Pattern, PatternEntry, SecretsFile, restore, swap};

/// Deterministic synthetic pattern: literal `PQ` followed by 1-2 digits.
/// The fixed salt makes the derived fakes reproducible for a given seed.
fn prefix_pattern(seed: u32) -> Vec<Pattern> {
    let mut salt = [0u8; 32];
    salt[..4].copy_from_slice(&seed.to_le_bytes());
    let mut sf = SecretsFile::new();
    sf.pattern.push(PatternEntry {
        identifier: "synth_prefix".into(),
        salt,
        digests: vec![],
        segments: vec![
            SegmentDef::Literal { value: "PQ".into() },
            SegmentDef::Variable {
                charset: "digits".into(),
                min: 1,
                max: 2,
            },
        ],
        trailing_run_guard: None,
        trailing_run_guard_charset: None,
    });
    sf.to_patterns().unwrap()
}

#[test]
fn test_restore_round_trips_when_one_fake_prefixes_another() {
    // INV-4: "restore MUST restore every fake present in the response stream
    //         regardless of where chunk boundaries fall."
    // VC-2: a full swap→restore cycle reproduces the original payload.
    // When one entry's fake is a proper prefix of another's, the shorter fake
    // must not shadow the longer one at the shared start.
    let payload: &[u8] = b"a PQ1 b PQ12 c";
    let mut prefix_cases = 0u32;
    for seed in 0..200u32 {
        let pats = prefix_pattern(seed);
        let r = swap(payload, &pats).expect("swap failed");
        assert_eq!(r.entries.len(), 2, "seed {seed}: expected two entries");
        let f0 = &r.entries[0].fake;
        let f1 = &r.entries[1].fake;
        if f0.starts_with(f1.as_slice()) || f1.starts_with(f0.as_slice()) {
            prefix_cases += 1;
        }
        let mut input = r.payload.as_slice();
        let mut out = Vec::new();
        restore(&mut input, &mut out, &r.entries, &r.session_key).unwrap();
        assert_eq!(out, payload, "seed {seed}");
    }
    assert!(
        prefix_cases > 0,
        "test must exercise prefix-related fakes (prefix_cases == 0)"
    );
}

#[cfg(feature = "async")]
#[test]
fn test_restore_stream_round_trips_when_one_fake_prefixes_another() {
    // INV-4 async variant: the streaming restore must restore every fake even
    // when one fake prefixes another, across 3-byte chunk boundaries.
    use bytes::Bytes;
    use doppel::restore_stream;
    use futures::{StreamExt, stream};
    use std::io;

    let payload: &[u8] = b"a PQ1 b PQ12 c";
    for seed in 0..200u32 {
        let pats = prefix_pattern(seed);
        let r = swap(payload, &pats).expect("swap failed");
        assert_eq!(r.entries.len(), 2, "seed {seed}: expected two entries");

        let chunks: Vec<Result<Bytes, io::Error>> = r
            .payload
            .chunks(3)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let inner = stream::iter(chunks);
        let stream = restore_stream(inner, r.entries, r.session_key).unwrap();

        let out = futures::executor::block_on(async {
            let mut all: Vec<u8> = Vec::new();
            futures::pin_mut!(stream);
            while let Some(item) = stream.next().await {
                all.extend_from_slice(&item.expect("restore_stream item"));
            }
            all
        });
        assert_eq!(out, payload, "seed {seed}");
    }
}
