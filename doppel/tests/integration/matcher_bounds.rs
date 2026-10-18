// Integration: variable-segment bounds must not overflow or do work
// proportional to an attacker-controlled `max`.

use doppel::{PatternEntry, SecretsFile, segment::SegmentDef, swap};

const SYNTH_SALT: [u8; 32] = [0x33; 32];
const SYNTH_PAYLOAD: &[u8] = b"xxPQ1234 tail";

/// One-entry pattern: literal `PQ` followed by 1..=max digit bytes.
fn synth_pattern(max: usize) -> Vec<doppel::Pattern> {
    let mut sf = SecretsFile::new();
    sf.pattern.push(PatternEntry {
        identifier: "synth_big".to_string(),
        salt: SYNTH_SALT,
        digests: vec![],
        segments: vec![
            SegmentDef::Literal {
                value: "PQ".to_string(),
            },
            SegmentDef::Variable {
                charset: "digits".to_string(),
                min: 1,
                max,
            },
        ],
        trailing_run_guard: None,
        trailing_run_guard_charset: None,
    });
    sf.to_patterns()
        .expect("synth pattern must build from public SecretsFile fields")
}

#[test]
fn test_swap_with_usize_max_variable_max_does_not_panic() {
    // D-3: `max = usize::MAX` makes `cur + var_len` overflow (debug panic /
    // release wrap) and iterates usize::MAX candidates. Clamping the range to
    // the bytes that remain is semantically equivalent: every overlong length
    // was skipped before.
    let pats = synth_pattern(usize::MAX);
    let result = swap(SYNTH_PAYLOAD, &pats).expect("swap must not panic or error on usize::MAX");

    assert_eq!(result.entries.len(), 1, "the digit run must be detected");
    assert_eq!(&result.payload[..2], &b"xx"[..], "prefix unchanged");
    assert_eq!(&result.payload[2..4], &b"PQ"[..], "literal preserved");
    assert_eq!(&result.payload[8..], &b" tail"[..], "suffix unchanged");
}

#[test]
fn test_swap_with_toml_max_variable_max_completes() {
    // The largest `max` a patterns file can hold is i64::MAX. Each candidate
    // used to run `max - min` iterations regardless of payload length; the
    // clamp bounds work by the remaining payload, so swap completes.
    let toml_bytes = br#"version = 3
[[pattern]]
identifier = "synth_big"
salt = "3333333333333333333333333333333333333333333333333333333333333333"
[[pattern.segments]]
type = "literal"
value = "PQ"
[[pattern.segments]]
type = "variable"
charset = "digits"
min = 1
max = 9223372036854775807
"#;

    let sf = SecretsFile::deserialize(toml_bytes).expect("synth TOML must load");
    let pats = sf.to_patterns().expect("synth TOML must build patterns");
    let result = swap(SYNTH_PAYLOAD, &pats).expect("swap must complete for i64::MAX");

    assert_eq!(result.entries.len(), 1, "the digit run must be detected");
}
