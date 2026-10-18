// Spec: SPEC.md §Detection Algorithm in swap, Behavioral Invariants 1 and 18

use doppel::{PatternEntry, SecretsFile, patterns, register, segment::SegmentDef, swap};

// Synthetic test keys — NOT real credentials. Formats match the real ones so
// structural detection is exercised, but every byte is fabricated.
const SYNTH_GITHUB_FG: &[u8] =
    b"github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const SYNTH_LINEAR: &[u8] = b"lin_api_SYNTHabcdefghijklmnopqrstuvwxyz012345678";

#[test]
fn test_swap_detects_secret_whose_anchor_contains_shorter_earlier_ending_anchor() {
    // INV-1/INV-18: the outer anchor `abcd` starts earlier than the inner
    // anchor `bc` (which is a substring of `abcd` and ends earlier). Leftmost
    // selection must detect the secret starting at `abcd`.
    let mut sf = SecretsFile::new();
    sf.pattern.push(PatternEntry {
        identifier: "outer".to_string(),
        salt: [0x11; 32],
        digests: vec![],
        segments: vec![
            SegmentDef::Literal {
                value: "abcd".to_string(),
            },
            SegmentDef::Variable {
                charset: "digits".to_string(),
                min: 4,
                max: 4,
            },
        ],
        trailing_run_guard: None,
        trailing_run_guard_charset: None,
    });
    sf.pattern.push(PatternEntry {
        identifier: "inner".to_string(),
        salt: [0x22; 32],
        digests: vec![],
        segments: vec![
            SegmentDef::Literal {
                value: "bc".to_string(),
            },
            SegmentDef::Variable {
                charset: "alphanumeric".to_string(),
                min: 10,
                max: 10,
            },
        ],
        trailing_run_guard: None,
        trailing_run_guard_charset: None,
    });

    let pats = sf.to_patterns().unwrap();
    let r = swap(b"x abcd1234 y", &pats).unwrap();

    assert_eq!(
        r.entries.len(),
        1,
        "INV-1/INV-18: the secret anchored at the earlier start `abcd` must be detected"
    );
    assert_eq!(&r.payload[..2], &b"x "[..], "INV-2: prefix unchanged");
    assert_eq!(&r.payload[2..6], &b"abcd"[..], "outer literal preserved");
    assert!(
        r.payload[6..10].iter().all(u8::is_ascii_digit),
        "outer variable region must be replaced with digits"
    );
    assert_ne!(
        &r.payload[6..10],
        &b"1234"[..],
        "the fake must differ from the original secret bytes"
    );
    assert_eq!(&r.payload[10..], &b" y"[..], "INV-2: suffix unchanged");
}

#[test]
fn test_registered_hub_anchor_does_not_hide_fine_grained_pat() {
    // INV-1/INV-18: `hub` (a substring of `github_pat_` that ends earlier) must
    // not mask the fine-grained PAT that starts earlier. Both pattern orders
    // must detect the PAT.
    let reg = register(b"hubSYNTHETICxq9Zt7Lm2Pw4Rv8Ks").unwrap();
    let payload = [b"tok=".as_slice(), SYNTH_GITHUB_FG, b" end"].concat();

    for pats in [
        vec![patterns::github_fine_grained(), reg.clone()],
        vec![reg.clone(), patterns::github_fine_grained()],
    ] {
        let r = swap(&payload, &pats).unwrap();
        assert_eq!(
            r.entries.len(),
            1,
            "INV-1: the fine-grained PAT must be detected in either pattern order"
        );
        assert!(
            !r.payload
                .windows(SYNTH_GITHUB_FG.len())
                .any(|w| w == SYNTH_GITHUB_FG),
            "INV-1: the original fine-grained PAT must not survive in the output"
        );
    }
}

#[test]
fn test_registered_api_anchor_does_not_hide_linear_key() {
    // INV-1/INV-18: `api` (a substring of `lin_api_` that ends earlier) must not
    // mask the Linear key whose anchor starts earlier.
    assert_eq!(SYNTH_LINEAR.len(), 48, "synthetic Linear key length");
    let reg = register(b"api_SYNTHETIC_tokenQ9z7Lm2Pw4Rv8Ks").unwrap();
    let payload = [b"x ".as_slice(), SYNTH_LINEAR, b" y"].concat();

    let r = swap(&payload, &[patterns::linear(), reg]).unwrap();
    assert_eq!(r.entries.len(), 1, "INV-1: the Linear key must be detected");
    assert!(
        !r.payload
            .windows(SYNTH_LINEAR.len())
            .any(|w| w == SYNTH_LINEAR),
        "INV-1: the original Linear key must not survive in the output"
    );
}
