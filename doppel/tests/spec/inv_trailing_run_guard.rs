// Spec: SPEC.md §Trailing Run Guard, §Registration Options, §Behavioral Invariants item 18 (tie-break clauses) and items 44-49

use doppel::{PatternEntry, SecretOptions, SecretsFile, register, register_with_options, swap};

// Synthetic test keys — NOT real credentials. Format matches real format for structural testing.
const SYNTH_GCP: &[u8] = b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SYNTH_ANTHROPIC: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const URL_SAFE_BASE64_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Deterministic filler drawn from the url-safe-base64 alphabet — no RNG needed,
/// the guard probe is charset-membership only.
fn base64_filler(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| URL_SAFE_BASE64_ALPHABET[i % URL_SAFE_BASE64_ALPHABET.len()])
        .collect()
}

const ALPHANUMERIC_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn alnum_filler(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ALPHANUMERIC_ALPHABET[i % ALPHANUMERIC_ALPHABET.len()])
        .collect()
}

const DIGITS_ALPHABET: &[u8] = b"0123456789";

fn digits_filler(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| DIGITS_ALPHABET[i % DIGITS_ALPHABET.len()])
        .collect()
}

/// Wide charset (0x21..=0x7E minus '"' and '\\') filler.
fn wide_filler(len: usize) -> Vec<u8> {
    let alphabet: Vec<u8> = (0x21u8..=0x7E)
        .filter(|&b| b != b'"' && b != b'\\')
        .collect();
    (0..len).map(|i| alphabet[i % alphabet.len()]).collect()
}

fn family_entry(
    identifier: &str,
    salt: [u8; 32],
    literal: &str,
    var_charset: &str,
    var_len: usize,
    guard: Option<u64>,
) -> PatternEntry {
    PatternEntry {
        identifier: identifier.to_string(),
        salt,
        digests: vec![],
        segments: vec![
            doppel::segment::SegmentDef::Literal {
                value: literal.to_string(),
            },
            doppel::segment::SegmentDef::Variable {
                charset: var_charset.to_string(),
                min: var_len,
                max: var_len,
            },
        ],
        trailing_run_guard: guard,
    }
}

#[test]
fn test_guard_suppresses_match_at_exact_threshold() {
    // item 44, VC-18: guarded pattern's structural match immediately followed by
    // at least the threshold count of guard-charset bytes MUST be discarded.
    let payload = [SYNTH_GCP, &base64_filler(2048)].concat();
    let result = swap(&payload, &[doppel::patterns::gcp()]).expect("swap failed");
    assert_eq!(
        result.payload, payload,
        "VC-18: guard at exact threshold must leave payload unchanged"
    );
    assert!(
        result.entries.is_empty(),
        "VC-18: guard at exact threshold must produce zero entries"
    );
}

#[test]
fn test_guard_does_not_fire_one_byte_under_threshold() {
    // item 44, VC-19: fewer than the threshold count of guard-charset bytes
    // (terminated by a non-charset byte) MUST replace the match normally.
    let payload = [SYNTH_GCP, &base64_filler(2047), b"\"".as_slice()].concat();
    let result = swap(&payload, &[doppel::patterns::gcp()]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "VC-19: one byte under threshold, terminated → must be replaced"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_GCP.len())
            .any(|w| w == SYNTH_GCP),
        "VC-19: original secret must not appear in swapped payload"
    );
}

#[test]
fn test_match_stands_when_eof_reached_before_threshold() {
    // item 44, VC-19: EOF reached before threshold count accumulated → match stands.
    let payload = [SYNTH_GCP, &base64_filler(2047)].concat();
    let result = swap(&payload, &[doppel::patterns::gcp()]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "VC-19: EOF before threshold → must be replaced"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_GCP.len())
            .any(|w| w == SYNTH_GCP),
        "VC-19: original secret must not appear in swapped payload"
    );
}

#[test]
fn test_guard_charset_is_last_variable_segment() {
    // item 45: the guard charset MUST be the charset of the pattern's LAST
    // variable segment, not the first. Two-variable pattern: first variable is
    // alphanumeric, last is digits, guard = 16 on the digits charset.
    let entry = PatternEntry {
        identifier: "two_var".into(),
        salt: [0x11; 32],
        digests: vec![],
        segments: vec![
            doppel::segment::SegmentDef::Literal {
                value: "tok_".into(),
            },
            doppel::segment::SegmentDef::Variable {
                charset: "alphanumeric".into(),
                min: 10,
                max: 10,
            },
            doppel::segment::SegmentDef::Literal { value: "_".into() },
            doppel::segment::SegmentDef::Variable {
                charset: "digits".into(),
                min: 5,
                max: 5,
            },
        ],
        trailing_run_guard: Some(16),
    };
    let pf = SecretsFile {
        version: 3,
        pattern: vec![entry],
    };
    let patterns = pf.to_patterns().expect("fixture must load");

    // Match followed by 16 digits → suppressed (guard fires on the digits tail).
    let match_bytes = [
        b"tok_".as_slice(),
        &alnum_filler(10),
        b"_",
        &digits_filler(5),
    ]
    .concat();
    let suppressed_payload = [match_bytes.as_slice(), &digits_filler(16)].concat();
    let result = swap(&suppressed_payload, &patterns).expect("swap failed");
    assert_eq!(
        result.payload, suppressed_payload,
        "guard on last (digits) variable segment must suppress when followed by 16 digits"
    );
    assert!(result.entries.is_empty());

    // Match followed by 16 non-digit (alphabetic) bytes → guard's own charset is
    // broken immediately, so the match stands (proves the probe used the LAST
    // variable segment's charset — digits — not the first, alphanumeric).
    let letters: Vec<u8> = (0..16).map(|i| b'a' + (i % 26) as u8).collect();
    let standing_payload = [match_bytes.as_slice(), &letters].concat();
    let result2 = swap(&standing_payload, &patterns).expect("swap failed");
    assert_eq!(
        result2.entries.len(),
        1,
        "guard must not fire when trailing bytes are outside the digits charset"
    );
}

#[test]
fn test_vc21_guard_without_variable_segment_rejected_at_load() {
    // item 45, VC-21: loading a patterns file where a guard is declared on an
    // all-literal pattern MUST fail with a clear error mentioning "trailing_run_guard".
    let pf_data = br#"
version = 3

[[pattern]]
identifier = "all_literal"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [{ type = "literal", value = "fixed-token" }]
trailing_run_guard = 2048
"#;
    let err = SecretsFile::deserialize(pf_data).unwrap_err();
    assert!(
        err.to_string().contains("trailing_run_guard"),
        "VC-21: error must mention trailing_run_guard, got: {err}"
    );
}

#[test]
fn test_suppressed_winner_does_not_cascade_to_shorter_pattern() {
    // item 46: suppression yields no detection at that position, full stop — no
    // cascade to a next-best (shorter, unguarded) match at the same position.
    // Unequal-length overlapping patterns: guarded 30-char variable region wins
    // the leftmost-longest selection outright (34 > 24, not a tie); when its
    // guard fires, the shorter unguarded 20-char pattern MUST NOT fire either.
    //
    // SPEC §Trailing Run Guard, "Selection order": uneven guard config across
    // overlapping patterns is the pattern author's responsibility — this test
    // pins the documented no-fallback behavior so it cannot regress silently.
    let guarded = family_entry(
        "guarded_long",
        [0x22; 32],
        "tok_",
        "alphanumeric",
        30,
        Some(64),
    );
    let unguarded = family_entry(
        "unguarded_short",
        [0x33; 32],
        "tok_",
        "alphanumeric",
        20,
        None,
    );
    let pf = SecretsFile {
        version: 3,
        pattern: vec![guarded, unguarded],
    };
    let patterns = pf.to_patterns().expect("fixture must load");

    let payload = [b"tok_".as_slice(), &alnum_filler(30), &alnum_filler(64)].concat();
    let result = swap(&payload, &patterns).expect("swap failed");
    assert_eq!(
        result.payload, payload,
        "item 46: suppressed winner must not cascade to the shorter unguarded pattern"
    );
    assert!(
        result.entries.is_empty(),
        "item 46: no detection at this position when the winner is suppressed"
    );
}

#[test]
fn test_vc20_genuine_secret_inside_probe_window_still_detected() {
    // item 47, VC-20: a different pattern's genuine secret inside the probe
    // window of a guard-suppressed match must be detected and replaced
    // normally at its own position.
    let payload = [
        SYNTH_GCP,
        &base64_filler(2048),
        b" ".as_slice(),
        SYNTH_ANTHROPIC,
    ]
    .concat();
    let result = swap(
        &payload,
        &[doppel::patterns::gcp(), doppel::patterns::anthropic()],
    )
    .expect("swap failed");

    assert_eq!(
        result.entries.len(),
        1,
        "VC-20: only the Anthropic key is detected; GCP match is suppressed"
    );
    assert!(
        result
            .payload
            .windows(SYNTH_GCP.len())
            .any(|w| w == SYNTH_GCP),
        "VC-20: GCP region must remain unchanged (guard suppressed the match)"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "VC-20: Anthropic key must be replaced"
    );
}

#[test]
fn test_unguarded_pattern_never_suppressed_by_trailing_context() {
    // item 48: a pattern with no trailing run guard retains unconditional
    // detection semantics regardless of trailing context.
    let payload = [SYNTH_ANTHROPIC, &base64_filler(4096)].concat();
    let result = swap(&payload, &[doppel::patterns::anthropic()]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "item 48: unguarded pattern must never be suppressed by trailing context"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC)
    );
}

#[test]
fn test_probe_is_forward_only() {
    // item 47: the probe examines bytes only forward from the match end; a
    // huge preceding run must be irrelevant. GCP key at the very end of the
    // payload has an empty forward window, so the guard cannot fire.
    let payload = [&base64_filler(4096), b" ".as_slice(), SYNTH_GCP].concat();
    let result = swap(&payload, &[doppel::patterns::gcp()]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "item 47: empty forward window (EOF) must not suppress the match"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_GCP.len())
            .any(|w| w == SYNTH_GCP),
        "GCP key at end of payload must be replaced"
    );
}

#[test]
fn test_inv49_registration_default_has_no_guard() {
    // items 48, 49: absent trailing-run-guard option means unconditional
    // detection — the option is opt-in.
    let secret = b"my-registered-secret-with-no-guard-01";
    let pat = register(secret).expect("registration must succeed");
    let payload = [secret.as_slice(), &wide_filler(4096)].concat();
    let result = swap(&payload, &[pat]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "item 49: absent guard option → unconditional detection"
    );
    assert!(!result.payload.windows(secret.len()).any(|w| w == secret));
}

#[test]
fn test_vc22_registered_guarded_secret_suppressed_and_replaced() {
    // item 49, VC-22: register_with_options with trailing_run_guard: Some(64).
    let secret = b"sec-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01";
    let opts = SecretOptions {
        trailing_run_guard: Some(64),
        ..Default::default()
    };
    let pat = register_with_options(secret, &opts).expect("registration must succeed");

    // Payload A: secret + 64 wide-charset bytes → suppressed.
    let payload_a = [secret.as_slice(), &wide_filler(64)].concat();
    let result_a = swap(&payload_a, std::slice::from_ref(&pat)).expect("swap failed");
    assert_eq!(
        result_a.payload, payload_a,
        "VC-22: 64 wide-charset trailing bytes must suppress the registered guard"
    );
    assert!(result_a.entries.is_empty());

    // Payload B: secret + '"' (outside the wide charset) → replaced.
    let payload_b = [secret.as_slice(), b"\"".as_slice()].concat();
    let result_b = swap(&payload_b, &[pat]).expect("swap failed");
    assert_eq!(
        result_b.entries.len(),
        1,
        "VC-22: terminator outside guard charset → match must stand"
    );
    assert!(!result_b.payload.windows(secret.len()).any(|w| w == secret));
}

#[test]
fn test_vc23_zero_guard_threshold_rejected_on_both_paths() {
    // item 45, VC-23: shared positivity contract across load and registration.
    let secret = b"another-registered-secret-value-here-02";
    let opts = SecretOptions {
        trailing_run_guard: Some(0),
        ..Default::default()
    };
    let err = register_with_options(secret, &opts).err().unwrap();
    assert!(
        err.to_string()
            .contains("trailing_run_guard must be a positive integer"),
        "VC-23: registration error must mention positivity, got: {err}"
    );

    let pf_data = br#"
version = 3

[[pattern]]
identifier = "zero_guard"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [{ type = "variable", charset = "alphanumeric", min = 10, max = 10 }]
trailing_run_guard = 0
"#;
    let load_err = SecretsFile::deserialize(pf_data).unwrap_err();
    assert!(
        load_err
            .to_string()
            .contains("trailing_run_guard must be a positive integer"),
        "VC-23: load error must mention the same positivity contract, got: {load_err}"
    );
}

#[test]
fn test_vc24_guarded_pattern_wins_persistent_tie_over_unguarded() {
    // item 18, VC-24: equal-shape fixture (both literal "tok_" + 30-alphanumeric
    // variable, same match length, same first-segment kind) — a genuine
    // persistent tie. Guard declaration is the deciding tie-break arm: the
    // guarded pattern wins over the unguarded one.
    //
    // Verify by inspection: both patterns share identical segment shape
    // (literal-first, variable(alphanumeric, 30, 30)) → same capture.end,
    // both literal-first — the tie is genuine and only the new guard
    // tie-break arm can decide the winner.
    let guarded = family_entry(
        "guarded_tie",
        [0x44; 32],
        "tok_",
        "alphanumeric",
        30,
        Some(64),
    );
    let unguarded = family_entry(
        "unguarded_tie",
        [0x55; 32],
        "tok_",
        "alphanumeric",
        30,
        None,
    );

    let payload = [b"tok_".as_slice(), &alnum_filler(30), b"\""].concat();

    // Observe fake_g / fake_u via fake stability (INV-13): swap the payload
    // against each pattern alone.
    let guarded_pat = SecretsFile {
        version: 3,
        pattern: vec![guarded.clone()],
    }
    .to_patterns()
    .unwrap()
    .remove(0);
    let unguarded_pat = SecretsFile {
        version: 3,
        pattern: vec![unguarded.clone()],
    }
    .to_patterns()
    .unwrap()
    .remove(0);

    let fake_g = swap(&payload, std::slice::from_ref(&guarded_pat))
        .unwrap()
        .entries[0]
        .fake
        .clone();
    let fake_u = swap(&payload, std::slice::from_ref(&unguarded_pat))
        .unwrap()
        .entries[0]
        .fake
        .clone();
    assert_ne!(fake_g, fake_u, "distinct salts must produce distinct fakes");

    for (a, b) in [
        (guarded_pat.clone(), unguarded_pat.clone()),
        (unguarded_pat, guarded_pat),
    ] {
        let result = swap(&payload, &[a, b]).expect("swap failed");
        assert_eq!(
            result.entries.len(),
            1,
            "VC-24: exactly one entry for the tied position"
        );
        assert!(
            result
                .payload
                .windows(fake_g.len())
                .any(|w| w == fake_g.as_slice()),
            "VC-24: guarded pattern must win the persistent tie (order-independent)"
        );
        assert!(
            !result
                .payload
                .windows(fake_u.len())
                .any(|w| w == fake_u.as_slice()),
            "VC-24: unguarded pattern's fake must not appear"
        );
    }
}

#[test]
fn test_vc25_larger_threshold_wins_tie_and_match_stands_between_thresholds() {
    // item 18, VC-25: equal-shape fixture, both guarded (thresholds 8 and 64).
    let low = family_entry("guard_low", [0x66; 32], "tok_", "alphanumeric", 30, Some(8));
    let high = family_entry(
        "guard_high",
        [0x77; 32],
        "tok_",
        "alphanumeric",
        30,
        Some(64),
    );

    let low_pat = SecretsFile {
        version: 3,
        pattern: vec![low.clone()],
    }
    .to_patterns()
    .unwrap()
    .remove(0);
    let high_pat = SecretsFile {
        version: 3,
        pattern: vec![high.clone()],
    }
    .to_patterns()
    .unwrap()
    .remove(0);

    let secret_bytes = [b"tok_".as_slice(), &alnum_filler(30)].concat();
    let fake_high = swap(&secret_bytes, std::slice::from_ref(&high_pat))
        .unwrap()
        .entries[0]
        .fake
        .clone();

    // Payload A: secret + '"' → replaced with the threshold-64 pattern's fake, both orders.
    let payload_a = [secret_bytes.as_slice(), b"\""].concat();
    for (a, b) in [
        (low_pat.clone(), high_pat.clone()),
        (high_pat.clone(), low_pat.clone()),
    ] {
        let result = swap(&payload_a, &[a, b]).expect("swap failed");
        assert_eq!(result.entries.len(), 1, "VC-25 A: exactly one entry");
        assert!(
            result
                .payload
                .windows(fake_high.len())
                .any(|w| w == fake_high.as_slice()),
            "VC-25 A: larger-threshold pattern must win the tie (order-independent)"
        );
    }

    // Payload B: secret + 32 alphanumeric bytes + '"' → satisfies threshold 8
    // but not 64. The threshold-64 pattern is still the winner (selection
    // happens before suppression) and its own guard does NOT fire at 32 < 64:
    // match stands, replaced with the threshold-64 fake.
    let payload_b = [secret_bytes.as_slice(), &alnum_filler(32), b"\""].concat();
    for (a, b) in [
        (low_pat.clone(), high_pat.clone()),
        (high_pat.clone(), low_pat.clone()),
    ] {
        let result = swap(&payload_b, &[a, b]).expect("swap failed");
        assert_eq!(
            result.entries.len(),
            1,
            "VC-25 B: threshold-64 winner's own guard must not fire at 32 trailing bytes"
        );
        assert!(
            result
                .payload
                .windows(fake_high.len())
                .any(|w| w == fake_high.as_slice()),
            "VC-25 B: replaced with the threshold-64 pattern's fake, not suppressed"
        );
    }

    // Payload C: secret + 64 alphanumeric bytes → both thresholds satisfied;
    // threshold-64 winner's own guard fires → suppressed, payload unchanged.
    let payload_c = [secret_bytes.as_slice(), &alnum_filler(64)].concat();
    for (a, b) in [
        (low_pat.clone(), high_pat.clone()),
        (high_pat.clone(), low_pat.clone()),
    ] {
        let result = swap(&payload_c, &[a, b]).expect("swap failed");
        assert_eq!(
            result.payload, payload_c,
            "VC-25 C: 64 trailing bytes must suppress the threshold-64 winner"
        );
        assert!(result.entries.is_empty(), "VC-25 C: zero entries");
    }
}
