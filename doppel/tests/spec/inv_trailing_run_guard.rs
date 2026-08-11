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
        trailing_run_guard_charset: None,
    }
}

/// Same shape as [`family_entry`] but with an explicit guard charset, used by
/// the VC-26 (item 51) tests where the guard charset must diverge from the
/// variable segment's own charset.
fn family_entry_with_guard_charset(
    identifier: &str,
    salt: [u8; 32],
    literal: &str,
    var_charset: &str,
    var_len: usize,
    guard: Option<u64>,
    guard_charset: &str,
) -> PatternEntry {
    PatternEntry {
        trailing_run_guard_charset: Some(guard_charset.to_string()),
        ..family_entry(identifier, salt, literal, var_charset, var_len, guard)
    }
}

#[test]
fn test_guard_suppresses_match_at_exact_threshold() {
    // item 44, VC-18: guarded pattern's structural match immediately followed by
    // at least the threshold count of guard-charset bytes MUST be discarded.
    let payload = [SYNTH_GCP, &base64_filler(1024)].concat();
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
    let payload = [SYNTH_GCP, &base64_filler(1023), b"\"".as_slice()].concat();
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
    let payload = [SYNTH_GCP, &base64_filler(1023)].concat();
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
        trailing_run_guard_charset: None,
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
    // item 45, VC-21 (amended): loading a patterns file where a guard is declared
    // with no explicit guard charset and no `variable` segment MUST fail with a
    // clear error mentioning "trailing_run_guard".
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
fn test_vc21_guard_with_explicit_charset_loads_without_variable_segment() {
    // item 51, VC-21 (amended): "A pattern MAY declare an explicit guard charset
    // alongside its trailing run guard. ... A pattern that declares both a
    // trailing run guard and an explicit guard charset MUST be accepted at load
    // time even when it contains no `variable` segment." Same degenerate shape
    // as the rejected case above (zero variable segments), but with an opaque
    // segment (not all-literal) so the pattern is also swap-viable — the
    // all-literal case is a known pathological config (item 51 closing
    // sentence about fake-derivation basis), not what this test targets.
    let pf_data = br#"
version = 3

[[pattern]]
identifier = "literal_opaque"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [
    { type = "literal", value = "fixed-" },
    { type = "opaque", value = "swap-me-1234567890" },
]
trailing_run_guard = 2048
trailing_run_guard_charset = "base64_any"
"#;
    let pf = SecretsFile::deserialize(pf_data)
        .expect("VC-21: guard + explicit charset must load without a variable segment");
    let patterns = pf
        .to_patterns()
        .expect("VC-21: to_patterns must also accept this shape");
    assert_eq!(patterns.len(), 1);

    // Swap-viable: the opaque segment gives the pattern a basis for fake
    // derivation, so a genuine match is detected and replaced normally.
    let payload = b"fixed-swap-me-1234567890".to_vec();
    let result = swap(&payload, &patterns).expect("swap failed");
    assert_eq!(result.entries.len(), 1);
    assert!(
        !result
            .payload
            .windows(payload.len())
            .any(|w| w == payload.as_slice())
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

#[test]
fn test_inv50_register_warns_but_succeeds_above_20000() {
    // item 50: register SHOULD emit a warning when trailing_run_guard > 20,000,
    // but MUST NOT reject it — advisory only.
    // TODO: add log-capture assertion when a test logger harness is available.
    use doppel::{SecretOptions, register_with_options};
    let secret = b"my-long-enough-secret-value-for-registration";
    let opts = SecretOptions {
        trailing_run_guard: Some(20_001),
        ..Default::default()
    };
    let result = register_with_options(secret, &opts);
    assert!(
        result.is_ok(),
        "item 50: registration with trailing_run_guard > 20,000 must succeed (got warning)"
    );
}

#[test]
fn test_inv50_patterns_file_load_warns_but_succeeds_above_20000() {
    // item 50: patterns-file load SHOULD emit the same warning above 20,000,
    // but MUST NOT reject it — advisory only.
    // TODO: add log-capture assertion when a test logger harness is available.
    let entry = family_entry(
        "big_guard",
        [0x22; 32],
        "tok_",
        "alphanumeric",
        16,
        Some(20_001),
    );
    let pf = SecretsFile {
        version: 3,
        pattern: vec![entry],
    };
    let bytes = pf.serialize().unwrap();
    let loaded =
        SecretsFile::deserialize(&bytes).expect("item 50: threshold > 20,000 must not be rejected");
    let patterns = loaded.to_patterns();
    assert!(
        patterns.is_ok(),
        "item 50: to_patterns must also accept threshold > 20,000"
    );
    assert_eq!(patterns.unwrap().len(), 1);
}

#[test]
fn test_vc26_explicit_guard_charset_broader_than_segment_suppresses() {
    // item 51, VC-26 (direction A): "a trailing run that meets the threshold
    // under the declared charset suppresses the match even when bytes in that
    // run fall outside the segment charset." Declared charset base64_any is a
    // strict superset of the last variable segment's url_safe_base64.
    let entry = family_entry_with_guard_charset(
        "vc26_broad",
        [0x88; 32],
        "tok_",
        "url_safe_base64",
        30,
        Some(64),
        "base64_any",
    );
    let pf = SecretsFile {
        version: 3,
        pattern: vec![entry],
    };
    let patterns = pf.to_patterns().expect("fixture must load");

    let match_bytes = [b"tok_".as_slice(), &base64_filler(30)].concat();
    // 64 bytes of '+': member of base64_any (declared), NOT of url_safe_base64
    // (segment charset) — only the explicit declaration can suppress this.
    let plus_run = vec![b'+'; 64];
    let payload = [match_bytes.as_slice(), &plus_run].concat();
    let result = swap(&payload, &patterns).expect("swap failed");
    assert_eq!(
        result.payload, payload,
        "VC-26 A: broader-than-segment declared charset must suppress"
    );
    assert!(
        result.entries.is_empty(),
        "VC-26 A: zero entries when suppressed"
    );
}

#[test]
fn test_vc26_explicit_guard_charset_narrower_than_segment_leaves_standing() {
    // item 51, VC-26 (direction B): "a trailing run that fails to meet the
    // threshold under the declared charset leaves the match standing even when
    // it would meet the threshold under the segment charset." Declared charset
    // digits does not contain 'a'; the segment charset url_safe_base64 does.
    let entry = family_entry_with_guard_charset(
        "vc26_narrow",
        [0x99; 32],
        "tok_",
        "url_safe_base64",
        30,
        Some(64),
        "digits",
    );
    let pf = SecretsFile {
        version: 3,
        pattern: vec![entry],
    };
    let patterns = pf.to_patterns().expect("fixture must load");

    let match_bytes = [b"tok_".as_slice(), &base64_filler(30)].concat();
    // 64 bytes of 'a': member of url_safe_base64 (segment charset), NOT of
    // digits (declared) — the segment charset must NOT rescue the match.
    let a_run = vec![b'a'; 64];
    let payload = [match_bytes.as_slice(), &a_run].concat();
    let result = swap(&payload, &patterns).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "VC-26 B: narrower-than-segment declared charset must leave the match standing"
    );
    assert!(
        !result
            .payload
            .windows(match_bytes.len())
            .any(|w| w == match_bytes.as_slice()),
        "VC-26 B: standing match must still be replaced"
    );
}

/// Deterministic standard-alphabet base64 filler containing '+' and '/' well
/// within the first 148 bytes (SPEC.md's measured real-world url-safe-run
/// bound) — the vector that distinguishes the item-51 fix from the old
/// inferred (url_safe_base64) guard-charset behavior.
fn gcp_std_base64_filler(len: usize) -> Vec<u8> {
    const CHUNK: &[u8] = b"Ab0+Cd1/";
    (0..len).map(|i| CHUNK[i % CHUNK.len()]).collect()
}

#[test]
fn test_vc27_gcp_default_suppresses_standard_base64_blob() {
    // VC-27: "Given the built-in GCP pattern at its default guard
    // configuration, a structural GCP-shaped candidate embedded in unwrapped
    // standard-alphabet base64 data and followed by at least the default
    // threshold count of standard-base64 bytes is suppressed and produces no
    // entry." Exercises the full patterns-file emission+load chain
    // (generate_missing_structural_salts -> serialize -> deserialize ->
    // to_patterns), not just the in-memory builtin constructor.
    let mut pf = SecretsFile {
        version: 3,
        pattern: vec![],
    };
    pf.generate_missing_structural_salts();
    let bytes = pf.serialize().expect("serialize must succeed");
    let loaded = SecretsFile::deserialize(&bytes).expect("deserialize must succeed");
    let patterns = loaded.to_patterns().expect("to_patterns must succeed");

    // filler contains '+' at offset 3 and '/' at offset 7 — an inferred
    // url_safe_base64 guard charset would terminate its probe run there, far
    // short of the 1024-byte threshold; only the explicit base64_any
    // declaration (SPEC.md §Built-in Family Patterns) can suppress this.
    let filler = gcp_std_base64_filler(1024);
    let payload = [SYNTH_GCP, &filler].concat();
    let result = swap(&payload, &patterns).expect("swap failed");
    assert_eq!(
        result.payload, payload,
        "VC-27: GCP default guard must suppress a standard-base64 blob at threshold"
    );
    assert!(
        result.entries.is_empty(),
        "VC-27: zero entries when suppressed"
    );

    // Contrast (root-cause proof): fewer than the threshold count, terminated,
    // must still replace normally — the guard still respects the threshold.
    let short_filler = gcp_std_base64_filler(1023);
    let payload_b = [SYNTH_GCP, &short_filler, b"\"".as_slice()].concat();
    let result_b = swap(&payload_b, &patterns).expect("swap failed");
    assert_eq!(
        result_b.entries.len(),
        1,
        "VC-27 contrast: one byte under threshold, terminated, must be replaced"
    );
    assert!(
        !result_b
            .payload
            .windows(SYNTH_GCP.len())
            .any(|w| w == SYNTH_GCP),
        "VC-27 contrast: original secret must not appear in swapped payload"
    );
}

#[test]
fn test_vc28_guard_charset_without_threshold_rejected_on_both_paths() {
    // item 51, VC-28: "An explicit guard charset declared without a trailing
    // run guard threshold MUST be rejected at load and registration time with
    // a clear error."
    let secret = b"registered-secret-charset-only-no-threshold-05";
    let opts = SecretOptions {
        trailing_run_guard_charset: Some("base64_any".into()),
        ..Default::default()
    };
    let err = register_with_options(secret, &opts).err().unwrap();
    assert!(
        err.to_string()
            .contains("trailing_run_guard_charset requires trailing_run_guard"),
        "VC-28: registration error must mention the dependency, got: {err}"
    );

    let pf_data = br#"
version = 3

[[pattern]]
identifier = "charset_only"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [{ type = "variable", charset = "alphanumeric", min = 10, max = 10 }]
trailing_run_guard_charset = "base64_any"
"#;
    let load_err = SecretsFile::deserialize(pf_data).unwrap_err();
    assert!(
        load_err
            .to_string()
            .contains("trailing_run_guard_charset requires trailing_run_guard"),
        "VC-28: load error must mention the same dependency, got: {load_err}"
    );
}

#[test]
fn test_inv49_registered_guard_uses_explicit_charset_when_supplied() {
    // items 49, 51: register_with_options with a threshold and an explicit
    // trailing_run_guard_charset must use the declared charset for the guard
    // probe, not the registered pattern's inferred (alphanumeric) segment
    // charset. Counterpart of test_vc22_registered_guarded_secret_suppressed_and_replaced.
    let secret = b"RegisteredSecretForCharsetOverrideTestZZ";
    let opts = SecretOptions {
        restrict_charset: true,
        trailing_run_guard: Some(64),
        trailing_run_guard_charset: Some("base64_any".into()),
        ..Default::default()
    };
    let pat = register_with_options(secret, &opts).expect("registration must succeed");

    // Payload A: secret + 64 bytes of '+'/'/' — outside the inferred
    // alphanumeric segment charset but inside the declared base64_any — must
    // suppress. Proves the declared charset, not the inferred one, governs.
    let plus_slash_filler: Vec<u8> = (0..64)
        .map(|i| if i % 2 == 0 { b'+' } else { b'/' })
        .collect();
    let payload_a = [secret.as_slice(), &plus_slash_filler].concat();
    let result_a = swap(&payload_a, std::slice::from_ref(&pat)).expect("swap failed");
    assert_eq!(
        result_a.payload, payload_a,
        "item 49/51: explicit guard charset must suppress a +/-mix trailing run"
    );
    assert!(result_a.entries.is_empty());

    // Payload B: secret + '"' (outside the declared charset too) — replaced.
    let payload_b = [secret.as_slice(), b"\"".as_slice()].concat();
    let result_b = swap(&payload_b, &[pat]).expect("swap failed");
    assert_eq!(
        result_b.entries.len(),
        1,
        "item 49/51: terminator outside guard charset — match must stand"
    );
    assert!(!result_b.payload.windows(secret.len()).any(|w| w == secret));
}

#[test]
fn test_guard_without_explicit_charset_behaves_identically_to_inference() {
    // item 51 closing MUST: "When no explicit guard charset is declared, guard
    // behavior MUST be identical to the inferred-charset behavior of item 45."
    // Backward-compat regression (HANDOFF downside 7): a guarded pattern
    // loaded from TOML that omits trailing_run_guard_charset entirely must
    // behave exactly as before this feature existed — probe uses the last
    // variable segment's charset (url_safe_base64 here), not any default.
    // test_guard_charset_is_last_variable_segment covers the segment-selection
    // half (last vs. first variable); this covers the standard-vs-url-safe
    // divergence half.
    let pf_data = br#"
version = 3

[[pattern]]
identifier = "no_explicit_charset"
salt = "0000000000000000000000000000000000000000000000000000000000000001"
segments = [
    { type = "literal", value = "tok_" },
    { type = "variable", charset = "url_safe_base64", min = 30, max = 30 },
]
trailing_run_guard = 64
"#;
    assert!(
        !std::str::from_utf8(pf_data)
            .unwrap()
            .contains("trailing_run_guard_charset"),
        "fixture must omit trailing_run_guard_charset entirely"
    );
    let pf =
        SecretsFile::deserialize(pf_data).expect("must load without an explicit guard charset");
    let patterns = pf.to_patterns().expect("must convert to patterns");

    let match_bytes = [b"tok_".as_slice(), &base64_filler(30)].concat();

    // url-safe trailing at exactly the threshold: member of the inferred
    // (segment) charset — must suppress, same as pre-item-51 behavior.
    let suppressed_payload = [match_bytes.as_slice(), &base64_filler(64)].concat();
    let result = swap(&suppressed_payload, &patterns).expect("swap failed");
    assert_eq!(
        result.payload, suppressed_payload,
        "inference: url-safe trailing at threshold must suppress"
    );
    assert!(result.entries.is_empty());

    // Standard-base64 trailing containing '+' before the threshold: '+' is
    // not a member of the inferred url_safe_base64 charset, so the probe run
    // terminates far short of 64 — must NOT suppress, same as pre-item-51
    // behavior (this is precisely the divergence item 51 exists to override,
    // and here there is no override, so the old behavior must be preserved).
    let mut standing_trailing = base64_filler(64);
    standing_trailing[10] = b'+';
    let standing_payload = [match_bytes.as_slice(), &standing_trailing].concat();
    let result2 = swap(&standing_payload, &patterns).expect("swap failed");
    assert_eq!(
        result2.entries.len(),
        1,
        "inference: '+' before threshold must not suppress"
    );
    assert!(
        !result2
            .payload
            .windows(match_bytes.len())
            .any(|w| w == match_bytes.as_slice()),
        "standing match must still be replaced"
    );
}

#[test]
fn test_vc27_aws_akia_default_suppresses_base64_blob() {
    // VC-27 parity for AWS AKIA: same weak shape as GCP (4-byte literal prefix,
    // single unanchored variable region), same real-world corpus motivation
    // (a structurally exact AKIA-shaped candidate occurring by chance inside
    // base64-encoded PNG image data). Exercises the full patterns-file
    // emission+load chain, not just the in-memory builtin constructor.
    let mut pf = SecretsFile {
        version: 3,
        pattern: vec![],
    };
    pf.generate_missing_structural_salts();
    let bytes = pf.serialize().expect("serialize must succeed");
    let loaded = SecretsFile::deserialize(&bytes).expect("deserialize must succeed");
    let patterns = loaded.to_patterns().expect("to_patterns must succeed");

    // Synthetic candidate — NOT a real credential.
    const SYNTH_AKIA: &[u8] = b"AKIALGUKFO74R8KHBHMW";

    // Mixed-case url-safe-base64 filler: an inferred guard (AKIA's match
    // charset is uppercase_alphanumeric) terminates on the first lowercase
    // byte, within a handful of bytes — only the explicit base64_any
    // declaration (SPEC.md §Built-in Family Patterns) suppresses this.
    let filler = base64_filler(1024);
    let payload = [SYNTH_AKIA, &filler].concat();
    let result = swap(&payload, &patterns).expect("swap failed");
    assert_eq!(
        result.payload, payload,
        "VC-27: AKIA default guard must suppress a base64 blob at threshold"
    );
    assert!(
        result.entries.is_empty(),
        "VC-27: zero entries when suppressed"
    );

    // Contrast: fewer than the threshold count, terminated, must still
    // replace normally — the guard still respects the threshold.
    let short_filler = base64_filler(1023);
    let payload_b = [SYNTH_AKIA, &short_filler, b"\"".as_slice()].concat();
    let result_b = swap(&payload_b, &patterns).expect("swap failed");
    assert_eq!(
        result_b.entries.len(),
        1,
        "VC-27 contrast: one byte under threshold, terminated, must be replaced"
    );
    assert!(
        !result_b
            .payload
            .windows(SYNTH_AKIA.len())
            .any(|w| w == SYNTH_AKIA),
        "VC-27 contrast: original secret must not appear in swapped payload"
    );
}
