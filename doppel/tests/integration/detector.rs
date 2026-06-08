use doppel::{Detector, patterns, restore};

// Synthetic test secret — NOT real credentials
const SYNTH_ANTHROPIC: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn test_detector_full_round_trip() {
    // Full swap→restore cycle using Detector::swap, verifying that the
    // Detector-produced entries and session key work correctly with restore.
    let pat = patterns::anthropic();
    let payload = [
        b"Authorization: ".as_slice(),
        SYNTH_ANTHROPIC,
        b"\nContent-Type: application/json",
    ]
    .concat();

    let detector = Detector::new(vec![pat]);
    let result = detector.swap(&payload).unwrap();

    // Secret must be absent from swapped output
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "secret must not appear in swapped payload"
    );
    assert_eq!(result.entries.len(), 1);

    // Restore must recover the original payload
    let mut input = result.payload.as_slice();
    let mut restored = Vec::new();
    restore(
        &mut input,
        &mut restored,
        &result.entries,
        &result.session_key,
    )
    .unwrap();
    assert_eq!(restored, payload, "restored payload must equal original");
}

#[test]
fn test_detector_registered_pattern_round_trip() {
    // Detector::new must work correctly with registered (instance) patterns,
    // not only structural (family) patterns. This exercises the HMAC-gate
    // code path through swap_with_ac.
    use doppel::{Detector, register, restore};

    let secret = b"my-registered-secret-for-detector-test-01";
    let pat = register(secret).unwrap();
    let detector = Detector::new(vec![pat]);

    let payload = [b"Authorization: Bearer ".as_slice(), secret, b"\n"].concat();
    let result = detector.swap(&payload).unwrap();

    assert_eq!(
        result.entries.len(),
        1,
        "registered secret must be detected"
    );
    assert!(
        !result.payload.windows(secret.len()).any(|w| w == secret),
        "secret must not appear in swapped payload"
    );

    // Restore must recover the original
    let mut input = result.payload.as_slice();
    let mut restored = Vec::new();
    restore(
        &mut input,
        &mut restored,
        &result.entries,
        &result.session_key,
    )
    .unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn test_detector_group_pattern_detects_both_members() {
    // A Detector built from a group pattern (single Pattern, 2 digests) must
    // detect and replace both member secrets, leaving non-members unchanged.
    use doppel::{Detector, SecretOptions, SecretsFile, register_with_options};

    let opts = SecretOptions::default();
    let secret_a = b"group-member-alpha-secret-value-for-det-test";
    let secret_b = b"group-member-beta-secrets-value-for-det-test";

    let pat_a = register_with_options(secret_a, &opts).unwrap();
    let mut pf = SecretsFile::new();
    pf.add_secret_pattern("group-key".to_string(), &pat_a)
        .unwrap();
    pf.add_secret_to_group("group-key", secret_b).unwrap();
    let patterns = pf.to_patterns().unwrap();
    assert_eq!(
        pf.pattern[0].digests.len(),
        2,
        "group entry must have two digests"
    );

    let detector = Detector::new(patterns);

    // A is detected
    let payload_a = [b"token: ".as_slice(), secret_a].concat();
    let r_a = detector.swap(&payload_a).unwrap();
    assert_eq!(r_a.entries.len(), 1, "secret_a must be detected");

    // B is detected
    let payload_b = [b"token: ".as_slice(), secret_b].concat();
    let r_b = detector.swap(&payload_b).unwrap();
    assert_eq!(r_b.entries.len(), 1, "secret_b must be detected");

    // Non-member with SAME anchor prefix as the group (starts "gro") and matching length.
    // The AC automaton fires, but the HMAC gate rejects it — verifying the gate works.
    let secret_c = b"group-impostor-zeta-secret-value-for-det!!!!";
    assert_eq!(
        secret_c.len(),
        secret_a.len(),
        "impostor must match group member length"
    );
    let payload_c = [b"token: ".as_slice(), secret_c].concat();
    let r_c = detector.swap(&payload_c).unwrap();
    assert_eq!(r_c.entries.len(), 0, "non-member must not be detected");
    assert_eq!(
        r_c.payload, payload_c,
        "non-member payload must be unchanged"
    );
}

#[test]
fn test_detector_concurrent_swap_is_safe() {
    // INV-40: Detector must be safe to share across threads (Send+Sync).
    // This test exercises actual concurrent calls through Arc<Detector>.
    use doppel::{Detector, patterns};
    use std::sync::Arc;
    use std::thread;

    let detector = Arc::new(Detector::new(patterns::all()));
    // NOT real credentials — synthetic key matching the Anthropic structural pattern
    let key: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let payload = Arc::new([b"Authorization: ".as_slice(), key, b"\n"].concat());

    // Compute reference result to verify fake correctness under concurrency.
    let reference_fake = Arc::new(detector.swap(&payload).unwrap().entries[0].fake.clone());

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let d = Arc::clone(&detector);
            let p = Arc::clone(&payload);
            let expected = Arc::clone(&reference_fake);
            thread::spawn(move || {
                let result = d.swap(&p).unwrap();
                assert_eq!(
                    result.entries.len(),
                    1,
                    "each thread must detect the secret"
                );
                assert!(!result.payload.windows(key.len()).any(|w| w == key));
                assert_eq!(
                    result.entries[0].fake, *expected,
                    "fake must be deterministic across concurrent calls"
                );
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn test_detector_mixed_structural_and_registered_payload() {
    // Critical test vector: a Detector built with both a structural (family) pattern
    // and a registered (instance) pattern must detect and replace both types of secrets
    // when they appear together in the same payload.
    use doppel::{Detector, patterns, register};

    let structural_pat = patterns::anthropic();
    // NOT real credentials — synthetic registered secret
    let reg_secret = b"my-registered-secret-for-mixed-detector-01";
    let reg_pat = register(reg_secret).unwrap();

    let detector = Detector::new(vec![structural_pat, reg_pat]);

    let payload = [
        b"key: ".as_slice(),
        SYNTH_ANTHROPIC,
        b" token: ".as_slice(),
        reg_secret,
    ]
    .concat();

    let result = detector.swap(&payload).unwrap();

    assert_eq!(
        result.entries.len(),
        2,
        "both structural and registered secrets must be detected"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "structural secret must not appear in swapped payload"
    );
    assert!(
        !result
            .payload
            .windows(reg_secret.len())
            .any(|w| w == reg_secret),
        "registered secret must not appear in swapped payload"
    );
    assert_ne!(
        result.entries[0].fake, result.entries[1].fake,
        "two different secrets in same swap call must produce distinct fakes"
    );
}

#[test]
fn test_detector_registered_hmac_mismatch_passthrough() {
    // HMAC mismatch via Detector::swap: a candidate that matches the registered pattern's
    // structural shape but fails HMAC verification must pass through unchanged.
    // This exercises a different failure mode than the free swap tests — verifying that
    // the shared AC automaton in Detector doesn't cause a wrong Pattern to be consulted.
    use doppel::{Detector, register};

    let real_secret = b"my-registered-secret-for-hmac-mismatch-test";
    let pat = register(real_secret).unwrap();
    let detector = Detector::new(vec![pat]);

    let mut lookalike = real_secret.to_vec();
    lookalike[12] ^= 0xFF;
    let payload = [b"token: ".as_slice(), &lookalike].concat();

    let result = detector.swap(&payload).unwrap();

    assert!(
        result.entries.is_empty(),
        "HMAC mismatch must not produce an entry"
    );
    assert_eq!(
        result.payload.as_slice(),
        payload.as_slice(),
        "HMAC mismatch must pass through unchanged"
    );
}
