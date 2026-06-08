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

    // Non-member passes through
    let secret_c = b"non-member-gamma-secrets-val-for-det-test!";
    let payload_c = [b"token: ".as_slice(), secret_c].concat();
    let r_c = detector.swap(&payload_c).unwrap();
    assert_eq!(r_c.entries.len(), 0, "non-member must not be detected");
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

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let d = Arc::clone(&detector);
            let p = Arc::clone(&payload);
            thread::spawn(move || {
                let result = d.swap(&p).unwrap();
                assert_eq!(
                    result.entries.len(),
                    1,
                    "each thread must detect the secret"
                );
                assert!(!result.payload.windows(key.len()).any(|w| w == key));
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}
