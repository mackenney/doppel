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
