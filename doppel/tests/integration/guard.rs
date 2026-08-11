// Integration: trailing run guard, INV-39 parity, and the motivating false-positive scenario.

use doppel::{Detector, patterns, swap};

const URL_SAFE_BASE64_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_filler(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| URL_SAFE_BASE64_ALPHABET[i % URL_SAFE_BASE64_ALPHABET.len()])
        .collect()
}

// Synthetic test key — NOT a real credential.
const SYNTH_GCP: &[u8] = b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn test_detector_swap_guard_parity_with_free_swap() {
    // INV-39: Detector::swap MUST produce identical results to the free swap
    // function for the same Patterns — including a guard-suppressing payload.
    let payload = [SYNTH_GCP, &base64_filler(2048)].concat();

    let free_result = swap(&payload, &[patterns::gcp()]).expect("free swap failed");

    let detector = Detector::new(vec![patterns::gcp()]);
    let detector_result = detector.swap(&payload).expect("detector swap failed");

    assert_eq!(
        free_result.payload, detector_result.payload,
        "INV-39: guard-suppressing payload must be identical via both swap paths"
    );
    assert_eq!(
        free_result.entries.len(),
        detector_result.entries.len(),
        "INV-39: entries count must match across both swap paths"
    );
    assert_eq!(
        free_result.payload, payload,
        "guard-suppressed payload must remain unchanged"
    );
    assert!(free_result.entries.is_empty());
    assert!(detector_result.entries.is_empty());
}

#[test]
fn test_gcp_key_in_realistic_json_context_still_detected() {
    // Guards must not regress the motivating real-world use: a GCP key inside
    // a small JSON body, structurally delimited by a quote, must still be detected.
    let payload = format!(
        "{{\"api_key\": \"{}\"}}",
        std::str::from_utf8(SYNTH_GCP).unwrap()
    )
    .into_bytes();

    let result = swap(&payload, &patterns::all()).expect("swap failed");

    assert_eq!(
        result.entries.len(),
        1,
        "GCP key delimited by a quote in realistic JSON context must be detected"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_GCP.len())
            .any(|w| w == SYNTH_GCP),
        "GCP key must not appear in swapped payload"
    );
}

#[test]
fn test_large_base64_blob_with_embedded_prefix_roundtrip() {
    // The original false-positive scenario: a large base64 blob (e.g. embedded
    // image data) containing the "AIza" 4-byte prefix at several interior
    // offsets by chance must not be corrupted — the guard defends it.
    let mut blob = base64_filler(64 * 1024);
    // Force several literal "AIza" occurrences deep inside the blob, each
    // followed by far more than 1024 bytes of base64-charset trailing data.
    for offset in [1000usize, 20_000, 40_000] {
        blob[offset..offset + 4].copy_from_slice(b"AIza");
    }

    let result = swap(&blob, &patterns::all()).expect("swap failed");

    assert_eq!(
        result.payload, blob,
        "large base64 blob with embedded AIza prefixes must round-trip byte-identical"
    );
    assert!(
        result.entries.is_empty(),
        "no detections must occur inside the guarded false-positive blob"
    );
}

#[test]
fn test_large_base64_blob_with_embedded_akia_prefix_roundtrip() {
    // Same false-positive class as AIza (see above): AWS AKIA/ASIA patterns have
    // a short 4-byte literal prefix and a single unanchored variable region, so
    // "AKIA" + 16 uppercase-alphanumeric characters can occur by chance inside a
    // large base64 blob (real-world corpus hit: embedded PNG image data).
    let mut blob = base64_filler(64 * 1024);
    // Structurally exact AKIA match, followed by far more than 1024 bytes of
    // base64-charset trailing data.
    blob[10_000..10_020].copy_from_slice(b"AKIALGUKFO74R8KHBHMW");

    let result = swap(&blob, &patterns::all()).expect("swap failed");

    assert_eq!(
        result.payload, blob,
        "large base64 blob with an embedded AKIA-shaped candidate must round-trip byte-identical"
    );
    assert!(
        result.entries.is_empty(),
        "no detections must occur inside the guarded false-positive blob"
    );
}
