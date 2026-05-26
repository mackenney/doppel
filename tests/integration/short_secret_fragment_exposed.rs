use its_classified::{register, scrub};

// 12-byte hex secret: first 8 bytes are "deadbeef", remaining 4 are "1234"
const SECRET: &[u8] = b"deadbeef1234";

#[test]
fn test_tier2_short_secret_fragment_exposed() {
    // INV-9 gap: start_fragment (first 8 bytes of secret) is embedded verbatim
    // in the fake field.  For a 12-byte hex secret the first 8 bytes are
    // b"deadbeef" — these appear unchanged in entry.fake[..8].
    let pat = register(SECRET);
    let payload = [b"token: ".as_slice(), SECRET].concat();
    let result = scrub(&payload, &[pat]).expect("scrub failed");

    assert_eq!(result.entries.len(), 1, "exactly one entry produced");

    let fake = &result.entries[0].fake;

    // Full length matches the secret
    assert_eq!(
        fake.len(),
        SECRET.len(),
        "fake length must equal secret length (12)"
    );

    // First 8 bytes of fake are the verbatim start_fragment — the exploit
    assert_eq!(
        &fake[..8],
        &SECRET[..8],
        "EXPLOIT: start_fragment bytes (deadbeef) leaked verbatim in fake[..8]"
    );
}
