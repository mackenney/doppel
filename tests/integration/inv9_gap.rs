use its_classified::{register, scrub, types::Entry};

// 32-byte Tier 2 secret with clearly identifiable ASCII start bytes
const SECRET: &[u8] = b"MySecret12345678901234567890ABCD";

#[test]
fn test_inv9_gap_demonstration() {
    // Proves the existing INV-9 test passes despite the start_fragment leakage.
    //
    // Tier 2 fake generation embeds the first 8 bytes of the secret verbatim
    // (start_fragment). The existing test only checks for the full-length secret
    // in the serialized entries, so it misses this partial leakage.
    let pat = register(SECRET);
    let payload = [b"token: ".as_slice(), SECRET].concat();
    let result = scrub(&payload, &[pat]).expect("scrub failed");

    let json = Entry::serialize_entries(&result.entries).unwrap();

    // The existing INV-9 check: full secret not present — PASSES even with the leak
    let full_secret_present = json.windows(SECRET.len()).any(|w| w == SECRET);
    assert!(
        !full_secret_present,
        "full secret should not appear in serialized entries"
    );

    // The actual leak: entry.fake starts with the same 8 bytes as the secret.
    // generate_fake_tier2 uses start_fragment as the fake's prefix verbatim.
    assert_eq!(
        &result.entries[0].fake[..8],
        &SECRET[..8],
        "EXPLOIT: start_fragment bytes leaked verbatim in fake field"
    );
}

#[test]
#[should_panic(expected = "INV-9 VIOLATED")]
fn test_inv9_gap_fixed() {
    // A corrected INV-9 check that catches start_fragment leakage.
    // This MUST FAIL against the current implementation because the fake field
    // starts with the first 8 bytes of the secret. #[should_panic] documents
    // that the vulnerability is proven — the test passes only because the bug fires.
    let pat = register(SECRET);
    let payload = [b"token: ".as_slice(), SECRET].concat();
    let result = scrub(&payload, &[pat]).expect("scrub failed");

    let entry_fake = &result.entries[0].fake;

    // A correct implementation would not embed any 4-byte (or longer) subsequence
    // of the secret in the fake. The first window (SECRET[0..4]) matches because
    // start_fragment is used verbatim as the fake's prefix.
    for window_start in 0..=SECRET.len().saturating_sub(4) {
        let window = &SECRET[window_start..window_start + 4];
        assert!(
            !entry_fake.windows(4).any(|w| w == window),
            "INV-9 VIOLATED: secret bytes {:?} appear in fake field at secret offset {}",
            std::str::from_utf8(window).unwrap_or("<binary>"),
            window_start
        );
    }
}
