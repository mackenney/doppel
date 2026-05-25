use its_classified::{register, scrub, tier1::patterns, unscrub};

// Synthetic test secrets — NOT real credentials
const SYNTH_ANTHROPIC: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
const SYNTH_OPENAI: &[u8] = b"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SYNTH_AWS: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
const SYNTH_GITHUB_CLASSIC: &[u8] = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SYNTH_GITHUB_FG: &[u8] =
    b"github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SYNTH_GCP: &[u8] = b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn round_trip(payload: &[u8], pats: &[its_classified::types::Pattern]) -> Vec<u8> {
    let scrub_result = scrub(payload, pats);
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    unscrub(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .expect("unscrub failed");
    output
}

fn round_trip_chunked(
    payload: &[u8],
    pats: &[its_classified::types::Pattern],
    chunk_size: usize,
) -> Vec<u8> {
    use std::io::Read;
    let scrub_result = scrub(payload, pats);

    struct ChunkedReader<'a> {
        data: &'a [u8],
        pos: usize,
        chunk: usize,
    }
    impl<'a> Read for ChunkedReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = (self.chunk).min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    let mut reader = ChunkedReader {
        data: &scrub_result.payload,
        pos: 0,
        chunk: chunk_size,
    };
    let mut output = Vec::new();
    unscrub(
        &mut reader,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .expect("chunked unscrub failed");
    output
}

// VC-1: Given a Tier 1 secret, scrubbed output contains no byte subsequence equal to original
#[test]
fn test_vc1_scrubbed_contains_no_original_secret() {
    // VC-1 from SPEC.md Verifiable Conditions
    let payload = [b"key: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = scrub(&payload, &[patterns::anthropic()]);
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "VC-1: scrubbed payload must not contain original secret"
    );
}

// VC-2: Round-trip: scrub → unscrub → original
#[test]
fn test_vc2_scrub_unscrub_round_trip_tier1() {
    // VC-2 from SPEC.md Verifiable Conditions
    for (key, pats) in [
        (SYNTH_ANTHROPIC, vec![patterns::anthropic()]),
        (SYNTH_OPENAI, vec![patterns::openai_classic()]),
        (SYNTH_AWS, vec![patterns::aws_akia()]),
        (SYNTH_GITHUB_CLASSIC, vec![patterns::github_classic()]),
        (SYNTH_GITHUB_FG, vec![patterns::github_fine_grained()]),
        (SYNTH_GCP, vec![patterns::gcp()]),
    ] {
        let payload = [b"secret: ".as_slice(), key].concat();
        let restored = round_trip(&payload, &pats);
        assert_eq!(
            restored,
            payload,
            "VC-2: round-trip failed for key {:?}",
            &key[..8]
        );
    }
}

// VC-3: Same secret, same Pattern → identical fake across two scrub calls
#[test]
fn test_vc3_two_scrub_calls_same_fake() {
    // VC-3 from SPEC.md Verifiable Conditions
    let payload = [b"k: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let pat = patterns::anthropic();
    let r1 = scrub(&payload, std::slice::from_ref(&pat));
    let r2 = scrub(&payload, std::slice::from_ref(&pat));
    assert_eq!(
        r1.entries[0].fake, r2.entries[0].fake,
        "VC-3: two scrub calls must produce identical fakes for same secret+Pattern"
    );
}

// VC-4: Fake straddles chunk boundary → still restored
#[test]
fn test_vc4_fake_straddles_chunk_boundary() {
    // VC-4 from SPEC.md Verifiable Conditions
    let payload = [b"ctx: ".as_slice(), SYNTH_ANTHROPIC, b" end"].concat();
    let restored = round_trip_chunked(&payload, &[patterns::anthropic()], 1);
    assert_eq!(restored, payload, "VC-4: chunk-boundary restoration failed");

    let restored2 = round_trip_chunked(&payload, &[patterns::anthropic()], 13);
    assert_eq!(restored2, payload, "VC-4: 13-byte chunk restoration failed");
}

// VC-5: No fake in stream → identical output, no error
#[test]
fn test_vc5_no_fake_in_stream_identical_output() {
    // VC-5 from SPEC.md Verifiable Conditions
    let scrub_result = scrub(b"no secrets", &[patterns::anthropic()]);
    let response = b"response: no fakes here at all, just regular text";
    let mut input = response.as_slice();
    let mut output = Vec::new();
    let result = unscrub(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    );
    assert!(result.is_ok(), "VC-5: no error when no fake present");
    assert_eq!(output, response, "VC-5: output identical to input");
}

// VC-6: Tampered AEAD tag → error, no partial output
#[test]
fn test_vc6_tampered_aead_tag_error_no_partial_output() {
    // VC-6 from SPEC.md Verifiable Conditions
    let payload = [b"key: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let mut scrub_result = scrub(&payload, &[patterns::anthropic()]);
    let last = scrub_result.entries[0].ciphertext.len() - 1;
    scrub_result.entries[0].ciphertext[last] ^= 0xFF;
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    let result = unscrub(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    );
    assert!(result.is_err(), "VC-6: tampered tag must return error");
    assert!(
        !output
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "VC-6: no secret bytes in partial output"
    );
}

// VC-7: Entries contain no original secret bytes
#[test]
fn test_vc7_entries_contain_no_secret_bytes() {
    // VC-7 from SPEC.md Verifiable Conditions
    let payload = [b"Authorization: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = scrub(&payload, &[patterns::anthropic()]);
    let json = its_classified::types::Entry::serialize_entries(&result.entries).unwrap();
    assert!(
        !json
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "VC-7: entries must not contain original secret bytes"
    );
}

// VC-10: Multiple occurrences → same fake at all positions
#[test]
fn test_vc10_multiple_occurrences_same_fake() {
    // VC-10 from SPEC.md Verifiable Conditions
    let payload = [SYNTH_ANTHROPIC, b" and ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = scrub(&payload, &[patterns::anthropic()]);
    let fake = &result.entries[0].fake;
    let fake_len = fake.len();
    assert_eq!(
        result.payload[..fake_len],
        *fake.as_slice(),
        "VC-10: first occurrence uses fake"
    );
    assert_eq!(
        result.payload[result.payload.len() - fake_len..],
        *fake.as_slice(),
        "VC-10: second occurrence uses same fake"
    );
}

// VC-11: Tier 2 HMAC mismatch → pass through unchanged
#[test]
fn test_vc11_tier2_hmac_mismatch_passthrough() {
    // VC-11 from SPEC.md Verifiable Conditions
    let real = b"my-registered-secret-value-12345";
    let pat = register(real);
    let mut similar = real.to_vec();
    similar[12] ^= 0xFF;
    let result = scrub(&similar, &[pat]);
    assert_eq!(
        result.payload, similar,
        "VC-11: HMAC mismatch → pass through"
    );
    assert!(result.entries.is_empty(), "VC-11: no entry produced");
}

// VC-12: Empty pattern set → payload unchanged, empty entries
#[test]
fn test_vc12_empty_patterns_unchanged() {
    // VC-12 from SPEC.md Verifiable Conditions
    let payload = b"any payload at all";
    let result = scrub(payload, &[]);
    assert_eq!(
        result.payload.as_slice(),
        payload,
        "VC-12: empty patterns → unchanged"
    );
    assert!(result.entries.is_empty(), "VC-12: empty entries");
}

// Additional integration: Tier 2 full round-trip
#[test]
fn test_tier2_full_round_trip() {
    let secret = b"my-custom-api-token-value-here!";
    let pat = register(secret);
    let payload = [b"token: ".as_slice(), secret].concat();
    let scrub_result = scrub(&payload, &[pat]);
    assert_eq!(scrub_result.entries.len(), 1);
    let fake = &scrub_result.entries[0].fake;
    assert_ne!(fake.as_slice(), secret, "fake must differ from original");

    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    unscrub(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .unwrap();
    assert_eq!(output, payload, "Tier 2 round-trip failed");
}

// Additional integration: Two different secrets → two entries
#[test]
fn test_two_different_secrets_two_entries() {
    let payload = [SYNTH_ANTHROPIC, b" and ".as_slice(), SYNTH_AWS].concat();
    let result = scrub(&payload, &[patterns::anthropic(), patterns::aws_akia()]);
    assert_eq!(
        result.entries.len(),
        2,
        "two different secrets → two entries"
    );

    let mut input = result.payload.as_slice();
    let mut output = Vec::new();
    unscrub(
        &mut input,
        &mut output,
        &result.entries,
        &result.session_key,
    )
    .unwrap();
    assert_eq!(output, payload);
}

// Additional: Large payload with multiple secrets
#[test]
fn test_large_payload_multiple_secrets() {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"First section. ");
    payload.extend_from_slice(SYNTH_ANTHROPIC);
    payload.extend_from_slice(b" middle text here ");
    payload.extend_from_slice(SYNTH_GCP);
    payload.extend_from_slice(b" end section.");
    let pats = vec![patterns::anthropic(), patterns::gcp()];
    let scrub_result = scrub(&payload, &pats);
    assert_eq!(scrub_result.entries.len(), 2);
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    unscrub(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .unwrap();
    assert_eq!(output, payload);
}
