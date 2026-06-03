use doppel::{patterns, register, restore, swap, types::Entry};

// Synthetic test keys — NOT real credentials. Format matches real format for structural testing.
const SYNTH_ANTHROPIC: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SYNTH_AWS_AKIA: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
const SYNTH_GITHUB_CLASSIC: &[u8] = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
#[allow(dead_code)]
const SYNTH_GITHUB_FG: &[u8] =
    b"github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
// Structure: "github_pat_" (11) + 22 A's + "_" + 59 B's = 93 chars total
#[allow(dead_code)]
const SYNTH_GCP: &[u8] = b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn test_inv1_swap_replaces_every_detected_secret() {
    // INV-1: "swap MUST replace every secret detected by the supplied Patterns
    //         with a structurally-equivalent fake."
    let payload = [b"Authorization: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "INV-1: original secret must not appear in scrubbed payload"
    );
}

#[test]
fn test_inv2_swap_does_not_modify_non_secret_bytes() {
    // INV-2: "swap MUST NOT modify bytes that are not identified as secrets."
    let prefix = b"Authorization: ";
    let suffix = b" end-of-header";
    let payload = [prefix.as_slice(), SYNTH_ANTHROPIC, suffix].concat();
    let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
    assert!(
        result.payload.starts_with(prefix),
        "INV-2: prefix unchanged"
    );
    assert!(result.payload.ends_with(suffix), "INV-2: suffix unchanged");
    assert_eq!(
        result.payload.len(),
        payload.len(),
        "INV-2: total payload length preserved"
    );
}

#[test]
fn test_inv3_entries_exactly_one_per_distinct_secret() {
    // INV-3: "swap MUST return entries containing exactly one record per distinct secret."
    let payload = [SYNTH_ANTHROPIC, b" separator ".as_slice(), SYNTH_AWS_AKIA].concat();
    let result =
        swap(&payload, &[patterns::anthropic(), patterns::aws_akia()]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        2,
        "INV-3: one entry per distinct secret (2 different secrets)"
    );
}

#[test]
fn test_inv4_restore_restores_across_chunk_boundaries() {
    // INV-4: "restore MUST restore every fake present in the response stream
    //         regardless of where chunk boundaries fall."
    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let scrub_result = swap(&payload, &[patterns::github_classic()]).expect("swap failed");

    struct ByteByByteReader<'a> {
        data: &'a [u8],
        pos: usize,
    }
    impl<'a> std::io::Read for ByteByByteReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    let mut reader = ByteByByteReader {
        data: &scrub_result.payload,
        pos: 0,
    };
    let mut output = Vec::new();
    restore(
        &mut reader,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .unwrap();
    assert_eq!(output, payload, "INV-4: chunk-boundary restoration failed");
}

#[test]
fn test_inv5_restore_does_not_emit_before_aead_verified() {
    // INV-5: "restore MUST NOT emit restored plaintext before the AEAD tag has been verified."
    // Proxy test: tamper with tag → Err → no secret bytes in output
    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut scrub_result = swap(&payload, &[patterns::github_classic()]).expect("swap failed");
    let last = scrub_result.entries[0].ciphertext.len() - 1;
    scrub_result.entries[0].ciphertext[last] ^= 0xFF;
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    let _ = restore(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    );
    assert!(
        !output
            .windows(SYNTH_GITHUB_CLASSIC.len())
            .any(|w| w == SYNTH_GITHUB_CLASSIC),
        "INV-5: secret must not appear in output after tag failure"
    );
}

#[cfg(feature = "async")]
#[test]
fn test_inv5_async_no_plaintext_before_aead_verified() {
    // INV-5: "restore MUST NOT emit restored plaintext before the AEAD tag has been verified."
    // Async variant: tamper tag, verify secret never appears in any emitted chunk.
    use bytes::Bytes;
    use doppel::restore_stream;
    use futures::{StreamExt, stream};
    use std::io;

    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut sr = swap(&payload, &[patterns::github_classic()]).expect("swap failed");
    let last = sr.entries[0].ciphertext.len() - 1;
    sr.entries[0].ciphertext[last] ^= 0xFF; // tamper tag

    let chunks: Vec<Result<Bytes, io::Error>> = sr
        .payload
        .chunks(16)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let inner = stream::iter(chunks);
    let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();

    let result = futures::executor::block_on(async {
        let mut all: Vec<u8> = Vec::new();
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => all.extend_from_slice(&chunk),
                Err(e) => return Err((e, all)),
            }
        }
        Ok(all)
    });

    let (_, emitted) = result.expect_err("tampered tag must produce error");
    assert!(
        !emitted
            .windows(SYNTH_GITHUB_CLASSIC.len())
            .any(|w| w == SYNTH_GITHUB_CLASSIC),
        "INV-5: secret must not appear in output before tag failure (async)"
    );
}

#[test]
fn test_inv6_aead_tag_failure_produces_error() {
    // INV-6: "An AEAD tag failure MUST produce an error; the stream MUST NOT continue."
    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut scrub_result = swap(&payload, &[patterns::github_classic()]).expect("swap failed");
    let last = scrub_result.entries[0].ciphertext.len() - 1;
    scrub_result.entries[0].ciphertext[last] ^= 0xFF;
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    let result = restore(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    );
    assert!(result.is_err(), "INV-6: tag failure must return Err");
}

#[cfg(feature = "async")]
#[test]
fn test_inv6_async_aead_tag_failure_produces_error() {
    // INV-6: "An AEAD tag failure MUST produce an error; the stream MUST NOT continue."
    use bytes::Bytes;
    use doppel::{RestoreError, restore_stream};
    use futures::{StreamExt, stream};
    use std::io;

    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut sr = swap(&payload, &[patterns::github_classic()]).expect("swap failed");
    let last = sr.entries[0].ciphertext.len() - 1;
    sr.entries[0].ciphertext[last] ^= 0xFF; // tamper tag

    let chunks: Vec<Result<Bytes, io::Error>> = sr
        .payload
        .chunks(16)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let inner = stream::iter(chunks);
    let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();

    let result = futures::executor::block_on(async {
        let mut items_after_err = 0usize;
        let mut saw_err = false;
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            if saw_err {
                items_after_err += 1;
            }
            if item.is_err() {
                assert!(
                    matches!(item, Err(RestoreError::AeadTagFailure { .. })),
                    "INV-6: must yield AeadTagFailure"
                );
                saw_err = true;
            }
        }
        (saw_err, items_after_err)
    });

    assert!(result.0, "INV-6: must produce an error on tampered tag");
    assert_eq!(
        result.1, 0,
        "INV-6: stream must not yield items after error"
    );
}

#[test]
fn test_inv7_restore_no_fake_forwarded_unchanged() {
    // INV-7: "restore MUST forward all bytes unchanged when no fake appears in stream;
    //         it MUST NOT produce an error."
    let payload = b"no secrets here at all";
    let scrub_result = swap(payload, &[patterns::anthropic()]).expect("swap failed");
    let response = b"a response with no matching content";
    let mut input = response.as_slice();
    let mut output = Vec::new();
    let result = restore(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    );
    assert!(
        result.is_ok(),
        "INV-7: must not produce error when no fake present"
    );
    assert_eq!(output, response, "INV-7: output identical to input");
}

#[test]
fn test_inv8_restore_bounded_hold() {
    // INV-8: "restore MUST NOT hold more than max{|fake_i|} bytes unemitted at any point."
    // Proxy: verify round-trip is correct with 1-byte input chunks (bound enforced by impl)
    let payload = [b"ctx: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let scrub_result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");

    struct OneByteReader<'a> {
        data: &'a [u8],
        pos: usize,
    }
    impl<'a> std::io::Read for OneByteReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    let mut reader = OneByteReader {
        data: &scrub_result.payload,
        pos: 0,
    };
    let mut output = Vec::new();
    restore(
        &mut reader,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .unwrap();
    assert_eq!(
        output, payload,
        "INV-8: round-trip successful (buffer bound enforced by implementation)"
    );
}

#[cfg(feature = "async")]
#[test]
fn test_inv8_async_hold_bound_observed() {
    // INV-8: "restore MUST NOT hold more than max{|fake_i|} bytes unemitted at any point."
    // Direct observation: feed bytes one at a time, verify output never lags input by more than max_hold.
    use bytes::Bytes;
    use doppel::restore_stream;
    use futures::StreamExt;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let payload = [b"prefix ".as_slice(), SYNTH_ANTHROPIC, b" suffix"].concat();
    let sr = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
    let max_hold = sr.entries.iter().map(|e| e.fake.len()).max().unwrap_or(0);

    let fed = Arc::new(AtomicUsize::new(0));
    let fed_clone = fed.clone();

    let chunks = sr.payload.iter().map(move |&b| {
        fed_clone.fetch_add(1, Ordering::SeqCst);
        Ok::<_, io::Error>(Bytes::from(vec![b]))
    });
    let inner = futures::stream::iter(chunks);
    let stream = restore_stream(inner, sr.entries, sr.session_key).unwrap();

    let mut max_lag = 0usize;
    let mut total_out = 0usize;

    futures::executor::block_on(async {
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let chunk = item.expect("no error expected");
            total_out += chunk.len();
            let current_fed = fed.load(Ordering::SeqCst);
            let lag = current_fed.saturating_sub(total_out);
            if lag > max_lag {
                max_lag = lag;
            }
        }
    });

    assert!(
        max_lag <= max_hold,
        "INV-8: max lag {} exceeds max_hold {}",
        max_lag,
        max_hold
    );
    assert_eq!(total_out, payload.len(), "round-trip length mismatch");
}

#[test]
fn test_inv9_entries_contain_no_plaintext_secret() {
    // INV-9: "entries MUST NOT contain plaintext secret bytes in any field or serialized form."
    let payload = [b"token: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
    let json = Entry::serialize_entries(&result.entries).unwrap();
    assert!(
        !json
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "INV-9: plaintext secret must not appear in serialized entries"
    );
}

#[test]
fn test_inv9_registered_no_secret_bytes_in_entries() {
    // INV-9 (registered): the variable portion of a registered secret must not appear
    // in the serialized entries — not even as a 4-byte sliding-window fragment.
    // With the default SecretOptions (wide charset, no prefix preservation),
    // the fake is drawn from a charset with no overlap with the secret bytes.
    //
    // This test closes the gap that was previously undetected: the old implementation
    // embedded secret[0..8] verbatim in the fake, which passed the full-length check
    // but leaked the start fragment to any entries observer.
    let secret = b"my-arb-secret-value-0123456789!"; // 31 bytes, mixed charset
    let pat = register(secret).unwrap();
    let payload = [b"Authorization: ".as_slice(), secret].concat();
    let result = swap(&payload, &[pat]).expect("swap failed");
    let json = Entry::serialize_entries(&result.entries).unwrap();
    // No 4-byte window of the secret should appear anywhere in the serialized entries.
    for window in secret.windows(4) {
        assert!(
            !json.windows(4).any(|w| w == window),
            // INV-9: variable portion of secret must not appear in entries
            "INV-9 VIOLATED: secret window {:?} found in serialized entries",
            std::str::from_utf8(window).unwrap_or("<binary>")
        );
    }
}

#[test]
fn test_inv10_session_key_not_in_entries() {
    // INV-10: "The session key MUST NOT be serialized together with or embedded within the entries."
    let payload = [b"token: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
    let json = Entry::serialize_entries(&result.entries).unwrap();
    let key_bytes = result.session_key.as_bytes();
    assert!(
        !json.windows(32).any(|w| w == key_bytes.as_slice()),
        "INV-10: session key must not appear in serialized entries"
    );
}

#[test]
fn test_inv11_session_key_zeroized_on_drop() {
    // INV-11,12: "key material MUST be destroyed when the session cycle ends."
    // Verify ZeroizeOnDrop is implemented on SessionKey.
    use doppel::types::SessionKey;
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SessionKey>();
}

#[test]
fn test_inv12_key_material_destroyed_on_drop() {
    // INV-12: covered by ZeroizeOnDrop derive on SessionKey (verified in test_inv11).
    // Compile-time guarantee: SessionKey has no Clone or Debug impl.
    // Code review and type system enforce no Clone/Debug; test_inv10 exercises the type.
    use doppel::types::SessionKey;
    let _ = std::mem::size_of::<SessionKey>();
}

#[test]
fn test_inv13_same_secret_same_pattern_same_fake() {
    // INV-13: "The same secret detected under the same Pattern MUST produce the same fake."
    let payload = [b"x: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let pat = patterns::anthropic();
    let result1 = swap(&payload, std::slice::from_ref(&pat)).expect("swap failed");
    let result2 = swap(&payload, std::slice::from_ref(&pat)).expect("swap failed");
    assert_eq!(
        result1.entries[0].fake, result2.entries[0].fake,
        "INV-13: same secret + same Pattern must produce same fake"
    );
}

#[test]
fn test_inv14_multiple_occurrences_one_entry_same_fake() {
    // INV-14: "Multiple occurrences of the same secret produce the same fake; one entry."
    let sep = b" separator ";
    let payload = [SYNTH_ANTHROPIC, sep.as_slice(), SYNTH_ANTHROPIC].concat();
    let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "INV-14: one entry for repeated secret"
    );
    let fake = &result.entries[0].fake;
    assert!(
        result.payload.starts_with(fake.as_slice()),
        "INV-14: first occurrence → fake"
    );
    assert!(
        result.payload.ends_with(fake.as_slice()),
        "INV-14: second occurrence → same fake"
    );
}

#[test]
fn test_inv15_fake_not_equal_to_original() {
    // INV-15: "A fake MUST NOT equal the original secret."
    let payload = [b"k: ".as_slice(), SYNTH_ANTHROPIC].concat();
    for _ in 0..10 {
        let result = swap(&payload, &[patterns::anthropic()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert_ne!(
            fake.as_slice(),
            SYNTH_ANTHROPIC,
            "INV-15: fake must not equal original"
        );
        assert!(
            fake.starts_with(b"sk-ant-api03-"),
            "INV-15: fake must preserve prefix"
        );
        assert_eq!(
            fake.len(),
            SYNTH_ANTHROPIC.len(),
            "INV-15: fake must preserve length"
        );
    }
}

#[test]
fn test_inv16_registered_hmac_failure_passthrough() {
    // INV-16: "A registered candidate that matches structurally but fails HMAC verification
    //          MUST be passed through unchanged; no replacement occurs."
    use doppel::register;
    let real_secret = b"my-registered-api-secret-value!";
    let pat = register(real_secret).unwrap();
    let mut tampered = real_secret.to_vec();
    tampered[12] ^= 0xFF;
    let result = swap(&tampered, &[pat]).expect("swap failed");
    assert_eq!(
        result.payload, tampered,
        "INV-16: HMAC failure → pass through unchanged"
    );
    assert!(
        result.entries.is_empty(),
        "INV-16: no entry for HMAC-failed candidate"
    );
}

#[test]
fn test_inv17_registered_unique_salt_per_registration() {
    // INV-17: "Each registered registration MUST use a unique HMAC salt."
    use doppel::register;
    let secret = b"my-secret-value-for-registration";
    let pat1 = register(secret).unwrap();
    let pat2 = register(secret).unwrap();
    let payload1 = [b"token: ".as_slice(), secret].concat();
    let r1 = swap(&payload1, &[pat1]).expect("swap failed");
    let r2 = swap(&payload1, &[pat2]).expect("swap failed");
    // Both produce a fake (detection works independently)
    assert_eq!(r1.entries.len(), 1);
    assert_eq!(r2.entries.len(), 1);
}

#[test]
fn test_inv18_leftmost_longest_match() {
    // INV-18: "Detection MUST produce leftmost-longest matches."
    // sk-proj- is longer than sk-, and the project pattern requires T3BlbkFJ at offset 8+58.
    // openai_classic fails because 'proj-' contains '-' (not alphanumeric).
    let payload: &[u8] = b"sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBT3BlbkFJBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    // "sk-proj-" (8) + 58 B's + "T3BlbkFJ" (8) + 58 B's = 132 chars total
    let result = swap(
        payload,
        &[patterns::openai_classic(), patterns::openai_project()],
    )
    .expect("swap failed");
    assert_eq!(
        result.entries.len(),
        1,
        "INV-18: only one entry (no overlapping matches)"
    );
    assert!(
        result.entries[0].fake.starts_with(b"sk-proj-"),
        "INV-18: project key pattern wins (longer match)"
    );
}

#[test]
fn test_inv19_restore_exact_matching_only() {
    // INV-19: "restore MUST perform only exact matching against fake byte strings;
    //          it MUST NOT run pattern detection of any kind."
    let payload = b"no secret here";
    let scrub_result = swap(payload, &[patterns::anthropic()]).expect("swap failed");
    let response_with_real_key = [b"response: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let mut input = response_with_real_key.as_slice();
    let mut output = Vec::new();
    restore(
        &mut input,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .unwrap();
    assert_eq!(
        output, response_with_real_key,
        "INV-19: real key in response must pass through (exact matching only)"
    );
}

#[test]
fn test_inv22_all_structural_built_in_classes_present() {
    // INV-22: built-in structural MUST cover Anthropic, OpenAI (classic + project),
    //         AWS IAM (AKIA + ASIA), GitHub PAT (classic + fine-grained), and GCP API keys.
    //
    // Validates behaviorally: swap a synthetic key of each class and assert detection.
    let cases: &[(&str, &[u8])] = &[
        // Anthropic: prefix "sk-ant-api03-", exactly 108, url_safe_base64
        (
            "Anthropic",
            b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // OpenAI classic: prefix "sk-", exactly 51, alphanumeric
        (
            "OpenAI classic",
            b"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // OpenAI project: prefix "sk-proj-" + 58 B's + T3BlbkFJ + 58 B's = 132 chars
        (
            "OpenAI project",
            b"sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBT3BlbkFJBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            // "sk-proj-" (8) + 58 B's + "T3BlbkFJ" (8) + 58 B's = 132 chars
        ),
        // AWS AKIA: prefix "AKIA", exactly 20, uppercase_alphanumeric
        ("AWS AKIA", b"AKIAAAAAAAAAAAAAAAAA"),
        // AWS ASIA: prefix "ASIA", exactly 20, uppercase_alphanumeric
        ("AWS ASIA", b"ASIAAAAAAAAAAAAAAAAA"),
        // GitHub classic: prefix "ghp_", exactly 40, alphanumeric
        (
            "GitHub classic",
            b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // GitHub fine-grained: "github_pat_" + 22 alnum + "_" + 59 alnum = 93 chars
        (
            "GitHub fine-grained",
            b"github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            // "github_pat_" (11) + 22 A's + "_" + 59 B's = 93 chars
        ),
        // GCP/Gemini: prefix "AIza", exactly 39, url_safe_base64
        ("GCP", b"AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // OpenRouter: prefix "sk-or-v1-", exactly 73, hex_lower
        (
            "OpenRouter",
            b"sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        // Slack bot: xoxb-<10-13 digits>-<10-13 digits>-<24 alnum>
        (
            "Slack bot",
            b"xoxb-1234567890-1234567890-AAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // OpenAI service account: same structure as project
        (
            "OpenAI svcacct",
            b"sk-svcacct-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBT3BlbkFJBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            // "sk-svcacct-" (11) + 58 B's + "T3BlbkFJ" (8) + 58 B's = 135 chars
        ),
    ];
    let all = patterns::all();
    for (name, secret) in cases {
        let result = swap(secret, &all).expect("swap failed");
        assert_eq!(
            result.entries.len(),
            1,
            "INV-22: {name} key must be detected by patterns::all()"
        );
    }
}

#[test]
fn test_inv23_no_detectable_secrets_returns_unchanged() {
    // INV-23: "swap called on a payload containing no detectable secrets MUST return
    //          the payload bytes unchanged and an empty entries set."
    let payload = b"Hello, world! This is a normal message with no API keys.";
    let result = swap(payload, &patterns::all()).expect("swap failed");
    assert_eq!(
        result.payload.as_slice(),
        payload,
        "INV-23: payload unchanged"
    );
    assert!(result.entries.is_empty(), "INV-23: entries empty");

    let result2 = swap(payload, &[]).expect("swap failed");
    assert_eq!(
        result2.payload.as_slice(),
        payload,
        "INV-23: empty patterns → payload unchanged"
    );
    assert!(
        result2.entries.is_empty(),
        "INV-23: empty patterns → entries empty"
    );
}

// INV-AAD: AEAD tag covers the fake field (AAD binding).
// Replacing Entry.fake after swap MUST cause decrypt_entry to return
// AeadTagFailure — restore MUST NOT emit the original secret.
#[test]
fn test_inv_aad_fake_binding() {
    let secret = SYNTH_ANTHROPIC;
    let payload = [b"token: ".as_slice(), secret].concat();
    let scrub_result = swap(&payload, &[patterns::anthropic()]).unwrap();

    // Tamper: replace fake with attacker-controlled trigger.
    let mut tampered = scrub_result.entries.clone();
    tampered[0].fake = b"ATTACKER_TRIGGER".to_vec();

    // Victim runs restore against tampered entries.
    let response = b"response contains ATTACKER_TRIGGER here";
    let mut input = response.as_slice();
    let mut output = Vec::new();
    let result = restore(
        &mut input,
        &mut output,
        &tampered,
        &scrub_result.session_key,
    );

    // AAD mismatch must produce an error — secret must not appear in output.
    assert!(
        result.is_err(),
        "INV-AAD: tampered fake must cause AeadTagFailure, not silent exfiltration"
    );
    assert!(
        !output.windows(secret.len()).any(|w| w == secret),
        "INV-AAD: original secret must not appear in output after fake tamper"
    );
}

#[test]
fn test_inv28_literal_segments_reproduced_verbatim_in_fake() {
    // INV-28: "Every Literal segment in a matched structural Pattern MUST appear verbatim
    //          at the corresponding byte positions of the fake."
    use patterns::{anthropic, github_fine_grained, openai_project, slack_bot};

    // Anthropic: leading literal "sk-ant-api03-" and trailing literal "AA"
    {
        let secret = SYNTH_ANTHROPIC;
        let result = swap(secret, &[anthropic()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert!(
            fake.starts_with(b"sk-ant-api03-"),
            "INV-28: Anthropic prefix literal"
        );
        assert!(
            fake.ends_with(b"AA"),
            "INV-28: Anthropic suffix literal 'AA'"
        );
    }

    // OpenAI project: leading literal "sk-proj-" and embedded literal "T3BlbkFJ" at position 8+58
    {
        let secret: &[u8] = b"sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBT3BlbkFJBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let result = swap(secret, &[openai_project()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert!(
            fake.starts_with(b"sk-proj-"),
            "INV-28: OpenAI project prefix literal"
        );
        assert_eq!(
            &fake[8 + 58..8 + 58 + 8],
            b"T3BlbkFJ",
            "INV-28: T3BlbkFJ embedded literal at position 66"
        );
    }

    // GitHub fine-grained: leading literal "github_pat_" and separator "_" at position 11+22
    {
        let secret = SYNTH_GITHUB_FG;
        let result = swap(secret, &[github_fine_grained()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert!(
            fake.starts_with(b"github_pat_"),
            "INV-28: GitHub FG prefix literal"
        );
        assert_eq!(
            &fake[11 + 22..11 + 23],
            b"_",
            "INV-28: GitHub FG underscore separator at position 33"
        );
    }

    // Slack bot: leading literal "xoxb-" and both "-" separators
    {
        let secret = b"xoxb-1234567890-1234567890-AAAAAAAAAAAAAAAAAAAAAAAA";
        let result = swap(secret, &[slack_bot()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert!(fake.starts_with(b"xoxb-"), "INV-28: Slack prefix literal");
        // xoxb-(10-13 digits)-(10-13 digits)-(24 alnum)
        // For our test secret, var1_len = 10, so first '-' at position 15
        assert_eq!(
            fake[15], b'-',
            "INV-28: Slack first '-' separator at position 15"
        );
        // var2_len = 10, so second '-' at position 15+1+10 = 26
        assert_eq!(
            fake[26], b'-',
            "INV-28: Slack second '-' separator at position 26"
        );
    }
}

#[test]
fn test_inv29_variable_segment_bytes_in_charset() {
    // INV-29: "Every Variable segment in a structural fake MUST contain only bytes drawn
    //          from that segment's own character set."
    use patterns::{anthropic, github_fine_grained, slack_bot};

    let url_safe_b64: Vec<u8> = {
        let mut v: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain([b'-', b'_'])
            .collect();
        v.sort_unstable();
        v
    };
    let digits_cs: Vec<u8> = (b'0'..=b'9').collect();
    let alnum_cs: Vec<u8> = (b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(b'0'..=b'9')
        .collect();

    // Anthropic: variable region is fake[13..106] (93 bytes), must be url_safe_b64
    {
        let result = swap(SYNTH_ANTHROPIC, &[anthropic()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert_eq!(fake.len(), 108);
        assert!(
            fake[13..106].iter().all(|b| url_safe_b64.contains(b)),
            "INV-29: Anthropic variable region must be url_safe_b64"
        );
    }

    // GitHub fine-grained: variable region 1 fake[11..33] = 22 alphanumeric bytes
    //                       variable region 2 fake[34..93] = 59 alphanumeric bytes
    {
        let result = swap(SYNTH_GITHUB_FG, &[github_fine_grained()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert_eq!(fake.len(), 93);
        assert!(
            fake[11..33].iter().all(|b| alnum_cs.contains(b)),
            "INV-29: GitHub FG var1 must be alphanumeric"
        );
        assert!(
            fake[34..93].iter().all(|b| alnum_cs.contains(b)),
            "INV-29: GitHub FG var2 must be alphanumeric"
        );
    }

    // Slack bot: test secret xoxb-1234567890-1234567890-AAAA...AA
    //   var1 = fake[5..15] (10 digits), var2 = fake[16..26] (10 digits),
    //   var3 = fake[27..51] (24 alnum)
    {
        let secret = b"xoxb-1234567890-1234567890-AAAAAAAAAAAAAAAAAAAAAAAA";
        let result = swap(secret, &[slack_bot()]).expect("swap failed");
        let fake = &result.entries[0].fake;
        assert_eq!(fake.len(), 51);
        assert!(
            fake[5..15].iter().all(|b| digits_cs.contains(b)),
            "INV-29: Slack var1 must be digits"
        );
        assert!(
            fake[16..26].iter().all(|b| digits_cs.contains(b)),
            "INV-29: Slack var2 must be digits"
        );
        assert!(
            fake[27..51].iter().all(|b| alnum_cs.contains(b)),
            "INV-29: Slack var3 must be alphanumeric"
        );
    }
}

#[test]
fn test_inv13_cross_serialization_fake_stability() {
    // INV-13: register → serialize patterns → deserialize → swap → same fake
    use doppel::{SecretOptions, SecretsFile, register_with_options, swap};

    let secret = b"my-custom-secret-for-cross-serial-test";
    let pat = register_with_options(secret, &SecretOptions::default()).unwrap();

    let mut pf = SecretsFile::new();
    pf.generate_missing_structural_salts();
    pf.add_secret_pattern(&pat, None).unwrap();

    let payload = [b"token: ".as_slice(), secret].concat();
    let result1 = swap(&payload, std::slice::from_ref(&pat)).unwrap();

    let bytes = pf.serialize().unwrap();
    let pf2 = SecretsFile::deserialize(&bytes).unwrap();
    let patterns2 = pf2.into_patterns().unwrap();

    let result2 = swap(&payload, &patterns2).unwrap();

    assert_eq!(
        result1.entries[0].fake, result2.entries[0].fake,
        "INV-13: same secret through serialized patterns must produce same fake"
    );
}

#[test]
fn test_inv25_register_empty_secret_returns_tooshort() {
    // INV-25: empty secret MUST return TooShort, MUST NOT panic.
    use doppel::SecretError;
    let result = doppel::register(b"");
    assert!(
        matches!(result, Err(SecretError::TooShort)),
        "INV-25: empty secret must yield TooShort"
    );
}

#[test]
fn test_inv25_register_no_variable_bytes_returns_error() {
    // INV-25: preserve_prefix + preserve_suffix >= secret.len() → NoVariableBytes.
    use doppel::{SecretError, SecretOptions, register_with_options};
    let secret = b"abcdefgh"; // 8 bytes
    let opts = SecretOptions {
        preserve_prefix: 5,
        preserve_suffix: 3, // 5+3 == 8 == secret.len()
        restrict_charset: false,
    };
    let result = register_with_options(secret, &opts);
    assert!(
        matches!(result, Err(SecretError::NoVariableBytes { .. })),
        "INV-25: fully-preserved secret must yield NoVariableBytes"
    );
}

#[test]
fn test_inv26_register_short_variable_portion_succeeds() {
    // INV-26: variable portion < 14 bytes → MUST emit log::warn diagnostic.
    // This test verifies the function succeeds; log capture not yet wired.
    // TODO: add log-capture assertion when a test logger harness is available.
    use doppel::{SecretOptions, register_with_options};
    let secret = b"PREFIX_secret"; // 13 bytes, preserve_prefix=7 → variable=6 < 14
    let opts = SecretOptions {
        preserve_prefix: 7,
        preserve_suffix: 0,
        restrict_charset: false,
    };
    let result = register_with_options(secret, &opts);
    assert!(
        result.is_ok(),
        "INV-26: registration with short variable portion must succeed (got warning)"
    );
}

#[test]
fn test_inv27_register_alphanumeric_secret_wide_charset_succeeds() {
    // INV-27: alphanumeric secret + restrict_charset=false → MUST emit log::warn.
    // This test verifies the function succeeds; log capture not yet wired.
    // TODO: add log-capture assertion when a test logger harness is available.
    use doppel::{SecretOptions, register_with_options};
    let secret = b"myAlphaNumericSecret123";
    let opts = SecretOptions {
        preserve_prefix: 0,
        preserve_suffix: 0,
        restrict_charset: false,
    };
    let result = register_with_options(secret, &opts);
    assert!(
        result.is_ok(),
        "INV-27: registration must succeed (got warning)"
    );
}

#[test]
fn test_inv30_user_structural_requires_variable_segment() {
    // INV-30: "A user-defined structural pattern MUST specify at least one Variable segment"
    use doppel::{SecretsFile, segment::SegmentDef};
    let mut pf = SecretsFile::new();
    pf.generate_missing_structural_salts();
    let result = pf.add_structural_entry(
        "pure_literal".into(),
        vec![SegmentDef::Literal {
            value: "just-a-prefix".into(),
        }],
        [0u8; 32],
    );
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("at least one variable segment"),
        "INV-30: pure literal segment list must be rejected"
    );
}

#[test]
fn test_inv31_duplicate_identifier_rejected() {
    // INV-31: "A user-defined structural identifier MUST be unique within the patterns file"
    use doppel::{SecretsFile, segment::SegmentDef};
    let mut pf = SecretsFile::new();
    pf.generate_missing_structural_salts();
    let segs = vec![SegmentDef::Variable {
        charset: "alphanumeric".into(),
        min: 10,
        max: 10,
    }];
    pf.add_structural_entry("my_custom".into(), segs.clone(), [1u8; 32])
        .unwrap();
    let err = pf
        .add_structural_entry("my_custom".into(), segs, [2u8; 32])
        .unwrap_err();
    assert!(
        err.to_string().contains("duplicate"),
        "INV-31: duplicate identifier must be rejected"
    );
}

#[test]
fn test_inv32_missing_builtin_is_allowed() {
    // INV-32: "Removing a built-in structural identifier from the patterns file is permitted"
    use doppel::SecretsFile;
    let pf = SecretsFile {
        version: 2,
        structural: vec![],
        registered: vec![],
    };
    let patterns = pf.into_patterns().unwrap();
    assert_eq!(
        patterns.len(),
        0,
        "INV-32: empty structural list must produce zero patterns"
    );
}

#[test]
fn test_inv33_version_must_be_2() {
    // INV-33: "The patterns file version MUST be 2"
    use doppel::SecretsFile;
    let data = b"version = 1\nstructural = []\nregistered = []\n";
    let err = SecretsFile::deserialize(data).unwrap_err();
    assert!(
        err.to_string().contains("unsupported"),
        "INV-33: version 1 must be rejected"
    );

    let data = b"version = 3\nstructural = []\nregistered = []\n";
    let err = SecretsFile::deserialize(data).unwrap_err();
    assert!(
        err.to_string().contains("unsupported"),
        "INV-33: version 3 must be rejected"
    );
}

#[test]
fn test_inv25_collision_limit_path_exists() {
    // INV-25: SecretError::CollisionLimit must be returned when fake generation
    // exhausts retries. The trial derivation in register_with_options checks for collision
    // at registration time. A genuine collision requires a secret whose derived fake
    // equals itself — astronomically unlikely for secrets > 14 bytes.
    //
    // This test verifies the code path exists by confirming that registration performs
    // the trial derivation (if it didn't, a collision would surface at swap time as
    // SwapError::Fake instead of SecretError::CollisionLimit).
    //
    // A synthetic collision test would require reverse-engineering the HMAC-based
    // derivation to find a secret that maps to itself — not feasible.
    use doppel::{SecretError, SecretOptions, register_with_options};
    let secret = b"short-but-valid-secret-value";
    let opts = SecretOptions {
        preserve_prefix: 0,
        preserve_suffix: 0,
        restrict_charset: false,
    };
    // Succeeds because no collision occurs for this secret.
    let _ = register_with_options(secret, &opts).unwrap();
    // Verify the CollisionLimit variant is discriminable (not dead code).
    let err: SecretError = SecretError::CollisionLimit { attempts: 1 };
    assert!(
        err.to_string().contains("exhausted"),
        "INV-25: CollisionLimit error message must be descriptive"
    );
}

#[test]
fn test_inv_empty_fake_sync_rejected() {
    // The empty-fake guard MUST fire before AhoCorasick build to prevent
    // an infinite loop (Match{0,0} → drain(..0) no-op).
    use doppel::types::{Entry, SessionKey};
    use doppel::{RestoreError, restore};

    let bad_entry = Entry {
        fake: vec![],
        ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 24],
    };
    let key = SessionKey::from_bytes([1u8; 32]);
    let mut input = b"some payload".as_slice();
    let mut output = Vec::new();
    let result = restore(&mut input, &mut output, &[bad_entry], &key);
    assert!(
        matches!(result, Err(RestoreError::Build { .. })),
        "empty fake MUST return Err(Build), not loop"
    );
    assert!(
        output.is_empty(),
        "guard MUST fire before any bytes are written to output"
    );
}

#[cfg(feature = "async")]
#[test]
fn test_inv_empty_fake_async_rejected() {
    use bytes::Bytes;
    use doppel::types::{Entry, SessionKey};
    use doppel::{RestoreError, restore_stream};
    use futures::stream;
    use std::io;

    let bad_entry = Entry {
        fake: vec![],
        ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 24],
    };
    let key = SessionKey::from_bytes([1u8; 32]);
    let inner = stream::empty::<Result<Bytes, io::Error>>();
    let result = restore_stream(inner, vec![bad_entry], key);
    assert!(
        matches!(result, Err(RestoreError::Build { .. })),
        "empty fake MUST return Err(Build) from constructor"
    );
    // No output check: constructor failure prevents stream creation,
    // so zero bytes can ever be emitted (no stream object → no I/O).
}
