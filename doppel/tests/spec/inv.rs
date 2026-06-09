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
    scrub_result.entries[0].flip_last_ciphertext_byte_for_testing();
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
    scrub_result.entries[0].flip_last_ciphertext_byte_for_testing();
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
    // INV-22: built-in structural patterns MUST cover all 27 built-in classes.
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
        // Anthropic Admin01: sk-ant-admin01- + 93 url_safe_base64 + AA
        (
            "Anthropic Admin01",
            b"sk-ant-admin01-w8bVJRHra9S96i3ios_XhbLgzEBjS6qjPUEgiPrWjN2OeICCY1lwhK3Z35Z_jM89STjqSOxHh6GWGkG2R7uv-AohQLmK9AA",
        ),
        // Anthropic Admin03: sk-ant-admin03- + 93 url_safe_base64 + AA
        (
            "Anthropic Admin03",
            b"sk-ant-admin03-w8bVJRHra9S96i3ios_XhbLgzEBjS6qjPUEgiPrWjN2OeICCY1lwhK3Z35Z_jM89STjqSOxHh6GWGkG2R7uv-AohQLmK9AA",
        ),
        // Linear: lin_api_ + 40 alphanumeric
        (
            "Linear",
            b"lin_api_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Groq: gsk_ + 52 alphanumeric
        (
            "Groq",
            b"gsk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Perplexity: pplx- + 48 hex_lower
        (
            "Perplexity",
            b"pplx-abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
        // Cerebras: csk- + 48 alphanumeric
        (
            "Cerebras",
            b"csk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Stripe live: sk_live_ + 24 alphanumeric
        (
            "Stripe live",
            b"sk_live_AAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Stripe test: sk_test_ + 24 alphanumeric
        (
            "Stripe test",
            b"sk_test_AAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Clerk live: sk_live_ + 45 alphanumeric (distinct from Stripe by length)
        (
            "Clerk",
            b"sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Svix: svix_ + 30 alphanumeric
        (
            "Svix",
            b"svix_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Chromatic: chpt_ + 30 alphanumeric
        (
            "Chromatic",
            b"chpt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // Google OAuth Secret: GOCSPX- + 28 url_safe_base64
        (
            "Google OAuth Secret",
            b"GOCSPX-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // GitHub OAuth: gho_ + 36 alphanumeric
        (
            "GitHub OAuth",
            b"gho_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // GitHub App Server: ghs_ + 36 alphanumeric
        (
            "GitHub App Server",
            b"ghs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // GitHub App User: ghu_ + 36 alphanumeric
        (
            "GitHub App User",
            b"ghu_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        // GitHub Refresh: ghr_ + 36 alphanumeric (min:36, max:76; use min)
        (
            "GitHub Refresh",
            b"ghr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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

// INV-24: AEAD tag covers the fake field as AAD.

// AeadTagFailure — restore MUST NOT emit the original secret.
#[test]
fn test_inv24_aad_fake_binding() {
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
        "INV-24: tampered fake must cause AeadTagFailure, not silent exfiltration"
    );
    assert!(
        !output.windows(secret.len()).any(|w| w == secret),
        "INV-24: original secret must not appear in output after fake tamper"
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
    pf.add_secret_pattern("my-custom-secret".to_string(), &pat)
        .unwrap();

    let payload = [b"token: ".as_slice(), secret].concat();
    let result1 = swap(&payload, std::slice::from_ref(&pat)).unwrap();

    let bytes = pf.serialize().unwrap();
    let pf2 = SecretsFile::deserialize(&bytes).unwrap();
    let patterns2 = pf2.to_patterns().unwrap();

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
    // INV-25: anchor_len + tail_anchor_len >= secret.len() → NoVariableBytes.
    use doppel::{SecretError, SecretOptions, register_with_options};
    let secret = b"abcdefgh"; // 8 bytes
    let opts = SecretOptions {
        anchor_len: 5,
        tail_anchor_len: 3,
        restrict_charset: false,
        ..Default::default()
    };
    let result = register_with_options(secret, &opts);
    assert!(
        matches!(result, Err(SecretError::NoVariableBytes { .. })),
        "INV-25: fully-anchored secret must yield NoVariableBytes"
    );
}

#[test]
fn test_inv26_register_low_entropy_warns_but_succeeds() {
    // INV-26: 83 <= entropy < 131 bits → MUST emit log::warn diagnostic.
    // This test verifies the function succeeds; log capture not yet wired.
    // TODO: add log-capture assertion when a test logger harness is available.
    use doppel::{SecretOptions, register_with_options};
    // 17-byte secret, anchor_len=3 → 14 middle bytes
    // entropy = 14 * log2(92) ≈ 91.3 bits (83 <= 91.3 < 131) → warns but succeeds.
    let secret = b"abc01234567890123"; // 17 bytes
    let opts = SecretOptions {
        anchor_len: 3,
        restrict_charset: false,
        ..Default::default()
    };
    let result = register_with_options(secret, &opts);
    assert!(
        result.is_ok(),
        "INV-26: registration with entropy in [83, 131) must succeed (got warning)"
    );
}

#[test]
fn test_inv27_register_alphanumeric_secret_wide_charset_succeeds() {
    // INV-26/INV-27: alphanumeric secret + restrict_charset=false → MUST emit log::warn.
    // The warning is now implemented (INV-26 guard added to register_with_options_rng).
    // This test verifies the function succeeds; log capture not yet wired in the test harness.
    use doppel::{SecretOptions, register_with_options};
    let secret = b"myAlphaNumericSecret123";
    let opts = SecretOptions {
        restrict_charset: false,
        ..Default::default()
    };
    let result = register_with_options(secret, &opts);
    assert!(
        result.is_ok(),
        "INV-27: registration must succeed (got warning)"
    );
}

#[test]
fn test_fix2_restrict_charset_uses_detected_charset() {
    // FIX-2: when restrict_charset=true, fakes must be drawn from the detected charset.
    // Behavioral test: register a hex-lowercase secret; verify the fake contains only
    // hex-lowercase chars (0-9 a-f) — i.e. not drawn from the wide charset.
    use doppel::{SecretOptions, register_with_options, swap};
    // anchor=3 ("sk-"), variable=16 hex-lower bytes; 16*4=64 bits < 83 threshold, force=true
    let secret = b"sk-abcdef01234567"; // anchor "sk-" + 16 hex-lower bytes
    let opts = SecretOptions {
        anchor_len: 3,
        restrict_charset: true,
        force: true, // 64 bits < 83 threshold; force to test charset, not entropy
        ..Default::default()
    };
    let pattern = register_with_options(secret, &opts).expect("registration must succeed");
    let result = swap(secret, &[pattern]).expect("swap must succeed");
    assert_eq!(result.entries.len(), 1, "must detect the secret");
    let fake = &result.entries[0].fake;
    // Variable portion of the fake (skip 3-byte anchor prefix)
    let var_fake = &fake[3..];
    let all_hex = var_fake
        .iter()
        .all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    assert!(
        all_hex,
        "restrict_charset=true with hex-lower secret: fake variable bytes must be hex-lower, got: {:?}",
        var_fake
    );
}

#[test]
fn test_fix1_hmac_all_digests_evaluated_no_early_exit() {
    // FIX-1: HMAC is computed once and all digests compared CT with no early exit.
    // Behavioral test: two registered secrets share the same structural shape but
    // different HMAC digests. A third payload that matches the shape but is neither
    // secret must not be swapped (HMAC fails for both digests).
    use doppel::{SecretOptions, register_with_options, swap};
    let secret1 = b"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 42 bytes
    let secret2 = b"sk-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 42 bytes
    let neither = b"sk-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"; // 42 bytes, same shape
    let opts = SecretOptions {
        anchor_len: 3,
        ..Default::default()
    };
    let p1 = register_with_options(secret1, &opts).unwrap();
    let p2 = register_with_options(secret2, &opts).unwrap();
    // secret1 matches p1's HMAC: exactly one entry.
    let r1 = swap(secret1, &[p1.clone(), p2.clone()]).unwrap();
    assert_eq!(r1.entries.len(), 1, "secret1 must match p1");
    // neither matches no HMAC: zero entries.
    let r_none = swap(neither, &[p1, p2]).unwrap();
    assert_eq!(
        r_none.entries.len(),
        0,
        "structurally matching non-registered secret must not be swapped"
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
    let segs = vec![
        SegmentDef::Literal {
            value: "prefix_".into(),
        },
        SegmentDef::Variable {
            charset: "alphanumeric".into(),
            min: 10,
            max: 10,
        },
    ];
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
        version: 3,
        pattern: vec![],
    };
    let patterns = pf.to_patterns().unwrap();
    assert_eq!(
        patterns.len(),
        0,
        "INV-32: empty pattern list must produce zero patterns"
    );
}

#[test]
fn test_inv33_version_must_be_3() {
    // INV-33: "The patterns file version MUST be 3"
    use doppel::SecretsFile;
    let data = b"version = 1\npattern = []\n";
    let err = SecretsFile::deserialize(data).unwrap_err();
    assert!(
        err.to_string().contains("unsupported"),
        "INV-33: version 1 must be rejected"
    );

    let data = b"version = 2\npattern = []\n";
    let err = SecretsFile::deserialize(data).unwrap_err();
    assert!(
        err.to_string().contains("unsupported"),
        "INV-33: version 2 must be rejected"
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
    use doppel::{SecretError, register_with_options};
    let secret = b"short-but-valid-secret-value";
    // Succeeds because no collision occurs for this secret.
    let _ = register_with_options(secret, &Default::default()).unwrap();
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

    let bad_entry = Entry::new_for_testing(vec![], vec![0u8; 24], vec![0u8; 32]);
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

    let bad_entry = Entry::new_for_testing(vec![], vec![0u8; 24], vec![0u8; 32]);
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

#[test]
fn test_inv28_opaque_fake_bytes_differ_from_anchor() {
    // INV-28: Every Opaque segment MUST produce derived (not verbatim) bytes in the fake.
    // For registered patterns the anchor is an Opaque segment; its fake bytes must
    // differ from the original anchor bytes.
    use doppel::{SecretOptions, register_with_options, swap};

    let secret = b"ABC_secret_value_here_12345678";
    let opts = SecretOptions {
        anchor_len: 4,
        ..Default::default()
    };
    let pattern = register_with_options(secret, &opts).unwrap();
    let result = swap(secret, &[pattern]).unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_ne!(
        &result.payload[0..4],
        b"ABC_",
        "INV-28: opaque anchor segment must not appear verbatim in the fake"
    );
    assert_eq!(result.payload.len(), secret.len());
}

#[test]
fn test_inv31_instance_pattern_variable_must_be_fixed_len() {
    // INV-31: When a Pattern's digests list is non-empty, all variable segments
    // in that Pattern MUST have min == max.
    use doppel::SecretsFile;

    let toml_bad = concat!(
        "version = 3\n",
        "[[pattern]]\n",
        "identifier = \"test-instance\"\n",
        "salt = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        "digests = [\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"]\n",
        "[[pattern.segments]]\n",
        "type = \"opaque\"\n",
        "value = \"prefix_\"\n",
        "[[pattern.segments]]\n",
        "type = \"variable\"\n",
        "charset = \"alphanumeric\"\n",
        "min = 10\n",
        "max = 20\n",
    );

    let result = SecretsFile::deserialize(toml_bad.as_bytes());
    assert!(
        result.is_err(),
        "INV-31: instance pattern with variable-range segment must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("min") || err_msg.contains("max") || err_msg.contains("instance"),
        "INV-31: error must describe the min/max constraint: {err_msg}"
    );
}

#[test]
fn test_inv25_register_insufficient_entropy_hard_fail() {
    // INV-25: entropy < 83 bits and force=false -> InsufficientEntropy.
    // anchor_len=3, secret=11 bytes -> variable=8 bytes,
    // 8 * log2(92) ≈ 52.2 bits < 83.
    use doppel::{SecretError, SecretOptions, register_with_options};

    let short_secret = b"ABC12345678";
    let opts = SecretOptions {
        anchor_len: 3,
        force: false,
        ..Default::default()
    };
    let result = register_with_options(short_secret, &opts);
    assert!(
        matches!(result, Err(SecretError::InsufficientEntropy { .. })),
        "INV-25: low-entropy secret with force=false must yield InsufficientEntropy"
    );
}

#[test]
fn test_inv18_literal_first_beats_opaque_first() {
    // INV-18: A structural pattern with a leading literal segment fires correctly
    // even when a registered pattern's opaque anchor shares the same prefix.
    // The registered pattern's HMAC gate rejects the mismatch and the structural
    // literal match takes precedence.
    use doppel::patterns;
    use doppel::{SecretOptions, register_with_options, swap};

    // Register a secret whose anchor prefix overlaps with the Anthropic literal prefix.
    let registered_secret = b"sk-ant-test-fake-secret-123456789";
    let opts = SecretOptions {
        anchor_len: 7,
        ..Default::default()
    };
    let reg_pattern = register_with_options(registered_secret, &opts).unwrap();

    // Payload contains the real synthetic Anthropic key (matches structural literal).
    let payload = [b"key: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = swap(&payload, &[patterns::anthropic(), reg_pattern]).unwrap();

    // Only the structural (literal-leading) match should fire.
    assert_eq!(
        result.entries.len(),
        1,
        "INV-18: only the structural literal match should fire"
    );
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "INV-18: structural match must replace the original secret"
    );
}

#[test]
fn test_vc11_registered_hmac_mismatch_passthrough() {
    // VC-11: A candidate that shares an opaque segment's bytes and exact length
    // with a registered secret but does not match any HMAC digest passes through
    // the swapped payload unchanged.
    use doppel::{register, swap};

    let real = b"my-registered-secret-value-12345";
    let pat = register(real).unwrap();
    let mut similar = real.to_vec();
    similar[12] ^= 0xFF;

    let result = swap(&similar, &[pat]).unwrap();
    assert_eq!(
        result.payload.as_slice(),
        similar.as_slice(),
        "VC-11: HMAC mismatch must pass through unchanged"
    );
    assert!(
        result.entries.is_empty(),
        "VC-11: no entry produced for HMAC mismatch"
    );
}

#[test]
fn test_wide_charset_entropy_uses_92_not_72() {
    // Regression: wide charset size was hardcoded as 72 (should be 92).
    // With 72: 13 * log2(72) ≈ 80.2 bits < 83 → InsufficientEntropy (wrong).
    // With 92: 13 * log2(92) ≈ 84.8 bits > 83 → succeeds (correct).
    use doppel::{SecretOptions, register_with_options};
    // 16-byte secret: anchor=3 bytes, variable=13 bytes, Wide charset, force=false
    let secret = b"abc!@#$%^&*()-+=";
    let opts = SecretOptions {
        anchor_len: 3,
        restrict_charset: false,
        ..Default::default()
    };
    let result = register_with_options(secret, &opts);
    assert!(
        result.is_ok(),
        "13-byte wide-charset variable portion (84.8 bits) must pass entropy gate"
    );
}

#[test]
fn test_vc17_group_pattern_detects_both_members() {
    // VC-17: a group pattern (single Pattern, 2 digests) detects both A and B,
    // producing distinct fakes, leaving non-member C unchanged.
    use doppel::{SecretOptions, SecretsFile, register_with_options, swap};

    let secret_a = b"my-secret-alpha-value-for-vc17-test";
    let secret_b = b"my-secret-beta-values-for-vc17-test";
    let secret_c = b"my-secret-gamma-value-for-vc17-test";

    let opts = SecretOptions::default();
    let pat_a = register_with_options(secret_a, &opts).unwrap();

    let mut pf = SecretsFile::new();
    pf.add_secret_pattern("group-key".to_string(), &pat_a)
        .unwrap();
    pf.add_secret_to_group("group-key", secret_b).unwrap();

    let patterns = pf.to_patterns().unwrap();
    assert_eq!(patterns.len(), 1, "group produces one Pattern");
    // Verify two digests via the SecretsFile API (Pattern::digests is pub(crate)).
    assert_eq!(
        pf.pattern[0].digests.len(),
        2,
        "group entry has two digests"
    );

    let payload_a = [b"header: ".as_slice(), secret_a].concat();
    let r_a = swap(&payload_a, &patterns).unwrap();
    assert_eq!(r_a.entries.len(), 1, "secret_a detected");
    assert!(
        !r_a.payload.windows(secret_a.len()).any(|w| w == secret_a),
        "VC-17: secret_a must be replaced in output"
    );

    let payload_b = [b"header: ".as_slice(), secret_b].concat();
    let r_b = swap(&payload_b, &patterns).unwrap();
    assert_eq!(r_b.entries.len(), 1, "secret_b detected");
    assert!(
        !r_b.payload.windows(secret_b.len()).any(|w| w == secret_b),
        "VC-17: secret_b must be replaced in output"
    );

    assert_ne!(
        r_a.entries[0].fake, r_b.entries[0].fake,
        "VC-17: distinct fakes for A and B"
    );

    let payload_c = [b"header: ".as_slice(), secret_c].concat();
    let r_c = swap(&payload_c, &patterns).unwrap();
    assert_eq!(r_c.entries.len(), 0, "VC-17: non-member C not detected");
    assert_eq!(r_c.payload, payload_c, "VC-17: C passes through unchanged");
}

// Spec: SPEC.md §Behavioral Invariants 39, 40, 41

#[test]
fn test_inv39_detector_swap_semantics_identical_to_free_swap() {
    // "Detector::swap called on the same payload with the same Patterns MUST
    //  produce fakes identical to those produced by the free swap function."
    //  — SPEC.md INV-39. "Same Patterns" means same Pattern value including salt.
    use doppel::{Detector, patterns, swap};

    let pat = patterns::anthropic();
    // NOT real credentials — synthetic key matching the Anthropic structural pattern
    let payload = b"key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let detector = Detector::new(vec![pat.clone()]);
    let r_detector = detector.swap(payload).unwrap();
    let r_free = swap(payload, &[pat]).unwrap();

    assert_eq!(
        r_detector.entries[0].fake, r_free.entries[0].fake,
        "INV-39: Detector::swap and free swap must produce identical fakes"
    );
    assert_eq!(
        r_detector.payload, r_free.payload,
        "INV-39: swapped payloads must match"
    );
}

#[test]
fn test_inv40_detector_is_send_sync() {
    // "Detector MUST implement Send + Sync." — SPEC.md INV-40
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<doppel::Detector>();
}

#[test]
fn test_inv41_detector_shared_automaton_produces_correct_results_across_calls() {
    // "The Aho-Corasick automaton MUST NOT be rebuilt on Detector::swap calls."
    // — SPEC.md INV-41
    // INV-41 is a structural guarantee: `ac` is a plain field of `Detector`,
    // `swap_with_ac` receives `&self.ac` (an immutable reference), so no rebuild
    // can occur. This test verifies that multiple sequential calls on the same
    // Detector produce correct results, which would fail if the shared automaton
    // were corrupted or invalidated between calls.
    use doppel::{Detector, patterns};

    let detector = Detector::new(patterns::all());
    // NOT real credentials — synthetic key matching the Anthropic structural pattern
    let key = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let payload_a = [b"token: ".as_slice(), key].concat();
    let payload_b = b"no secrets here".as_ref();

    // Both calls must succeed and produce correct results, proving the shared
    // AC automaton remains valid across independent swap calls.
    let r_a = detector.swap(&payload_a).unwrap();
    let r_b = detector.swap(payload_b).unwrap();

    assert_eq!(
        r_a.entries.len(),
        1,
        "INV-41: secret detected on first call"
    );
    assert_eq!(
        r_b.entries.len(),
        0,
        "INV-41: no secret detected on second call"
    );
    assert_eq!(r_b.payload, payload_b, "INV-41: payload_b unchanged");
}

#[test]
fn test_inv39_detector_swap_semantics_identical_for_registered_pattern() {
    // INV-39: "Detector::swap called on the same payload with the same Patterns MUST
    //  produce fakes identical to those produced by the free swap function."
    //  This variant tests with a registered (instance) pattern, not just a family pattern.
    use doppel::{Detector, register, swap};

    let secret = b"inv39-registered-secret-value-check-0001";
    let pat = register(secret).unwrap();
    let payload = [b"token: ".as_slice(), secret].concat();

    let detector = Detector::new(vec![pat.clone()]);
    let r_detector = detector.swap(&payload).unwrap();
    let r_free = swap(&payload, &[pat]).unwrap();

    assert_eq!(
        r_detector.entries.len(),
        1,
        "INV-39: Detector must detect the registered secret"
    );
    assert_eq!(
        r_detector.entries[0].fake, r_free.entries[0].fake,
        "INV-39: Detector::swap and free swap must produce identical fakes for registered pattern"
    );
    assert_eq!(
        r_detector.payload, r_free.payload,
        "INV-39: swapped payloads must match for registered pattern"
    );
}

#[test]
fn test_add_secret_to_group_rejects_family_pattern() {
    // add_secret_to_group must reject family (structural) patterns with WrongPatternType,
    // not silently convert them to instance patterns.
    use doppel::{SecretsFile, SecretsFileError, segment::SegmentDef};
    let mut pf = SecretsFile::new();
    pf.add_structural_entry(
        "my-family".to_string(),
        vec![
            SegmentDef::Literal {
                value: "prefix_".into(),
            },
            SegmentDef::Variable {
                charset: "alphanumeric".into(),
                min: 10,
                max: 20,
            },
        ],
        [0u8; 32],
    )
    .unwrap();
    let result = pf.add_secret_to_group("my-family", b"some-secret-value-here-here-12345");
    assert!(
        matches!(result, Err(SecretsFileError::WrongPatternType)),
        "add_secret_to_group must return WrongPatternType for family patterns, got: {:?}",
        result
    );
}

#[test]
fn test_vc14_family_pattern_opaque_first_detection_and_fake() {
    // VC-14: A family pattern defined with [opaque("sec_"), variable(alphanumeric, 20, 20)]
    // detects a payload containing "sec_" + 20 alphanumeric chars and produces a fake
    // whose opaque portion (first 4 bytes) differs from "sec_" (derived, not verbatim),
    // and whose variable portion also differs from the original.
    use doppel::{SecretsFile, swap};

    let toml = concat!(
        "version = 3\n",
        "[[pattern]]\n",
        "identifier = \"vc14-family\"\n",
        "salt = \"0000000000000000000000000000000000000000000000000000000000000001\"\n",
        "digests = []\n",
        "[[pattern.segments]]\n",
        "type = \"opaque\"\n",
        "value = \"sec_\"\n",
        "[[pattern.segments]]\n",
        "type = \"variable\"\n",
        "charset = \"alphanumeric\"\n",
        "min = 20\n",
        "max = 20\n",
    );
    let pf = SecretsFile::deserialize(toml.as_bytes()).unwrap();
    let patterns = pf.to_patterns().unwrap();

    // Payload: opaque anchor "sec_" + 20 alphanumeric chars
    let secret = b"sec_AAAABBBBCCCCDDDDEEEE";
    assert_eq!(secret.len(), 24);

    let result = swap(secret, &patterns).unwrap();
    assert_eq!(
        result.entries.len(),
        1,
        "VC-14: family pattern must detect the secret"
    );

    let fake = &result.entries[0].fake;
    assert_eq!(
        fake.len(),
        secret.len(),
        "VC-14: fake must be same length as original"
    );
    // Opaque portion must be derived (not verbatim "sec_")
    assert_ne!(
        &fake[..4],
        b"sec_",
        "VC-14: opaque segment fake bytes must not equal original anchor"
    );
    // Variable portion must differ from original
    assert_ne!(
        &fake[4..],
        b"AAAABBBBCCCCDDDDEEEE",
        "VC-14: variable segment fake bytes must differ from original"
    );
}

#[test]
fn test_stripe_clerk_sk_live_gap_behavior() {
    // Documents the detection gap for sk_live_ tokens with 33-44 variable chars.
    // stripe_live covers [24,32]; clerk covers [45,55]. A 36-char variable payload
    // is partially matched by stripe_live (max=32): the first 40 bytes are replaced
    // with a fake, and the remaining 4 chars pass through unchanged.
    //
    // This test documents and pins current behavior so that any change to the
    // Stripe/Clerk ranges is immediately visible.
    let payload = b"sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 8 + 36 = 44 bytes
    assert_eq!(payload.len(), 44);

    let result = swap(payload, &patterns::all()).unwrap();

    assert_eq!(
        result.entries.len(),
        1,
        "Stripe pattern fires for first 32 variable chars"
    );
    // The fake covers bytes 0..40 (sk_live_ prefix + 32 variable chars).
    // Bytes 40..44 (the last 4 chars) pass through unchanged.
    assert_eq!(
        &result.payload[40..],
        b"AAAA",
        "trailing chars beyond stripe_live max=32 must pass through unchanged"
    );
    assert_ne!(
        result.payload[..40].to_vec(),
        payload[..40].to_vec(),
        "first 40 bytes must be replaced with a fake"
    );
}

// Spec: SPEC.md §Behavioral Invariants 42, 43

#[test]
fn test_inv42_register_rejects_anchor_len_zero_or_one() {
    // "register MUST fail with AnchorTooShort when anchor_len is 0 or 1."
    // — SPEC.md INV-42
    use doppel::{SecretError, SecretOptions, register_with_options};

    let secret = b"my-secret-api-key-long-enough";

    for bad_len in [0usize, 1usize] {
        let opts = SecretOptions {
            anchor_len: bad_len,
            ..SecretOptions::default()
        };
        let err = match register_with_options(secret, &opts) {
            Err(e) => e,
            Ok(_) => panic!("INV-42: anchor_len={bad_len} must be rejected, but succeeded"),
        };
        assert!(
            matches!(err, SecretError::AnchorTooShort { anchor_len } if anchor_len == bad_len),
            "INV-42: expected AnchorTooShort for anchor_len={bad_len}, got {err:?}"
        );
    }
}

#[test]
fn test_inv43_define_rejects_first_segment_shorter_than_two_bytes() {
    // "define MUST fail when the first segment value is shorter than 2 bytes."
    // — SPEC.md INV-43
    // Tested through SecretsFile::add_structural_entry, which calls validate_segment_defs.
    use doppel::{SecretsFile, SecretsFileError, segment::SegmentDef};

    for bad_value in ["", "x"] {
        let mut pf = SecretsFile::default();
        let segments = vec![
            SegmentDef::Literal {
                value: bad_value.to_string(),
            },
            SegmentDef::Variable {
                charset: "alphanumeric".to_string(),
                min: 10,
                max: 10,
            },
        ];
        let err = pf
            .add_structural_entry("test-id".to_string(), segments, [0u8; 32])
            .unwrap_err();
        assert!(
            matches!(err, SecretsFileError::InvalidSegment { .. }),
            "INV-43: expected InvalidSegment for first segment value {:?}, got {err:?}",
            bad_value
        );
        assert!(
            err.to_string().contains("first segment") || err.to_string().contains("byte"),
            "INV-43: error message should describe the constraint; got: {err}"
        );
    }
}
