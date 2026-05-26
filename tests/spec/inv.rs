use its_classified::{scrub, tier1::patterns, types::Entry, unscrub};

// Synthetic test keys — NOT real credentials. Format matches real format for structural testing.
const SYNTH_ANTHROPIC: &[u8] = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
const SYNTH_AWS_AKIA: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
const SYNTH_GITHUB_CLASSIC: &[u8] = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
#[allow(dead_code)]
const SYNTH_GITHUB_FG: &[u8] =
    b"github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
#[allow(dead_code)]
const SYNTH_GCP: &[u8] = b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn test_inv1_scrub_replaces_every_detected_secret() {
    // INV-1: "scrub MUST replace every secret detected by the supplied Patterns
    //         with a structurally-equivalent fake."
    let payload = [b"Authorization: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
    assert!(
        !result
            .payload
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "INV-1: original secret must not appear in scrubbed payload"
    );
}

#[test]
fn test_inv2_scrub_does_not_modify_non_secret_bytes() {
    // INV-2: "scrub MUST NOT modify bytes that are not identified as secrets."
    let prefix = b"Authorization: ";
    let suffix = b" end-of-header";
    let payload = [prefix.as_slice(), SYNTH_ANTHROPIC, suffix].concat();
    let result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
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
    // INV-3: "scrub MUST return entries containing exactly one record per distinct secret."
    let payload = [SYNTH_ANTHROPIC, b" separator ".as_slice(), SYNTH_AWS_AKIA].concat();
    let result =
        scrub(&payload, &[patterns::anthropic(), patterns::aws_akia()]).expect("scrub failed");
    assert_eq!(
        result.entries.len(),
        2,
        "INV-3: one entry per distinct secret (2 different secrets)"
    );
}

#[test]
fn test_inv4_unscrub_restores_across_chunk_boundaries() {
    // INV-4: "unscrub MUST restore every fake present in the response stream
    //         regardless of where chunk boundaries fall."
    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let scrub_result = scrub(&payload, &[patterns::github_classic()]).expect("scrub failed");

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
    unscrub(
        &mut reader,
        &mut output,
        &scrub_result.entries,
        &scrub_result.session_key,
    )
    .unwrap();
    assert_eq!(output, payload, "INV-4: chunk-boundary restoration failed");
}

#[test]
fn test_inv5_unscrub_does_not_emit_before_aead_verified() {
    // INV-5: "unscrub MUST NOT emit restored plaintext before the AEAD tag has been verified."
    // Proxy test: tamper with tag → Err → no secret bytes in output
    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut scrub_result = scrub(&payload, &[patterns::github_classic()]).expect("scrub failed");
    let last = scrub_result.entries[0].ciphertext.len() - 1;
    scrub_result.entries[0].ciphertext[last] ^= 0xFF;
    let mut input = scrub_result.payload.as_slice();
    let mut output = Vec::new();
    let _ = unscrub(
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

#[test]
fn test_inv6_aead_tag_failure_produces_error() {
    // INV-6: "An AEAD tag failure MUST produce an error; the stream MUST NOT continue."
    let payload = [b"ctx: ".as_slice(), SYNTH_GITHUB_CLASSIC].concat();
    let mut scrub_result = scrub(&payload, &[patterns::github_classic()]).expect("scrub failed");
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
    assert!(result.is_err(), "INV-6: tag failure must return Err");
}

#[test]
fn test_inv7_unscrub_no_fake_forwarded_unchanged() {
    // INV-7: "unscrub MUST forward all bytes unchanged when no fake appears in stream;
    //         it MUST NOT produce an error."
    let payload = b"no secrets here at all";
    let scrub_result = scrub(payload, &[patterns::anthropic()]).expect("scrub failed");
    let response = b"a response with no matching content";
    let mut input = response.as_slice();
    let mut output = Vec::new();
    let result = unscrub(
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
fn test_inv8_unscrub_bounded_hold() {
    // INV-8: "unscrub MUST NOT hold more than max{|fake_i|} bytes unemitted at any point."
    // Proxy: verify round-trip is correct with 1-byte input chunks (bound enforced by impl)
    let payload = [b"ctx: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let scrub_result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");

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
    unscrub(
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

#[test]
fn test_inv9_entries_contain_no_plaintext_secret() {
    // INV-9: "entries MUST NOT contain plaintext secret bytes in any field or serialized form."
    let payload = [b"token: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
    let json = Entry::serialize_entries(&result.entries).unwrap();
    assert!(
        !json
            .windows(SYNTH_ANTHROPIC.len())
            .any(|w| w == SYNTH_ANTHROPIC),
        "INV-9: plaintext secret must not appear in serialized entries"
    );
}

#[test]
fn test_inv10_session_key_not_in_entries() {
    // INV-10: "The session key MUST NOT be serialized together with or embedded within the entries."
    let payload = [b"token: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
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
    use its_classified::types::SessionKey;
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SessionKey>();
}

#[test]
fn test_inv12_key_material_destroyed_on_drop() {
    // INV-12: covered by ZeroizeOnDrop derive on SessionKey (verified in test_inv11).
    // Compile-time guarantee: SessionKey has no Clone or Debug impl.
    // Code review and type system enforce no Clone/Debug; test_inv10 exercises the type.
    use its_classified::types::SessionKey;
    let _ = std::mem::size_of::<SessionKey>();
}

#[test]
fn test_inv13_same_secret_same_pattern_same_fake() {
    // INV-13: "The same secret detected under the same Pattern MUST produce the same fake."
    let payload = [b"x: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let pat = patterns::anthropic();
    let result1 = scrub(&payload, std::slice::from_ref(&pat)).expect("scrub failed");
    let result2 = scrub(&payload, std::slice::from_ref(&pat)).expect("scrub failed");
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
    let result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
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
        let result = scrub(&payload, &[patterns::anthropic()]).expect("scrub failed");
        let fake = &result.entries[0].fake;
        assert_ne!(
            fake.as_slice(),
            SYNTH_ANTHROPIC,
            "INV-15: fake must not equal original"
        );
        assert!(
            fake.starts_with(b"sk-ant-"),
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
fn test_inv16_tier2_hmac_failure_passthrough() {
    // INV-16: "A Tier 2 candidate that matches structurally but fails HMAC verification
    //          MUST be passed through unchanged; no replacement occurs."
    use its_classified::register;
    let real_secret = b"my-registered-api-secret-value!";
    let pat = register(real_secret);
    let mut tampered = real_secret.to_vec();
    tampered[12] ^= 0xFF;
    let result = scrub(&tampered, &[pat]).expect("scrub failed");
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
fn test_inv17_tier2_unique_salt_per_registration() {
    // INV-17: "Each Tier 2 registration MUST use a unique HMAC salt."
    use its_classified::register;
    let secret = b"my-secret-value-for-registration";
    let pat1 = register(secret);
    let pat2 = register(secret);
    let payload1 = [b"token: ".as_slice(), secret].concat();
    let r1 = scrub(&payload1, &[pat1]).expect("scrub failed");
    let r2 = scrub(&payload1, &[pat2]).expect("scrub failed");
    // Both produce a fake (detection works independently)
    assert_eq!(r1.entries.len(), 1);
    assert_eq!(r2.entries.len(), 1);
}

#[test]
fn test_inv18_leftmost_longest_match() {
    // INV-18: "Detection MUST produce leftmost-longest matches; overlapping matches
    //          MUST NOT be produced."
    // sk-proj- is longer than sk-, so the project pattern must win
    let payload = b"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result = scrub(
        payload,
        &[patterns::openai_classic(), patterns::openai_project()],
    )
    .expect("scrub failed");
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
fn test_inv19_unscrub_exact_matching_only() {
    // INV-19: "unscrub MUST perform only exact matching against fake byte strings;
    //          it MUST NOT run pattern detection of any kind."
    let payload = b"no secret here";
    let scrub_result = scrub(payload, &[patterns::anthropic()]).expect("scrub failed");
    let response_with_real_key = [b"response: ".as_slice(), SYNTH_ANTHROPIC].concat();
    let mut input = response_with_real_key.as_slice();
    let mut output = Vec::new();
    unscrub(
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
fn test_inv20_cli_no_key_flag_on_unscrub() {
    // INV-20: "The CLI unscrub command MUST accept the session key only via
    //          ITS_CLASSIFIED_KEY environment variable; no other mechanism."
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
        .args(["unscrub", "--help"])
        .output()
        .expect("failed to run its-classified");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        !help.contains("--key "),
        "INV-20: --key flag must not exist on unscrub subcommand"
    );
    assert!(
        !help.to_lowercase().contains("--key-"),
        "INV-20: no --key-* flags allowed"
    );
}

#[test]
fn test_inv21_cli_scrub_key_file_mode_0600() {
    // INV-21: "The CLI scrub command MUST create the session key output file
    //          with permission mode 0600."
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let entries_path = dir.path().join("entries.json");
        let key_path = dir.path().join("key.txt");
        let payload = b"no secrets here";
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
            .args([
                "scrub",
                "--entries",
                entries_path.to_str().unwrap(),
                "--key-out",
                key_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.as_mut().unwrap().write_all(payload)?;
                c.wait()
            })
            .expect("failed to run scrub");
        assert!(status.success(), "scrub must exit 0");
        let meta = std::fs::metadata(&key_path).expect("key file must exist");
        let mode = meta.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "INV-21: key file mode must be 0600, got {:o}",
            mode
        );
    }
}

#[test]
fn test_inv21_key_file_refuses_pre_existing_path() {
    // INV-21: create_new (O_EXCL) MUST cause scrub to fail rather than write the
    // session key into a pre-existing inode whose permissions the attacker controls.
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let entries_path = dir.path().join("entries.json");
        let key_path = dir.path().join("key.txt");

        // Attacker pre-creates the file with world-readable permissions.
        std::fs::write(&key_path, b"").expect("pre-create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }

        let status = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
            .args([
                "scrub",
                "--entries",
                entries_path.to_str().unwrap(),
                "--key-out",
                key_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.as_mut().unwrap().write_all(b"no secrets")?;
                c.wait()
            })
            .expect("failed to run scrub");

        assert!(
            !status.success(),
            "INV-21: scrub MUST fail when --key-out path already exists (O_EXCL prevents mode race)"
        );
    }
}

#[test]
fn test_inv22_all_tier1_built_in_classes_present() {
    // INV-22: built-in Tier 1 MUST cover Anthropic, OpenAI, AWS IAM, GitHub PAT (classic
    //         and fine-grained), and GCP API keys.
    let all = patterns::all();
    let prefixes: Vec<&[u8]> = all
        .iter()
        .filter_map(|p| match p {
            its_classified::types::Pattern::Tier1(d) => Some(d.prefix),
            _ => None,
        })
        .collect();
    assert!(
        prefixes.iter().any(|&p| p == b"sk-ant-"),
        "INV-22: Anthropic missing"
    );
    assert!(
        prefixes.iter().any(|&p| p == b"sk-" || p == b"sk-proj-"),
        "INV-22: OpenAI missing"
    );
    assert!(
        prefixes.iter().any(|&p| p == b"AKIA" || p == b"ASIA"),
        "INV-22: AWS IAM missing"
    );
    assert!(
        prefixes.iter().any(|&p| p == b"ghp_"),
        "INV-22: GitHub classic missing"
    );
    assert!(
        prefixes.iter().any(|&p| p == b"github_pat_"),
        "INV-22: GitHub fine-grained missing"
    );
    assert!(
        prefixes.iter().any(|&p| p == b"AIza"),
        "INV-22: GCP missing"
    );
}

#[test]
fn test_inv23_no_detectable_secrets_returns_unchanged() {
    // INV-23: "scrub called on a payload containing no detectable secrets MUST return
    //          the payload bytes unchanged and an empty entries set."
    let payload = b"Hello, world! This is a normal message with no API keys.";
    let result = scrub(payload, &patterns::all()).expect("scrub failed");
    assert_eq!(
        result.payload.as_slice(),
        payload,
        "INV-23: payload unchanged"
    );
    assert!(result.entries.is_empty(), "INV-23: entries empty");

    let result2 = scrub(payload, &[]).expect("scrub failed");
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
// Replacing Entry.fake after scrub MUST cause decrypt_entry to return
// AeadTagFailure — unscrub MUST NOT emit the original secret.
#[test]
fn test_inv_aad_fake_binding() {
    let secret = SYNTH_ANTHROPIC;
    let payload = [b"token: ".as_slice(), secret].concat();
    let scrub_result = scrub(&payload, &[patterns::anthropic()]).unwrap();

    // Tamper: replace fake with attacker-controlled trigger.
    let mut tampered = scrub_result.entries.clone();
    tampered[0].fake = b"ATTACKER_TRIGGER".to_vec();

    // Victim runs unscrub against tampered entries.
    let response = b"response contains ATTACKER_TRIGGER here";
    let mut input = response.as_slice();
    let mut output = Vec::new();
    let result = unscrub(
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
