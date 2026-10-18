// Spec: SPEC.md §Registration, INV-52, VC-29
//
// Every secret here is synthetic (SYNTH*); none is a real credential.

use doppel::{SecretError, SecretOptions, register_with_options, swap};

/// All option combinations of restrict-charset × force must reject the same
/// out-of-charset variable portion with `UnsupportedSecretBytes`.
fn assert_rejected(secret: &[u8], anchor_len: usize, expected_offset: usize) {
    for restrict_charset in [false, true] {
        for force in [false, true] {
            let opts = SecretOptions {
                anchor_len,
                restrict_charset,
                force,
                ..SecretOptions::default()
            };
            match register_with_options(secret, &opts) {
                Err(SecretError::UnsupportedSecretBytes { offset }) => {
                    assert_eq!(
                        offset, expected_offset,
                        "offset must point at the first offending byte (restrict={restrict_charset} force={force})"
                    );
                }
                Err(other) => panic!(
                    "expected UnsupportedSecretBytes at offset {expected_offset} (restrict={restrict_charset} force={force}), got {other:?}"
                ),
                Ok(_) => panic!(
                    "expected UnsupportedSecretBytes at offset {expected_offset} (restrict={restrict_charset} force={force}), got Ok"
                ),
            }
        }
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// INV-52: the error must not carry the secret. Single digits from the offset
/// number may coincide with a secret digit, so the value-level check is that the
/// full secret and every 4-byte window of it are absent from both representations.
fn assert_no_secret_leak(display: &str, debug: &str, secret: &[u8]) {
    for msg in [display.as_bytes(), debug.as_bytes()] {
        assert!(
            !contains_subslice(msg, secret),
            "error message must not contain the secret"
        );
        if secret.len() >= 4 {
            for window in secret.windows(4) {
                assert!(
                    !contains_subslice(msg, window),
                    "error message must not contain a run of secret bytes"
                );
            }
        }
    }
}

#[test]
fn test_inv52_space_in_variable_portion_rejected() {
    // The exact D-4 reproducer: variable portion `THETIC secret value ...` holds a space.
    let secret = b"SYNTHETIC secret value 9f8e7d6c5b4a";
    assert_rejected(secret, 3, 9);
}

#[test]
fn test_inv52_newline_in_variable_portion_rejected() {
    let secret = b"SYNTHxq9Zt7Lm2Pw4Rv8KsAbCd\n";
    assert_rejected(secret, 3, secret.len() - 1);
}

#[test]
fn test_inv52_double_quote_in_variable_portion_rejected() {
    let secret = b"SYNTHxq9Zt7Lm2Pw\"4Rv8KsAbCd";
    assert_rejected(secret, 3, 16);
}

#[test]
fn test_inv52_backslash_in_variable_portion_rejected() {
    let secret = b"SYNTHxq9Zt7Lm2Pw4\\Rv8KsAbCd";
    assert_rejected(secret, 3, 17);
}

#[test]
fn test_inv52_nul_in_variable_portion_rejected() {
    let secret = b"SYNTHxq9Zt7Lm2Pw\x004Rv8KsAbCd";
    assert_rejected(secret, 3, 16);
}

#[test]
fn test_inv52_non_ascii_in_variable_portion_rejected() {
    let secret = b"SYNTHxq9Zt7Lm2Pw\xC3\xA9Rv8KsAbCd";
    assert_rejected(secret, 3, 16);
}

#[test]
fn test_inv52_error_contains_no_secret_bytes() {
    let secret = b"SYNTHxq9Zt7Lm2Pw 4Rv8KsAbCd";
    let opts = SecretOptions::default();
    let err = match register_with_options(secret, &opts) {
        Err(e) => e,
        Ok(_) => panic!("expected UnsupportedSecretBytes, got Ok"),
    };
    assert_no_secret_leak(&err.to_string(), &format!("{err:?}"), secret);
}

#[test]
fn test_inv52_offending_bytes_in_leading_anchor_register_ok() {
    // Anchor bytes are matched exactly by an opaque segment, so they are exempt:
    // space, newline, double quote and backslash live only in the leading anchor.
    let secret = b" \n\"\\SYNTHETICmiddlevalueQ9z7Lm2Pw4Rv8Ks";
    let opts = SecretOptions {
        anchor_len: 4,
        force: true,
        ..SecretOptions::default()
    };
    assert!(
        register_with_options(secret, &opts).is_ok(),
        "INV-52: out-of-charset bytes in the leading anchor must register successfully"
    );
}

#[test]
fn test_inv52_offending_bytes_in_tail_anchor_register_ok() {
    // NUL and a non-ASCII byte live only in the trailing anchor.
    let secret = b"SYNTHETICmiddlevalueQ9z7Lm2Pw4Rv8Ks\x00\x80";
    let opts = SecretOptions {
        anchor_len: 3,
        tail_anchor_len: 2,
        force: true,
        ..SecretOptions::default()
    };
    assert!(
        register_with_options(secret, &opts).is_ok(),
        "INV-52: out-of-charset bytes in the trailing anchor must register successfully"
    );
}

#[test]
fn test_vc29_registered_secret_is_detected_when_delimited() {
    // VC-29: a secret that registers successfully is replaced by swap when it
    // appears delimited by bytes outside every charset (here NUL).
    let secret = b" \n\"\\SYNTHETICmiddlevalueQ9z7Lm2Pw4Rv8Ks";
    let opts = SecretOptions {
        anchor_len: 4,
        ..SecretOptions::default()
    };
    let pattern = register_with_options(secret, &opts).expect("registration must succeed");

    let mut payload = vec![0x00u8];
    payload.extend_from_slice(secret);
    payload.push(0x00);

    let result = swap(&payload, std::slice::from_ref(&pattern)).expect("swap must succeed");
    assert_eq!(
        result.entries.len(),
        1,
        "VC-29: a successfully registered secret must be self-detected when delimited"
    );
    assert_eq!(result.payload.len(), payload.len());
}
