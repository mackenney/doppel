// P-REG: registration error classification, no-panic, self-detection, and
// HMAC near-miss rejection. Registration draws its salt from OsRng
// (`doppel/src/secrets.rs`), so these properties assert only salt-independent
// outcomes: the error class, self-detection, and near-miss pass-through. Never
// read the session key, nonce, or ciphertext, and never assert on the random
// fake beyond the structural facts the step lists.

use crate::generators::FILLER;
use crate::oracle::Cs;
use doppel::{SecretError, SecretOptions};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// The registration error conditions the independent oracle models. Error
/// precedence is unspecified by SPEC.md, so the oracle computes the *set* of
/// applicable conditions and the property checks membership only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    AnchorTooShort,
    TooShort,
    ZeroGuard,
    GuardCharsetWithoutGuard,
    UnknownGuardCharset,
    NoVariableBytes,
    UnsupportedSecretBytes,
    InsufficientEntropy,
}

/// Charsets `detect_charset_name` can return, in the order it probes them
/// (ascending cardinality). `base64_any` is deliberately absent: detection
/// never yields it (note A-4).
const DETECTED_CS: [Cs; 5] = [
    Cs::Digits,
    Cs::HexLower,
    Cs::UppercaseAlphanumeric,
    Cs::Alphanumeric,
    Cs::UrlSafeBase64,
];

/// Charsets the self-detection and near-miss properties may choose as the
/// effective (detected) charset on the restrict path.
const EFFECTIVE_CS: [Cs; 6] = [
    Cs::Wide,
    Cs::Alphanumeric,
    Cs::UrlSafeBase64,
    Cs::UppercaseAlphanumeric,
    Cs::HexLower,
    Cs::Digits,
];

fn known_charset_names() -> Vec<String> {
    crate::oracle::ALL_CS
        .iter()
        .map(|cs| cs.name().to_string())
        .collect()
}

/// Independent model of the effective variable charset (SPEC §Registration): the
/// smallest detectable charset that contains every middle byte on the restrict path,
/// else `Wide`, matching production's `detect_charset_name` fallback.
fn effective_charset(middle: &[u8], restrict: bool) -> Cs {
    if restrict {
        for cs in DETECTED_CS {
            if middle.iter().all(|&b| cs.contains(b)) {
                return cs;
            }
        }
    }
    Cs::Wide
}

/// The middle (variable) portion for these options, clamped the way production
/// clamps `tail_anchor_len`. `None` when the anchors consume the whole secret.
fn middle_portion<'a>(secret: &'a [u8], opts: &SecretOptions) -> Option<&'a [u8]> {
    let anchor_len = opts.anchor_len;
    if anchor_len < 2 || secret.len() < anchor_len {
        return None;
    }
    let tail = opts.tail_anchor_len.min(secret.len() - anchor_len);
    let middle_len = secret.len() - anchor_len - tail;
    if middle_len == 0 {
        return None;
    }
    Some(&secret[anchor_len..secret.len() - tail])
}

/// INV-52: true when some middle byte is outside the effective variable charset
/// and registration should therefore reject with `UnsupportedSecretBytes`.
fn middle_has_unsupported_byte(secret: &[u8], opts: &SecretOptions) -> bool {
    match middle_portion(secret, opts) {
        None => false,
        Some(middle) => {
            let cs = effective_charset(middle, opts.restrict_charset);
            middle.iter().any(|&b| !cs.contains(b))
        }
    }
}

/// The set of `Kind`s whose conditions hold for this input. Mirrors the
/// registration preconditions independently; it does not call production.
fn applicable_errors(secret: &[u8], opts: &SecretOptions) -> Vec<Kind> {
    let mut kinds = Vec::new();
    let anchor_len = opts.anchor_len;

    if anchor_len < 2 {
        kinds.push(Kind::AnchorTooShort);
    }
    if secret.is_empty() || secret.len() < anchor_len {
        kinds.push(Kind::TooShort);
    }
    if opts.trailing_run_guard == Some(0) {
        kinds.push(Kind::ZeroGuard);
    }
    if opts.trailing_run_guard_charset.is_some() && opts.trailing_run_guard.is_none() {
        kinds.push(Kind::GuardCharsetWithoutGuard);
    }
    if let Some(name) = &opts.trailing_run_guard_charset {
        if !known_charset_names().contains(name) {
            kinds.push(Kind::UnknownGuardCharset);
        }
    }
    if secret.len() >= anchor_len {
        let tail = opts.tail_anchor_len.min(secret.len() - anchor_len);
        let middle_len = secret.len() - anchor_len - tail;
        if middle_len == 0 {
            kinds.push(Kind::NoVariableBytes);
        } else {
            let middle = &secret[anchor_len..secret.len() - tail];
            let cs = effective_charset(middle, opts.restrict_charset);
            if middle.iter().any(|&b| !cs.contains(b)) {
                kinds.push(Kind::UnsupportedSecretBytes);
            }
            if !opts.force && crate::oracle::entropy_bits(middle_len, cs.bytes().len()) < 83.0 {
                kinds.push(Kind::InsufficientEntropy);
            }
        }
    }
    kinds
}

/// Maps a production error to its oracle `Kind`. Exhaustive over the current
/// `SecretError` variants plus a final `_` arm (the enum is
/// `#[non_exhaustive]`); both remaining cases fail the property.
fn classify(err: &SecretError) -> Result<Kind, String> {
    match err {
        SecretError::TooShort => Ok(Kind::TooShort),
        SecretError::AnchorTooShort { .. } => Ok(Kind::AnchorTooShort),
        SecretError::NoVariableBytes { .. } => Ok(Kind::NoVariableBytes),
        SecretError::UnsupportedSecretBytes { .. } => Ok(Kind::UnsupportedSecretBytes),
        SecretError::ZeroTrailingRunGuard => Ok(Kind::ZeroGuard),
        SecretError::GuardCharsetWithoutGuard => Ok(Kind::GuardCharsetWithoutGuard),
        SecretError::UnknownGuardCharset { .. } => Ok(Kind::UnknownGuardCharset),
        SecretError::InsufficientEntropy { .. } => Ok(Kind::InsufficientEntropy),
        SecretError::CollisionLimit { .. } => {
            Err("CollisionLimit is a finding: registration exhausted fake derivation".to_string())
        }
        other => Err(format!("unhandled SecretError variant: {other:?}")),
    }
}

#[derive(Debug)]
struct RegCase {
    secret: Vec<u8>,
    opts: SecretOptions,
}

fn guard_strategy() -> impl Strategy<Value = Option<usize>> {
    prop_oneof![
        2 => Just(None),
        1 => Just(Some(0usize)),
        4 => (1usize..=64).prop_map(Some),
        1 => Just(Some(25_000usize)),
    ]
}

fn guard_cs_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        3 => Just(None),
        5 => prop::sample::select(known_charset_names()).prop_map(Some),
        1 => Just(Some("bogus".to_string())),
    ]
}

/// A secret whose length sits on the entropy edge: `anchor_len + {12,13}` bytes
/// from `Wide` (floor 13) or `anchor_len + {24,25}` bytes from `Digits`
/// (floor 25), so the `entropy_bits < 83.0` boundary is exercised.
fn boundary_secret(anchor_len: usize) -> BoxedStrategy<Vec<u8>> {
    let choice = prop_oneof![
        (Just(Cs::Wide), prop::sample::select(vec![12usize, 13])),
        (Just(Cs::Digits), prop::sample::select(vec![24usize, 25])),
    ];
    choice
        .prop_flat_map(move |(cs, middle)| {
            let total = anchor_len + middle;
            prop::collection::vec(prop::sample::select(cs.bytes()), total..=total)
        })
        .boxed()
}

/// Prop 1's fixture: random or boundary-biased bytes plus independently drawn
/// options. This is an exempt registration-boundary fixture: it never swaps, so
/// the generated-pattern fake-capacity floor does not apply.
fn reg_case() -> BoxedStrategy<RegCase> {
    (
        0usize..=6,
        0usize..=6,
        any::<bool>(),
        any::<bool>(),
        guard_strategy(),
        guard_cs_strategy(),
    )
        .prop_flat_map(|(anchor_len, tail, restrict, force, guard, guard_cs)| {
            let secret = prop_oneof![
                1 => prop::collection::vec(any::<u8>(), 0..=48),
                1 => boundary_secret(anchor_len),
            ];
            secret.prop_map(move |mut bytes| {
                if restrict {
                    // A-4: restrict-charset detection never yields base64_any, so
                    // `+ / =` make the entropy oracle's charset ambiguous. Map them
                    // to a wide-safe byte so the detected charset is unambiguous.
                    for b in bytes.iter_mut() {
                        if matches!(*b, b'+' | b'/' | b'=') {
                            *b = b'A';
                        }
                    }
                }
                RegCase {
                    secret: bytes,
                    opts: SecretOptions {
                        anchor_len,
                        tail_anchor_len: tail,
                        restrict_charset: restrict,
                        force,
                        trailing_run_guard: guard,
                        trailing_run_guard_charset: guard_cs.clone(),
                    },
                }
            })
        })
        .boxed()
}

proptest! {
    #![proptest_config(crate::support::config(256))]

    #[test]
    fn prop_registration_never_panics_and_errors_are_applicable(case in reg_case()) {
        let RegCase { secret, opts } = case;
        let applicable = applicable_errors(&secret, &opts);

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            doppel::register_with_options(&secret, &opts)
        }));

        match outcome {
            Err(_) => {
                prop_assert!(
                    false,
                    "registration panicked for secret={:?} opts={:?}",
                    secret,
                    opts
                );
            }
            Ok(Ok(_pattern)) => {
                prop_assert!(
                    applicable.is_empty(),
                    "registration returned Ok but applicable errors are {:?} for secret={:?} opts={:?}",
                    applicable,
                    secret,
                    opts
                );
            }
            Ok(Err(err)) => {
                let kind = classify(&err).map_err(TestCaseError::fail)?;
                prop_assert!(
                    applicable.contains(&kind),
                    "registration returned {:?}, which is not applicable: applicable={:?} secret={:?} opts={:?}",
                    kind,
                    applicable,
                    secret,
                    opts
                );
            }
        }
    }
}

/// A registered secret whose variable (middle) portion is detected to a chosen
/// charset. D-4 is now rejected by registration (INV-52), so these fixtures draw
/// every middle byte from `effective_cs` and pin detection with a distinguishing
/// byte to exercise the success path: registration accepts them and their Pattern
/// self-detects its own secret. The middle length is at least
/// `floor_len(effective_cs)` so the fake capacity also meets the 83-bit floor
/// (D5 = A) on the restrict path too.
#[derive(Clone, Debug)]
struct WideRegCase {
    secret: Vec<u8>,
    opts: SecretOptions,
    effective_cs: Cs,
    anchor_len: usize,
    middle_len: usize,
}

/// A byte in `cs` that is in none of the smaller detectable charsets, so
/// production's `detect_charset_name` must resolve a middle containing it to
/// exactly `cs`.
fn distinguishing_byte(cs: Cs) -> u8 {
    match cs {
        Cs::Digits => b'5',
        Cs::HexLower => b'f',
        Cs::UppercaseAlphanumeric => b'G',
        Cs::Alphanumeric => b'g',
        Cs::UrlSafeBase64 => b'-',
        Cs::Wide => b'!',
        // Not a detectable charset; never selected by `wide_reg_case`.
        Cs::Base64Any => b'!',
    }
}

fn wide_reg_case() -> BoxedStrategy<WideRegCase> {
    (
        2usize..=5,
        0usize..=3,
        any::<bool>(),
        prop::sample::select(EFFECTIVE_CS.to_vec()),
    )
        .prop_flat_map(|(anchor_len, tail, restrict, chosen)| {
            let effective_cs = if restrict { chosen } else { Cs::Wide };
            let min_middle = crate::generators::floor_len(effective_cs).max(14);
            (min_middle..=40).prop_flat_map(move |middle_len| {
                let total = anchor_len + middle_len + tail;
                prop::collection::vec(prop::sample::select(effective_cs.bytes()), total..=total)
                    .prop_map(move |mut bytes| {
                        bytes[anchor_len] = distinguishing_byte(effective_cs);
                        WideRegCase {
                            secret: bytes,
                            opts: SecretOptions {
                                anchor_len,
                                tail_anchor_len: tail,
                                restrict_charset: restrict,
                                force: true,
                                ..SecretOptions::default()
                            },
                            effective_cs,
                            anchor_len,
                            middle_len,
                        }
                    })
            })
        })
        .boxed()
}

/// Prop 3's fixture: a `WideRegCase` plus a payload carrying one middle byte
/// mutated to a *different* byte of the same effective charset.
fn wide_mutation() -> BoxedStrategy<(WideRegCase, Vec<u8>)> {
    wide_reg_case()
        .prop_flat_map(|case| {
            let anchor_len = case.anchor_len;
            let middle_len = case.middle_len;
            let cs = case.effective_cs;
            let secret = case.secret.clone();
            let base_case = case.clone();
            (0..middle_len).prop_flat_map(move |idx| {
                let current = secret[anchor_len + idx];
                let choices: Vec<u8> = cs.bytes().into_iter().filter(|&b| b != current).collect();
                let secret = secret.clone();
                let base_case = base_case.clone();
                prop::sample::select(choices).prop_map(move |new_byte| {
                    let mut mutated = secret.clone();
                    mutated[anchor_len + idx] = new_byte;
                    let mut payload = Vec::with_capacity(mutated.len() + 2);
                    payload.push(b' ');
                    payload.extend_from_slice(&mutated);
                    payload.push(b'\n');
                    (base_case.clone(), payload)
                })
            })
        })
        .boxed()
}

/// Prop 4's fixture: arbitrary secret bytes (including bytes outside every
/// charset) with `force: true` and valid anchors. INV-52 fixes the outcome
/// exactly: `Ok` iff no middle byte lies outside the effective variable charset.
fn arbitrary_bytes_case() -> BoxedStrategy<(Vec<u8>, SecretOptions)> {
    (2usize..=4, 0usize..=3, 1usize..=16, any::<bool>())
        .prop_flat_map(|(anchor_len, tail, middle_len, restrict)| {
            let total = anchor_len + middle_len + tail;
            prop::collection::vec(any::<u8>(), total..=total).prop_map(move |bytes| {
                (
                    bytes,
                    SecretOptions {
                        anchor_len,
                        tail_anchor_len: tail,
                        restrict_charset: restrict,
                        force: true,
                        ..SecretOptions::default()
                    },
                )
            })
        })
        .boxed()
}

proptest! {
    #![proptest_config(crate::support::config(64))]

    #[test]
    fn prop_registered_wide_secret_is_self_detected(case in wide_reg_case()) {
        let WideRegCase { secret, opts, anchor_len, .. } = case;
        let pattern = doppel::register_with_options(&secret, &opts)
            .expect("constructed registration must succeed");

        let mut payload = Vec::with_capacity(secret.len() + 2);
        payload.push(b' ');
        payload.extend_from_slice(&secret);
        payload.push(b'\n');

        let result = doppel::swap(&payload, std::slice::from_ref(&pattern))
            .expect("swap must succeed");

        prop_assert_eq!(
            result.entries.len(),
            1,
            "registered secret must produce exactly one entry"
        );
        prop_assert_eq!(result.payload.len(), payload.len());
        prop_assert_eq!(result.payload[0], b' ');
        prop_assert_eq!(result.payload[payload.len() - 1], b'\n');

        let fake = &result.payload[1..1 + secret.len()];
        prop_assert_ne!(fake, secret.as_slice(), "fake must differ from the secret");
        prop_assert_ne!(
            &fake[..anchor_len],
            &secret[..anchor_len],
            "INV-28: the anchor opaque bytes must not reappear verbatim"
        );
    }

    #[test]
    fn prop_one_byte_mutation_of_registered_secret_passes_through(
        (case, payload) in wide_mutation()
    ) {
        let pattern = doppel::register_with_options(&case.secret, &case.opts)
            .expect("constructed registration must succeed");
        let result = doppel::swap(&payload, std::slice::from_ref(&pattern))
            .expect("swap must succeed");

        prop_assert_eq!(
            result.entries.len(),
            0,
            "INV-16/VC-11: an HMAC near-miss must produce no entry"
        );
        prop_assert_eq!(
            result.payload,
            payload,
            "INV-16: an HMAC near-miss passes through unchanged"
        );
    }
}

proptest! {
    #![proptest_config(crate::support::config(256))]

    #[test]
    fn prop_ok_registration_is_self_detected((secret, opts) in arbitrary_bytes_case()) {
        let unsupported = middle_has_unsupported_byte(&secret, &opts);
        match doppel::register_with_options(&secret, &opts) {
            Ok(pattern) => {
                prop_assert!(
                    !unsupported,
                    "INV-52: registration accepted a middle byte outside the effective charset; secret={:?} opts={:?}",
                    secret,
                    opts
                );
                let mut payload = Vec::with_capacity(secret.len() + 2);
                payload.push(FILLER[0]);
                payload.extend_from_slice(&secret);
                payload.push(FILLER[1]);
                let result = doppel::swap(&payload, std::slice::from_ref(&pattern))
                    .expect("swap must succeed");
                prop_assert_eq!(
                    result.entries.len(),
                    1,
                    "VC-29: a registered secret must be self-detected when delimited; secret={:?} opts={:?}",
                    secret,
                    opts
                );
                prop_assert_eq!(result.payload.len(), payload.len());
            }
            Err(err) => {
                let kind = classify(&err).map_err(TestCaseError::fail)?;
                prop_assert!(
                    unsupported && kind == Kind::UnsupportedSecretBytes,
                    "unexpected registration error {:?} for secret={:?} opts={:?} (oracle out-of-charset={})",
                    kind,
                    secret,
                    opts,
                    unsupported
                );
            }
        }
    }
}
