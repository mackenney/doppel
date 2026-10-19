// P-REG-GRD: registration-time trailing run guard end to end (SPEC.md
// Verifiable Conditions 22, 23, 26, 28; Behavioral Invariants 49, 51).
// Registration draws its salt from OsRng, so only salt-independent outcomes
// are asserted: the declared guard, whether the secret was replaced, and the
// error class. Never read the session key, nonce, or ciphertext.

use crate::detection::check_swap_against_oracle;
use crate::generators::FILLER;
use crate::oracle::{ALL_CS, Cs, OPattern, Seg};
use doppel::segment::SegmentDef;
use doppel::{Pattern, PatternEntry, SecretError, SecretOptions, SecretsFile};
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::TestCaseError;

/// Charsets secret bytes are drawn from. All are subsets of `wide`, so the
/// secret registers with or without restrict-charset; `base64_any` is left out
/// because restrict-charset detection never yields it.
const SECRET_CS: [Cs; 6] = [
    Cs::Digits,
    Cs::HexLower,
    Cs::UppercaseAlphanumeric,
    Cs::Alphanumeric,
    Cs::UrlSafeBase64,
    Cs::Wide,
];

#[derive(Clone, Debug)]
struct GuardRegCase {
    secret: Vec<u8>,
    opts: SecretOptions,
    prefix: Vec<u8>,
    /// Draw the run from the effective guard charset (true) or from the
    /// variable segment charset (false); they differ under an explicit charset.
    run_from_guard_cs: bool,
    /// Run bytes as indices into the chosen alphabet, which is only known once
    /// registration has resolved the variable charset.
    run: Vec<Index>,
    eof: bool,
}

fn guard_reg_case() -> BoxedStrategy<GuardRegCase> {
    (
        2usize..=4,
        0usize..=2,
        any::<bool>(),
        prop::sample::select(SECRET_CS.to_vec()),
        25usize..=32,
        prop_oneof![1 => Just(None), 6 => (1usize..=48).prop_map(Some)],
        prop::option::of(prop::sample::select(ALL_CS.to_vec())),
        -2i32..=2,
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(prop::sample::select(FILLER.to_vec()), 0..=3),
    )
        .prop_flat_map(
            |(
                anchor_len,
                tail,
                restrict,
                secret_cs,
                middle_len,
                guard,
                guard_cs,
                delta,
                run_from_guard_cs,
                eof,
                prefix,
            )| {
                // A middle of >= 25 bytes meets the 83-bit floor even if
                // detection narrows it to digits; force covers the rest.
                let total = anchor_len + middle_len + tail;
                // Unguarded cases still get a trailing same-charset run, so
                // INV-48 (no guard, no suppression) is exercised too.
                let base = guard.unwrap_or(12) as i32;
                let run_len = (base + delta).max(0) as usize;
                let guard_cs_name = guard.and(guard_cs).map(|cs| cs.name().to_string());
                (
                    prop::collection::vec(prop::sample::select(secret_cs.bytes()), total..=total),
                    prop::collection::vec(any::<Index>(), run_len..=run_len),
                )
                    .prop_map(move |(secret, run)| GuardRegCase {
                        secret,
                        opts: SecretOptions {
                            anchor_len,
                            tail_anchor_len: tail,
                            restrict_charset: restrict,
                            force: true,
                            trailing_run_guard: guard,
                            trailing_run_guard_charset: guard_cs_name.clone(),
                        },
                        prefix: prefix.clone(),
                        run_from_guard_cs,
                        run,
                        eof,
                    })
            },
        )
        .boxed()
}

fn cs_named(name: &str) -> Result<Cs, TestCaseError> {
    ALL_CS
        .iter()
        .copied()
        .find(|cs| cs.name() == name)
        .ok_or_else(|| TestCaseError::fail(format!("unknown charset name {name:?}")))
}

fn seg_from_def(def: &SegmentDef) -> Result<Seg, TestCaseError> {
    Ok(match def {
        SegmentDef::Literal { value } => Seg::Lit(value.as_bytes().to_vec()),
        SegmentDef::Opaque { value, charset } => {
            let name = charset
                .as_deref()
                .ok_or_else(|| TestCaseError::fail("registered opaque segment has no charset"))?;
            Seg::Opq(value.as_bytes().to_vec(), cs_named(name)?)
        }
        SegmentDef::Variable { charset, min, max } => Seg::Var(cs_named(charset)?, *min, *max),
    })
}

struct Registered {
    pattern: Pattern,
    /// The patterns-file view: the only public window on the declared guard.
    entry: PatternEntry,
    oracle: OPattern,
    var_cs: Cs,
}

fn register_case(case: &GuardRegCase) -> Result<Registered, TestCaseError> {
    let pattern = doppel::register_with_options(&case.secret, &case.opts).map_err(|e| {
        TestCaseError::fail(format!("registration of a valid secret failed: {e:?}"))
    })?;
    let mut file = SecretsFile::new();
    file.add_secret_pattern("registered".to_string(), &pattern)
        .map_err(|e| TestCaseError::fail(format!("add_secret_pattern failed: {e:?}")))?;
    let entry = file
        .pattern
        .pop()
        .ok_or_else(|| TestCaseError::fail("add_secret_pattern added no entry"))?;
    let segs = entry
        .segments
        .iter()
        .map(seg_from_def)
        .collect::<Result<Vec<_>, _>>()?;
    let var_cs = segs
        .iter()
        .find_map(|s| match s {
            Seg::Var(cs, _, _) => Some(*cs),
            _ => None,
        })
        .ok_or_else(|| TestCaseError::fail("registered pattern has no variable segment"))?;
    let guard_cs = entry
        .trailing_run_guard_charset
        .as_deref()
        .map(cs_named)
        .transpose()?;
    let oracle = OPattern {
        segs,
        guard: entry.trailing_run_guard.map(|g| g as usize),
        guard_cs,
        accepted: Some(vec![case.secret.clone()]),
    };
    Ok(Registered {
        pattern,
        entry,
        oracle,
        var_cs,
    })
}

struct Planted {
    payload: Vec<u8>,
    start: usize,
    end: usize,
    run: Vec<u8>,
}

fn plant(case: &GuardRegCase, var_cs: Cs, guard_cs: Cs) -> Planted {
    let alphabet = if case.run_from_guard_cs {
        guard_cs.bytes()
    } else {
        var_cs.bytes()
    };
    let run: Vec<u8> = case
        .run
        .iter()
        .map(|i| alphabet[i.index(alphabet.len())])
        .collect();
    let mut payload = case.prefix.clone();
    let start = payload.len();
    payload.extend_from_slice(&case.secret);
    let end = payload.len();
    payload.extend_from_slice(&run);
    if !case.eof {
        payload.push(FILLER[0]);
    }
    Planted {
        payload,
        start,
        end,
        run,
    }
}

fn leading_in(cs: Cs, run: &[u8]) -> usize {
    run.iter().take_while(|&&b| cs.contains(b)).count()
}

proptest! {
    #![proptest_config(crate::support::config(128))]

    #[test]
    fn prop_registered_guard_matches_oracle(case in guard_reg_case()) {
        let reg = register_case(&case)?;

        // INV-49 / INV-51: the declared guard is exactly what was requested.
        prop_assert_eq!(
            reg.entry.trailing_run_guard,
            case.opts.trailing_run_guard.map(|t| t as u64),
            "INV-49: declared threshold"
        );
        prop_assert_eq!(
            &reg.entry.trailing_run_guard_charset,
            &case.opts.trailing_run_guard_charset,
            "INV-51: declared guard charset"
        );
        if !case.opts.restrict_charset {
            prop_assert_eq!(reg.var_cs, Cs::Wide, "variable charset without restrict-charset");
        }

        let effective = reg.oracle.guard_cs.unwrap_or(reg.var_cs);
        let planted = plant(&case, reg.var_cs, effective);
        check_swap_against_oracle(
            std::slice::from_ref(&reg.pattern),
            std::slice::from_ref(&reg.oracle),
            &planted.payload,
        )?;

        // Independent boundary rule (VC-22, VC-26): suppressed iff the leading
        // run of effective-guard-charset bytes reaches the threshold.
        let leading = leading_in(effective, &planted.run);
        let fires = matches!(case.opts.trailing_run_guard, Some(t) if leading >= t);
        let result = doppel::swap(&planted.payload, std::slice::from_ref(&reg.pattern))
            .expect("swap must succeed");
        if fires {
            prop_assert_eq!(
                &result.payload,
                &planted.payload,
                "VC-22: suppressed secret must pass through; t={:?} leading={} cs={}",
                case.opts.trailing_run_guard,
                leading,
                effective.name()
            );
            prop_assert!(result.entries.is_empty(), "suppressed secret must produce no entry");
        } else {
            prop_assert_eq!(
                result.entries.len(),
                1,
                "standing match must produce one entry; t={:?} leading={} cs={}",
                case.opts.trailing_run_guard,
                leading,
                effective.name()
            );
            prop_assert_ne!(&result.payload[planted.start..planted.end], case.secret.as_slice());
            prop_assert_eq!(&result.payload[..planted.start], &planted.payload[..planted.start]);
            prop_assert_eq!(&result.payload[planted.end..], &planted.payload[planted.end..]);
        }
    }

    #[test]
    fn prop_registration_guard_option_errors(
        (case, cs, zero, with_cs) in (
            guard_reg_case(),
            prop::sample::select(ALL_CS.to_vec()),
            any::<bool>(),
            any::<bool>(),
        ),
    ) {
        let mut opts = case.opts.clone();
        if zero {
            // VC-23: a zero threshold is rejected, with or without a charset.
            opts.trailing_run_guard = Some(0);
            opts.trailing_run_guard_charset = with_cs.then(|| cs.name().to_string());
        } else {
            // VC-28: a guard charset without a threshold is rejected.
            opts.trailing_run_guard = None;
            opts.trailing_run_guard_charset = Some(cs.name().to_string());
        }
        // Everything else about the secret is valid, so exactly one error
        // condition applies and the class can be asserted exactly.
        match doppel::register_with_options(&case.secret, &opts) {
            Ok(_) => prop_assert!(false, "registration accepted invalid guard options {:?}", opts),
            Err(SecretError::ZeroTrailingRunGuard) => {
                prop_assert!(zero, "unexpected ZeroTrailingRunGuard for {:?}", opts)
            }
            Err(SecretError::GuardCharsetWithoutGuard) => {
                prop_assert!(!zero, "unexpected GuardCharsetWithoutGuard for {:?}", opts)
            }
            Err(other) => prop_assert!(false, "unexpected error {:?} for {:?}", other, opts),
        }
    }
}

/// Coverage guard, not a correctness check: both outcomes and both VC-26
/// divergence directions must occur. Fixed seed, so it cannot flake; the
/// counted outcomes do not depend on the registration salt.
#[test]
fn registration_guard_covers_outcomes_and_explicit_charset() {
    use proptest::test_runner::TestRunner;

    const CASES: u32 = 512;
    let strategy = guard_reg_case();
    let mut runner = TestRunner::deterministic();
    let mut suppressed = 0u32;
    let mut replaced = 0u32;
    let mut declared_suppresses_beyond_var = 0u32;
    let mut var_run_but_stands = 0u32;
    for _ in 0..CASES {
        let case = strategy
            .new_tree(&mut runner)
            .expect("coverage sample must generate a case")
            .current();
        let reg = register_case(&case).expect("constructed registration must succeed");
        let effective = reg.oracle.guard_cs.unwrap_or(reg.var_cs);
        let planted = plant(&case, reg.var_cs, effective);
        let Some(t) = case.opts.trailing_run_guard else {
            replaced += 1;
            continue;
        };
        let explicit = reg.oracle.guard_cs.is_some();
        if leading_in(effective, &planted.run) >= t {
            suppressed += 1;
            if explicit && planted.run[..t].iter().any(|&b| !reg.var_cs.contains(b)) {
                declared_suppresses_beyond_var += 1;
            }
        } else {
            replaced += 1;
            if explicit && leading_in(reg.var_cs, &planted.run) >= t {
                var_run_but_stands += 1;
            }
        }
    }
    println!(
        "registration_guard over {CASES}: suppressed={suppressed} replaced={replaced} \
         declared_beyond_var={declared_suppresses_beyond_var} var_run_but_stands={var_run_but_stands}"
    );
    assert!(
        suppressed * 5 >= CASES,
        "suppressed share below 20%: {suppressed}/{CASES}"
    );
    assert!(
        replaced * 5 >= CASES,
        "replaced share below 20%: {replaced}/{CASES}"
    );
    assert!(
        declared_suppresses_beyond_var >= 5,
        "VC-26 first clause rarely exercised"
    );
    assert!(
        var_run_but_stands >= 5,
        "VC-26 second clause rarely exercised"
    );
}
