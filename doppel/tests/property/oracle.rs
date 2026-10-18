// Independent reference model of SPEC.md §Detection Algorithm, §Trailing Run Guard and §Fake Generation. Deliberately brute-force; never call doppel here.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cs {
    Alphanumeric,
    UrlSafeBase64,
    Base64Any,
    UppercaseAlphanumeric,
    Digits,
    HexLower,
    Wide,
}

pub const ALL_CS: [Cs; 7] = [
    Cs::Alphanumeric,
    Cs::UrlSafeBase64,
    Cs::Base64Any,
    Cs::UppercaseAlphanumeric,
    Cs::Digits,
    Cs::HexLower,
    Cs::Wide,
];

impl Cs {
    pub fn name(self) -> &'static str {
        match self {
            Cs::Alphanumeric => "alphanumeric",
            Cs::UrlSafeBase64 => "url_safe_base64",
            Cs::Base64Any => "base64_any",
            Cs::UppercaseAlphanumeric => "uppercase_alphanumeric",
            Cs::Digits => "digits",
            Cs::HexLower => "hex_lower",
            Cs::Wide => "wide",
        }
    }

    pub fn contains(self, b: u8) -> bool {
        match self {
            Cs::Alphanumeric => b.is_ascii_alphanumeric(),
            Cs::UrlSafeBase64 => b.is_ascii_alphanumeric() || b == b'-' || b == b'_',
            Cs::Base64Any => {
                b.is_ascii_alphanumeric()
                    || b == b'+'
                    || b == b'/'
                    || b == b'-'
                    || b == b'_'
                    || b == b'='
            }
            Cs::UppercaseAlphanumeric => b.is_ascii_uppercase() || b.is_ascii_digit(),
            Cs::Digits => b.is_ascii_digit(),
            Cs::HexLower => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            // SPEC §Patterns File "wide": printable ASCII minus `"` and `\` (92 bytes).
            Cs::Wide => (0x21..=0x7E).contains(&b) && b != b'"' && b != b'\\',
        }
    }

    pub fn bytes(self) -> Vec<u8> {
        (0u8..=255).filter(|&b| self.contains(b)).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seg {
    Lit(Vec<u8>),
    Opq(Vec<u8>, Cs),
    Var(Cs, usize, usize),
}

#[derive(Clone, Debug)]
pub struct OPattern {
    pub segs: Vec<Seg>,
    pub guard: Option<usize>,
    pub guard_cs: Option<Cs>,
    /// None = family pattern; Some(set) = instance/group pattern accepting exactly these candidates.
    pub accepted: Option<Vec<Vec<u8>>>,
}

impl OPattern {
    pub fn first_is_literal(&self) -> bool {
        matches!(self.segs.first(), Some(Seg::Lit(_)))
    }

    pub fn effective_guard_cs(&self) -> Option<Cs> {
        self.guard_cs.or_else(|| {
            self.segs.iter().rev().find_map(|s| match s {
                Seg::Var(cs, _, _) => Some(*cs),
                _ => None,
            })
        })
    }
}

/// Every way `segs` can consume `payload[pos..]`: `(end, per-segment lengths)`.
/// `Var` tries every length in `min..=max` that stays in bounds and has all bytes
/// in its charset. Panics if more than 100_000 segmentations are produced.
pub fn segmentations(segs: &[Seg], payload: &[u8], pos: usize) -> Vec<(usize, Vec<usize>)> {
    let mut out: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut lens: Vec<usize> = Vec::new();
    walk(segs, 0, pos, payload, &mut lens, &mut out);
    out
}

fn walk(
    segs: &[Seg],
    si: usize,
    cur: usize,
    payload: &[u8],
    lens: &mut Vec<usize>,
    out: &mut Vec<(usize, Vec<usize>)>,
) {
    if out.len() > 100_000 {
        panic!("segmentation enumeration exceeded 100_000 — generator bug guard");
    }
    let Some(seg) = segs.get(si) else {
        out.push((cur, lens.clone()));
        return;
    };
    match seg {
        Seg::Lit(bytes) | Seg::Opq(bytes, _) => {
            let end = cur + bytes.len();
            if payload.get(cur..end) == Some(bytes.as_slice()) {
                lens.push(bytes.len());
                walk(segs, si + 1, end, payload, lens, out);
                lens.pop();
            }
        }
        Seg::Var(cs, min, max) => {
            for len in *min..=*max {
                let Some(slice) = payload.get(cur..cur + len) else {
                    break;
                };
                if slice.iter().all(|&b| cs.contains(b)) {
                    lens.push(len);
                    walk(segs, si + 1, cur + len, payload, lens, out);
                    lens.pop();
                }
            }
        }
    }
}

/// Max end over segmentations whose candidate `payload[pos..end]` is accepted
/// (family: always; instance: candidate ∈ accepted). None if none.
pub fn accepted_end(p: &OPattern, payload: &[u8], pos: usize) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (end, _) in segmentations(&p.segs, payload, pos) {
        let candidate = &payload[pos..end];
        let accepted = match &p.accepted {
            None => true,
            Some(set) => set.iter().any(|c| c.as_slice() == candidate),
        };
        let better = match best {
            None => true,
            Some(b) => end > b,
        };
        if accepted && better {
            best = Some(end);
        }
    }
    best
}

/// SPEC §Trailing Run Guard: `Some(t)` and a resolvable charset and `end + t <= len`
/// and all `payload[end..end + t]` in the charset. EOF before `t` bytes → false.
pub fn guard_fires(p: &OPattern, payload: &[u8], end: usize) -> bool {
    let Some(t) = p.guard else {
        return false;
    };
    let Some(cs) = p.effective_guard_cs() else {
        return false;
    };
    let Some(stop) = end.checked_add(t) else {
        return false;
    };
    if stop > payload.len() {
        return false;
    }
    payload[end..stop].iter().all(|&b| cs.contains(b))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub winners: Vec<usize>,
}

#[derive(Debug)]
pub enum Scan {
    Spans(Vec<Span>),
    Unspecified { at: usize },
}

pub fn scan(patterns: &[OPattern], payload: &[u8]) -> Scan {
    let mut pos = 0;
    let mut spans: Vec<Span> = Vec::new();
    while pos < payload.len() {
        let cands: Vec<(usize, usize)> = patterns
            .iter()
            .enumerate()
            .filter_map(|(i, p)| accepted_end(p, payload, pos).map(|e| (i, e)))
            .collect();
        if cands.is_empty() {
            pos += 1;
            continue;
        }
        let best = cands
            .iter()
            .map(|&(_, e)| e)
            .max()
            .expect("cands non-empty");
        let mut c: Vec<usize> = cands
            .iter()
            .filter(|&&(_, e)| e == best)
            .map(|&(i, _)| i)
            .collect();
        if c.iter().any(|&i| patterns[i].first_is_literal()) {
            c.retain(|&i| patterns[i].first_is_literal());
        }
        let g = c
            .iter()
            .map(|&i| patterns[i].guard)
            .max()
            .expect("c non-empty");
        c.retain(|&i| patterns[i].guard == g);
        let fires: Vec<bool> = c
            .iter()
            .map(|&i| guard_fires(&patterns[i], payload, best))
            .collect();
        if fires.iter().any(|&f| f != fires[0]) {
            return Scan::Unspecified { at: pos };
        }
        if fires[0] {
            pos += 1;
            continue;
        }
        spans.push(Span {
            start: pos,
            end: best,
            winners: c,
        });
        pos = best;
    }
    Scan::Spans(spans)
}

/// SPEC §Fake Generation + INV-15/27/28/29: same length, fake != original, and some
/// full segmentation of `original` (end == original.len()) under which every Lit
/// slice is verbatim, every Var slice is in its cs, and every Opq slice is in its cs
/// and differs from the opaque value.
pub fn fake_conforms(p: &OPattern, original: &[u8], fake: &[u8]) -> bool {
    if fake.len() != original.len() || fake == original {
        return false;
    }
    for (end, lens) in segmentations(&p.segs, original, 0) {
        if end != original.len() {
            continue;
        }
        if slices_conform(&p.segs, &lens, fake) {
            return true;
        }
    }
    false
}

fn slices_conform(segs: &[Seg], lens: &[usize], fake: &[u8]) -> bool {
    let mut off = 0;
    for (seg, &len) in segs.iter().zip(lens) {
        let slice = &fake[off..off + len];
        let ok = match seg {
            Seg::Lit(bytes) => slice == bytes.as_slice(),
            Seg::Var(cs, _, _) => slice.iter().all(|&b| cs.contains(b)),
            Seg::Opq(bytes, cs) => {
                slice.iter().all(|&b| cs.contains(b)) && slice != bytes.as_slice()
            }
        };
        if !ok {
            return false;
        }
        off += len;
    }
    true
}

/// SPEC §Entropy Requirements: `len × log2(cs_size)`; 0.0 when `cs_size <= 1`.
pub fn entropy_bits(len: usize, cs_size: usize) -> f64 {
    if cs_size <= 1 {
        0.0
    } else {
        len as f64 * (cs_size as f64).log2()
    }
}

fn pat(
    segs: Vec<Seg>,
    guard: Option<usize>,
    guard_cs: Option<Cs>,
    accepted: Option<Vec<Vec<u8>>>,
) -> OPattern {
    OPattern {
        segs,
        guard,
        guard_cs,
        accepted,
    }
}

#[test]
fn test_oracle_charset_cardinalities_and_names() {
    let expected: [(Cs, usize); 7] = [
        (Cs::Alphanumeric, 62),
        (Cs::UrlSafeBase64, 64),
        (Cs::Base64Any, 67),
        (Cs::UppercaseAlphanumeric, 36),
        (Cs::Digits, 10),
        (Cs::HexLower, 16),
        (Cs::Wide, 92),
    ];
    assert_eq!(ALL_CS.len(), expected.len());
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for (i, &cs) in ALL_CS.iter().enumerate() {
        let (want, n) = expected[i];
        assert_eq!(cs, want);
        assert_eq!(cs.bytes().len(), n, "{} cardinality", cs.name());
        assert!(names.insert(cs.name()), "duplicate name {}", cs.name());
    }
    assert_eq!(names.len(), 7);
}

#[test]
fn test_oracle_segmentations_literal_and_variable() {
    let segs = vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 1, 3)];
    let ends: BTreeSet<usize> = segmentations(&segs, b"ab12x", 0)
        .into_iter()
        .map(|(end, _)| end)
        .collect();
    assert_eq!(ends, [3usize, 4].into_iter().collect());
}

#[test]
fn test_oracle_segmentations_internal_marker() {
    let segs = vec![
        Seg::Lit(b"s".to_vec()),
        Seg::Var(Cs::Alphanumeric, 1, 4),
        Seg::Lit(b"T".to_vec()),
        Seg::Var(Cs::Alphanumeric, 1, 2),
    ];
    let ends: BTreeSet<usize> = segmentations(&segs, b"saTbTc", 0)
        .into_iter()
        .map(|(end, _)| end)
        .collect();
    assert_eq!(ends, [4usize, 5, 6].into_iter().collect());
    let p = pat(segs, None, None, None);
    assert_eq!(accepted_end(&p, b"saTbTc", 0), Some(6));
}

#[test]
fn test_oracle_instance_acceptance_filters_segmentations() {
    let segs = vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 1, 3)];
    let accept_one = pat(segs.clone(), None, None, Some(vec![b"ab1".to_vec()]));
    assert_eq!(accepted_end(&accept_one, b"ab12", 0), Some(3));
    let accept_none = pat(segs, None, None, Some(vec![]));
    assert_eq!(accepted_end(&accept_none, b"ab12", 0), None);
}

#[test]
fn test_oracle_literal_first_tie_break() {
    let a = pat(
        vec![
            Seg::Opq(b"ab".to_vec(), Cs::Alphanumeric),
            Seg::Var(Cs::Digits, 2, 2),
        ],
        None,
        None,
        None,
    );
    let b = pat(
        vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 2, 2)],
        None,
        None,
        None,
    );
    match scan(&[a, b], b"ab12") {
        Scan::Spans(spans) => {
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].start, 0);
            assert_eq!(spans[0].end, 4);
            assert_eq!(spans[0].winners, vec![1]);
        }
        other => panic!("expected spans, got {other:?}"),
    }
}

#[test]
fn test_oracle_guard_boundary() {
    let guarded = |threshold| {
        pat(
            vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 2, 2)],
            Some(threshold),
            Some(Cs::Digits),
            None,
        )
    };
    assert!(guard_fires(&guarded(3), b"ab12345", 4));
    assert!(matches!(scan(&[guarded(3)], b"ab12345"), Scan::Spans(s) if s.is_empty()));
    assert!(
        matches!(scan(&[guarded(3)], b"ab1234"), Scan::Spans(s) if s.len() == 1 && s[0].end == 4)
    );
    assert!(!guard_fires(&guarded(4), b"ab12345x", 4));
    assert!(matches!(scan(&[guarded(4)], b"ab12345x"), Scan::Spans(s) if s.len() == 1));
}

#[test]
fn test_oracle_guard_no_cascade() {
    let long = pat(
        vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 3, 3)],
        Some(2),
        Some(Cs::Digits),
        None,
    );
    let short = pat(
        vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 2, 2)],
        None,
        None,
        None,
    );
    assert!(matches!(scan(&[long, short], b"ab12345"), Scan::Spans(s) if s.is_empty()));
}

#[test]
fn test_oracle_guard_tie_is_unspecified() {
    let mk = |cs| {
        pat(
            vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 2, 2)],
            Some(2),
            Some(cs),
            None,
        )
    };
    assert!(matches!(
        scan(&[mk(Cs::Digits), mk(Cs::HexLower)], b"ab12aa"),
        Scan::Unspecified { at: 0 }
    ));
}

#[test]
fn test_oracle_fake_conformance() {
    let literal = pat(
        vec![Seg::Lit(b"ab".to_vec()), Seg::Var(Cs::Digits, 2, 2)],
        None,
        None,
        None,
    );
    assert!(fake_conforms(&literal, b"ab12", b"ab77"));
    assert!(!fake_conforms(&literal, b"ab12", b"ab12"));
    assert!(!fake_conforms(&literal, b"ab12", b"xb77"));
    assert!(!fake_conforms(&literal, b"ab12", b"ab7z"));

    let opaque = pat(
        vec![
            Seg::Opq(b"ab".to_vec(), Cs::Alphanumeric),
            Seg::Var(Cs::Digits, 1, 1),
        ],
        None,
        None,
        None,
    );
    assert!(fake_conforms(&opaque, b"ab1", b"cd2"));
    assert!(!fake_conforms(&opaque, b"ab1", b"ab2"));
}

#[test]
fn test_oracle_entropy_bits_boundary() {
    assert!(entropy_bits(13, 92) >= 83.0);
    assert!(entropy_bits(12, 92) < 83.0);
    assert!(entropy_bits(25, 10) >= 83.0);
    assert!(entropy_bits(24, 10) < 83.0);
}
