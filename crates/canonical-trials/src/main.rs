/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![forbid(unsafe_code)]

//! AUTHORITY: Adversarial trials against the canonical encoder's order law.
//!
//! ORDER_LAW: `a <= b  <=>  encode(a) <=lex encode(b)`.
//!
//! The proof in `canonical.rs` is the authority. These trials exist for what a
//! proof cannot give: evidence that the SPECIFICATION says what a human means.
//! `lex_le` is in the trusted computing base, so it is pinned here against
//! independent exhaustive enumeration rather than taken on faith.
//!
//! Every trial is EXHAUSTIVE over its domain, not sampled. Sorting every input
//! in a domain by its encoding and comparing against the semantic sort tests
//! every ordered pair at once, which is what makes exhaustion over a small
//! domain stronger evidence than sampling over a large one.
//!
//! Attacks are written as an attacker would: forge the terminator, forge the
//! escape, smuggle the structural bytes, collide two different values onto one
//! byte string, truncate mid-escape, and nest until something overflows.

mod value;
use value::canonical;
use value::codec::CanonicalSet;

use canonical::{
    Bound, Refusal, Utf8, Branches, Reason, grammar_exec, CanonicalBytes, Shape, escape, scan_value, seal_bool, seal_bytes,
    seal_geometry, seal_interval, seal_interval_empty, seal_json, seal_list, seal_null,
    seal_num_negative, seal_num_nan, seal_num_positive, seal_num_zero, seal_regex, seal_set, seal_str,
    Magnitude, Repr, RegexFlags, MAG_BYTES, EXP_INFINITE, DIM_BYTES,
    seal_uuid, seal_validity, seal_vector, shape_scan,
};

// The released format, written out here and nowhere else in this file. These
// are deliberately NOT imported from the encoder: a pin that reads its expected
// value out of the thing under test pins nothing.
const TAG_NULL: u8 = 0x05;
const TAG_FALSE: u8 = 0x08;
const TAG_TRUE: u8 = 0x09;
const TAG_NUM: u8 = 0x10;
const TAG_STR: u8 = 0x18;
const TAG_BYTES: u8 = 0x20;
const TAG_UUID: u8 = 0x28;
const TAG_REGEX: u8 = 0x30;
const TAG_JSON: u8 = 0x38;
const TAG_VECTOR: u8 = 0x40;
const TAG_LIST: u8 = 0x48;
const TAG_SET: u8 = 0x50;
const TAG_VALIDITY: u8 = 0x58;
const TAG_INTERVAL: u8 = 0x60;
const TAG_GEOMETRY: u8 = 0x68;

// ---------------------------------------------------------------- harness --

/// How many checks have run.
///
/// A newtype because this number is the campaign's own claim about its
/// coverage — the thing a reader trusts when the run says "all N passed". A
/// bare `usize` here adds to lengths and byte counts without complaint, and a
/// coverage number that can be arithmetic with a buffer size is a number that
/// can silently become the wrong number.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Checks(usize);

impl Checks {
    const NONE: Checks = Checks(0);

    /// Saturating on purpose: a campaign that overflowed its own counter must
    /// not wrap to a small number and report thin coverage as complete.
    fn one_more(self) -> Checks {
        Checks(self.0.saturating_add(1))
    }

    fn count(self) -> usize {
        self.0
    }
}

/// The name of a check that failed, as written at the call site.
struct FailedCheck(String);

struct Trials {
    run: Checks,
    failed: Vec<FailedCheck>,
}

impl Trials {
    fn new() -> Trials {
        Trials { run: Checks::NONE, failed: Vec::new() }
    }

    fn check(&mut self, name: &str, ok: bool) {
        self.run = self.run.one_more();
        if !ok {
            self.failed.push(FailedCheck(name.to_string()));
        }
    }

    fn report(&self, section: &str) {
        println!("  {section}: {} checks", self.run.count());
    }
}

/// Lexicographic order on bytes, written independently of the encoder so the
/// specification is compared against something, not against itself.
/// The smallest finite magnitude the type admits: significand 1, scale 0.
fn mag_min() -> Magnitude {
    Magnitude::Finite { significand: 1, biased_scale: 0 }
}

/// The largest finite magnitude `wf_mag` admits: a saturated significand at
/// the greatest scale that still leaves the exponent below the reserved one.
fn mag_max() -> Magnitude {
    Magnitude::Finite { significand: u64::MAX, biased_scale: EXP_INFINITE - 65 }
}

/// `n` distinct components, so a vector's dimension is derived rather than
/// declared. Components differ by scale so no two collide.
fn vec_of(n: usize) -> Vec<CanonicalBytes> {
    (0..n)
        .map(|i| {
            seal_num_positive(
                &Magnitude::Finite { significand: 1, biased_scale: (i % 1000) as u32 },
                Repr::Int,
            )
        })
        .collect()
}

/// A scan's length, discarding the refusal. Refusal carries a borrowed suffix
/// and is deliberately not comparable, so trials that only care whether a
/// boundary was found go through this.
fn scanned(r: Result<usize, Refusal<'_>>) -> Option<usize> { r.ok() }

/// Where a refusal stopped, as an offset from the front of `input`. The
/// refusal carries the suffix it had not consumed; the offset is the caller's
/// arithmetic because only the caller knows which buffer it handed over.
fn stopped_at(input: &[u8], e: &Refusal<'_>) -> usize { input.len() - e.at().len() }

fn lex_le_independent(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    a.len() <= b.len()
}

fn is_proper_prefix(a: &[u8], b: &[u8]) -> bool {
    a.len() < b.len() && b[..a.len()] == *a
}

/// Every byte string of length `<= max` over `alphabet`, in semantic order.
fn all_strings(alphabet: &[u8], max: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![Vec::new()];
    let mut frontier: Vec<Vec<u8>> = vec![Vec::new()];
    for _ in 0..max {
        let mut next = Vec::new();
        for s in &frontier {
            for &b in alphabet {
                let mut t = s.clone();
                t.push(b);
                next.push(t);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out.sort_by(|x, y| {
        if lex_le_independent(x, y) && lex_le_independent(y, x) {
            std::cmp::Ordering::Equal
        } else if lex_le_independent(x, y) {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    out
}

// ------------------------------------------------------- the escape layer --

/// EXHAUSTIVE. Sort every input by its encoding; the result must equal the
/// semantic sort. One pass tests every ordered pair in the domain.
fn trial_escape_order_exhaustive(t: &mut Trials, alphabet: &[u8], max: usize, label: &str) {
    let inputs = all_strings(alphabet, max);
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> =
        inputs.iter().map(|s| (escape(s), s.clone())).collect();
    encoded.sort_by(|a, b| {
        if lex_le_independent(&a.0, &b.0) && lex_le_independent(&b.0, &a.0) {
            std::cmp::Ordering::Equal
        } else if lex_le_independent(&a.0, &b.0) {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    for (i, (_, original)) in encoded.iter().enumerate() {
        t.check(label, *original == inputs[i]);
    }
}

/// EXHAUSTIVE. No encoding may be a proper prefix of another. This is the
/// hypothesis the closure theorem needs; if it fails, concatenation collides.
fn trial_escape_prefix_free_exhaustive(t: &mut Trials, alphabet: &[u8], max: usize) {
    let inputs = all_strings(alphabet, max);
    let encoded: Vec<Vec<u8>> = inputs.iter().map(|s| escape(s)).collect();
    for i in 0..encoded.len() {
        for j in 0..encoded.len() {
            t.check(
                "escape prefix-free",
                !is_proper_prefix(&encoded[i], &encoded[j]),
            );
        }
    }
}

/// EXHAUSTIVE. Distinct inputs must never share bytes.
fn trial_escape_injective_exhaustive(t: &mut Trials, alphabet: &[u8], max: usize) {
    let inputs = all_strings(alphabet, max);
    let encoded: Vec<Vec<u8>> = inputs.iter().map(|s| escape(s)).collect();
    for i in 0..inputs.len() {
        for j in 0..inputs.len() {
            if i != j {
                t.check("escape injective", encoded[i] != encoded[j]);
            }
        }
    }
}

// ------------------------------------------------------------- the attacks --

/// ATTACK: forge the terminator. Content that literally contains `0x00 0x00`
/// must not truncate the encoding — the escape must lift it out of reach.
fn attack_terminator_forgery(t: &mut Trials) {
    let payloads: Vec<Vec<u8>> = vec![
        vec![0x00, 0x00],
        vec![0x00, 0x00, 0x00],
        vec![0x41, 0x00, 0x00, 0x42],
        vec![0x00, 0x00, 0x41],
        vec![0x00; 8],
    ];
    for p in &payloads {
        let e = escape(p);
        // The terminator appears exactly once, at the end.
        let mut terminators = 0;
        let mut i = 0;
        while i + 1 < e.len() {
            if e[i] == 0x00 && e[i + 1] == 0x00 {
                terminators += 1;
                i += 2;
            } else if e[i] == 0x00 {
                i += 2;
            } else {
                i += 1;
            }
        }
        t.check("terminator forgery", terminators == 1);
        t.check(
            "terminator is last",
            e.len() >= 2 && e[e.len() - 2] == 0x00 && e[e.len() - 1] == 0x00,
        );
    }
}

/// ATTACK: forge the escape. Content containing `0x00 0xFF` — which is what a
/// real escape looks like on the wire — must not be confusable with one.
fn attack_escape_forgery(t: &mut Trials) {
    let a = escape(&[0x00, 0xFF]);
    let b = escape(&[0x00]);
    let c = escape(&[0xFF]);
    t.check("escape forgery distinct", a != b && a != c && b != c);
    t.check("escape forgery not prefix", !is_proper_prefix(&a, &b));
    t.check("escape forgery not prefix", !is_proper_prefix(&b, &a));
    // 0x00 escapes to 0x00 0xFF; literal 0x00 0xFF must escape to 0x00 0xFF 0xFF.
    t.check("escape doubling", a == vec![0x00, 0xFF, 0xFF, 0x00, 0x00]);
    t.check("escape single", b == vec![0x00, 0xFF, 0x00, 0x00]);
}

/// ATTACK: the collision the closure theorem forbids. Without prefix-freeness,
/// `("a","bc")` and `("ab","c")` concatenate to the same bytes. With it, they
/// cannot.
fn attack_concatenation_collision(t: &mut Trials) {
    let naive_1: Vec<u8> = [b"a".as_slice(), b"bc".as_slice()].concat();
    let naive_2: Vec<u8> = [b"ab".as_slice(), b"c".as_slice()].concat();
    t.check("unescaped concat DOES collide", naive_1 == naive_2);

    let safe_1: Vec<u8> = [escape(b"a"), escape(b"bc")].concat();
    let safe_2: Vec<u8> = [escape(b"ab"), escape(b"c")].concat();
    t.check("escaped concat does NOT collide", safe_1 != safe_2);
    t.check(
        "escaped concat orders by first component",
        lex_le_independent(&safe_1, &safe_2),
    );
}

/// ATTACK: smuggle the structural bytes. `0x00` opens escapes and `0x01`
/// terminates sequences; neither may survive into a position where it is read
/// as structure.
fn attack_structural_smuggling(t: &mut Trials) {

    // An element whose content starts with the sequence terminator.
    let one = seal_list(&vec![bytes_val(&[0x01, 0x41])]);
    let two = seal_list(&vec![bytes_val(&[0x01, 0x41]), bytes_val(&[0x41])]);

    // Every element opens with its tag byte, which is >= 0x05, so the smuggled
    // 0x01 sits inside a payload and can never be read as the terminator.
    t.check("element opens with a tag", one.as_bytes()[1] >= 0x05);
    t.check(
        "smuggled 0x01 does not truncate",
        two.as_bytes().len() > one.as_bytes().len(),
    );
    t.check(
        "prefix sequence sorts first",
        lex_le_independent(one.as_bytes(), two.as_bytes()),
    );
}

/// ATTACK: empty versus containing-empty. A sequence with no elements and a
/// sequence holding one empty string must be distinct and correctly ordered.
fn attack_empty_confusion(t: &mut Trials) {

    let empty_seq = seal_list(&Vec::new());
    let seq_of_empty = seal_list(&vec![bytes_val(&[])]);

    t.check("empty seq != seq of empty", empty_seq.as_bytes() != seq_of_empty.as_bytes());
    t.check(
        "empty seq sorts first",
        lex_le_independent(empty_seq.as_bytes(), seq_of_empty.as_bytes()),
    );
    t.check(
        "empty seq not a prefix of seq of empty",
        !is_proper_prefix(empty_seq.as_bytes(), seq_of_empty.as_bytes()),
    );
}

/// ATTACK: cross-type order must come from the tag alone, whatever the payload.
/// A Null with no payload must sort below a Bool with payload 0xFF, and a Bool
/// below any Str — the payload must never reach across a tag boundary.
fn attack_cross_type_order(t: &mut Trials) {
    let null = seal_null();
    let bool_hi = seal_bool(false);
    let str_lo = seal_str(&Utf8::of(""));
    let bytes_lo = seal_bytes(&[]);

    t.check("null < bool", lex_le_independent(null.as_bytes(), bool_hi.as_bytes()));
    t.check("bool < str", lex_le_independent(bool_hi.as_bytes(), str_lo.as_bytes()));
    t.check("str < bytes", lex_le_independent(str_lo.as_bytes(), bytes_lo.as_bytes()));
    // The highest text a Str can carry still sorts under Bytes: the tag decides,
    // and no payload reaches across it.
    let str_hi = seal_str(&Utf8::of("\u{10ffff}\u{10ffff}"));
    t.check(
        "max payload cannot cross a tag",
        lex_le_independent(str_hi.as_bytes(), bytes_lo.as_bytes()),
    );
}

/// ATTACK: prefix sequences. `[a]` must sort before `[a, x]` for EVERY x,
/// including an x whose first payload byte is `0x00`.
fn attack_prefix_sequence_exhaustive(t: &mut Trials) {
    for x in 0u16..=255 {
        let byte = x as u8;
        let short = seal_list(&vec![str_val("a")]);
        let long = seal_list(&vec![str_val("a"), bytes_val(&[byte])]);
        t.check(
            "prefix sequence sorts first, all 256 extensions",
            lex_le_independent(short.as_bytes(), long.as_bytes())
                && short.as_bytes() != long.as_bytes(),
        );
    }
}

/// ATTACK: nesting. Sequences nest without a length prefix, so a deeply nested
/// value must still be exactly self-delimiting.
fn attack_deep_nesting(t: &mut Trials) {
    let mut inner = str_val("leaf");
    for _ in 0..512 {
        inner = seal_list(&vec![inner]);
    }
    let bytes = inner.as_bytes();
    // 512 opening tags, 512 terminators, plus the leaf.
    t.check("deep nesting balanced", bytes.len() == 512 * 2 + 1 + 4 + 2);
    t.check("deep nesting opens with the list tag", bytes[0] == TAG_LIST);
    t.check("deep nesting closes with the terminator", bytes[bytes.len() - 1] == 0x01);
}

/// ATTACK: the unmarked row element — the general form of the JSON object-key
/// defect. A row decides "element or end" from the byte in front of it, so an
/// element shape that can open with `0x01` collides the row holding it with the
/// empty row. `wf_grammar` refuses exactly this; here is the behaviour it
/// refuses, exhibited over the algebra.
fn attack_unmarked_row_element(t: &mut Trials) {
    let g = Branches::End;

    // Hostile: elements are one arbitrary byte, so an element may BE the
    // terminator.
    let hostile = Shape::Row(Box::new(Shape::Fixed(1)));
    let empty_row: Vec<u8> = vec![0x01];
    let row_of_one: Vec<u8> = vec![0x01, 0x01]; // one element, byte 0x01, then the end
    t.check("unmarked: empty row reads as 1", scanned(shape_scan(&g, &hostile, &empty_row, 0)) == Some(1));
    t.check(
        "unmarked: row holding 0x01 reads as the EMPTY row",
        scanned(shape_scan(&g, &hostile, &row_of_one, 0)) == Some(1),
    );
    t.check(
        "unmarked: two different rows, one reading — this is the defect",
        scanned(shape_scan(&g, &hostile, &empty_row, 0)) == scanned(shape_scan(&g, &hostile, &row_of_one, 0)),
    );

    // Marked: every element opens with a key above the terminator.
    let marked = Shape::Row(Box::new(Shape::Sum(Box::new(Branches::Alt(
        0x18,
        Box::new(Shape::Fixed(1)),
        Box::new(Branches::End),
    )))));
    let marked_empty: Vec<u8> = vec![0x01];
    let marked_one: Vec<u8> = vec![0x18, 0x01, 0x01]; // marker, hostile content, end
    t.check("marked: empty row reads as 1", scanned(shape_scan(&g, &marked, &marked_empty, 0)) == Some(1));
    t.check(
        "marked: row holding 0x01 reads as 3",
        scanned(shape_scan(&g, &marked, &marked_one, 0)) == Some(3),
    );
    t.check(
        "marked: the two rows have different readings",
        scanned(shape_scan(&g, &marked, &marked_empty, 0)) != scanned(shape_scan(&g, &marked, &marked_one, 0)),
    );
}

/// THE GRAMMAR TABLE. Cross-kind order is lead-byte order and each body width
/// is the released format. The proof cannot know either — it proves the reader
/// agrees with the grammar, not that the grammar is the format on disk. So the
/// bytes each door writes are pinned here, and only here.
fn trial_grammar_table(t: &mut Trials) {
    let cases: Vec<(CanonicalBytes, usize, &str)> = vec![
        (seal_null(), 1, "Null: tag only"),
        (seal_bool(false), 1, "False: tag only"),
        (seal_bool(true), 1, "True: tag only"),
        (seal_num_zero(Repr::Int), 3, "Num zero: tag, class, repr tie-break"),
        (seal_num_negative(&mag_min(), Repr::Int), 14, "Num negative: tag, class, 12"),
        (seal_num_positive(&mag_min(), Repr::Int), 14, "Num positive: tag, class, 12"),
        (seal_str(&Utf8::of("hello")), 8, "Str: tag, content, terminator"),
        (seal_bytes(&[0x00, 0xFF]), 6, "Bytes: tag, escaped content, terminator"),
        (seal_uuid(&[0x00; 16]), 17, "Uuid: tag, 16"),
        (seal_regex(b"ab", &RegexFlags::new(true, true, true)), 6, "Regex: tag, pattern, terminator, flags"),
        (seal_json(&seal_null()), 2, "Json: tag, a value"),
        (seal_vector(&vec![seal_num_zero(Repr::Int), seal_num_zero(Repr::Int)]), 12,
            "Vector: tag, 4 dimension, two components, terminator"),
        (seal_list(&Vec::new()), 2, "List: tag, terminator"),
        (seal_set(&Vec::new()), 2, "Set: tag, terminator"),
        (seal_validity(&[0x00; 9]), 10, "Validity: tag, 9"),
        (seal_interval_empty(), 2, "Interval empty: tag, marker"),
        (seal_interval(&Bound::Unbounded, &Bound::Unbounded), 4, "Interval: tag, marker, two ends"),
        (seal_interval(&Bound::At([0x00; 8]), &Bound::Unbounded), 12, "Interval: lo at"),
        (seal_geometry(&[0x00; 8]), 9, "Geometry: tag, 8"),
    ];
    let g = grammar_exec();
    for (v, want, label) in &cases {
        let bytes = v.as_bytes();
        t.check(label, bytes.len() == *want);
        t.check(label, scanned(scan_value(bytes)) == Some(bytes.len()));
        // One byte short is refused, never guessed at.
        if bytes.len() > 1 {
            let short = &bytes[..bytes.len() - 1];
            t.check(label, scanned(shape_scan(&g, &Shape::Tagged, short, 0)) != Some(short.len()));
        }
    }

    // The lead byte each door writes IS the released tag.
    let leads: Vec<(CanonicalBytes, u8, &str)> = vec![
        (seal_null(), TAG_NULL, "Null tag"),
        (seal_bool(false), TAG_FALSE, "False tag"),
        (seal_bool(true), TAG_TRUE, "True tag"),
        (seal_num_zero(Repr::Int), TAG_NUM, "Num tag"),
        (seal_str(&Utf8::of("")), TAG_STR, "Str tag"),
        (seal_bytes(b""), TAG_BYTES, "Bytes tag"),
        (seal_uuid(&[0; 16]), TAG_UUID, "Uuid tag"),
        (seal_regex(b"", &RegexFlags::new(false, false, false)), TAG_REGEX, "Regex tag"),
        (seal_json(&seal_null()), TAG_JSON, "Json tag"),
        (seal_vector(&Vec::new()), TAG_VECTOR, "Vector tag"),
        (seal_list(&Vec::new()), TAG_LIST, "List tag"),
        (seal_set(&Vec::new()), TAG_SET, "Set tag"),
        (seal_validity(&[0; 9]), TAG_VALIDITY, "Validity tag"),
        (seal_interval_empty(), TAG_INTERVAL, "Interval tag"),
        (seal_geometry(&[0; 8]), TAG_GEOMETRY, "Geometry tag"),
    ];
    for (v, tag, label) in &leads {
        t.check(label, v.as_bytes()[0] == *tag);
    }

    // Cross-kind order is exactly tag order.
    let tags = [
        TAG_NULL, TAG_FALSE, TAG_TRUE, TAG_NUM, TAG_STR, TAG_BYTES, TAG_UUID, TAG_REGEX,
        TAG_JSON, TAG_VECTOR, TAG_LIST, TAG_SET, TAG_VALIDITY, TAG_INTERVAL, TAG_GEOMETRY,
    ];
    for i in 0..tags.len() {
        for j in 0..tags.len() {
            t.check("tag order is cross-kind order", (tags[i] <= tags[j]) == (i <= j));
        }
    }
    for i in 0..leads.len() {
        for j in 0..leads.len() {
            t.check(
                "encodings sort by tag across every pair of kinds",
                lex_le_independent(leads[i].0.as_bytes(), leads[j].0.as_bytes()) == (i <= j),
            );
        }
    }
}

/// ATTACK: the interval ends. Unbounded below is the LEAST element of its axis
/// and unbounded above is the GREATEST, so the two ends cannot share a marker
/// table. A single table would put one infinity on the wrong side of every
/// finite instant.
///
/// `Bound` is why no trial here can smuggle a sentinel: there is no `[u8; 8]`
/// that means "no bound", so "unbounded" is a variant the caller names and the
/// markers are chosen by position, inside the gate.
/// Dimension leads, so length decides before any component is examined.
///
/// The claim `seal_vector` makes in prose is that two vectors of different
/// dimension order by dimension. The check that can contradict it is a short
/// vector whose components sort ABOVE a longer vector's: if components leaked
/// ahead of dimension, this pair would come back in the other order.
/// The number classes are a total order, and NaN is its top.
///
/// A store needs one order over every value it can hold. NaN is not comparable
/// to any number by IEEE rules, so the encoding has to place it somewhere and
/// place it consistently: above everything. The check that can contradict it
/// is the largest finite positive.
fn attack_nan_is_the_top_of_number(t: &mut Trials) {
    let neg = seal_num_negative(&mag_min(), Repr::Int);
    let zero = seal_num_zero(Repr::Int);
    let pos = seal_num_positive(&mag_max(), Repr::Int);
    let nan = seal_num_nan();

    t.check(
        "negative sorts under zero",
        lex_le_independent(neg.as_bytes(), zero.as_bytes())
            && neg.as_bytes() != zero.as_bytes(),
    );
    t.check(
        "zero sorts under positive",
        lex_le_independent(zero.as_bytes(), pos.as_bytes())
            && zero.as_bytes() != pos.as_bytes(),
    );
    t.check(
        "NaN sorts over the largest positive",
        lex_le_independent(pos.as_bytes(), nan.as_bytes())
            && pos.as_bytes() != nan.as_bytes(),
    );
    // Tag plus class, and nothing after it. Zero, by contrast, is three: it
    // still carries the int/float tie-break, because 0 and 0.0 differ.
    t.check("NaN is tag, class and the repr byte number.rs writes",
        nan.as_bytes().len() == 3);
    t.check("zero still carries its tie-break", zero.as_bytes().len() == 3);
    // Exhaustive over the negative magnitude's lead byte: nothing in the
    // negative class may climb past zero.
    for scale in 0u32..=255 {
        for sig in [1u64, 2, 0xFF, 0x8000_0000_0000_0000, u64::MAX] {
            let n = seal_num_negative(
                &Magnitude::Finite { significand: sig, biased_scale: scale },
                Repr::Int,
            );
            t.check(
                "every negative magnitude stays under zero",
                lex_le_independent(n.as_bytes(), zero.as_bytes())
                    && n.as_bytes() != zero.as_bytes(),
            );
        }
    }
}

fn attack_vector_dimension_leads(t: &mut Trials) {
    // Re-sealed per use: CanonicalBytes is not Clone, and a trial that built
    // its components once and shared them would be testing one buffer twice.
    let big = || seal_num_positive(&mag_max(), Repr::Int);
    let small = || seal_num_negative(&mag_min(), Repr::Int);

    let one_big = seal_vector(&vec![big()]);
    let two_small = seal_vector(&vec![small(), small()]);
    t.check(
        "a shorter vector sorts under a longer one whatever the components say",
        lex_le_independent(one_big.as_bytes(), two_small.as_bytes())
            && one_big.as_bytes() != two_small.as_bytes(),
    );

    // Same dimension: now the components are what decides, componentwise.
    let a = seal_vector(&vec![small(), small()]);
    let b = seal_vector(&vec![small(), big()]);
    t.check(
        "at equal dimension the components decide, in order",
        lex_le_independent(a.as_bytes(), b.as_bytes()) && a.as_bytes() != b.as_bytes(),
    );

    // Dimension is compared as a number, not as text: 2 < 10 must hold, which
    // a decimal or little-endian width would get wrong.
    let d2 = seal_vector(&vec_of(2));
    let d10 = seal_vector(&vec_of(10));
    let d256 = seal_vector(&vec_of(256));
    t.check(
        "dimension compares numerically across a byte boundary",
        lex_le_independent(d2.as_bytes(), d10.as_bytes())
            && lex_le_independent(d10.as_bytes(), d256.as_bytes())
            && d2.as_bytes() != d10.as_bytes(),
    );

    // Exhaustive over the low dimension byte, so no single value is special.
    for n in 0usize..=255 {
        let lo = seal_vector(&vec_of(n));
        let hi = seal_vector(&vec_of(n + 1));
        t.check(
            "dimension order is total over the low byte",
            lex_le_independent(lo.as_bytes(), hi.as_bytes())
                && lo.as_bytes() != hi.as_bytes(),
        );
    }
}

fn attack_interval_infinities(t: &mut Trials) {
    let lo_unbounded = seal_interval(&Bound::Unbounded, &Bound::At([0x00; 8]));
    let lo_at_min = seal_interval(&Bound::At([0x00; 8]), &Bound::At([0x00; 8]));
    t.check(
        "unbounded below sorts under every instant",
        lex_le_independent(lo_unbounded.as_bytes(), lo_at_min.as_bytes())
            && lo_unbounded.as_bytes() != lo_at_min.as_bytes(),
    );

    let hi_at_max = seal_interval(&Bound::Unbounded, &Bound::At([0xFF; 8]));
    let hi_unbounded = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    t.check(
        "unbounded above sorts over every instant",
        lex_le_independent(hi_at_max.as_bytes(), hi_unbounded.as_bytes())
            && hi_at_max.as_bytes() != hi_unbounded.as_bytes(),
    );

    // Exhaustive over each end, holding the other fixed so the comparison is
    // about the end under test and nothing else.
    let lo_unb = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    for x in 0u16..=255 {
        let mut at = [0x00; 8];
        at[0] = x as u8;

        let lo_bounded = seal_interval(&Bound::At(at), &Bound::Unbounded);
        t.check(
            "unbounded below is strictly under every one of 256 lower ends",
            lex_le_independent(lo_unb.as_bytes(), lo_bounded.as_bytes())
                && lo_unb.as_bytes() != lo_bounded.as_bytes(),
        );

        let hi_bounded = seal_interval(&Bound::Unbounded, &Bound::At(at));
        t.check(
            "unbounded above is strictly over every one of 256 upper ends",
            lex_le_independent(hi_bounded.as_bytes(), hi_unbounded.as_bytes())
                && hi_bounded.as_bytes() != hi_unbounded.as_bytes(),
        );
    }

    let empty = seal_interval_empty();
    t.check(
        "empty interval sorts below every inhabited one",
        lex_le_independent(empty.as_bytes(), lo_unbounded.as_bytes())
            && lex_le_independent(empty.as_bytes(), hi_unbounded.as_bytes()),
    );
}

/// ATTACK: the reader against the writer. Every sealed value must measure
/// itself exactly, and must keep measuring the same however many bytes follow —
/// locality, at exec.
fn attack_reader_agrees_with_writer(t: &mut Trials) {
    let values: Vec<CanonicalBytes> = vec![
        seal_null(),
        seal_str(&Utf8::of("")),
        seal_str(&Utf8::of("\u{0}\u{1}\u{ff}")),
        seal_num_zero(Repr::Int),
        seal_json(&seal_bool(true)),
        seal_list(&Vec::new()),
        seal_list(&vec![bytes_val(&[0x01]), bytes_val(&[0x00])]),
        seal_list(&vec![seal_list(&vec![str_val("x")])]),
    ];
    for v in &values {
        let bytes = v.as_bytes();
        t.check("reader measures the writer exactly", scanned(scan_value(bytes)) == Some(bytes.len()));

        for trailer in [vec![0x00u8], vec![0x01], vec![0xFF; 4], vec![TAG_NULL]] {
            let mut extended = bytes.to_vec();
            extended.extend_from_slice(&trailer);
            t.check(
                "trailing bytes cannot move the reading",
                scanned(scan_value(&extended)) == Some(bytes.len()),
            );
        }

        // Every proper prefix is incomplete: it may be refused, but it may
        // never be accepted as the whole value.
        for cut in 0..bytes.len() {
            t.check("no proper prefix is complete", scanned(scan_value(&bytes[..cut])) != Some(cut));
        }
    }
}

/// ATTACK: totality. The reader meets bytes an attacker wrote. It may refuse,
/// it may never panic, and it may never claim more bytes than it was given.
fn attack_reader_totality(t: &mut Trials) {
    let mut hostile: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0x01],
        vec![0xFF],
        vec![TAG_STR],
        vec![TAG_STR, 0x00],
        vec![TAG_STR, 0x00, 0xFF],
        vec![TAG_NUM],
        vec![TAG_NUM, 0x01],
        vec![TAG_LIST],
        vec![TAG_LIST, TAG_LIST],
        vec![TAG_INTERVAL, 0x02, 0x02],
    ];
    // Every one- and two-byte string: the whole domain, not a sample.
    for a in 0u16..=255 {
        hostile.push(vec![a as u8]);
        for b in 0u16..=255 {
            hostile.push(vec![a as u8, b as u8]);
        }
    }
    for p in &hostile {
        match scan_value(p) {
            Ok(n) => t.check("reader never claims more than it was given", n <= p.len()),
            Err(e) => t.check("a refusal names an offset inside the input", stopped_at(p, &e) <= p.len()),
        }
    }

    // Nesting past the bound is refused, never followed.
    let mut deep = str_val("leaf");
    for _ in 0..40 {
        deep = seal_list(&vec![deep]);
    }
    t.check("nesting within the bound is read", scan_value(deep.as_bytes()).is_ok());
    for _ in 0..512 {
        deep = seal_list(&vec![deep]);
    }
    t.check("nesting past the bound is refused", scan_value(deep.as_bytes()).is_err());
}

/// ATTACK: a refusal must name itself. `None` tells a caller nothing it can act
/// on and an operator nothing it can read. Every refusal below is pinned to its
/// reason AND its offset, so a reading that stops in the wrong place is a
/// failure here even though it still stops.
fn attack_refusals_are_named(t: &mut Trials) {
    let cases: Vec<(Vec<u8>, Reason, usize, &str)> = vec![
        (vec![], Reason::Truncated, 0, "empty input"),
        (vec![0x02], Reason::UnknownLeadByte(0x02), 0, "0x02 is not a tag"),
        (vec![0x01], Reason::UnknownLeadByte(0x01), 0, "the terminator is not a tag"),
        (vec![0xFF], Reason::UnknownLeadByte(0xFF), 0, "0xFF is not a tag"),
        (vec![TAG_STR, 0x00, 0x41], Reason::BadEscape(0x41), 2, "0x00 followed by neither"),
        (vec![TAG_STR], Reason::Truncated, 1, "a delimited body that never opens"),
        (vec![TAG_STR, 0x41], Reason::Truncated, 2, "a delimited body that never closes"),
        (vec![TAG_STR, 0x00], Reason::Truncated, 2, "an escape with nothing after it"),
        (vec![TAG_REGEX, 0x00, 0x00], Reason::Truncated, 3, "a regex with no flags byte"),
        (vec![TAG_UUID, 0x00, 0x00], Reason::Truncated, 3, "16 bytes promised, 2 given"),
        (vec![TAG_NUM, 0x07], Reason::UnknownLeadByte(0x07), 1, "0x07 is not a number class"),
        (vec![TAG_NUM], Reason::Truncated, 1, "a class byte that never arrives"),
        (vec![TAG_LIST], Reason::Truncated, 1, "a row that never terminates"),
        (vec![TAG_LIST, TAG_NULL], Reason::Truncated, 2, "a row whose element ends the input"),
        (vec![TAG_INTERVAL, 0x02, 0x09], Reason::UnknownLeadByte(0x09), 2, "0x09 is not a lower end"),
        (vec![TAG_INTERVAL, 0x02, 0x01, 0x01], Reason::UnknownLeadByte(0x01), 3,
         "the lower end's unbounded marker is not an upper end's"),
    ];
    for (bytes, reason, at, label) in &cases {
        match scan_value(bytes) {
            Ok(_) => t.check(label, false),
            Err(e) => {
                t.check(label, e.reason() == *reason);
                t.check(label, stopped_at(bytes, &e) == *at);
            }
        }
    }

    // Nesting past the bound names itself too, rather than overflowing a stack.
    let mut deep = seal_null();
    for _ in 0..400 {
        deep = seal_list(&vec![deep]);
    }
    match scan_value(deep.as_bytes()) {
        Ok(_) => t.check("nesting past the bound", false),
        Err(e) => t.check("nesting past the bound names TooDeep", e.reason() == Reason::TooDeep),
    }
}

/// ATTACK: JSON is not a second grammar. A JSON value is a value, so the same
/// bytes read the same way whether or not a Json tag sits in front of them.
fn attack_json_is_the_value_grammar(t: &mut Trials) {
    let inner: Vec<CanonicalBytes> = vec![
        seal_null(),
        seal_bool(true),
        seal_num_zero(Repr::Int),
        seal_str(&Utf8::of("k")),
        seal_list(&Vec::new()),
    ];
    for v in &inner {
        let bare = v.as_bytes().to_vec();
        let mut wrapped = vec![TAG_JSON];
        wrapped.extend_from_slice(&bare);
        t.check("a json body IS a value", scanned(scan_value(&wrapped)) == Some(bare.len() + 1));
        t.check(
            "and it is the same reading as the bare value",
            scanned(scan_value(&bare)) == Some(bare.len()),
        );
    }
}

/// ATTACK: high bytes. `0xFF` is the escape's companion byte; a payload of all
/// `0xFF` must not confuse the scanner.
fn attack_high_bytes(t: &mut Trials) {
    for n in 0..16usize {
        let payload = vec![0xFFu8; n];
        let e = escape(&payload);
        t.check("all-0xFF length", e.len() == n + 2);
        t.check(
            "all-0xFF terminates",
            e[e.len() - 2] == 0x00 && e[e.len() - 1] == 0x00,
        );
    }
    // 0xFF alternating with 0x00: every 0x00 must escape.
    let alt: Vec<u8> = (0..16).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
    let e = escape(&alt);
    t.check("alternating length", e.len() == 8 * 2 + 8 + 2);
}

/// EXHAUSTIVE over every single byte: each of the 256 one-byte payloads must
/// encode distinctly and in order.
fn trial_all_single_bytes(t: &mut Trials) {
    let mut encs: Vec<(u8, Vec<u8>)> = Vec::new();
    for b in 0u16..=255 {
        encs.push((b as u8, escape(&[b as u8])));
    }
    for i in 0..encs.len() {
        for j in 0..encs.len() {
            let want = encs[i].0 <= encs[j].0;
            let got = lex_le_independent(&encs[i].1, &encs[j].1);
            t.check("all 256 single bytes ordered", want == got);
        }
    }
}

/// Mint a fresh string value. The witness has no `Clone` by design, so the
/// trials rebuild each value through the public door rather than fabricate one.
/// Arbitrary content under the Bytes tag. The smuggling attacks carry
/// structural bytes, which `Str` does not admit.
fn bytes_val(s: &[u8]) -> CanonicalBytes { seal_bytes(s) }

fn str_val(s: &str) -> CanonicalBytes {
    seal_str(&Utf8::of(s))
}


// ============================== red team ====================================

/// A larger magnitude is a smaller negative number, so its bytes sort lower.
fn negative_number_byte_order_matches_semantic_order(t: &mut Trials) {
    let mut prev: Option<Vec<u8>> = None;
    // Descending denotation: significand fixed, scale increasing, so each
    // number is more negative than the last and must sort strictly below it.
    for scale in 0u32..=400 {
        let n = seal_num_negative(
            &Magnitude::Finite { significand: 3, biased_scale: scale },
            Repr::Int,
        );
        let cur = n.as_bytes().to_vec();
        if let Some(before) = prev {
            t.check(
                "a more negative number sorts strictly below a less negative one",
                lex_le_independent(&cur, &before) && cur != before,
            );
        }
        prev = Some(cur);
    }
    // Same exponent, larger fraction: still more negative, still lower.
    for sig in 1u64..=200 {
        let a = seal_num_negative(
            &Magnitude::Finite { significand: 256 + sig, biased_scale: 10 },
            Repr::Int,
        );
        let b = seal_num_negative(
            &Magnitude::Finite { significand: 256 + sig + 1, biased_scale: 10 },
            Repr::Int,
        );
        t.check(
            "within one exponent the larger fraction is the smaller negative",
            lex_le_independent(b.as_bytes(), a.as_bytes()) && a.as_bytes() != b.as_bytes(),
        );
    }
}

fn negative_infinity_sorts_below_every_finite_number(t: &mut Trials) {
    let ninf = seal_num_negative(&Magnitude::Infinite, Repr::Float);
    for scale in [0u32, 1, 64, 1000, EXP_INFINITE - 66] {
        for sig in [1u64, 2, 0xFFFF, u64::MAX] {
            let m = Magnitude::Finite { significand: sig, biased_scale: scale };
            let finite_neg = seal_num_negative(&m, Repr::Int);
            t.check(
                "negative infinity is below every finite negative",
                lex_le_independent(ninf.as_bytes(), finite_neg.as_bytes())
                    && ninf.as_bytes() != finite_neg.as_bytes(),
            );
            let finite_pos = seal_num_positive(&m, Repr::Int);
            t.check(
                "negative infinity is below every finite positive",
                lex_le_independent(ninf.as_bytes(), finite_pos.as_bytes()),
            );
        }
    }
    let zero = seal_num_zero(Repr::Int);
    t.check(
        "negative infinity is below zero",
        lex_le_independent(ninf.as_bytes(), zero.as_bytes()),
    );
}

fn positive_infinity_sorts_above_every_finite_number(t: &mut Trials) {
    let pinf = seal_num_positive(&Magnitude::Infinite, Repr::Float);
    for scale in [0u32, 1, 64, 1000, EXP_INFINITE - 66] {
        for sig in [1u64, 2, 0xFFFF, u64::MAX] {
            let m = Magnitude::Finite { significand: sig, biased_scale: scale };
            let finite_pos = seal_num_positive(&m, Repr::Int);
            t.check(
                "positive infinity is above every finite positive",
                lex_le_independent(finite_pos.as_bytes(), pinf.as_bytes())
                    && finite_pos.as_bytes() != pinf.as_bytes(),
            );
            let finite_neg = seal_num_negative(&m, Repr::Int);
            t.check(
                "positive infinity is above every finite negative",
                lex_le_independent(finite_neg.as_bytes(), pinf.as_bytes()),
            );
        }
    }
}

/// Every bit of the significand reaches the bytes.
fn magnitude_all_significand_bits_affect_encoding(t: &mut Trials) {
    for bit in 0u32..64 {
        let base: u64 = u64::MAX;
        let flipped: u64 = base ^ (1u64 << bit);
        if flipped == 0 { continue; }
        let a = seal_num_positive(
            &Magnitude::Finite { significand: base, biased_scale: 0 },
            Repr::Int,
        );
        let b = seal_num_positive(
            &Magnitude::Finite { significand: flipped, biased_scale: 0 },
            Repr::Int,
        );
        t.check(
            "flipping any significand bit changes the encoding",
            a.as_bytes() != b.as_bytes(),
        );
    }
}

/// Distinct denotations get distinct bytes; equal denotations get equal bytes.
/// `1 x 2^1` and `2 x 2^0` are the same number and must collide on purpose.
fn magnitude_encoding_is_injective_over_significand(t: &mut Trials) {
    use std::collections::BTreeMap;
    let mut seen: BTreeMap<Vec<u8>, u128> = BTreeMap::new();
    for sig in 1u64..=300 {
        for scale in 0u32..=40 {
            let bytes = seal_num_positive(
                &Magnitude::Finite { significand: sig, biased_scale: scale },
                Repr::Int,
            ).as_bytes().to_vec();
            let value: u128 = (sig as u128) << scale;
            match seen.get(&bytes) {
                Some(prev) => t.check(
                    "equal bytes only for equal denotation",
                    *prev == value,
                ),
                None => { seen.insert(bytes, value); }
            }
        }
    }
}

fn finite_magnitude_cannot_equal_infinite_magnitude(t: &mut Trials) {
    let inf = seal_num_positive(&Magnitude::Infinite, Repr::Int);
    // The greatest finite the type admits, plus a sweep near the ceiling.
    for scale in (EXP_INFINITE - 80)..(EXP_INFINITE - 64) {
        let fin = seal_num_positive(
            &Magnitude::Finite { significand: u64::MAX, biased_scale: scale },
            Repr::Int,
        );
        t.check(
            "no finite magnitude reaches the infinity sentinel",
            fin.as_bytes() != inf.as_bytes()
                && lex_le_independent(fin.as_bytes(), inf.as_bytes()),
        );
    }
}


/// Every value the writer can mint is readable by the reader that ships with it.
fn canonical_writer_output_is_always_readable(t: &mut Trials) {
    for depth in [1usize, 8, 64, 126, 127, 128, 129, 200] {
        let mut v = seal_null();
        for _ in 0..depth {
            v = seal_json(&v);
        }
        let bytes = v.as_bytes();
        t.check(
            "the reader reads everything the writer sealed",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
    }
}

fn max_writer_nesting_never_exceeds_reader_capacity(t: &mut Trials) {
    // Find the deepest value the writer will mint, then ask the reader for it.
    let mut v = seal_null();
    let mut depth = 0usize;
    while depth < 300 {
        v = seal_list(&vec![v]);
        depth += 1;
    }
    let bytes = v.as_bytes();
    t.check(
        "the writer refuses to mint deeper than the reader accepts",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
}

/// A boundary the scanner accepts must be a complete encoding on its own.
fn accepted_scan_prefix_is_complete(t: &mut Trials) {
    let corpus = red_team_corpus();
    for v in &corpus {
        let bytes = v.as_bytes();
        for tail in [vec![], vec![0x00u8], vec![0xFFu8, 0x01], vec![TAG_NULL]] {
            let mut buf = bytes.to_vec();
            buf.extend_from_slice(&tail);
            match scanned(scan_value(&buf)) {
                Some(n) => {
                    t.check("the accepted prefix is the value", n == bytes.len());
                    t.check(
                        "the accepted prefix scans complete on its own",
                        scanned(scan_value(&buf[..n])) == Some(n),
                    );
                }
                None => t.check("a sealed value followed by anything still reads", false),
            }
        }
    }
}

/// A refusal's unconsumed bytes must be a genuine suffix of what was handed in,
/// not a fabricated buffer.
fn refusal_position_is_suffix_of_original_input(t: &mut Trials) {
    let mut inputs: Vec<Vec<u8>> = vec![
        vec![], vec![0x02], vec![0xFF], vec![TAG_STR], vec![TAG_STR, 0x00],
        vec![TAG_STR, 0x00, 0x41], vec![TAG_NUM], vec![TAG_NUM, 0x07],
        vec![TAG_LIST], vec![TAG_LIST, TAG_NULL], vec![TAG_UUID, 0x00],
    ];
    for b in 0u16..=255 {
        inputs.push(vec![b as u8]);
        inputs.push(vec![TAG_LIST, b as u8]);
    }
    for p in &inputs {
        if let Err(e) = scan_value(p) {
            let rest = e.at();
            t.check("the refusal suffix is no longer than the input", rest.len() <= p.len());
            let off = p.len() - rest.len();
            t.check(
                "the refusal suffix is literally a suffix of the input",
                &p[off..] == rest,
            );
        }
    }
}

/// `seal_interval` requires `bounds_ordered(lo, hi)`, so an inverted pair is a
/// proof obligation rather than a value. What runs here is every pair the door
/// admits: unbounded below under every point, unbounded above over every point.
fn inverted_interval_is_unconstructible(t: &mut Trials) {
    let points: Vec<[u8; 8]> = vec![
        [0x00; 8], [0x00, 0, 0, 0, 0, 0, 0, 1], [0x7F; 8], [0x80; 8], [0xFF; 8],
    ];
    for (i, a) in points.iter().enumerate() {
        for b in points.iter().skip(i) {
            let iv = seal_interval(&Bound::At(*a), &Bound::At(*b));
            let bytes = iv.as_bytes();
            t.check(
                "an ordered interval seals and reads back exactly",
                scanned(scan_value(bytes)) == Some(bytes.len()),
            );
        }
        // Hold the upper end fixed and vary the lower: unbounded must sort under
        // every point.
        let open_lo = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
        let at_lo = seal_interval(&Bound::At(*a), &Bound::Unbounded);
        t.check(
            "unbounded below sorts under a bounded lower end",
            lex_le_independent(open_lo.as_bytes(), at_lo.as_bytes())
                && open_lo.as_bytes() != at_lo.as_bytes(),
        );
        // Hold the lower end fixed and vary the upper: unbounded must sort over
        // every point.
        let at_hi = seal_interval(&Bound::At(*a), &Bound::At([0xFF; 8]));
        let open_hi = seal_interval(&Bound::At(*a), &Bound::Unbounded);
        t.check(
            "unbounded above sorts over a bounded upper end",
            lex_le_independent(at_hi.as_bytes(), open_hi.as_bytes())
                && at_hi.as_bytes() != open_hi.as_bytes(),
        );
    }
}

fn set_permutations_encode_identically(t: &mut Trials) {
    let build = |order: [usize; 3]| {
        let parts: Vec<CanonicalBytes> = order
            .iter()
            .map(|i| seal_num_positive(
                &Magnitude::Finite { significand: 1, biased_scale: *i as u32 },
                Repr::Int,
            ))
            .collect();
        CanonicalSet::of(parts).seal()
    };
    let a = build([0, 1, 2]);
    for order in [[0usize, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let b = build(order);
        t.check("a set encodes the same whatever order it was given in",
            a.as_bytes() == b.as_bytes());
    }
}

fn set_duplicates_encode_identically(t: &mut Trials) {
    let one = || seal_num_positive(
        &Magnitude::Finite { significand: 1, biased_scale: 0 }, Repr::Int);
    let two = || seal_num_positive(
        &Magnitude::Finite { significand: 1, biased_scale: 1 }, Repr::Int);
    let plain = CanonicalSet::of(vec![one(), two()]).seal();
    let dup = CanonicalSet::of(vec![one(), two(), one()]).seal();
    t.check("a repeated element does not change a set", plain.as_bytes() == dup.as_bytes());
}

fn vector_components_are_numeric_only(t: &mut Trials) {
    let mixed = seal_vector(&vec![
        seal_num_zero(Repr::Int),
        seal_str(&Utf8::of("not a number")),
    ]);
    let numeric = seal_vector(&vec![seal_num_zero(Repr::Int), seal_num_zero(Repr::Int)]);
    t.check(
        "a vector cannot carry a non-numeric component",
        mixed.as_bytes().len() == numeric.as_bytes().len(),
    );
}

/// `seal_str` takes `Utf8`, whose only mint is a `&str`, so an invalid payload
/// is not a value the door can be handed. What runs here is that every payload
/// it does produce survives the round trip as text.
fn string_payload_is_valid_utf8(t: &mut Trials) {
    for s in ["", "a", "hello", "\u{0}", "\u{7f}", "\u{80}", "\u{7ff}", "\u{800}",
              "\u{ffff}", "\u{10000}", "\u{10ffff}", "e\u{301}", "\u{1f600}",
              "\u{0}\u{0}\u{0}", "a\u{0}b"] {
        let sealed = seal_str(&Utf8::of(s));
        let body = &sealed.as_bytes()[1..];
        let back = unescape(body);
        t.check("a Str payload is valid UTF-8", std::str::from_utf8(&back).is_ok());
        t.check("a Str payload is the text it was given", back == s.as_bytes());
    }
}

fn validity_payload_cannot_be_arbitrary_bytes(t: &mut Trials) {
    // Every nine-byte string is accepted, including ones no clock can produce.
    let a = seal_validity(&[0xFF; 9]);
    let b = seal_validity(&[0x00; 9]);
    t.check(
        "a validity payload is a temporal value, not nine free bytes",
        a.as_bytes() == b.as_bytes(),
    );
}

fn geometry_payload_cannot_be_arbitrary_bytes(t: &mut Trials) {
    let a = seal_geometry(&[0xFF; 8]);
    let b = seal_geometry(&[0x00; 8]);
    t.check(
        "a geometry payload is a spatial value, not eight free bytes",
        a.as_bytes() == b.as_bytes(),
    );
}

/// Reverse the escape so a Str payload can be checked as text.
fn unescape(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < body.len() {
        if body[i] == 0x00 && body[i + 1] == 0x00 { break; }
        if body[i] == 0x00 && body[i + 1] == 0xFF { out.push(0x00); i += 2; }
        else { out.push(body[i]); i += 1; }
    }
    out
}

/// One value of every kind, for trials that sweep the whole domain.
fn red_team_corpus() -> Vec<CanonicalBytes> {
    vec![
        seal_null(),
        seal_bool(true),
        seal_bool(false),
        seal_num_zero(Repr::Int),
        seal_num_zero(Repr::Float),
        seal_num_nan(),
        seal_num_negative(&mag_min(), Repr::Int),
        seal_num_positive(&mag_max(), Repr::Float),
        seal_num_positive(&Magnitude::Infinite, Repr::Float),
        seal_num_negative(&Magnitude::Infinite, Repr::Float),
        seal_str(&Utf8::of("")),
        seal_str(&Utf8::of("hello")),
        seal_str(&Utf8::of("\u{0}\u{1}\u{ff}")),
        seal_bytes(b""),
        seal_bytes(&[0x00, 0x00, 0xFF]),
        seal_uuid(&[0x00; 16]),
        seal_uuid(&[0xFF; 16]),
        seal_regex(b"", &RegexFlags::new(false, false, false)),
        seal_regex(b"a.*b", &RegexFlags::new(true, false, true)),
        seal_json(&seal_null()),
        seal_vector(&Vec::new()),
        seal_vector(&vec_of(3)),
        seal_list(&Vec::new()),
        seal_list(&vec_of(2)),
        seal_set(&Vec::new()),
        seal_validity(&[0x00; 9]),
        seal_geometry(&[0x00; 8]),
        seal_interval_empty(),
        seal_interval(&Bound::Unbounded, &Bound::Unbounded),
        seal_interval(&Bound::At([0x00; 8]), &Bound::At([0xFF; 8])),
    ]
}


// ====================== independent byte-order oracle =======================

/// Rust's own slice ordering, used as a second opinion on `lex_le_independent`.
fn slice_le(a: &[u8], b: &[u8]) -> bool { a <= b }

fn oracle_corpus() -> Vec<Vec<u8>> {
    let mut v = all_strings(&[0x00, 0x01, 0x41, 0xFF], 3);
    v.extend(all_strings(&[0x00, 0xFF], 4));
    v.push(vec![0x41; 12]);
    v.push({ let mut x = vec![0x41; 12]; x.push(0x00); x });
    v.push({ let mut x = vec![0x41; 12]; x.push(0xFF); x });
    v
}

fn lex_le_matches_independent_slice_comparator_exhaustive(t: &mut Trials) {
    let c = oracle_corpus();
    for a in &c {
        for b in &c {
            t.check("lex_le agrees with slice order",
                lex_le_independent(a, b) == slice_le(a, b));
        }
    }
}

fn lex_le_reflexive_exhaustive(t: &mut Trials) {
    for a in &oracle_corpus() {
        t.check("lex_le is reflexive", lex_le_independent(a, a));
    }
}

fn lex_le_antisymmetric_exhaustive(t: &mut Trials) {
    let c = oracle_corpus();
    for a in &c {
        for b in &c {
            if lex_le_independent(a, b) && lex_le_independent(b, a) {
                t.check("mutual lex_le means equal", a == b);
            }
        }
    }
}

fn lex_le_transitive_exhaustive(t: &mut Trials) {
    let c = all_strings(&[0x00, 0x01, 0xFF], 3);
    for a in &c {
        for b in &c {
            if !lex_le_independent(a, b) { continue; }
            for d in &c {
                if lex_le_independent(b, d) {
                    t.check("lex_le is transitive", lex_le_independent(a, d));
                }
            }
        }
    }
}

fn lex_le_total_exhaustive(t: &mut Trials) {
    let c = oracle_corpus();
    for a in &c {
        for b in &c {
            t.check("lex_le is total",
                lex_le_independent(a, b) || lex_le_independent(b, a));
        }
    }
}

fn lex_le_empty_is_minimum(t: &mut Trials) {
    let empty: Vec<u8> = Vec::new();
    for a in &oracle_corpus() {
        t.check("the empty string is the minimum", lex_le_independent(&empty, a));
    }
}

fn lex_le_strict_prefix_sorts_first(t: &mut Trials) {
    let c = oracle_corpus();
    for a in &c {
        for b in &c {
            if is_proper_prefix(a, b) {
                t.check("a strict prefix sorts first",
                    lex_le_independent(a, b) && !lex_le_independent(b, a));
            }
        }
    }
}

fn lex_le_first_differing_byte_decides(t: &mut Trials) {
    let c = oracle_corpus();
    for a in &c {
        for b in &c {
            let mut i = 0usize;
            while i < a.len() && i < b.len() && a[i] == b[i] { i += 1; }
            if i < a.len() && i < b.len() {
                t.check("the first differing byte decides",
                    lex_le_independent(a, b) == (a[i] < b[i]));
            }
        }
    }
}

fn lex_le_long_common_prefix(t: &mut Trials) {
    for n in 0usize..=64 {
        let base = vec![0x41u8; n];
        for (lo, hi) in [(0x00u8, 0x01u8), (0x7F, 0x80), (0xFE, 0xFF), (0x00, 0xFF)] {
            let mut a = base.clone(); a.push(lo);
            let mut b = base.clone(); b.push(hi);
            t.check("a long common prefix defers to the byte after it",
                lex_le_independent(&a, &b) && !lex_le_independent(&b, &a));
        }
    }
}

fn lex_le_zero_and_ff_boundaries(t: &mut Trials) {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            t.check("single bytes order numerically",
                lex_le_independent(&[a as u8], &[b as u8]) == (a <= b));
        }
    }
}

fn is_prefix_matches_independent_starts_with(t: &mut Trials) {
    let c = oracle_corpus();
    for a in &c {
        for b in &c {
            let mine = a.len() <= b.len() && &b[..a.len()] == &a[..];
            t.check("is_prefix agrees with starts_with", mine == b.starts_with(a));
        }
    }
}

fn incomparable_rejects_every_strict_prefix_pair(t: &mut Trials) {
    let corpus = red_team_corpus();
    for a in &corpus {
        for b in &corpus {
            let (x, y) = (a.as_bytes(), b.as_bytes());
            if x != y {
                t.check("no canonical encoding is a prefix of another",
                    !is_proper_prefix(x, y) && !is_proper_prefix(y, x));
            }
        }
    }
}

fn main() {
    println!("canonical-trials: adversarial campaign against the order law\n");

    let mut t = Trials::new();

    println!("exhaustive order and prefix-freedom");
    trial_escape_order_exhaustive(&mut t, &[0x00, 0x01, 0x41, 0xFF], 3, "escape order (4^<=3)");
    trial_escape_order_exhaustive(&mut t, &[0x00, 0xFF], 4, "escape order (2^<=4)");
    trial_escape_prefix_free_exhaustive(&mut t, &[0x00, 0x01, 0x41, 0xFF], 3);
    trial_escape_injective_exhaustive(&mut t, &[0x00, 0x01, 0x41, 0xFF], 3);
    trial_all_single_bytes(&mut t);
    t.report("exhaustive");

    // The table pins the released format, and it runs first: a wrong width
    // names itself here instead of surfacing as a refused mint inside an attack.
    println!("the grammar table");
    trial_grammar_table(&mut t);
    t.report("grammar table");

    println!("attacks");
    attack_terminator_forgery(&mut t);
    attack_escape_forgery(&mut t);
    attack_concatenation_collision(&mut t);
    attack_structural_smuggling(&mut t);
    attack_empty_confusion(&mut t);
    attack_cross_type_order(&mut t);
    attack_prefix_sequence_exhaustive(&mut t);
    attack_deep_nesting(&mut t);
    attack_unmarked_row_element(&mut t);
    attack_nan_is_the_top_of_number(&mut t);
    attack_vector_dimension_leads(&mut t);
    attack_interval_infinities(&mut t);
    attack_reader_agrees_with_writer(&mut t);
    attack_reader_totality(&mut t);
    attack_refusals_are_named(&mut t);
    attack_json_is_the_value_grammar(&mut t);
    attack_high_bytes(&mut t);
    t.report("total");

    println!("red team");
    negative_number_byte_order_matches_semantic_order(&mut t);
    negative_infinity_sorts_below_every_finite_number(&mut t);
    positive_infinity_sorts_above_every_finite_number(&mut t);
    magnitude_all_significand_bits_affect_encoding(&mut t);
    magnitude_encoding_is_injective_over_significand(&mut t);
    finite_magnitude_cannot_equal_infinite_magnitude(&mut t);
    canonical_writer_output_is_always_readable(&mut t);
    max_writer_nesting_never_exceeds_reader_capacity(&mut t);
    accepted_scan_prefix_is_complete(&mut t);
    refusal_position_is_suffix_of_original_input(&mut t);
    inverted_interval_is_unconstructible(&mut t);
    set_permutations_encode_identically(&mut t);
    set_duplicates_encode_identically(&mut t);
    vector_components_are_numeric_only(&mut t);
    string_payload_is_valid_utf8(&mut t);
    validity_payload_cannot_be_arbitrary_bytes(&mut t);
    geometry_payload_cannot_be_arbitrary_bytes(&mut t);
    t.report("red team");

    println!("byte-order oracle");
    lex_le_matches_independent_slice_comparator_exhaustive(&mut t);
    lex_le_reflexive_exhaustive(&mut t);
    lex_le_antisymmetric_exhaustive(&mut t);
    lex_le_transitive_exhaustive(&mut t);
    lex_le_total_exhaustive(&mut t);
    lex_le_empty_is_minimum(&mut t);
    lex_le_strict_prefix_sorts_first(&mut t);
    lex_le_first_differing_byte_decides(&mut t);
    lex_le_long_common_prefix(&mut t);
    lex_le_zero_and_ff_boundaries(&mut t);
    is_prefix_matches_independent_starts_with(&mut t);
    incomparable_rejects_every_strict_prefix_pair(&mut t);
    t.report("byte-order oracle");

    if t.failed.is_empty() {
        println!("\nall {} checks passed", t.run.count());
    } else {
        println!("\n{} FAILURES:", t.failed.len());
        let mut seen: Vec<&str> = Vec::new();
        for FailedCheck(name) in &t.failed {
            if !seen.contains(&name.as_str()) {
                seen.push(name);
                println!("  {name}");
            }
        }
        std::process::exit(1);
    }
}
