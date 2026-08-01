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

mod reference;
mod value;
use value::canonical;
use value::codec::CanonicalSet;

use canonical::{
    Bound, Refusal, Utf8, NumericBytes, Branches, Reason, grammar_exec, CanonicalBytes, Shape, escape, scan_value, seal_bool, seal_bytes,
    seal_geometry, seal_interval, seal_interval_empty, seal_json, seal_list, seal_null,
    seal_num_negative, seal_num_nan, seal_num_positive, seal_num_zero, seal_regex, seal_set, seal_str,
    FiniteMagnitude, Magnitude, Repr, RegexFlags, EXP_INFINITE, DIM_BYTES, MAG_BYTES,
    seal_uuid, seal_validity, seal_vector, shape_scan, Components, Geometry, RowItem, Validity,
    Wrapped, MAX_DIMENSION,
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

/// A finite magnitude, or the harness stops: a zero significand and a scale
/// that would carry the exponent out of its field are not magnitudes, and the
/// mint is where that is decided.
fn mag(significand: u64, biased_scale: u32) -> Magnitude {
    match FiniteMagnitude::of(significand, biased_scale) {
        Some(f) => Magnitude::Finite(f),
        None => {
            eprintln!("canonical-trials: {significand}x2^{biased_scale} is not a magnitude");
            std::process::exit(2)
        }
    }
}

/// The smallest finite magnitude the type admits: significand 1, scale 0.
fn mag_min() -> Magnitude {
    mag(1, 0)
}

/// The largest finite magnitude the type admits: a saturated significand at
/// the greatest scale that still leaves the exponent below the reserved one.
fn mag_max() -> Magnitude {
    mag(u64::MAX, EXP_INFINITE - 65)
}

/// `n` distinct components, so a vector's dimension is derived rather than
/// declared. Components differ by scale so no two collide.
fn vec_of(n: usize) -> Vec<NumericBytes> {
    (0..n)
        .map(|i| {
            seal_num_positive(
                &mag(1, (i % 1000) as u32),
                Repr::Int,
            )
        })
        .collect()
}

/// A scan's length, discarding the refusal. Refusal carries a borrowed suffix
/// and is deliberately not comparable, so trials that only care whether a
/// boundary was found go through this.
fn scanned(r: Result<usize, Refusal<'_>>) -> Option<usize> { r.ok() }

/// A row member. The mint refuses a value the reader could not reach inside a
/// row; every value built here is shallow, and the boundary is tested where the
/// mint is asked directly.
fn member(v: CanonicalBytes) -> RowItem {
    match RowItem::of(v) {
        Ok(m) => m,
        Err(refused) => harness_cannot_continue("row member", &refused),
    }
}

/// A wrapped value, minted the same way and for the same reason.
fn wrap(v: CanonicalBytes) -> Wrapped {
    match Wrapped::of(v) {
        Ok(w) => w,
        Err(refused) => harness_cannot_continue("wrapper", &refused),
    }
}

/// Components the harness asserts are countable: the dimension field holds
/// four billion of them and no trial here builds that many.
fn components(values: Vec<NumericBytes>) -> Components {
    match Components::of(values) {
        Ok(c) => c,
        Err(back) => {
            eprintln!("canonical-trials: {} components is too many to count", back.len());
            std::process::exit(2)
        }
    }
}

/// A validity the harness asserts is representable. Assert at the terminal
/// tick is not, and the trial that says so asks the mint directly.
fn validity(ts_micros: i64, is_assert: bool) -> Validity {
    match Validity::new(ts_micros, is_assert) {
        Some(v) => v,
        None => {
            eprintln!("canonical-trials: the validity mint refused ({ts_micros}, {is_assert})");
            std::process::exit(2)
        }
    }
}

/// A refusal here is not a failing check: the harness asked for a member or a
/// wrapper it cannot have, so there is no trial to report. Shell owns the exit,
/// and this is one.
fn harness_cannot_continue(door: &str, refused: &CanonicalBytes) -> ! {
    eprintln!(
        "canonical-trials: {door} refused a value of descent {} that the harness built as shallow",
        refused.descent(),
    );
    std::process::exit(2)
}

fn row(items: Vec<CanonicalBytes>) -> Vec<RowItem> {
    items.into_iter().map(member).collect()
}

/// Nest by hand, past what the writer will mint. A reader is judged on input no
/// writer of ours produced, so the attack has to forge the bytes itself.
fn forged_nest(inner: &[u8], levels: usize) -> Vec<u8> {
    let mut b = inner.to_vec();
    for _ in 0..levels {
        let mut o = vec![TAG_LIST];
        o.extend_from_slice(&b);
        o.push(0x01);
        b = o;
    }
    b
}

/// The deepest value the writer will mint, by wrapping until the mint refuses,
/// and the number of levels it took.
fn deepest_wrapped() -> (CanonicalBytes, usize) {
    let mut v = seal_null();
    let mut levels = 0usize;
    loop {
        match Wrapped::of(v) {
            Ok(w) => { v = seal_json(&w); levels += 1; }
            Err(back) => return (back, levels),
        }
    }
}

/// The same, for rows: one element per level.
fn deepest_nested_row() -> (CanonicalBytes, usize) {
    let mut v = seal_null();
    let mut levels = 0usize;
    loop {
        match RowItem::of(v) {
            Ok(m) => { v = seal_list(&vec![m]); levels += 1; }
            Err(back) => return (back, levels),
        }
    }
}

/// Where a refusal stopped, as an offset from the front of `input`. The
/// refusal carries the suffix it had not consumed; the offset is the caller's
/// arithmetic because only the caller knows which buffer it handed over.
fn stopped_at(input: &[u8], e: &Refusal<'_>) -> usize { input.len() - e.at().len() }

/// Lexicographic order on bytes, written independently of the encoder so the
/// specification is compared against something, not against itself.
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
    let one = seal_list(&row(vec![bytes_val(&[0x01, 0x41])]));
    let two = seal_list(&row(vec![bytes_val(&[0x01, 0x41]), bytes_val(&[0x41])]));

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
    let seq_of_empty = seal_list(&row(vec![bytes_val(&[])]));

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
        let short = seal_list(&row(vec![str_val("a")]));
        let long = seal_list(&row(vec![str_val("a"), bytes_val(&[byte])]));
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
    let mut levels = 0usize;
    loop {
        match RowItem::of(inner) {
            Ok(m) => { inner = seal_list(&vec![m]); levels += 1; }
            Err(back) => { inner = back; break; }
        }
    }
    let bytes = inner.as_bytes();
    // One opening tag and one terminator per level, plus the leaf: tag, two
    // escaped-empty bytes, and four content bytes.
    t.check("deep nesting balanced", bytes.len() == levels * 2 + 1 + 4 + 2);
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
        (seal_num_zero(Repr::Int).into_value(), 3, "Num zero: tag, class, repr tie-break"),
        (seal_num_negative(&mag_min(), Repr::Int).into_value(), 14, "Num negative: tag, class, 12"),
        (seal_num_positive(&mag_min(), Repr::Int).into_value(), 14, "Num positive: tag, class, 12"),
        (seal_str(&Utf8::of("hello")), 8, "Str: tag, content, terminator"),
        (seal_bytes(&[0x00, 0xFF]), 6, "Bytes: tag, escaped content, terminator"),
        (seal_uuid(&[0x00; 16]), 17, "Uuid: tag, 16"),
        (seal_regex(&Utf8::of("ab"), &RegexFlags::new(true, true, true)), 6, "Regex: tag, pattern, terminator, flags"),
        (seal_json(&wrap(seal_null())), 2, "Json: tag, a value"),
        (seal_vector(components(vec![seal_num_zero(Repr::Int), seal_num_zero(Repr::Int)])), 12,
            "Vector: tag, 4 dimension, two components, terminator"),
        (seal_list(&Vec::new()), 2, "List: tag, terminator"),
        (seal_set(&Vec::new()), 2, "Set: tag, terminator"),
        (seal_validity(&validity(0, true)), 10, "Validity: tag, 9"),
        (seal_interval_empty(), 2, "Interval empty: tag, marker"),
        (seal_interval(&Bound::Unbounded, &Bound::Unbounded), 4, "Interval: tag, marker, two ends"),
        (seal_interval(&Bound::At([0x00; 8]), &Bound::Unbounded), 12, "Interval: lo at"),
        (seal_geometry(&Geometry::new(0)), 9, "Geometry: tag, 8"),
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
        (seal_num_zero(Repr::Int).into_value(), TAG_NUM, "Num tag"),
        (seal_str(&Utf8::of("")), TAG_STR, "Str tag"),
        (seal_bytes(b""), TAG_BYTES, "Bytes tag"),
        (seal_uuid(&[0; 16]), TAG_UUID, "Uuid tag"),
        (seal_regex(&Utf8::of(""), &RegexFlags::new(false, false, false)), TAG_REGEX, "Regex tag"),
        (seal_json(&wrap(seal_null())), TAG_JSON, "Json tag"),
        (seal_vector(components(Vec::new())), TAG_VECTOR, "Vector tag"),
        (seal_list(&Vec::new()), TAG_LIST, "List tag"),
        (seal_set(&Vec::new()), TAG_SET, "Set tag"),
        (seal_validity(&validity(0, true)), TAG_VALIDITY, "Validity tag"),
        (seal_interval_empty(), TAG_INTERVAL, "Interval tag"),
        (seal_geometry(&Geometry::new(0)), TAG_GEOMETRY, "Geometry tag"),
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
                &mag(sig, scale),
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

    let one_big = seal_vector(components(vec![big()]));
    let two_small = seal_vector(components(vec![small(), small()]));
    t.check(
        "a shorter vector sorts under a longer one whatever the components say",
        lex_le_independent(one_big.as_bytes(), two_small.as_bytes())
            && one_big.as_bytes() != two_small.as_bytes(),
    );

    // Same dimension: now the components are what decides, componentwise.
    let a = seal_vector(components(vec![small(), small()]));
    let b = seal_vector(components(vec![small(), big()]));
    t.check(
        "at equal dimension the components decide, in order",
        lex_le_independent(a.as_bytes(), b.as_bytes()) && a.as_bytes() != b.as_bytes(),
    );

    // Dimension is compared as a number, not as text: 2 < 10 must hold, which
    // a decimal or little-endian width would get wrong.
    let d2 = seal_vector(components(vec_of(2)));
    let d10 = seal_vector(components(vec_of(10)));
    let d256 = seal_vector(components(vec_of(256)));
    t.check(
        "dimension compares numerically across a byte boundary",
        lex_le_independent(d2.as_bytes(), d10.as_bytes())
            && lex_le_independent(d10.as_bytes(), d256.as_bytes())
            && d2.as_bytes() != d10.as_bytes(),
    );

    // Exhaustive over the low dimension byte, so no single value is special.
    for n in 0usize..=255 {
        let lo = seal_vector(components(vec_of(n)));
        let hi = seal_vector(components(vec_of(n + 1)));
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
        seal_num_zero(Repr::Int).into_value(),
        seal_json(&wrap(seal_bool(true))),
        seal_list(&Vec::new()),
        seal_list(&row(vec![bytes_val(&[0x01]), bytes_val(&[0x00])])),
        seal_list(&row(vec![seal_list(&row(vec![str_val("x")]))])),
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
        deep = seal_list(&vec![member(deep)]);
    }
    t.check("nesting within the bound is read", scan_value(deep.as_bytes()).is_ok());
    let forged = forged_nest(deep.as_bytes(), 512);
    t.check("nesting past the bound is refused", scan_value(&forged).is_err());
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
    let deep = forged_nest(seal_null().as_bytes(), 400);
    match scan_value(&deep) {
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
        seal_num_zero(Repr::Int).into_value(),
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
            &mag(3, scale),
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
            &mag(256 + sig, 10),
            Repr::Int,
        );
        let b = seal_num_negative(
            &mag(256 + sig + 1, 10),
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
            let m = mag(sig, scale);
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
            let m = mag(sig, scale);
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
            &mag(base, 0),
            Repr::Int,
        );
        let b = seal_num_positive(
            &mag(flipped, 0),
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
                &mag(sig, scale),
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
            &mag(u64::MAX, scale),
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
    let mut v = seal_null();
    let mut levels = 0usize;
    loop {
        match Wrapped::of(v) {
            Ok(w) => {
                v = seal_json(&w);
                levels += 1;
                let bytes = v.as_bytes();
                t.check(
                    "the reader reads everything the writer sealed",
                    scanned(scan_value(bytes)) == Some(bytes.len()),
                );
            }
            Err(back) => { v = back; break; }
        }
    }
    // The released bound, written out here rather than read from the encoder:
    // the reader descends 128 levels, a leaf spends one of them, and each
    // wrapper spends one more, so 126 wrappers is the last that fits.
    t.check("wrapping reaches the reader's bound", levels == 126);
    t.check("the deepest value spends every level but one", v.descent() == 127);
}

/// The writer's bound is the reader's, exactly: the deepest value it will mint
/// reads, and one level more — which only a forger can write — is refused.
fn max_writer_nesting_never_exceeds_reader_capacity(t: &mut Trials) {
    for (deepest, levels) in [deepest_wrapped(), deepest_nested_row()] {
        let bytes = deepest.as_bytes();
        t.check(
            "the writer refuses to mint deeper than the reader accepts",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check("the writer nests at all", levels > 0);
        let forged = forged_nest(bytes, 1);
        match scan_value(&forged) {
            Ok(_) => t.check("one level past the writer's bound is refused", false),
            Err(e) => t.check(
                "one level past the writer's bound is refused as TooDeep",
                e.reason() == Reason::TooDeep,
            ),
        }
    }
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
        let parts: Vec<RowItem> = order
            .iter()
            .map(|i| seal_num_positive(
                &mag(1, *i as u32),
                Repr::Int,
            ).into_row_item())
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
        &mag(1, 0), Repr::Int).into_row_item();
    let two = || seal_num_positive(
        &mag(1, 1), Repr::Int).into_row_item();
    let plain = CanonicalSet::of(vec![one(), two()]).seal();
    let dup = CanonicalSet::of(vec![one(), two(), one()]).seal();
    t.check("a repeated element does not change a set", plain.as_bytes() == dup.as_bytes());
}

/// `seal_vector` takes `Vec<NumericBytes>`, whose only mints are the four
/// numeric doors, so a component of another kind is not a value the door can
/// be handed. What runs here is that every component it does accept reads back
/// as a Num, and that the row ends where the value does.
fn vector_components_are_numeric_only(t: &mut Trials) {
    for n in 0usize..=8 {
        let v = seal_vector(components(vec_of(n)));
        let bytes = v.as_bytes();
        t.check("a vector reads back exactly",
            scanned(scan_value(bytes)) == Some(bytes.len()));
        let mut at = 1 + DIM_BYTES;
        let mut counted = 0usize;
        while counted < n {
            t.check("every vector component is a Num", bytes[at] == TAG_NUM);
            match scanned(scan_value(&bytes[at..])) {
                Some(len) => { at += len; counted += 1; }
                None => { t.check("a component scans", false); break; }
            }
        }
        t.check("the component row ends where the value does", at + 1 == bytes.len());
    }
}
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

fn validity_orders_latest_first(t: &mut Trials) {
    let later = seal_validity(&validity(2, true));
    let earlier = seal_validity(&validity(1, true));
    t.check(
        "a later valid instant sorts before an earlier one",
        later.as_bytes() < earlier.as_bytes(),
    );
    let neg = seal_validity(&validity(-1, true));
    t.check(
        "instant zero sorts before instant minus one",
        seal_validity(&validity(0, true)).as_bytes() < neg.as_bytes(),
    );
    let max = seal_validity(&validity(i64::MAX, false));
    let min = seal_validity(&validity(i64::MIN, false));
    t.check(
        "the greatest instant sorts before the least",
        max.as_bytes() < min.as_bytes(),
    );
    let assert_at = seal_validity(&validity(7, true));
    let retract_at = seal_validity(&validity(7, false));
    t.check(
        "at one instant an assert sorts before a retract",
        assert_at.as_bytes() < retract_at.as_bytes(),
    );
    t.check(
        "a validity payload is a temporal value, not nine free bytes",
        seal_validity(&validity(0, true)).as_bytes()
            == seal_validity(&validity(0, true)).as_bytes(),
    );
}

fn geometry_orders_by_curve_index(t: &mut Trials) {
    for a in [0u64, 1, 255, 256, 1 << 32, u64::MAX - 1] {
        for b in [0u64, 1, 255, 256, 1 << 32, u64::MAX - 1] {
            let x = seal_geometry(&Geometry::new(a));
            let y = seal_geometry(&Geometry::new(b));
            t.check(
                "geometry byte order is curve-index order",
                (x.as_bytes() < y.as_bytes()) == (a < b),
            );
        }
    }
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
        seal_num_zero(Repr::Int).into_value(),
        seal_num_zero(Repr::Float).into_value(),
        seal_num_nan().into_value(),
        seal_num_negative(&mag_min(), Repr::Int).into_value(),
        seal_num_positive(&mag_max(), Repr::Float).into_value(),
        seal_num_positive(&Magnitude::Infinite, Repr::Float).into_value(),
        seal_num_negative(&Magnitude::Infinite, Repr::Float).into_value(),
        seal_str(&Utf8::of("")),
        seal_str(&Utf8::of("hello")),
        seal_str(&Utf8::of("\u{0}\u{1}\u{ff}")),
        seal_bytes(b""),
        seal_bytes(&[0x00, 0x00, 0xFF]),
        seal_uuid(&[0x00; 16]),
        seal_uuid(&[0xFF; 16]),
        seal_regex(&Utf8::of(""), &RegexFlags::new(false, false, false)),
        seal_regex(&Utf8::of("a.*b"), &RegexFlags::new(true, false, true)),
        seal_json(&wrap(seal_null())),
        seal_vector(components(Vec::new())),
        seal_vector(components(vec_of(3))),
        seal_list(&Vec::new()),
        seal_list(&vec_of(2).into_iter().map(|n| n.into_row_item()).collect()),
        seal_set(&Vec::new()),
        seal_validity(&validity(0, true)),
        seal_geometry(&Geometry::new(0)),
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
    validity_orders_latest_first(&mut t);
    geometry_orders_by_curve_index(&mut t);
    t.report("red team");

    validity_payload_is_nine_bytes_of_meaning(&mut t);
    validity_invalid_states_are_unconstructible(&mut t);
    validity_and_geometry_are_injective(&mut t);
    validity_golden_vectors_cover_temporal_boundaries(&mut t);
    geometry_golden_vectors_cover_spatial_boundaries(&mut t);
    geometry_payload_is_eight_bytes_of_index(&mut t);
    geometry_invalid_states_are_unconstructible(&mut t);
    t.report("validity and geometry");

    println!("independent reference");
    differential_encoder_matches_independent_reference(&mut t);
    differential_scanner_matches_independent_reference(&mut t);
    exhaustive_all_byte_strings_up_to_small_bound(&mut t);
    exhaustive_all_small_semantic_values(&mut t);
    property_random_nested_values_are_complete(&mut t);
    property_random_nested_values_are_prefix_free(&mut t);
    property_random_semantic_pairs_preserve_order(&mut t);
    property_random_semantic_values_are_injective(&mut t);
    fuzz_scan_value_never_panics(&mut t);
    fuzz_shape_scan_never_panics(&mut t);
    fuzz_delim_scan_never_panics(&mut t);
    fuzz_mutated_valid_encodings_never_overread(&mut t);
    fuzz_mutated_valid_encodings_never_have_two_readings(&mut t);
    t.report("independent reference");

    println!("construction authority");
    raw_set_sealer_has_only_canonical_set_callers(&mut t);
    public_api_does_not_expose_raw_grammar_authority(&mut t);
    t.report("construction authority");

    println!("numeric");
    numeric_classes_sort_negative_zero_positive_nan(&mut t);
    zero_int_sorts_before_zero_float(&mut t);
    equal_magnitude_int_sorts_before_float(&mut t);
    tie_break_is_consulted_only_after_magnitude(&mut t);
    magnitude_is_exactly_released_width(&mut t);
    magnitude_exponent_is_big_endian(&mut t);
    magnitude_fraction_is_big_endian(&mut t);
    magnitude_all_input_bits_affect_output(&mut t);
    magnitude_finite_constructor_is_injective(&mut t);
    magnitude_infinite_constructor_is_unique(&mut t);
    finite_domain_excludes_infinity_sentinel(&mut t);
    positive_magnitude_order_matches_semantic_order(&mut t);
    negative_magnitude_order_is_reversed_correctly(&mut t);
    negative_exponent_boundary_orders_correctly(&mut t);
    negative_fraction_boundary_orders_correctly(&mut t);
    positive_exponent_boundary_orders_correctly(&mut t);
    positive_fraction_boundary_orders_correctly(&mut t);
    fraction_carry_transition_preserves_order(&mut t);
    exponent_carry_transition_preserves_order(&mut t);
    negative_infinity_is_global_numeric_minimum(&mut t);
    positive_infinity_sorts_below_nan(&mut t);
    nan_sorts_above_every_numeric_value(&mut t);
    nan_has_exactly_one_encoding(&mut t);
    numeric_encoding_is_injective_across_classes(&mut t);
    numeric_semantic_equality_implies_identical_bytes(&mut t);
    numeric_semantic_order_matches_bytes_property(&mut t);
    numeric_total_order_matches_database_number_order(&mut t);
    numeric_golden_vectors_cover_every_boundary(&mut t);
    t.report("numeric");

    println!("strings, regex, uuid");
    empty_string_encodes_canonically(&mut t);
    empty_bytes_encodes_canonically(&mut t);
    string_prefix_sorts_before_string_extension(&mut t);
    bytes_prefix_sorts_before_bytes_extension(&mut t);
    string_order_matches_semantic_string_order(&mut t);
    bytes_order_matches_raw_byte_order(&mut t);
    string_and_bytes_same_payload_have_distinct_encodings(&mut t);
    string_rejects_invalid_utf8(&mut t);
    string_embedded_zero_roundtrips(&mut t);
    bytes_all_values_roundtrip(&mut t);
    string_golden_vectors_cover_utf8_boundaries(&mut t);
    bytes_golden_vectors_cover_zero_and_ff(&mut t);
    regex_all_eight_flag_combinations_are_unique(&mut t);
    regex_unknown_flag_bits_are_unconstructible(&mut t);
    regex_pattern_is_primary_sort_key(&mut t);
    regex_flags_are_secondary_sort_key(&mut t);
    regex_flag_bit_layout_matches_released_format(&mut t);
    regex_empty_pattern_is_canonical(&mut t);
    regex_pattern_rejects_invalid_utf8(&mut t);
    regex_encoding_is_injective(&mut t);
    regex_golden_vectors_cover_all_flags(&mut t);
    uuid_encoding_is_exactly_sixteen_bytes_after_tag(&mut t);
    uuid_encoding_is_injective(&mut t);
    uuid_order_matches_semantic_uuid_order(&mut t);
    uuid_zero_and_ff_boundaries(&mut t);
    uuid_golden_vectors_are_architecture_independent(&mut t);
    t.report("strings, regex, uuid");

    println!("json");
    json_wraps_exactly_one_complete_value(&mut t);
    json_encoding_order_matches_inner_value_order(&mut t);
    json_encoding_is_injective(&mut t);
    json_nested_lists_roundtrip(&mut t);
    json_depth_boundary_matches_reader_policy(&mut t);
    json_golden_vectors_cover_every_json_kind(&mut t);
    t.report("json");

    println!("vectors");
    vector_dimension_equals_component_count(&mut t);
    vector_dimension_is_big_endian(&mut t);
    vector_dimension_is_primary_sort_key(&mut t);
    vector_components_are_secondary_sort_key(&mut t);
    shorter_dimension_sorts_before_longer_dimension(&mut t);
    same_dimension_uses_component_lexicographic_order(&mut t);
    zero_dimension_vector_is_canonical(&mut t);
    vector_rejects_non_numeric_components(&mut t);
    vector_rejects_heterogeneous_components(&mut t);
    vector_nan_component_order_is_defined(&mut t);
    vector_encoding_is_injective(&mut t);
    vector_component_count_overflow_is_unconstructible(&mut t);
    vector_large_row_is_stack_safe(&mut t);
    vector_golden_vectors_cover_dimension_boundaries(&mut t);
    t.report("vectors");

    println!("lists and sets");
    list_preserves_element_order(&mut t);
    list_prefix_sorts_before_list_extension(&mut t);
    list_first_differing_element_decides(&mut t);
    list_encoding_is_injective(&mut t);
    empty_list_and_empty_set_are_distinct(&mut t);
    list_and_set_same_elements_are_distinct(&mut t);
    set_input_is_sorted_before_sealing(&mut t);
    set_input_is_deduplicated_before_sealing(&mut t);
    set_permutation_invariance(&mut t);
    set_duplicate_invariance(&mut t);
    set_normalization_is_idempotent(&mut t);
    set_encoding_is_injective_over_semantic_sets(&mut t);
    set_order_matches_canonical_element_order(&mut t);
    nested_list_set_values_remain_prefix_free(&mut t);
    raw_set_sealer_cannot_bypass_normalization(&mut t);
    t.report("lists and sets");

    println!("intervals");
    empty_interval_sorts_before_every_inhabited_interval(&mut t);
    empty_interval_has_exactly_one_encoding(&mut t);
    unbounded_lower_sorts_before_every_bounded_lower(&mut t);
    unbounded_upper_sorts_after_every_bounded_upper(&mut t);
    lower_endpoint_is_primary_sort_key(&mut t);
    upper_endpoint_is_secondary_sort_key(&mut t);
    fully_unbounded_interval_is_canonical(&mut t);
    point_interval_is_canonical(&mut t);
    empty_interval_cannot_collide_with_inhabited_interval(&mut t);
    lower_unbounded_marker_cannot_collide_with_timestamp(&mut t);
    upper_unbounded_marker_cannot_collide_with_timestamp(&mut t);
    interval_encoding_is_injective(&mut t);
    interval_semantic_order_matches_byte_order(&mut t);
    interval_golden_vectors_cover_all_bound_combinations(&mut t);
    t.report("intervals");

    println!("depth");
    mixed_container_nesting_boundary_is_exact(&mut t);
    wide_structure_does_not_consume_depth_budget(&mut t);
    depth_limit_prevents_stack_overflow(&mut t);
    canonical_bytes_invariant_implies_executable_readability(&mut t);
    t.report("depth");

    println!("whole domain");
    every_public_mint_produces_complete_encoding(&mut t);
    every_public_mint_produces_executable_reading(&mut t);
    every_pair_of_canonical_encodings_is_prefix_incomparable(&mut t);
    every_semantically_equal_pair_has_identical_bytes(&mut t);
    every_semantically_distinct_pair_has_distinct_bytes(&mut t);
    every_semantic_order_pair_matches_lexicographic_bytes(&mut t);
    cross_kind_order_matches_tag_order(&mut t);
    whole_domain_order_is_reflexive(&mut t);
    whole_domain_order_is_antisymmetric(&mut t);
    whole_domain_order_is_transitive(&mut t);
    whole_domain_order_is_total(&mut t);
    whole_domain_encoding_is_injective(&mut t);
    whole_domain_encoding_is_deterministic(&mut t);
    nested_whole_domain_values_preserve_order(&mut t);
    semantic_oracle_does_not_reuse_encoded_byte_comparison(&mut t);
    freeze_v1_candidate_golden_corpus(&mut t);
    t.report("whole domain");

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

// ======================= the independent reference ==========================
//
// Everything below judges the encoder against `reference`, which states the
// format a second time and shares no line with it. A trial here fails when the
// two disagree; which one is wrong is then a question for a person.

/// Build the encoder's value for a semantic one. This is the only bridge
/// between the two statements of the format, and it carries no format
/// knowledge of its own: it names doors, and the doors decide bytes.
fn built(v: &reference::Sem) -> CanonicalBytes {
    use reference::Sem;
    match v {
        Sem::Null => seal_null(),
        Sem::Bool(b) => seal_bool(*b),
        Sem::Number(n) => built_num(*n).into_value(),
        Sem::Text(s) => seal_str(&Utf8::of(s)),
        Sem::Blob(b) => seal_bytes(b),
        Sem::Uuid(id) => seal_uuid(id),
        Sem::Regex { pattern, case_insensitive, multi_line, dot_matches_new_line } => seal_regex(
            &Utf8::of(pattern),
            &RegexFlags::new(*case_insensitive, *multi_line, *dot_matches_new_line),
        ),
        Sem::Json(inner) => seal_json(&wrap(built(inner))),
        Sem::Vector(parts) => {
            seal_vector(components(parts.iter().map(|c| built_num(*c)).collect()))
        }
        Sem::List(elems) => seal_list(&row(elems.iter().map(built).collect())),
        Sem::Set(_) => match v.normalized() {
            Sem::Set(members) => {
                CanonicalSet::of(members.iter().map(|e| member(built(e)))).seal()
            }
            _ => seal_null(),
        },
        Sem::Validity { ts_micros, is_assert } => {
            seal_validity(&validity(*ts_micros, *is_assert))
        }
        Sem::Interval(None) => seal_interval_empty(),
        Sem::Interval(Some((lo, hi))) => seal_interval(&bound_of(*lo), &bound_of(*hi)),
        Sem::Geometry(curve_index) => seal_geometry(&Geometry::new(*curve_index)),
    }
}

fn bound_of(b: reference::Bound) -> Bound {
    match b {
        reference::Bound::Unbounded => Bound::Unbounded,
        reference::Bound::At(t) => Bound::At(t),
    }
}

fn repr_of(r: reference::Repr) -> Repr {
    match r {
        reference::Repr::Int => Repr::Int,
        reference::Repr::Float => Repr::Float,
    }
}

fn mag_of(m: reference::Mag) -> Magnitude {
    match m {
        reference::Mag::Infinite => Magnitude::Infinite,
        reference::Mag::Finite { significand, scale } => mag(significand, scale),
    }
}

fn built_num(n: reference::Num) -> NumericBytes {
    match n {
        reference::Num::Negative(m, t) => seal_num_negative(&mag_of(m), repr_of(t)),
        reference::Num::Zero(t) => seal_num_zero(repr_of(t)),
        reference::Num::Positive(m, t) => seal_num_positive(&mag_of(m), repr_of(t)),
        reference::Num::NotANumber => seal_num_nan(),
    }
}

/// A seeded generator. Randomness is declared here and it is reproducible: an
/// unreproducible failure is not evidence.
struct Seeded(u64);

impl Seeded {
    fn new(seed: u64) -> Seeded {
        Seeded(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let n = self.below(max_len as u64 + 1) as usize;
        (0..n).map(|_| self.byte()).collect()
    }
}

/// One magnitude the doors will accept.
fn some_mag(g: &mut Seeded) -> reference::Mag {
    match g.below(8) {
        0 => reference::Mag::Infinite,
        _ => {
            let sig = 1 + g.below(1 << 20);
            let scale = g.below(64) as u32;
            match reference::Mag::finite(sig, scale) {
                Some(m) => m,
                None => reference::Mag::Infinite,
            }
        }
    }
}

fn some_repr(g: &mut Seeded) -> reference::Repr {
    match g.below(2) {
        0 => reference::Repr::Int,
        _ => reference::Repr::Float,
    }
}

fn some_num(g: &mut Seeded) -> reference::Num {
    match g.below(4) {
        0 => reference::Num::Negative(some_mag(g), some_repr(g)),
        1 => reference::Num::Zero(some_repr(g)),
        2 => reference::Num::Positive(some_mag(g), some_repr(g)),
        _ => reference::Num::NotANumber,
    }
}

fn some_bound(g: &mut Seeded) -> reference::Bound {
    match g.below(3) {
        0 => reference::Bound::Unbounded,
        _ => {
            let mut t = [0u8; 8];
            for b in t.iter_mut() {
                *b = g.byte();
            }
            reference::Bound::At(t)
        }
    }
}

/// A random value. `fuel` bounds the nesting, so the generator cannot ask for a
/// value deeper than the writer will mint.
fn some_value(g: &mut Seeded, fuel: u32) -> reference::Sem {
    use reference::Sem;
    let leaf = fuel == 0;
    let pick = g.below(if leaf { 11 } else { 15 });
    match pick {
        0 => Sem::Null,
        1 => Sem::Bool(g.below(2) == 0),
        2 => Sem::Number(some_num(g)),
        3 => Sem::Text(
            String::from_utf8(g.bytes(6).into_iter().map(|b| b & 0x7F).collect())
                .unwrap_or_default(),
        ),
        4 => Sem::Blob(g.bytes(6)),
        5 => {
            let mut id = [0u8; 16];
            for b in id.iter_mut() {
                *b = g.byte();
            }
            Sem::Uuid(id)
        }
        6 => Sem::Regex {
            pattern: String::from_utf8(g.bytes(5).into_iter().map(|b| b & 0x7F).collect())
                .unwrap_or_default(),
            case_insensitive: g.below(2) == 0,
            multi_line: g.below(2) == 0,
            dot_matches_new_line: g.below(2) == 0,
        },
        7 => {
            let is_assert = g.below(2) == 0;
            let ts_micros = g.next() as i64;
            // Assert at the terminal tick is not a validity, so the generator
            // does not ask for one: it moves the instant, never the flag.
            let moved = match (is_assert, ts_micros == i64::MAX) {
                (true, true) => i64::MAX - 1,
                _ => ts_micros,
            };
            Sem::Validity { ts_micros: moved, is_assert }
        }
        8 => Sem::Geometry(g.next()),
        9 => Sem::Interval(None),
        10 => {
            let lo = some_bound(g);
            let hi = some_bound(g);
            // The door takes ordered ends, so the pair is put in order here
            // rather than handed over backwards.
            match ordered_pair(lo, hi) {
                Some(pair) => Sem::Interval(Some(pair)),
                None => Sem::Interval(None),
            }
        }
        11 => Sem::Vector((0..g.below(4)).map(|_| some_num(g)).collect()),
        12 => Sem::Json(Box::new(some_value(g, fuel - 1))),
        13 => Sem::List(
            (0..g.below(3))
                .map(|_| some_value(g, fuel - 1))
                .collect(),
        ),
        _ => Sem::Set(
            (0..g.below(3))
                .map(|_| some_value(g, fuel - 1))
                .collect(),
        ),
    }
}

/// Put two ends in the order the interval door requires, or refuse the pair
/// when neither ordering is the one asked for.
fn ordered_pair(
    lo: reference::Bound,
    hi: reference::Bound,
) -> Option<(reference::Bound, reference::Bound)> {
    use reference::Bound as B;
    match (lo, hi) {
        (B::Unbounded, _) | (_, B::Unbounded) => Some((lo, hi)),
        (B::At(a), B::At(b)) => match a <= b {
            true => Some((B::At(a), B::At(b))),
            false => Some((B::At(b), B::At(a))),
        },
    }
}

/// Every kind, at its edges, as semantic values. The whole-domain trials sweep
/// this corpus pairwise, so it is small on purpose and wide on purpose.
fn semantic_corpus() -> Vec<reference::Sem> {
    use reference::{Bound as B, Mag, Num, Repr as R, Sem};
    let big = Mag::finite(u64::MAX, 0).unwrap_or(Mag::Infinite);
    let small = Mag::finite(1, 0).unwrap_or(Mag::Infinite);
    let mid = Mag::finite(3, 17).unwrap_or(Mag::Infinite);
    vec![
        Sem::Null,
        Sem::Bool(false),
        Sem::Bool(true),
        Sem::Number(Num::Negative(Mag::Infinite, R::Float)),
        Sem::Number(Num::Negative(big, R::Int)),
        Sem::Number(Num::Negative(mid, R::Float)),
        Sem::Number(Num::Negative(small, R::Int)),
        Sem::Number(Num::Zero(R::Int)),
        Sem::Number(Num::Zero(R::Float)),
        Sem::Number(Num::Positive(small, R::Int)),
        Sem::Number(Num::Positive(small, R::Float)),
        Sem::Number(Num::Positive(mid, R::Int)),
        Sem::Number(Num::Positive(big, R::Float)),
        Sem::Number(Num::Positive(Mag::Infinite, R::Float)),
        Sem::Number(Num::NotANumber),
        Sem::Text(String::new()),
        Sem::Text("a".to_string()),
        Sem::Text("ab".to_string()),
        Sem::Text("b".to_string()),
        Sem::Text("\u{0}".to_string()),
        Sem::Text("\u{10ffff}".to_string()),
        Sem::Blob(Vec::new()),
        Sem::Blob(vec![0x00]),
        Sem::Blob(vec![0x00, 0x00]),
        Sem::Blob(vec![0x00, 0xFF]),
        Sem::Blob(vec![0x01]),
        Sem::Blob(vec![0xFF]),
        Sem::Uuid([0x00; 16]),
        Sem::Uuid([0xFF; 16]),
        Sem::Regex { pattern: String::new(), case_insensitive: false, multi_line: false, dot_matches_new_line: false },
        Sem::Regex { pattern: String::new(), case_insensitive: true, multi_line: true, dot_matches_new_line: true },
        Sem::Regex { pattern: "a".to_string(), case_insensitive: false, multi_line: false, dot_matches_new_line: false },
        Sem::Json(Box::new(Sem::Null)),
        Sem::Json(Box::new(Sem::Bool(true))),
        Sem::Json(Box::new(Sem::Json(Box::new(Sem::Null)))),
        Sem::Vector(Vec::new()),
        Sem::Vector(vec![Num::Zero(R::Int)]),
        Sem::Vector(vec![Num::Zero(R::Int), Num::Positive(small, R::Int)]),
        Sem::Vector(vec![Num::Negative(small, R::Int), Num::Zero(R::Int)]),
        Sem::List(Vec::new()),
        Sem::List(vec![Sem::Null]),
        Sem::List(vec![Sem::Null, Sem::Null]),
        Sem::List(vec![Sem::Bool(false)]),
        Sem::List(vec![Sem::List(vec![Sem::Null])]),
        Sem::Set(Vec::new()),
        Sem::Set(vec![Sem::Null]),
        Sem::Set(vec![Sem::Null, Sem::Bool(true)]),
        Sem::Validity { ts_micros: i64::MIN, is_assert: true },
        Sem::Validity { ts_micros: -1, is_assert: true },
        Sem::Validity { ts_micros: 0, is_assert: true },
        Sem::Validity { ts_micros: 0, is_assert: false },
        Sem::Validity { ts_micros: 1, is_assert: true },
        Sem::Validity { ts_micros: i64::MAX, is_assert: false },
        Sem::Interval(None),
        Sem::Interval(Some((B::Unbounded, B::Unbounded))),
        Sem::Interval(Some((B::Unbounded, B::At([0x00; 8])))),
        Sem::Interval(Some((B::At([0x00; 8]), B::At([0xFF; 8])))),
        Sem::Interval(Some((B::At([0xFF; 8]), B::Unbounded))),
        Sem::Geometry(0),
        Sem::Geometry(1),
        Sem::Geometry(u64::MAX),
    ]
}

fn differential_encoder_matches_independent_reference(t: &mut Trials) {
    for v in semantic_corpus() {
        t.check(
            "the encoder writes what the reference writes",
            built(&v).as_bytes() == reference::encode(&v).as_slice(),
        );
    }
    let mut g = Seeded::new(0x5EED_0001);
    for _ in 0..4000 {
        let v = some_value(&mut g, 3);
        t.check(
            "the encoder writes what the reference writes, at random",
            built(&v).as_bytes() == reference::encode(&v).as_slice(),
        );
    }
}

/// The two readings agree on every input: same acceptance, same end.
fn differential_scanner_matches_independent_reference(t: &mut Trials) {
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for v in semantic_corpus() {
        let bytes = reference::encode(&v);
        inputs.push(bytes.clone());
        let mut extended = bytes.clone();
        extended.push(0x00);
        inputs.push(extended);
        for cut in 0..bytes.len() {
            inputs.push(bytes[..cut].to_vec());
        }
    }
    let mut g = Seeded::new(0x5EED_0002);
    for _ in 0..3000 {
        inputs.push(g.bytes(12));
    }
    for p in &inputs {
        let theirs = reference::scan(p).map(|r| r.end).ok();
        let ours = scanned(scan_value(p));
        t.check("both readings accept the same inputs", theirs.is_some() == ours.is_some());
        t.check("both readings end in the same place", theirs == ours);
    }
}

/// Every byte string up to two bytes, and a wide sample of three, read the same
/// way in both statements of the format.
fn exhaustive_all_byte_strings_up_to_small_bound(t: &mut Trials) {
    let mut buf: Vec<u8> = Vec::new();
    t.check(
        "the empty input reads the same in both",
        reference::scan(&buf).map(|r| r.end).ok() == scanned(scan_value(&buf)),
    );
    for a in 0u16..=255 {
        buf = vec![a as u8];
        t.check(
            "every one-byte input reads the same in both",
            reference::scan(&buf).map(|r| r.end).ok() == scanned(scan_value(&buf)),
        );
        for b in 0u16..=255 {
            buf = vec![a as u8, b as u8];
            t.check(
                "every two-byte input reads the same in both",
                reference::scan(&buf).map(|r| r.end).ok() == scanned(scan_value(&buf)),
            );
        }
    }
    let alphabet: [u8; 8] = [0x00, 0x01, 0x05, 0x10, 0x18, 0x48, 0x60, 0xFF];
    for a in alphabet {
        for b in alphabet {
            for c in alphabet {
                let p = [a, b, c];
                t.check(
                    "every three-byte input over the structural alphabet agrees",
                    reference::scan(&p).map(|r| r.end).ok() == scanned(scan_value(&p)),
                );
            }
        }
    }
}

fn exhaustive_all_small_semantic_values(t: &mut Trials) {
    for v in semantic_corpus() {
        let bytes = built(&v);
        let p = bytes.as_bytes();
        t.check("every small value reads back whole", scanned(scan_value(p)) == Some(p.len()));
        t.check(
            "every small value reads back whole in the reference",
            reference::scan(p).map(|r| r.end).ok() == Some(p.len()),
        );
        t.check(
            "the reference agrees on how deep every small value is",
            reference::scan(p).map(|r| r.descent).ok() == Some(bytes.descent()),
        );
    }
}

fn property_random_nested_values_are_complete(t: &mut Trials) {
    let mut g = Seeded::new(0x5EED_0003);
    for _ in 0..3000 {
        let v = some_value(&mut g, 4);
        let bytes = built(&v);
        let p = bytes.as_bytes();
        t.check("a random value reads back whole", scanned(scan_value(p)) == Some(p.len()));
    }
}

fn property_random_nested_values_are_prefix_free(t: &mut Trials) {
    let mut g = Seeded::new(0x5EED_0004);
    let values: Vec<CanonicalBytes> = (0..120).map(|_| built(&some_value(&mut g, 3))).collect();
    for a in &values {
        for b in &values {
            let (x, y) = (a.as_bytes(), b.as_bytes());
            if x != y {
                t.check(
                    "no random encoding is a prefix of another",
                    !is_proper_prefix(x, y) && !is_proper_prefix(y, x),
                );
            }
        }
    }
}

fn property_random_semantic_pairs_preserve_order(t: &mut Trials) {
    let mut g = Seeded::new(0x5EED_0005);
    for _ in 0..3000 {
        let a = some_value(&mut g, 3).normalized();
        let b = some_value(&mut g, 3).normalized();
        let (x, y) = (built(&a), built(&b));
        t.check(
            "semantic order is byte order, at random",
            (a.cmp_sem(&b) == std::cmp::Ordering::Less)
                == (x.as_bytes() < y.as_bytes()),
        );
    }
}

fn property_random_semantic_values_are_injective(t: &mut Trials) {
    let mut g = Seeded::new(0x5EED_0006);
    let values: Vec<reference::Sem> = (0..200)
        .map(|_| some_value(&mut g, 3).normalized())
        .collect();
    for a in &values {
        for b in &values {
            let same_value = a.cmp_sem(b) == std::cmp::Ordering::Equal;
            let same_bytes = built(a).as_bytes() == built(b).as_bytes();
            t.check("equal values encode equal, distinct values distinct", same_value == same_bytes);
        }
    }
}

/// A corpus of hostile bytes: valid encodings, their mutations, and noise.
fn hostile_inputs(seed: u64, count: usize) -> Vec<Vec<u8>> {
    let mut g = Seeded::new(seed);
    let mut out: Vec<Vec<u8>> = Vec::new();
    let corpus: Vec<Vec<u8>> = semantic_corpus().iter().map(reference::encode).collect();
    for base in &corpus {
        out.push(base.clone());
    }
    while out.len() < count {
        let base = &corpus[g.below(corpus.len() as u64) as usize];
        let mut p = base.clone();
        match g.below(4) {
            0 => {
                if !p.is_empty() {
                    let at = g.below(p.len() as u64) as usize;
                    p[at] = g.byte();
                }
            }
            1 => {
                if !p.is_empty() {
                    let at = g.below(p.len() as u64) as usize;
                    p.truncate(at);
                }
            }
            2 => {
                let at = g.below(p.len() as u64 + 1) as usize;
                p.insert(at, g.byte());
            }
            _ => p.extend(g.bytes(4)),
        }
        out.push(p);
    }
    out
}

fn fuzz_scan_value_never_panics(t: &mut Trials) {
    for p in hostile_inputs(0x5EED_0007, 4000) {
        let survived = std::panic::catch_unwind(|| scan_value(&p).is_ok()).is_ok();
        t.check("scan_value returns on every input", survived);
    }
}

fn fuzz_shape_scan_never_panics(t: &mut Trials) {
    let g = grammar_exec();
    for p in hostile_inputs(0x5EED_0008, 2000) {
        let shapes = [Shape::Tagged, Shape::Delimited, Shape::Fixed(8), Shape::Row(Box::new(Shape::Tagged))];
        for s in &shapes {
            let survived = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                shape_scan(&g, s, &p, 0).is_ok()
            }))
            .is_ok();
            t.check("shape_scan returns on every input and shape", survived);
        }
    }
}

fn fuzz_delim_scan_never_panics(t: &mut Trials) {
    for p in hostile_inputs(0x5EED_0009, 2000) {
        let survived = std::panic::catch_unwind(|| canonical::delim_scan(&p).is_ok()).is_ok();
        t.check("delim_scan returns on every input", survived);
    }
}

fn fuzz_mutated_valid_encodings_never_overread(t: &mut Trials) {
    for p in hostile_inputs(0x5EED_000A, 4000) {
        match scan_value(&p) {
            Ok(n) => {
                t.check("a reading never claims more than it was given", n <= p.len());
                t.check(
                    "the bytes a reading claimed are a complete value on their own",
                    scanned(scan_value(&p[..n])) == Some(n),
                );
            }
            Err(e) => t.check(
                "a refusal names an offset inside the input",
                stopped_at(&p, &e) <= p.len(),
            ),
        }
    }
}

fn fuzz_mutated_valid_encodings_never_have_two_readings(t: &mut Trials) {
    for p in hostile_inputs(0x5EED_000B, 3000) {
        let first = scanned(scan_value(&p));
        let second = scanned(scan_value(&p));
        t.check("a reading is a function of its input", first == second);
        if let Some(n) = first {
            for shorter in 0..n {
                t.check(
                    "no shorter prefix is also a complete value",
                    scanned(scan_value(&p[..shorter])) != Some(shorter),
                );
            }
        }
    }
}

/// The nine bytes are a temporal value: eight for the instant, one for the
/// flag, and no room for anything else.
fn validity_payload_is_nine_bytes_of_meaning(t: &mut Trials) {
    for ts in [i64::MIN, -2, -1, 0, 1, 2, i64::MAX] {
        for is_assert in [true, false] {
            match Validity::new(ts, is_assert) {
                None => t.check(
                    "only assert at the terminal tick has no encoding",
                    is_assert && ts == i64::MAX,
                ),
                Some(v) => {
                    let sealed = seal_validity(&v);
                    let bytes = sealed.as_bytes();
                    t.check("a validity is a tag and nine payload bytes", bytes.len() == 10);
                    t.check("a validity opens with its tag", bytes[0] == TAG_VALIDITY);
                    t.check(
                        "the flag byte is assert-low",
                        bytes[9] == if is_assert { 0x00 } else { 0x01 },
                    );
                    t.check(
                        "a validity reads back whole",
                        scanned(scan_value(bytes)) == Some(bytes.len()),
                    );
                }
            }
        }
    }
}

/// Assert at the terminal tick is the one state the type refuses, and it
/// refuses it rather than encoding something else in its place.
fn validity_invalid_states_are_unconstructible(t: &mut Trials) {
    t.check(
        "assert at the terminal tick is not a validity",
        Validity::new(i64::MAX, true).is_none(),
    );
    t.check(
        "retract at the terminal tick is a validity",
        Validity::new(i64::MAX, false).is_some(),
    );
    for ts in [i64::MIN, -1, 0, 1, i64::MAX - 1] {
        t.check(
            "every other instant asserts",
            Validity::new(ts, true).is_some(),
        );
    }
}

fn validity_and_geometry_are_injective(t: &mut Trials) {
    let mut seen: Vec<(Vec<u8>, i64, bool)> = Vec::new();
    for ts in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
        for is_assert in [true, false] {
            if let Some(v) = Validity::new(ts, is_assert) {
                let bytes = seal_validity(&v).as_bytes().to_vec();
                for (other, ots, oassert) in &seen {
                    let same_value = *ots == ts && *oassert == is_assert;
                    t.check(
                        "distinct validities encode distinctly",
                        (other == &bytes) == same_value,
                    );
                }
                seen.push((bytes, ts, is_assert));
            }
        }
    }
    let mut points: Vec<(Vec<u8>, u64)> = Vec::new();
    for c in [0u64, 1, 2, 255, 256, 1 << 31, 1 << 32, u64::MAX - 1, u64::MAX] {
        let bytes = seal_geometry(&Geometry::new(c)).as_bytes().to_vec();
        for (other, oc) in &points {
            t.check(
                "distinct curve indices encode distinctly",
                (other == &bytes) == (*oc == c),
            );
        }
        points.push((bytes, c));
    }
}

/// The temporal boundaries, pinned: the ends of the instant axis, the tick
/// either side of zero, and both flags at one instant.
fn validity_golden_vectors_cover_temporal_boundaries(t: &mut Trials) {
    let cases: Vec<(i64, bool, [u8; 10])> = vec![
        (i64::MIN, true, [0x58, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]),
        (i64::MIN, false, [0x58, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
        (-1, true, [0x58, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (0, true, [0x58, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]),
        (0, false, [0x58, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
        (1, true, [0x58, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00]),
        (i64::MAX, false, [0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
    ];
    for (ts, is_assert, expected) in &cases {
        let sealed = seal_validity(&validity(*ts, *is_assert));
        t.check("a validity encodes to its pinned bytes", sealed.as_bytes() == expected);
    }
}

fn geometry_golden_vectors_cover_spatial_boundaries(t: &mut Trials) {
    let cases: Vec<(u64, [u8; 9])> = vec![
        (0, [0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (1, [0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
        (256, [0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]),
        (1 << 32, [0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        (u64::MAX, [0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ];
    for (curve_index, expected) in &cases {
        let sealed = seal_geometry(&Geometry::new(*curve_index));
        t.check("a geometry encodes to its pinned bytes", sealed.as_bytes() == expected);
    }
}

/// A curve index is eight bytes of index and nothing else: every one of the
/// 2^64 points has an encoding, and the payload is the index big-endian.
fn geometry_payload_is_eight_bytes_of_index(t: &mut Trials) {
    for c in [0u64, 1, 0x0102_0304_0506_0708, u64::MAX] {
        let sealed = seal_geometry(&Geometry::new(c));
        let bytes = sealed.as_bytes();
        t.check("a geometry is a tag and eight payload bytes", bytes.len() == 9);
        t.check("a geometry opens with its tag", bytes[0] == TAG_GEOMETRY);
        t.check("the payload is the index big-endian", bytes[1..] == c.to_be_bytes());
        t.check(
            "a geometry reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
    }
}

/// Geometry has no unconstructible state to exhibit: every `u64` is a point on
/// the curve. What IS forbidden is a caller supplying the eight bytes, and the
/// door takes a [`Geometry`], so there is no argument that could carry them.
fn geometry_invalid_states_are_unconstructible(t: &mut Trials) {
    for c in [0u64, 1, u64::MAX] {
        let from_meaning = seal_geometry(&Geometry::new(c));
        t.check(
            "the only geometry payload is one a curve index produced",
            from_meaning.as_bytes()[1..] == c.to_be_bytes(),
        );
    }
}

// ========================== the whole domain ================================
//
// One corpus, every kind, swept pairwise and in triples. The law under test is
// the foundational one: semantic order IS byte order, equal values ARE equal
// bytes, and no encoding is a prefix of another.

use std::cmp::Ordering;

/// The corpus as both statements at once: what a value means, and the bytes
/// the encoder produced for it.
fn domain() -> Vec<(reference::Sem, CanonicalBytes)> {
    semantic_corpus()
        .into_iter()
        .map(|v| {
            let normal = v.normalized();
            let bytes = built(&normal);
            (normal, bytes)
        })
        .collect()
}

fn every_public_mint_produces_complete_encoding(t: &mut Trials) {
    for v in red_team_corpus() {
        let p = v.as_bytes();
        t.check("every door mints a complete encoding", scanned(scan_value(p)) == Some(p.len()));
    }
    for (_, bytes) in domain() {
        let p = bytes.as_bytes();
        t.check("every corpus value is a complete encoding", scanned(scan_value(p)) == Some(p.len()));
    }
}

fn every_public_mint_produces_executable_reading(t: &mut Trials) {
    for v in red_team_corpus() {
        let p = v.as_bytes();
        t.check(
            "the reference reads every door's output",
            reference::scan(p).map(|r| r.end).ok() == Some(p.len()),
        );
        let g = grammar_exec();
        t.check(
            "the grammar reads every door's output",
            scanned(shape_scan(&g, &Shape::Tagged, p, 0)) == Some(p.len()),
        );
    }
}

fn every_pair_of_canonical_encodings_is_prefix_incomparable(t: &mut Trials) {
    let all = domain();
    for (_, a) in &all {
        for (_, b) in &all {
            let (x, y) = (a.as_bytes(), b.as_bytes());
            if x != y {
                t.check(
                    "no encoding in the domain is a prefix of another",
                    !is_proper_prefix(x, y) && !is_proper_prefix(y, x),
                );
            }
        }
    }
}

fn every_semantically_equal_pair_has_identical_bytes(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            if va.cmp_sem(vb) == Ordering::Equal {
                t.check("equal values encode identically", a.as_bytes() == b.as_bytes());
            }
        }
    }
    // Written differently, meaning the same: the encoder must not be able to
    // tell these apart, because nothing else in the system can.
    let same: Vec<(reference::Sem, reference::Sem)> = vec![
        (
            reference::Sem::Number(reference::Num::Positive(
                reference::Mag::finite(2, 0).unwrap_or(reference::Mag::Infinite),
                reference::Repr::Int,
            )),
            reference::Sem::Number(reference::Num::Positive(
                reference::Mag::finite(1, 1).unwrap_or(reference::Mag::Infinite),
                reference::Repr::Int,
            )),
        ),
        (
            reference::Sem::Set(vec![reference::Sem::Null, reference::Sem::Bool(true)]),
            reference::Sem::Set(vec![reference::Sem::Bool(true), reference::Sem::Null]),
        ),
        (
            reference::Sem::Set(vec![reference::Sem::Null]),
            reference::Sem::Set(vec![reference::Sem::Null, reference::Sem::Null]),
        ),
    ];
    for (a, b) in &same {
        t.check(
            "two writings of one value are one byte string",
            built(&a.normalized()).as_bytes() == built(&b.normalized()).as_bytes(),
        );
    }
}

fn every_semantically_distinct_pair_has_distinct_bytes(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            if va.cmp_sem(vb) != Ordering::Equal {
                t.check("distinct values encode distinctly", a.as_bytes() != b.as_bytes());
            }
        }
    }
}

fn every_semantic_order_pair_matches_lexicographic_bytes(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            t.check(
                "semantic order is byte order across the whole domain",
                va.cmp_sem(vb) == a.as_bytes().cmp(b.as_bytes()),
            );
        }
    }
}

/// Every kind's tag decides order against every other kind's, whatever the two
/// payloads are.
fn cross_kind_order_matches_tag_order(t: &mut Trials) {
    let all = domain();
    for (_, a) in &all {
        for (_, b) in &all {
            let (x, y) = (a.as_bytes(), b.as_bytes());
            if x[0] != y[0] {
                t.check(
                    "a payload never reaches across a tag",
                    (x < y) == (x[0] < y[0]),
                );
            }
        }
    }
}

fn whole_domain_order_is_reflexive(t: &mut Trials) {
    for (v, bytes) in domain() {
        t.check("every value equals itself semantically", v.cmp_sem(&v) == Ordering::Equal);
        t.check(
            "every value equals itself in bytes",
            bytes.as_bytes().cmp(bytes.as_bytes()) == Ordering::Equal,
        );
    }
}

fn whole_domain_order_is_antisymmetric(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            let forward = va.cmp_sem(vb);
            let backward = vb.cmp_sem(va);
            t.check("the order reverses when its arguments do", forward == backward.reverse());
            if forward == Ordering::Equal {
                t.check("mutual order means equal bytes", a.as_bytes() == b.as_bytes());
            }
        }
    }
}

fn whole_domain_order_is_transitive(t: &mut Trials) {
    let all = domain();
    for (va, _) in &all {
        for (vb, _) in &all {
            if va.cmp_sem(vb) != Ordering::Greater {
                for (vc, _) in &all {
                    if vb.cmp_sem(vc) != Ordering::Greater {
                        t.check(
                            "the order is transitive over the whole domain",
                            va.cmp_sem(vc) != Ordering::Greater,
                        );
                    }
                }
            }
        }
    }
}

fn whole_domain_order_is_total(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            t.check(
                "every pair is comparable one way or the other",
                va.cmp_sem(vb) != Ordering::Greater || vb.cmp_sem(va) != Ordering::Greater,
            );
            t.check(
                "every pair of encodings is comparable",
                a.as_bytes() <= b.as_bytes() || b.as_bytes() <= a.as_bytes(),
            );
        }
    }
}

fn whole_domain_encoding_is_injective(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            t.check(
                "one byte string means one value",
                (a.as_bytes() == b.as_bytes()) == (va.cmp_sem(vb) == Ordering::Equal),
            );
        }
    }
}

fn whole_domain_encoding_is_deterministic(t: &mut Trials) {
    for (v, once) in domain() {
        for _ in 0..3 {
            t.check(
                "sealing a value twice gives one byte string",
                built(&v).as_bytes() == once.as_bytes(),
            );
        }
    }
}

/// Order survives being carried: inside a wrapper and inside a row, two values
/// keep the order they had on their own.
fn nested_whole_domain_values_preserve_order(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            let flat = a.as_bytes().cmp(b.as_bytes());
            let wrapped_a = seal_json(&wrap(built(va)));
            let wrapped_b = seal_json(&wrap(built(vb)));
            t.check(
                "wrapping preserves order",
                wrapped_a.as_bytes().cmp(wrapped_b.as_bytes()) == flat,
            );
            let listed_a = seal_list(&row(vec![built(va)]));
            let listed_b = seal_list(&row(vec![built(vb)]));
            t.check(
                "a row of one preserves order",
                listed_a.as_bytes().cmp(listed_b.as_bytes()) == flat,
            );
        }
    }
}

/// The oracle is checked against arithmetic, not against the bytes it is
/// supposed to be independent of. A magnitude small enough to hold in an `i128`
/// is compared as a number; the oracle must agree.
fn semantic_oracle_does_not_reuse_encoded_byte_comparison(t: &mut Trials) {
    use reference::{Mag, Num, Repr as R, Sem};
    let pairs: Vec<(u64, u32)> = vec![
        (1, 0), (2, 0), (3, 0), (1, 1), (1, 2), (5, 3), (3, 17), (255, 8),
        (1 << 20, 0), (1, 20), (7, 40), (u32::MAX as u64, 1),
    ];
    let value = |sig: u64, scale: u32| (sig as i128) << scale;
    for (sa, ka) in &pairs {
        for (sb, kb) in &pairs {
            let (ma, mb) = (Mag::finite(*sa, *ka), Mag::finite(*sb, *kb));
            match (ma, mb) {
                (Some(x), Some(y)) => {
                    let arithmetic = value(*sa, *ka).cmp(&value(*sb, *kb));
                    let positive = Sem::Number(Num::Positive(x, R::Int))
                        .cmp_sem(&Sem::Number(Num::Positive(y, R::Int)));
                    t.check("the oracle orders positives as arithmetic does", positive == arithmetic);
                    let negative = Sem::Number(Num::Negative(x, R::Int))
                        .cmp_sem(&Sem::Number(Num::Negative(y, R::Int)));
                    t.check(
                        "the oracle orders negatives as arithmetic reversed",
                        negative == arithmetic.reverse(),
                    );
                }
                _ => t.check("a magnitude in range is a magnitude", false),
            }
        }
    }
    // The classes, in the order the number line puts them.
    let line = vec![
        Sem::Number(Num::Negative(Mag::Infinite, R::Int)),
        Sem::Number(Num::Negative(Mag::finite(1, 0).unwrap_or(Mag::Infinite), R::Int)),
        Sem::Number(Num::Zero(R::Int)),
        Sem::Number(Num::Positive(Mag::finite(1, 0).unwrap_or(Mag::Infinite), R::Int)),
        Sem::Number(Num::Positive(Mag::Infinite, R::Int)),
        Sem::Number(Num::NotANumber),
    ];
    for i in 0..line.len() {
        for j in 0..line.len() {
            t.check(
                "the oracle puts the number classes on the line in order",
                line[i].cmp_sem(&line[j]) == i.cmp(&j),
            );
        }
    }
}

/// The v1 candidate corpus, frozen. These are the bytes the format promises;
/// a change here is a format break, and the trial exists so that the break is
/// a decision somebody made rather than one that happened.
const GOLDEN_V1: [&str; 61] = [
    "05",
    "08",
    "09",
    "1001000000000000000000000001",
    "1001ffbf0000000000000000ff00",
    "1001ffec3fffffffffffffffff01",
    "1001fffe7fffffffffffffffff00",
    "100200",
    "100201",
    "1003000180000000000000000000",
    "1003000180000000000000000001",
    "10030013c0000000000000000000",
    "10030040ffffffffffffffff0001",
    "1003ffffffffffffffffffffff01",
    "100401",
    "180000",
    "18610000",
    "1861620000",
    "18620000",
    "1800ff0000",
    "18f48fbfbf0000",
    "200000",
    "2000ff0000",
    "2000ff00ff0000",
    "2000ffff0000",
    "20010000",
    "20ff0000",
    "2800000000000000000000000000000000",
    "28ffffffffffffffffffffffffffffffff",
    "30000000",
    "30000007",
    "3061000000",
    "3805",
    "3809",
    "383805",
    "400000000001",
    "400000000110020001",
    "4000000002100200100300018000000000000000000001",
    "40000000021001fffe7fffffffffffffffff0010020001",
    "4801",
    "480501",
    "48050501",
    "480801",
    "4848050101",
    "5001",
    "500501",
    "50050901",
    "58ffffffffffffffff00",
    "58800000000000000000",
    "587fffffffffffffff00",
    "587fffffffffffffff01",
    "587ffffffffffffffe00",
    "58000000000000000001",
    "6001",
    "60020103",
    "600201020000000000000000",
    "600202000000000000000002ffffffffffffffff",
    "600202ffffffffffffffff03",
    "680000000000000000",
    "680000000000000001",
    "68ffffffffffffffff",
];

fn freeze_v1_candidate_golden_corpus(t: &mut Trials) {
    let all = domain();
    t.check(
        "the frozen corpus covers the domain corpus exactly",
        all.len() == GOLDEN_V1.len(),
    );
    for (i, (_, bytes)) in all.iter().enumerate() {
        let hex: String = bytes.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        t.check("every value still encodes to its frozen bytes", hex == GOLDEN_V1[i]);
    }
}

/// Wrappers and rows spend from the same budget, so alternating them lands on
/// the same bound as either alone.
fn mixed_container_nesting_boundary_is_exact(t: &mut Trials) {
    let mut v = seal_null();
    let mut levels = 0usize;
    loop {
        let wrapped = match Wrapped::of(v) {
            Ok(w) => seal_json(&w),
            Err(back) => {
                v = back;
                break;
            }
        };
        match RowItem::of(wrapped) {
            Ok(m) => {
                v = seal_list(&vec![m]);
                levels += 1;
            }
            Err(back) => {
                v = back;
                break;
            }
        }
    }
    let bytes = v.as_bytes();
    t.check("alternating containers nest at all", levels > 0);
    t.check(
        "a mixed nest reads back whole",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
    t.check(
        "a mixed nest stops within one level of the bound",
        v.descent() >= 126,
    );
    let forged = forged_nest(bytes, 2);
    match scan_value(&forged) {
        Ok(_) => t.check("two levels past a mixed nest is refused", false),
        Err(e) => t.check(
            "two levels past a mixed nest is refused as TooDeep",
            e.reason() == Reason::TooDeep,
        ),
    }
}

/// Width is not depth. A row with many members spends one level, not one per
/// member, and the reader must read all of them.
fn wide_structure_does_not_consume_depth_budget(t: &mut Trials) {
    for width in [1usize, 10, 100, 1000, 5000] {
        let members: Vec<RowItem> = (0..width).map(|_| member(seal_null())).collect();
        let wide = seal_list(&members);
        let bytes = wide.as_bytes();
        t.check("a wide row spends one level", wide.descent() == 3);
        t.check(
            "a wide row reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check("a wide row is its members and its frame", bytes.len() == width + 2);
    }
}

/// The reader refuses before it descends, so forged input far past the bound
/// returns rather than exhausting the stack.
fn depth_limit_prevents_stack_overflow(t: &mut Trials) {
    for levels in [200usize, 1000, 10_000, 100_000] {
        let forged = forged_nest(seal_null().as_bytes(), levels);
        match scan_value(&forged) {
            Ok(_) => t.check("a forged deep nest is refused", false),
            Err(e) => t.check(
                "a forged deep nest is refused as TooDeep, however deep",
                e.reason() == Reason::TooDeep,
            ),
        }
        t.check(
            "the reference refuses the same forged nest",
            reference::scan(&forged).is_err(),
        );
    }
}

/// The type invariant is the readability guarantee: anything that IS a
/// `CanonicalBytes` reads back whole, whatever door built it.
fn canonical_bytes_invariant_implies_executable_readability(t: &mut Trials) {
    let mut g = Seeded::new(0x5EED_000C);
    for _ in 0..2000 {
        let v = built(&some_value(&mut g, 5));
        let bytes = v.as_bytes();
        t.check(
            "every CanonicalBytes reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check(
            "every CanonicalBytes is within the reader's descent",
            v.descent() <= 127,
        );
    }
    for v in red_team_corpus() {
        let bytes = v.as_bytes();
        t.check(
            "every door's output reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
    }
}

// ============================== intervals ===================================
//
// An interval's order is two axes, not one: unbounded below is the least point
// of the lower axis and unbounded above the greatest of the upper. The trials
// below hold both axes against the bytes at once.

/// Every interval, as a semantic value, with its ends in order.
fn interval_corpus() -> Vec<(Option<(reference::Bound, reference::Bound)>, CanonicalBytes)> {
    use reference::Bound as B;
    let stamps: [[u8; 8]; 5] = [
        [0x00; 8],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x7F; 8],
        [0xFF; 8],
    ];
    let mut ends: Vec<B> = vec![B::Unbounded];
    for s in stamps {
        ends.push(B::At(s));
    }
    let mut out: Vec<(Option<(B, B)>, CanonicalBytes)> = vec![(None, seal_interval_empty())];
    for lo in &ends {
        for hi in &ends {
            match ordered_lo_hi(*lo, *hi) {
                None => {}
                Some(()) => out.push((
                    Some((*lo, *hi)),
                    seal_interval(&bound_of(*lo), &bound_of(*hi)),
                )),
            }
        }
    }
    out
}

/// Whether the pair is one the door accepts: the lower end at or below the
/// upper one.
fn ordered_lo_hi(lo: reference::Bound, hi: reference::Bound) -> Option<()> {
    use reference::Bound as B;
    match (lo, hi) {
        (B::Unbounded, _) | (_, B::Unbounded) => Some(()),
        (B::At(a), B::At(b)) => match a <= b {
            true => Some(()),
            false => None,
        },
    }
}

fn empty_interval_sorts_before_every_inhabited_interval(t: &mut Trials) {
    let empty = seal_interval_empty();
    for (kind, bytes) in interval_corpus() {
        if kind.is_some() {
            t.check(
                "the empty interval sorts below every inhabited one",
                empty.as_bytes() < bytes.as_bytes(),
            );
        }
    }
}

fn empty_interval_has_exactly_one_encoding(t: &mut Trials) {
    let a = seal_interval_empty();
    let b = seal_interval_empty();
    t.check("the empty interval has one encoding", a.as_bytes() == b.as_bytes());
    t.check("the empty interval is a tag and a marker", a.as_bytes().len() == 2);
    t.check(
        "the empty interval opens with the interval tag",
        a.as_bytes()[0] == TAG_INTERVAL,
    );
}

fn unbounded_lower_sorts_before_every_bounded_lower(t: &mut Trials) {
    use reference::Bound as B;
    let open = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    for (kind, bytes) in interval_corpus() {
        match kind {
            Some((B::At(_), _)) => t.check(
                "an unbounded lower end sorts below every instant",
                open.as_bytes() < bytes.as_bytes(),
            ),
            _ => {}
        }
    }
}

fn unbounded_upper_sorts_after_every_bounded_upper(t: &mut Trials) {
    use reference::Bound as B;
    for (kind, bytes) in interval_corpus() {
        match kind {
            Some((lo, B::At(_))) => {
                let open_above = seal_interval(&bound_of(lo), &Bound::Unbounded);
                t.check(
                    "an unbounded upper end sorts above every instant",
                    bytes.as_bytes() < open_above.as_bytes(),
                )
            }
            _ => {}
        }
    }
}

fn lower_endpoint_is_primary_sort_key(t: &mut Trials) {
    use reference::Bound as B;
    let all = interval_corpus();
    for (ka, a) in &all {
        for (kb, b) in &all {
            match (ka, kb) {
                (Some((la, _)), Some((lb, _))) => {
                    let lower = cmp_bound_low(*la, *lb);
                    if lower != Ordering::Equal {
                        t.check(
                            "the lower end decides before the upper is read",
                            a.as_bytes().cmp(b.as_bytes()) == lower,
                        );
                    }
                }
                _ => {}
            }
        }
    }
    let _ = B::Unbounded;
}

fn upper_endpoint_is_secondary_sort_key(t: &mut Trials) {
    let all = interval_corpus();
    for (ka, a) in &all {
        for (kb, b) in &all {
            match (ka, kb) {
                (Some((la, ha)), Some((lb, hb))) => {
                    if cmp_bound_low(*la, *lb) == Ordering::Equal {
                        t.check(
                            "equal lower ends are decided by the upper one",
                            a.as_bytes().cmp(b.as_bytes()) == cmp_bound_high(*ha, *hb),
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

fn cmp_bound_low(a: reference::Bound, b: reference::Bound) -> Ordering {
    use reference::Bound as B;
    match (a, b) {
        (B::Unbounded, B::Unbounded) => Ordering::Equal,
        (B::Unbounded, B::At(_)) => Ordering::Less,
        (B::At(_), B::Unbounded) => Ordering::Greater,
        (B::At(x), B::At(y)) => x.cmp(&y),
    }
}

fn cmp_bound_high(a: reference::Bound, b: reference::Bound) -> Ordering {
    use reference::Bound as B;
    match (a, b) {
        (B::Unbounded, B::Unbounded) => Ordering::Equal,
        (B::Unbounded, B::At(_)) => Ordering::Greater,
        (B::At(_), B::Unbounded) => Ordering::Less,
        (B::At(x), B::At(y)) => x.cmp(&y),
    }
}

fn fully_unbounded_interval_is_canonical(t: &mut Trials) {
    let open = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    let again = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    let bytes = open.as_bytes();
    t.check("the open interval has one encoding", bytes == again.as_bytes());
    t.check(
        "the open interval reads back whole",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
    t.check(
        "the open interval is tag, marker, and two end markers",
        bytes.len() == 4,
    );
}

fn point_interval_is_canonical(t: &mut Trials) {
    for stamp in [[0x00u8; 8], [0x7F; 8], [0xFF; 8]] {
        let point = seal_interval(&Bound::At(stamp), &Bound::At(stamp));
        let bytes = point.as_bytes();
        t.check(
            "a point interval reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check(
            "a point interval is both ends written out",
            bytes.len() == 2 + 9 + 9,
        );
        t.check(
            "a point interval has one encoding",
            bytes == seal_interval(&Bound::At(stamp), &Bound::At(stamp)).as_bytes(),
        );
    }
}

fn empty_interval_cannot_collide_with_inhabited_interval(t: &mut Trials) {
    let empty = seal_interval_empty();
    for (kind, bytes) in interval_corpus() {
        if kind.is_some() {
            t.check(
                "the empty interval is not an inhabited one",
                empty.as_bytes() != bytes.as_bytes(),
            );
            t.check(
                "the empty interval is not a prefix of an inhabited one",
                !is_proper_prefix(empty.as_bytes(), bytes.as_bytes()),
            );
        }
    }
}

/// The marker that means "no lower bound" must not be a byte an instant can
/// open with, or an unbounded end would read as a timestamp.
fn lower_unbounded_marker_cannot_collide_with_timestamp(t: &mut Trials) {
    let open = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    let marker = open.as_bytes()[2];
    for first in 0u16..=255 {
        let mut stamp = [0u8; 8];
        stamp[0] = first as u8;
        let bounded = seal_interval(&Bound::At(stamp), &Bound::Unbounded);
        t.check(
            "an instant never opens with the unbounded-lower marker",
            bounded.as_bytes()[2] != marker,
        );
        t.check(
            "the unbounded lower end sorts below every instant",
            open.as_bytes() < bounded.as_bytes(),
        );
    }
}

fn upper_unbounded_marker_cannot_collide_with_timestamp(t: &mut Trials) {
    let open = seal_interval(&Bound::Unbounded, &Bound::Unbounded);
    let marker = open.as_bytes()[3];
    for first in 0u16..=255 {
        let mut stamp = [0u8; 8];
        stamp[0] = first as u8;
        let bounded = seal_interval(&Bound::Unbounded, &Bound::At(stamp));
        t.check(
            "an instant never opens with the unbounded-upper marker",
            bounded.as_bytes()[2] != marker,
        );
        t.check(
            "the unbounded upper end sorts above every instant",
            bounded.as_bytes() < open.as_bytes(),
        );
    }
}

fn interval_encoding_is_injective(t: &mut Trials) {
    let all = interval_corpus();
    for (ka, a) in &all {
        for (kb, b) in &all {
            t.check(
                "one interval, one byte string",
                (a.as_bytes() == b.as_bytes()) == (ka == kb),
            );
        }
    }
}

fn interval_semantic_order_matches_byte_order(t: &mut Trials) {
    let all = interval_corpus();
    for (ka, a) in &all {
        for (kb, b) in &all {
            let semantic = match (ka, kb) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some((la, ha)), Some((lb, hb))) => {
                    cmp_bound_low(*la, *lb).then(cmp_bound_high(*ha, *hb))
                }
            };
            t.check(
                "interval order is byte order",
                a.as_bytes().cmp(b.as_bytes()) == semantic,
            );
        }
    }
}

fn interval_golden_vectors_cover_all_bound_combinations(t: &mut Trials) {
    let zero = [0x00u8; 8];
    let ones = [0xFFu8; 8];
    let cases: Vec<(CanonicalBytes, Vec<u8>)> = vec![
        (seal_interval_empty(), vec![0x60, 0x01]),
        (
            seal_interval(&Bound::Unbounded, &Bound::Unbounded),
            vec![0x60, 0x02, 0x01, 0x03],
        ),
        (
            seal_interval(&Bound::Unbounded, &Bound::At(zero)),
            vec![0x60, 0x02, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            seal_interval(&Bound::At(zero), &Bound::Unbounded),
            vec![0x60, 0x02, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x03],
        ),
        (
            seal_interval(&Bound::At(zero), &Bound::At(ones)),
            vec![
                0x60, 0x02, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ],
        ),
    ];
    for (sealed, expected) in &cases {
        t.check(
            "an interval encodes to its pinned bytes",
            sealed.as_bytes() == expected.as_slice(),
        );
    }
}

// ============================= lists and sets ===============================
//
// A row is ordered and a set is not, which is the whole difference: the list
// door writes what it is handed, and the set door decides what it was handed
// means before it writes anything.

/// A short list of leaf values, by index, so the trials can name what they
/// built without repeating it.
fn leaf(i: usize) -> CanonicalBytes {
    match i {
        0 => seal_null(),
        1 => seal_bool(false),
        2 => seal_bool(true),
        3 => seal_str(&Utf8::of("")),
        4 => seal_str(&Utf8::of("a")),
        5 => seal_str(&Utf8::of("b")),
        6 => seal_bytes(&[0x00]),
        _ => seal_bytes(&[0xFF]),
    }
}

fn list_of(indices: &[usize]) -> CanonicalBytes {
    seal_list(&row(indices.iter().map(|i| leaf(*i)).collect()))
}

fn set_of(indices: &[usize]) -> CanonicalBytes {
    CanonicalSet::of(indices.iter().map(|i| member(leaf(*i)))).seal()
}

fn list_preserves_element_order(t: &mut Trials) {
    let ab = list_of(&[4, 5]);
    let ba = list_of(&[5, 4]);
    t.check("a list keeps the order it was given", ab.as_bytes() != ba.as_bytes());
    t.check("the earlier element decides", ab.as_bytes() < ba.as_bytes());
    for i in 0..8usize {
        for j in 0..8usize {
            let x = list_of(&[i, j]);
            let y = list_of(&[j, i]);
            t.check(
                "a list of two orders by its first element",
                (x.as_bytes() < y.as_bytes())
                    == (leaf(i).as_bytes() < leaf(j).as_bytes()),
            );
        }
    }
}

fn list_prefix_sorts_before_list_extension(t: &mut Trials) {
    for i in 0..8usize {
        let short = list_of(&[i]);
        for j in 0..8usize {
            let long = list_of(&[i, j]);
            t.check(
                "a list sorts before its own extension",
                short.as_bytes() < long.as_bytes(),
            );
            t.check(
                "a list is not a byte prefix of its extension",
                !is_proper_prefix(short.as_bytes(), long.as_bytes()),
            );
        }
    }
}

fn list_first_differing_element_decides(t: &mut Trials) {
    for i in 0..8usize {
        for j in 0..8usize {
            if i == j {
                continue;
            }
            let a = list_of(&[0, i, 7]);
            let b = list_of(&[0, j, 0]);
            t.check(
                "the first element that differs decides the list",
                (a.as_bytes() < b.as_bytes())
                    == (leaf(i).as_bytes() < leaf(j).as_bytes()),
            );
        }
    }
}

fn list_encoding_is_injective(t: &mut Trials) {
    let shapes: Vec<Vec<usize>> = vec![
        vec![],
        vec![0],
        vec![1],
        vec![0, 0],
        vec![0, 1],
        vec![1, 0],
        vec![0, 0, 0],
        vec![4, 5],
        vec![5, 4],
    ];
    for a in &shapes {
        for b in &shapes {
            t.check(
                "one list, one byte string",
                (list_of(a).as_bytes() == list_of(b).as_bytes()) == (a == b),
            );
        }
    }
}

fn empty_list_and_empty_set_are_distinct(t: &mut Trials) {
    let list = seal_list(&Vec::new());
    let set = set_of(&[]);
    t.check("an empty list is not an empty set", list.as_bytes() != set.as_bytes());
    t.check("a list sorts below a set", list.as_bytes() < set.as_bytes());
    t.check("both read back whole", scanned(scan_value(list.as_bytes())) == Some(2));
    t.check("both read back whole", scanned(scan_value(set.as_bytes())) == Some(2));
}

fn list_and_set_same_elements_are_distinct(t: &mut Trials) {
    for members in [vec![0usize], vec![4, 5], vec![0, 1, 2]] {
        let list = list_of(&members);
        let set = set_of(&members);
        t.check(
            "a list and a set of the same members are different values",
            list.as_bytes() != set.as_bytes(),
        );
        t.check(
            "the two differ in their tag, not their contents",
            list.as_bytes()[1..] == set.as_bytes()[1..],
        );
    }
}

fn set_input_is_sorted_before_sealing(t: &mut Trials) {
    let given = set_of(&[5, 4, 0]);
    let sorted = set_of(&[0, 4, 5]);
    t.check("a set is sealed in order", given.as_bytes() == sorted.as_bytes());
    // Read the row back and check it ascends, rather than trusting the door.
    let body = &given.as_bytes()[1..given.as_bytes().len() - 1];
    let mut at = 0usize;
    let mut previous: Option<Vec<u8>> = None;
    while at < body.len() {
        match scan_value(&body[at..]) {
            Ok(n) => {
                let element = body[at..at + n].to_vec();
                if let Some(before) = &previous {
                    t.check("members come out ascending", before.as_slice() < element.as_slice());
                }
                previous = Some(element);
                at += n;
            }
            Err(_) => {
                t.check("a set body is a row of whole values", false);
                return;
            }
        }
    }
}

fn set_input_is_deduplicated_before_sealing(t: &mut Trials) {
    for i in 0..8usize {
        let once = set_of(&[i]);
        let thrice = set_of(&[i, i, i]);
        t.check("a repeated member is one member", once.as_bytes() == thrice.as_bytes());
        t.check(
            "a set of one is its member and its frame",
            once.as_bytes().len() == leaf(i).as_bytes().len() + 2,
        );
    }
}

fn set_permutation_invariance(t: &mut Trials) {
    let base = [0usize, 4, 5];
    let expected = set_of(&base);
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let permuted: Vec<usize> = order.iter().map(|k| base[*k]).collect();
        t.check(
            "a set encodes the same however it is ordered",
            set_of(&permuted).as_bytes() == expected.as_bytes(),
        );
    }
}

fn set_duplicate_invariance(t: &mut Trials) {
    let expected = set_of(&[0, 4, 5]);
    for repeated in [
        vec![0usize, 0, 4, 5],
        vec![0, 4, 4, 5],
        vec![0, 4, 5, 5],
        vec![5, 4, 0, 5, 4, 0],
    ] {
        t.check(
            "repeats do not change a set",
            set_of(&repeated).as_bytes() == expected.as_bytes(),
        );
    }
}

/// Normalising a set twice is normalising it once. The second pass is the
/// reference's, so the two normalisations have to land on the same members for
/// this to hold rather than merely agreeing with themselves.
fn set_normalization_is_idempotent(t: &mut Trials) {
    use reference::Sem;
    let sets: Vec<Vec<Sem>> = vec![
        vec![Sem::Bool(true), Sem::Bool(false), Sem::Null],
        vec![Sem::Null, Sem::Null, Sem::Bool(true)],
        vec![Sem::Text("b".to_string()), Sem::Text("a".to_string()), Sem::Null],
        Vec::new(),
    ];
    for given in &sets {
        let raw = Sem::Set(given.clone());
        let once = raw.normalized();
        let twice = once.normalized();
        t.check("the reference normalises to a fixpoint", once == twice);
        let sealed_raw = built(&raw);
        let sealed_once = built(&once);
        t.check(
            "the encoder lands on the same members the reference does",
            sealed_raw.as_bytes() == sealed_once.as_bytes(),
        );
        let members = match &once {
            Sem::Set(m) => m.clone(),
            _ => Vec::new(),
        };
        let resealed = CanonicalSet::of(members.iter().map(|e| member(built(e)))).seal();
        t.check(
            "sealing already-normal members changes nothing",
            resealed.as_bytes() == sealed_raw.as_bytes(),
        );
        let reversed: Vec<Sem> = members.iter().rev().cloned().collect();
        let backwards = CanonicalSet::of(reversed.iter().map(|e| member(built(e)))).seal();
        t.check(
            "a normalised set handed back reversed is the same set",
            backwards.as_bytes() == sealed_raw.as_bytes(),
        );
    }
}

fn set_encoding_is_injective_over_semantic_sets(t: &mut Trials) {
    let sets: Vec<Vec<usize>> = vec![
        vec![],
        vec![0],
        vec![1],
        vec![0, 1],
        vec![0, 4],
        vec![4, 5],
        vec![0, 4, 5],
        vec![0, 1, 2, 3, 4, 5, 6, 7],
    ];
    for a in &sets {
        for b in &sets {
            t.check(
                "one semantic set, one byte string",
                (set_of(a).as_bytes() == set_of(b).as_bytes()) == (a == b),
            );
        }
    }
}

fn set_order_matches_canonical_element_order(t: &mut Trials) {
    for i in 0..8usize {
        for j in 0..8usize {
            if i == j {
                continue;
            }
            let one = set_of(&[i]);
            let other = set_of(&[j]);
            t.check(
                "a set of one orders as its member does",
                (one.as_bytes() < other.as_bytes())
                    == (leaf(i).as_bytes() < leaf(j).as_bytes()),
            );
        }
    }
}

fn nested_list_set_values_remain_prefix_free(t: &mut Trials) {
    let mut values: Vec<CanonicalBytes> = Vec::new();
    for shape in [vec![], vec![0usize], vec![0, 1], vec![4, 5]] {
        values.push(list_of(&shape));
        values.push(set_of(&shape));
        values.push(seal_list(&row(vec![list_of(&shape)])));
        values.push(seal_list(&row(vec![set_of(&shape)])));
        values.push(seal_json(&wrap(list_of(&shape))));
    }
    for a in &values {
        for b in &values {
            let (x, y) = (a.as_bytes(), b.as_bytes());
            if x != y {
                t.check(
                    "nested rows stay prefix-free",
                    !is_proper_prefix(x, y) && !is_proper_prefix(y, x),
                );
            }
        }
    }
}

/// The raw row-in-set-order door is not public, so the only way to a Set tag
/// from outside this crate is through the door that normalises. What runs here
/// is that the two doors disagree exactly when the input is not already
/// normal — which is why the raw one is not exported.
fn raw_set_sealer_cannot_bypass_normalization(t: &mut Trials) {
    let unsorted = vec![member(leaf(5)), member(leaf(4))];
    let raw = canonical::seal_set(&unsorted);
    let normalised = set_of(&[5, 4]);
    t.check(
        "the raw door writes the order it is given",
        raw.as_bytes() != normalised.as_bytes(),
    );
    let already = vec![member(leaf(4)), member(leaf(5))];
    t.check(
        "the two doors agree on an input that is already normal",
        canonical::seal_set(&already).as_bytes() == normalised.as_bytes(),
    );
    let duplicated = vec![member(leaf(4)), member(leaf(4))];
    t.check(
        "the raw door writes a repeat the public door would drop",
        canonical::seal_set(&duplicated).as_bytes() != set_of(&[4, 4]).as_bytes(),
    );
}

// ================================ vectors ===================================
//
// A vector is a length and then its components, and the length leads: two
// vectors of different dimension order by dimension before a single component
// is read. Everything below holds that division.

/// A component, by index, so a trial can name the vector it built.
fn part(i: usize) -> NumericBytes {
    match i {
        0 => seal_num_negative(&Magnitude::Infinite, Repr::Float),
        1 => seal_num_negative(&mag_max(), Repr::Int),
        2 => seal_num_negative(&mag_min(), Repr::Int),
        3 => seal_num_zero(Repr::Int),
        4 => seal_num_zero(Repr::Float),
        5 => seal_num_positive(&mag_min(), Repr::Int),
        6 => seal_num_positive(&mag_max(), Repr::Float),
        7 => seal_num_positive(&Magnitude::Infinite, Repr::Float),
        _ => seal_num_nan(),
    }
}

fn vector_of(indices: &[usize]) -> CanonicalBytes {
    seal_vector(components(indices.iter().map(|i| part(*i)).collect()))
}

fn vector_dimension_equals_component_count(t: &mut Trials) {
    for n in [0usize, 1, 2, 3, 8, 64, 300] {
        let indices: Vec<usize> = (0..n).map(|k| k % 9).collect();
        let v = vector_of(&indices);
        let bytes = v.as_bytes();
        let declared = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        t.check("the dimension field is the component count", declared as usize == n);
        t.check(
            "a vector reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
    }
}

fn vector_dimension_is_big_endian(t: &mut Trials) {
    for n in [0usize, 1, 255, 256, 257] {
        let indices: Vec<usize> = (0..n).map(|_| 3).collect();
        let v = vector_of(&indices);
        let bytes = v.as_bytes();
        t.check(
            "the dimension is written most significant byte first",
            bytes[1..1 + DIM_BYTES] == (n as u32).to_be_bytes(),
        );
    }
}

fn vector_dimension_is_primary_sort_key(t: &mut Trials) {
    // A short vector of the greatest components against a long vector of the
    // least: if the dimension did not lead, the components would win.
    for short in 0usize..4 {
        for long in (short + 1)..5 {
            let high: Vec<usize> = (0..short).map(|_| 8).collect();
            let low: Vec<usize> = (0..long).map(|_| 0).collect();
            t.check(
                "the dimension decides before any component is read",
                vector_of(&high).as_bytes() < vector_of(&low).as_bytes(),
            );
        }
    }
}

fn vector_components_are_secondary_sort_key(t: &mut Trials) {
    for n in 1usize..4 {
        for i in 0..9usize {
            for j in 0..9usize {
                let a: Vec<usize> = (0..n).map(|k| if k == 0 { i } else { 3 }).collect();
                let b: Vec<usize> = (0..n).map(|k| if k == 0 { j } else { 3 }).collect();
                t.check(
                    "at equal dimension the components decide",
                    vector_of(&a).as_bytes().cmp(vector_of(&b).as_bytes())
                        == part(i).as_bytes().cmp(part(j).as_bytes()),
                );
            }
        }
    }
}

fn shorter_dimension_sorts_before_longer_dimension(t: &mut Trials) {
    let mut previous: Option<CanonicalBytes> = None;
    for n in 0usize..40 {
        let indices: Vec<usize> = (0..n).map(|_| 8).collect();
        let v = vector_of(&indices);
        if let Some(before) = &previous {
            t.check(
                "a shorter vector sorts before a longer one",
                before.as_bytes() < v.as_bytes(),
            );
            t.check(
                "a shorter vector is not a prefix of a longer one",
                !is_proper_prefix(before.as_bytes(), v.as_bytes()),
            );
        }
        previous = Some(v);
    }
}

fn same_dimension_uses_component_lexicographic_order(t: &mut Trials) {
    for i in 0..9usize {
        for j in 0..9usize {
            let a = vector_of(&[3, i]);
            let b = vector_of(&[3, j]);
            t.check(
                "equal-dimension vectors compare component by component",
                a.as_bytes().cmp(b.as_bytes()) == part(i).as_bytes().cmp(part(j).as_bytes()),
            );
        }
    }
}

fn zero_dimension_vector_is_canonical(t: &mut Trials) {
    let empty = vector_of(&[]);
    let bytes = empty.as_bytes();
    t.check("an empty vector has one encoding", bytes == vector_of(&[]).as_bytes());
    t.check(
        "an empty vector is tag, dimension, terminator",
        bytes.len() == 1 + DIM_BYTES + 1,
    );
    t.check("its dimension is zero", bytes[1..1 + DIM_BYTES] == [0u8; 4]);
    t.check(
        "an empty vector reads back whole",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
    for n in 1usize..5 {
        let indices: Vec<usize> = (0..n).map(|_| 0).collect();
        t.check(
            "the empty vector sorts below every inhabited one",
            bytes < vector_of(&indices).as_bytes(),
        );
    }
}

/// The door takes `NumericBytes`, whose only mints are the four numeric doors,
/// so a component of another kind is not an argument that exists. What runs
/// here is that every component in a sealed vector reads back as a Num.
fn vector_rejects_non_numeric_components(t: &mut Trials) {
    for n in 1usize..6 {
        let indices: Vec<usize> = (0..n).map(|k| k % 9).collect();
        let v = vector_of(&indices);
        let bytes = v.as_bytes();
        let mut at = 1 + DIM_BYTES;
        let mut counted = 0usize;
        while bytes[at] != 0x01 {
            match scan_value(&bytes[at..]) {
                Ok(len) => {
                    t.check("every component opens with the Num tag", bytes[at] == TAG_NUM);
                    at += len;
                    counted += 1;
                }
                Err(_) => {
                    t.check("every component is a whole value", false);
                    return;
                }
            }
        }
        t.check("the row holds exactly the components given", counted == n);
    }
}

/// Heterogeneous components are the same argument by another name: there is no
/// `NumericBytes` that is not a number, so a mixed row cannot be handed over.
/// Every component of every vector below is a Num of a different class, and the
/// row still reads as one kind.
fn vector_rejects_heterogeneous_components(t: &mut Trials) {
    let mixed = vector_of(&[0, 3, 5, 7, 8]);
    let bytes = mixed.as_bytes();
    let mut at = 1 + DIM_BYTES;
    let mut classes: Vec<u8> = Vec::new();
    while bytes[at] != 0x01 {
        match scan_value(&bytes[at..]) {
            Ok(len) => {
                classes.push(bytes[at + 1]);
                at += len;
            }
            Err(_) => {
                t.check("a mixed vector is still a row of whole values", false);
                return;
            }
        }
    }
    t.check("every class of number is admissible as a component", classes.len() == 5);
    t.check(
        "the classes are the ones the doors were asked for",
        classes == vec![0x01, 0x02, 0x03, 0x03, 0x04],
    );
}

fn vector_nan_component_order_is_defined(t: &mut Trials) {
    let nan = vector_of(&[8]);
    for i in 0..8usize {
        let other = vector_of(&[i]);
        t.check(
            "a NaN component sorts above every number",
            other.as_bytes() < nan.as_bytes(),
        );
    }
    t.check(
        "two NaN components are one value",
        nan.as_bytes() == vector_of(&[8]).as_bytes(),
    );
    t.check(
        "NaN keeps its place inside a longer vector",
        vector_of(&[3, 7]).as_bytes() < vector_of(&[3, 8]).as_bytes(),
    );
}

fn vector_encoding_is_injective(t: &mut Trials) {
    let shapes: Vec<Vec<usize>> = vec![
        vec![],
        vec![3],
        vec![4],
        vec![3, 3],
        vec![3, 4],
        vec![4, 3],
        vec![3, 3, 3],
        vec![0, 8],
        vec![8, 0],
    ];
    for a in &shapes {
        for b in &shapes {
            t.check(
                "one vector, one byte string",
                (vector_of(a).as_bytes() == vector_of(b).as_bytes()) == (a == b),
            );
        }
    }
}

/// The dimension field holds four billion components, and a list longer than
/// that is not a `Components` — so `seal_vector` has no argument that could
/// carry a count it cannot write. The refusing arm needs 2^32 components and is
/// not executable on this machine; what runs is that every constructible count
/// is accepted and lands in the field exactly.
fn vector_component_count_overflow_is_unconstructible(t: &mut Trials) {
    t.check(
        "the dimension field's capacity is what the mint refuses past",
        MAX_DIMENSION == 1u64 << (8 * DIM_BYTES as u64),
    );
    for n in [0usize, 1, 2, 255, 256, 65_535, 65_536] {
        let values: Vec<NumericBytes> = (0..n).map(|_| seal_num_zero(Repr::Int)).collect();
        match Components::of(values) {
            Err(_) => t.check("a constructible count is countable", false),
            Ok(c) => {
                t.check("the mint counts what it was given", c.count() == n);
                let v = seal_vector(c);
                let bytes = v.as_bytes();
                t.check(
                    "the count reaches the dimension field unchanged",
                    bytes[1..1 + DIM_BYTES] == (n as u32).to_be_bytes(),
                );
            }
        }
    }
}

fn vector_large_row_is_stack_safe(t: &mut Trials) {
    for n in [1000usize, 10_000, 50_000] {
        let v = seal_vector(components(
            (0..n).map(|_| seal_num_zero(Repr::Int)).collect(),
        ));
        let bytes = v.as_bytes();
        t.check(
            "a large vector reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check("a large vector spends no extra depth", v.descent() == 4);
        t.check(
            "the reference reads a large vector too",
            reference::scan(bytes).map(|r| r.end).ok() == Some(bytes.len()),
        );
    }
}

fn vector_golden_vectors_cover_dimension_boundaries(t: &mut Trials) {
    let zero_int: Vec<u8> = vec![0x10, 0x02, 0x00];
    let cases: Vec<(CanonicalBytes, Vec<u8>)> = vec![
        (vector_of(&[]), vec![0x40, 0x00, 0x00, 0x00, 0x00, 0x01]),
        (
            vector_of(&[3]),
            [
                vec![0x40, 0x00, 0x00, 0x00, 0x01],
                zero_int.clone(),
                vec![0x01],
            ]
            .concat(),
        ),
        (
            vector_of(&[3, 3]),
            [
                vec![0x40, 0x00, 0x00, 0x00, 0x02],
                zero_int.clone(),
                zero_int.clone(),
                vec![0x01],
            ]
            .concat(),
        ),
    ];
    for (sealed, expected) in &cases {
        t.check(
            "a vector encodes to its pinned bytes",
            sealed.as_bytes() == expected.as_slice(),
        );
    }
    let wide = seal_vector(components(
        (0..256).map(|_| seal_num_zero(Repr::Int)).collect(),
    ));
    t.check(
        "a dimension of 256 crosses into the third byte",
        wide.as_bytes()[1..5] == [0x00, 0x00, 0x01, 0x00],
    );
}

// ================================= json =====================================
//
// The Json tag carries one whole value, and the value grammar is the JSON
// grammar: a wrapped value reads exactly as it does bare.

fn json_wraps_exactly_one_complete_value(t: &mut Trials) {
    for v in red_team_corpus() {
        let bare = v.as_bytes().to_vec();
        let sealed = seal_json(&wrap(v));
        let bytes = sealed.as_bytes();
        t.check("a wrapper is its tag and one value", bytes.len() == bare.len() + 1);
        t.check("a wrapper opens with the json tag", bytes[0] == TAG_JSON);
        t.check("the value follows unchanged", bytes[1..] == bare[..]);
        t.check(
            "a wrapped value reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check(
            "the wrapped value ends where the wrapper does",
            scanned(scan_value(&bytes[1..])) == Some(bare.len()),
        );
    }
}

fn json_encoding_order_matches_inner_value_order(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            let wrapped_a = seal_json(&wrap(built(va)));
            let wrapped_b = seal_json(&wrap(built(vb)));
            t.check(
                "wrapped values order as their contents do",
                wrapped_a.as_bytes().cmp(wrapped_b.as_bytes())
                    == a.as_bytes().cmp(b.as_bytes()),
            );
        }
    }
}

fn json_encoding_is_injective(t: &mut Trials) {
    let all = domain();
    for (va, a) in &all {
        for (vb, b) in &all {
            let same_inner = a.as_bytes() == b.as_bytes();
            let wrapped_a = seal_json(&wrap(built(va)));
            let wrapped_b = seal_json(&wrap(built(vb)));
            t.check(
                "one wrapped value, one byte string",
                (wrapped_a.as_bytes() == wrapped_b.as_bytes()) == same_inner,
            );
        }
    }
}

/// The nested shapes, built fresh each call so a trial can seal the same shape
/// twice without a door from bytes back to a value.
fn nested_list_shapes() -> Vec<CanonicalBytes> {
    vec![
        list_of(&[]),
        list_of(&[0]),
        list_of(&[4, 5]),
        seal_list(&row(vec![list_of(&[0]), list_of(&[])])),
        seal_list(&row(vec![seal_list(&row(vec![list_of(&[4])]))])),
    ]
}

fn json_nested_lists_roundtrip(t: &mut Trials) {
    for (i, shape) in nested_list_shapes().into_iter().enumerate() {
        let bare = shape.as_bytes().to_vec();
        let wrapped = seal_json(&wrap(shape));
        let bytes = wrapped.as_bytes();
        t.check(
            "a wrapped list reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check("the list survives the wrapper unchanged", bytes[1..] == bare[..]);
        let again = nested_list_shapes().remove(i);
        t.check(
            "wrapping is deterministic",
            seal_json(&wrap(again)).as_bytes() == bytes,
        );
    }
}

/// A wrapper spends exactly one level, so the bound on wrapping is the reader's
/// bound minus what the value inside it already spends.
fn json_depth_boundary_matches_reader_policy(t: &mut Trials) {
    let (deepest, levels) = deepest_wrapped();
    t.check("wrapping stops at the reader's bound", levels == 126);
    t.check("the deepest wrapper is one below the limit", deepest.descent() == 127);
    let bytes = deepest.as_bytes();
    t.check(
        "the deepest wrapper reads back whole",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
    t.check(
        "the reference agrees on the deepest wrapper",
        reference::scan(bytes).map(|r| r.descent).ok() == Some(127),
    );
    // One more level, which only a forger can write.
    let mut forged = vec![TAG_JSON];
    forged.extend_from_slice(bytes);
    match scan_value(&forged) {
        Ok(_) => t.check("one wrapper past the bound is refused", false),
        Err(e) => t.check(
            "one wrapper past the bound is refused as TooDeep",
            e.reason() == Reason::TooDeep,
        ),
    }
    t.check(
        "the reference refuses it too",
        reference::scan(&forged).is_err(),
    );
}

fn json_golden_vectors_cover_every_json_kind(t: &mut Trials) {
    let cases: Vec<(CanonicalBytes, Vec<u8>)> = vec![
        (seal_json(&wrap(seal_null())), vec![0x38, 0x05]),
        (seal_json(&wrap(seal_bool(false))), vec![0x38, 0x08]),
        (seal_json(&wrap(seal_bool(true))), vec![0x38, 0x09]),
        (
            seal_json(&wrap(seal_num_zero(Repr::Int).into_value())),
            vec![0x38, 0x10, 0x02, 0x00],
        ),
        (
            seal_json(&wrap(seal_str(&Utf8::of("")))),
            vec![0x38, 0x18, 0x00, 0x00],
        ),
        (
            seal_json(&wrap(seal_str(&Utf8::of("a")))),
            vec![0x38, 0x18, 0x61, 0x00, 0x00],
        ),
        (seal_json(&wrap(list_of(&[]))), vec![0x38, 0x48, 0x01]),
        (
            seal_json(&wrap(list_of(&[0]))),
            vec![0x38, 0x48, 0x05, 0x01],
        ),
        (
            seal_json(&wrap(seal_json(&wrap(seal_null())))),
            vec![0x38, 0x38, 0x05],
        ),
    ];
    for (sealed, expected) in &cases {
        t.check(
            "a wrapped value encodes to its pinned bytes",
            sealed.as_bytes() == expected.as_slice(),
        );
    }
}

// ========================= strings and byte strings =========================
//
// Two kinds share one payload shape and differ in one thing: a Str carries text
// and a Bytes carries content. The escape is the same, the tags are not, and
// nothing may cross between them.

/// The strings the trials sweep: empty, ordering neighbours, the escape byte,
/// and the edges of UTF-8.
fn text_corpus() -> Vec<String> {
    vec![
        String::new(),
        "a".to_string(),
        "aa".to_string(),
        "ab".to_string(),
        "b".to_string(),
        "\u{0}".to_string(),
        "\u{0}\u{0}".to_string(),
        "\u{1}".to_string(),
        "a\u{0}b".to_string(),
        "\u{7f}".to_string(),
        "\u{80}".to_string(),
        "\u{7ff}".to_string(),
        "\u{800}".to_string(),
        "\u{ffff}".to_string(),
        "\u{10000}".to_string(),
        "\u{10ffff}".to_string(),
        "héllo".to_string(),
        "日本語".to_string(),
    ]
}

fn empty_string_encodes_canonically(t: &mut Trials) {
    let empty = seal_str(&Utf8::of(""));
    let bytes = empty.as_bytes();
    t.check("the empty string is tag and terminator", bytes.len() == 3);
    t.check("it opens with the Str tag", bytes[0] == TAG_STR);
    t.check("its payload is the terminator alone", bytes[1..] == [0x00, 0x00]);
    t.check("it has one encoding", bytes == seal_str(&Utf8::of("")).as_bytes());
    t.check(
        "it reads back whole",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
    for s in text_corpus() {
        if !s.is_empty() {
            t.check(
                "the empty string sorts below every other",
                bytes < seal_str(&Utf8::of(&s)).as_bytes(),
            );
        }
    }
}

fn empty_bytes_encodes_canonically(t: &mut Trials) {
    let empty = seal_bytes(&[]);
    let bytes = empty.as_bytes();
    t.check("the empty byte string is tag and terminator", bytes.len() == 3);
    t.check("it opens with the Bytes tag", bytes[0] == TAG_BYTES);
    t.check("its payload is the terminator alone", bytes[1..] == [0x00, 0x00]);
    for b in 0u16..=255 {
        t.check(
            "the empty byte string sorts below every one-byte one",
            bytes < seal_bytes(&[b as u8]).as_bytes(),
        );
    }
}

fn string_prefix_sorts_before_string_extension(t: &mut Trials) {
    for s in text_corpus() {
        let short = seal_str(&Utf8::of(&s));
        for extra in text_corpus() {
            if extra.is_empty() {
                continue;
            }
            let long = seal_str(&Utf8::of(&(s.clone() + &extra)));
            t.check(
                "a string sorts before its own extension",
                short.as_bytes() < long.as_bytes(),
            );
            t.check(
                "a string is not a byte prefix of its extension",
                !is_proper_prefix(short.as_bytes(), long.as_bytes()),
            );
        }
    }
}

fn bytes_prefix_sorts_before_bytes_extension(t: &mut Trials) {
    let payloads: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0x00, 0x00],
        vec![0x01],
        vec![0x41],
        vec![0xFF],
        vec![0x00, 0xFF],
    ];
    for base in &payloads {
        let short = seal_bytes(base);
        for extra in 0u16..=255 {
            let mut long_payload = base.clone();
            long_payload.push(extra as u8);
            let long = seal_bytes(&long_payload);
            t.check(
                "a byte string sorts before its own extension",
                short.as_bytes() < long.as_bytes(),
            );
            t.check(
                "a byte string is not a byte prefix of its extension",
                !is_proper_prefix(short.as_bytes(), long.as_bytes()),
            );
        }
    }
}

fn string_order_matches_semantic_string_order(t: &mut Trials) {
    for a in text_corpus() {
        for b in text_corpus() {
            t.check(
                "string order is the order of the text",
                seal_str(&Utf8::of(&a))
                    .as_bytes()
                    .cmp(seal_str(&Utf8::of(&b)).as_bytes())
                    == a.as_bytes().cmp(b.as_bytes()),
            );
        }
    }
}

fn bytes_order_matches_raw_byte_order(t: &mut Trials) {
    let mut payloads: Vec<Vec<u8>> = vec![Vec::new()];
    for b in 0u16..=255 {
        payloads.push(vec![b as u8]);
    }
    for b in [0x00u8, 0x01, 0xFE, 0xFF] {
        payloads.push(vec![b, 0x00]);
        payloads.push(vec![b, 0xFF]);
    }
    for a in &payloads {
        for b in &payloads {
            t.check(
                "byte-string order is raw byte order",
                seal_bytes(a).as_bytes().cmp(seal_bytes(b).as_bytes()) == a.cmp(b),
            );
        }
    }
}

fn string_and_bytes_same_payload_have_distinct_encodings(t: &mut Trials) {
    for s in text_corpus() {
        let as_text = seal_str(&Utf8::of(&s));
        let as_content = seal_bytes(s.as_bytes());
        t.check(
            "text and content are different values",
            as_text.as_bytes() != as_content.as_bytes(),
        );
        t.check(
            "they differ in the tag and nowhere else",
            as_text.as_bytes()[1..] == as_content.as_bytes()[1..],
        );
        t.check(
            "text sorts below content, whatever the payload",
            as_text.as_bytes() < as_content.as_bytes(),
        );
    }
}

/// The Str door takes [`Utf8`], whose only mint takes a `&str`, so a byte
/// string that is not text is not an argument that exists. What runs here is
/// that every payload it does produce is text on the way out.
fn string_rejects_invalid_utf8(t: &mut Trials) {
    for s in text_corpus() {
        let sealed = seal_str(&Utf8::of(&s));
        let body = &sealed.as_bytes()[1..];
        let payload = unescape(body);
        t.check("a Str payload is the text it was given", payload == s.as_bytes());
        t.check(
            "a Str payload is valid UTF-8",
            std::str::from_utf8(&payload).is_ok(),
        );
    }
    // The content door is the one that takes bytes, and its output is not a
    // Str: there is no path from invalid UTF-8 to the Str tag.
    for bad in [vec![0x80u8], vec![0xFFu8, 0xFE], vec![0xC0, 0x80]] {
        t.check(
            "invalid UTF-8 seals as content, never as text",
            seal_bytes(&bad).as_bytes()[0] == TAG_BYTES,
        );
        t.check("and it is not valid text", std::str::from_utf8(&bad).is_err());
    }
}

fn string_embedded_zero_roundtrips(t: &mut Trials) {
    let cases = [
        "\u{0}",
        "\u{0}\u{0}",
        "a\u{0}",
        "\u{0}a",
        "a\u{0}b\u{0}c",
        "\u{0}\u{0}\u{0}\u{0}",
    ];
    for s in cases {
        let sealed = seal_str(&Utf8::of(s));
        let bytes = sealed.as_bytes();
        t.check(
            "an embedded zero reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check(
            "an embedded zero survives the escape",
            unescape(&bytes[1..]) == s.as_bytes(),
        );
        // Only the zero bytes double, so the payload grows by exactly the
        // number of them and never by more.
        let zeros = s.as_bytes().iter().filter(|b| **b == 0x00).count();
        t.check(
            "an embedded zero does not terminate the payload",
            bytes.len() == 1 + s.len() + zeros + 2,
        );
    }
}

fn bytes_all_values_roundtrip(t: &mut Trials) {
    for b in 0u16..=255 {
        let payload = vec![b as u8];
        let sealed = seal_bytes(&payload);
        let bytes = sealed.as_bytes();
        t.check(
            "every byte value reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
        t.check("every byte value survives the escape", unescape(&bytes[1..]) == payload);
        for c in 0u16..=255 {
            let pair = vec![b as u8, c as u8];
            let sealed_pair = seal_bytes(&pair);
            t.check(
                "every byte pair survives the escape",
                unescape(&sealed_pair.as_bytes()[1..]) == pair,
            );
        }
    }
}

fn string_golden_vectors_cover_utf8_boundaries(t: &mut Trials) {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("", vec![0x18, 0x00, 0x00]),
        ("a", vec![0x18, 0x61, 0x00, 0x00]),
        ("\u{0}", vec![0x18, 0x00, 0xFF, 0x00, 0x00]),
        ("\u{7f}", vec![0x18, 0x7F, 0x00, 0x00]),
        ("\u{80}", vec![0x18, 0xC2, 0x80, 0x00, 0x00]),
        ("\u{7ff}", vec![0x18, 0xDF, 0xBF, 0x00, 0x00]),
        ("\u{800}", vec![0x18, 0xE0, 0xA0, 0x80, 0x00, 0x00]),
        ("\u{ffff}", vec![0x18, 0xEF, 0xBF, 0xBF, 0x00, 0x00]),
        ("\u{10000}", vec![0x18, 0xF0, 0x90, 0x80, 0x80, 0x00, 0x00]),
        ("\u{10ffff}", vec![0x18, 0xF4, 0x8F, 0xBF, 0xBF, 0x00, 0x00]),
    ];
    for (s, expected) in &cases {
        t.check(
            "a string encodes to its pinned bytes",
            seal_str(&Utf8::of(s)).as_bytes() == expected.as_slice(),
        );
    }
}

fn bytes_golden_vectors_cover_zero_and_ff(t: &mut Trials) {
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (vec![], vec![0x20, 0x00, 0x00]),
        (vec![0x00], vec![0x20, 0x00, 0xFF, 0x00, 0x00]),
        (vec![0x00, 0x00], vec![0x20, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0x00]),
        (vec![0x01], vec![0x20, 0x01, 0x00, 0x00]),
        (vec![0xFF], vec![0x20, 0xFF, 0x00, 0x00]),
        (vec![0x00, 0xFF], vec![0x20, 0x00, 0xFF, 0xFF, 0x00, 0x00]),
        (vec![0xFF, 0x00], vec![0x20, 0xFF, 0x00, 0xFF, 0x00, 0x00]),
    ];
    for (payload, expected) in &cases {
        t.check(
            "a byte string encodes to its pinned bytes",
            seal_bytes(payload).as_bytes() == expected.as_slice(),
        );
    }
}

// ================================= regex ====================================

fn flags_of(bits: u8) -> RegexFlags {
    RegexFlags::new(bits & 1 != 0, bits & 2 != 0, bits & 4 != 0)
}

fn regex_all_eight_flag_combinations_are_unique(t: &mut Trials) {
    let mut seen: Vec<(u8, Vec<u8>)> = Vec::new();
    for bits in 0u8..8 {
        let sealed = seal_regex(&Utf8::of("a"), &flags_of(bits));
        let bytes = sealed.as_bytes().to_vec();
        for (other_bits, other) in &seen {
            t.check(
                "each flag combination has its own encoding",
                (other == &bytes) == (*other_bits == bits),
            );
        }
        seen.push((bits, bytes));
    }
    t.check("all eight combinations are present", seen.len() == 8);
}

/// The flags type has three fields and no fourth, so bit 3 and above are not a
/// value a caller can name. What runs here is that no combination it can name
/// ever sets one.
fn regex_unknown_flag_bits_are_unconstructible(t: &mut Trials) {
    for bits in 0u8..8 {
        let sealed = seal_regex(&Utf8::of(""), &flags_of(bits));
        let bytes = sealed.as_bytes();
        let written = bytes[bytes.len() - 1];
        t.check("the flags byte holds only the three known bits", written < 8);
        t.check("the flags byte is the combination asked for", written == bits);
    }
}

fn regex_pattern_is_primary_sort_key(t: &mut Trials) {
    let patterns = ["", "a", "aa", "ab", "b", "a.*b", "\u{0}"];
    for a in patterns {
        for b in patterns {
            if a == b {
                continue;
            }
            // The lower pattern with every flag set still sorts below the
            // higher pattern with none: the pattern decides first.
            let low = seal_regex(&Utf8::of(a), &flags_of(7));
            let high = seal_regex(&Utf8::of(b), &flags_of(0));
            t.check(
                "the pattern decides before the flags are read",
                (low.as_bytes() < high.as_bytes()) == (a.as_bytes() < b.as_bytes()),
            );
        }
    }
}

fn regex_flags_are_secondary_sort_key(t: &mut Trials) {
    for pattern in ["", "a", "a.*b"] {
        for x in 0u8..8 {
            for y in 0u8..8 {
                let a = seal_regex(&Utf8::of(pattern), &flags_of(x));
                let b = seal_regex(&Utf8::of(pattern), &flags_of(y));
                t.check(
                    "equal patterns are decided by their flags",
                    a.as_bytes().cmp(b.as_bytes()) == x.cmp(&y),
                );
            }
        }
    }
}

fn regex_flag_bit_layout_matches_released_format(t: &mut Trials) {
    let cases: [(bool, bool, bool, u8); 4] = [
        (true, false, false, 0x01),
        (false, true, false, 0x02),
        (false, false, true, 0x04),
        (true, true, true, 0x07),
    ];
    for (ci, ml, dot, expected) in cases {
        let sealed = seal_regex(&Utf8::of(""), &RegexFlags::new(ci, ml, dot));
        let bytes = sealed.as_bytes();
        t.check(
            "the flag bits sit where the format puts them",
            bytes[bytes.len() - 1] == expected,
        );
    }
}

fn regex_empty_pattern_is_canonical(t: &mut Trials) {
    let empty = seal_regex(&Utf8::of(""), &flags_of(0));
    let bytes = empty.as_bytes();
    t.check("an empty pattern is tag, terminator, flags", bytes.len() == 4);
    t.check("it opens with the Regex tag", bytes[0] == TAG_REGEX);
    t.check(
        "it has one encoding",
        bytes == seal_regex(&Utf8::of(""), &flags_of(0)).as_bytes(),
    );
    t.check(
        "it reads back whole",
        scanned(scan_value(bytes)) == Some(bytes.len()),
    );
    for p in ["a", "\u{0}", "z"] {
        t.check(
            "the empty pattern sorts below every other",
            bytes < seal_regex(&Utf8::of(p), &flags_of(0)).as_bytes(),
        );
    }
}

/// The pattern is [`Utf8`], so a pattern that is not text is not an argument.
/// What runs here is that every pattern the door writes comes back as text.
fn regex_pattern_rejects_invalid_utf8(t: &mut Trials) {
    for p in text_corpus() {
        let sealed = seal_regex(&Utf8::of(&p), &flags_of(3));
        let bytes = sealed.as_bytes();
        let payload = unescape(&bytes[1..]);
        t.check("a pattern survives the escape", payload == p.as_bytes());
        t.check(
            "a pattern is valid UTF-8",
            std::str::from_utf8(&payload).is_ok(),
        );
        t.check(
            "a regex reads back whole",
            scanned(scan_value(bytes)) == Some(bytes.len()),
        );
    }
}

fn regex_encoding_is_injective(t: &mut Trials) {
    let patterns = ["", "a", "ab", "b", "\u{0}"];
    let mut seen: Vec<((usize, u8), Vec<u8>)> = Vec::new();
    for (i, p) in patterns.iter().enumerate() {
        for bits in 0u8..8 {
            let bytes = seal_regex(&Utf8::of(p), &flags_of(bits)).as_bytes().to_vec();
            for (key, other) in &seen {
                t.check(
                    "one regex, one byte string",
                    (other == &bytes) == (*key == (i, bits)),
                );
            }
            seen.push(((i, bits), bytes));
        }
    }
}

fn regex_golden_vectors_cover_all_flags(t: &mut Trials) {
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        ("", 0, vec![0x30, 0x00, 0x00, 0x00]),
        ("", 7, vec![0x30, 0x00, 0x00, 0x07]),
        ("a", 0, vec![0x30, 0x61, 0x00, 0x00, 0x00]),
        ("a", 1, vec![0x30, 0x61, 0x00, 0x00, 0x01]),
        ("a", 2, vec![0x30, 0x61, 0x00, 0x00, 0x02]),
        ("a", 4, vec![0x30, 0x61, 0x00, 0x00, 0x04]),
        ("\u{0}", 0, vec![0x30, 0x00, 0xFF, 0x00, 0x00, 0x00]),
    ];
    for (pattern, bits, expected) in &cases {
        t.check(
            "a regex encodes to its pinned bytes",
            seal_regex(&Utf8::of(pattern), &flags_of(*bits)).as_bytes() == expected.as_slice(),
        );
    }
}

// ================================== uuid ====================================

fn uuid_corpus() -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = vec![[0x00; 16], [0xFF; 16], [0x01; 16]];
    for at in [0usize, 1, 7, 8, 15] {
        let mut id = [0x00u8; 16];
        id[at] = 0x01;
        out.push(id);
        let mut high = [0x00u8; 16];
        high[at] = 0xFF;
        out.push(high);
    }
    out
}

fn uuid_encoding_is_exactly_sixteen_bytes_after_tag(t: &mut Trials) {
    for id in uuid_corpus() {
        let sealed = seal_uuid(&id);
        let bytes = sealed.as_bytes();
        t.check("a uuid is a tag and sixteen bytes", bytes.len() == 17);
        t.check("it opens with the Uuid tag", bytes[0] == TAG_UUID);
        t.check("the payload is the identifier unchanged", bytes[1..] == id);
        t.check(
            "a uuid reads back whole",
            scanned(scan_value(bytes)) == Some(17),
        );
    }
}

fn uuid_encoding_is_injective(t: &mut Trials) {
    let all = uuid_corpus();
    for a in &all {
        for b in &all {
            t.check(
                "one uuid, one byte string",
                (seal_uuid(a).as_bytes() == seal_uuid(b).as_bytes()) == (a == b),
            );
        }
    }
}

fn uuid_order_matches_semantic_uuid_order(t: &mut Trials) {
    let all = uuid_corpus();
    for a in &all {
        for b in &all {
            t.check(
                "uuid order is the order of its bytes",
                seal_uuid(a).as_bytes().cmp(seal_uuid(b).as_bytes()) == a.cmp(b),
            );
        }
    }
}

fn uuid_zero_and_ff_boundaries(t: &mut Trials) {
    let zero = seal_uuid(&[0x00; 16]);
    let ones = seal_uuid(&[0xFF; 16]);
    for id in uuid_corpus() {
        let sealed = seal_uuid(&id);
        t.check(
            "the zero uuid sorts at or below every uuid",
            zero.as_bytes() <= sealed.as_bytes(),
        );
        t.check(
            "the all-ones uuid sorts at or above every uuid",
            sealed.as_bytes() <= ones.as_bytes(),
        );
    }
    // A zero byte inside the payload is not an escape: a uuid is fixed-width.
    let mut middle = [0xFFu8; 16];
    middle[8] = 0x00;
    let sealed = seal_uuid(&middle);
    t.check(
        "a zero byte inside a uuid is payload, not structure",
        scanned(scan_value(sealed.as_bytes())) == Some(17),
    );
}

fn uuid_golden_vectors_are_architecture_independent(t: &mut Trials) {
    let ordered: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF,
    ];
    let expected: Vec<u8> = [vec![0x28u8], ordered.to_vec()].concat();
    t.check(
        "a uuid encodes to its pinned bytes",
        seal_uuid(&ordered).as_bytes() == expected.as_slice(),
    );
    t.check(
        "the identifier is written in the order it was given",
        seal_uuid(&ordered).as_bytes()[1..] == ordered,
    );
    // Byte order is the identifier's own, so no host word order reaches it.
    let mut reversed = ordered;
    reversed.reverse();
    t.check(
        "reversing the identifier reverses the payload",
        seal_uuid(&reversed).as_bytes()[1..] == reversed,
    );
}

// ============================ numeric encoding ==============================
//
// The number line, written down: negatives descending, zero, positives
// ascending, NaN above all of it. Every trial below holds the encoding against
// arithmetic, never against another encoding.

/// The tie-break by index. `Repr` is not `Copy`, so a trial that wants one
/// twice names it twice rather than holding it.
///
/// The magnitude mint lives beside the other harness doors, above.
fn tie(k: usize) -> Repr {
    match k {
        0 => Repr::Int,
        _ => Repr::Float,
    }
}

/// Magnitudes in ascending order of what they denote, with the boundaries the
/// packing has to cross: binade edges, a saturated significand, and the scale
/// either side of a carry.
fn ascending_magnitudes() -> Vec<Magnitude> {
    let mut out = vec![
        mag(1, 0),
        mag(3, 0),
        mag(1, 2),
        mag(5, 0),
        mag(3, 1),
        mag(7, 0),
        mag(1, 3),
        mag(255, 0),
        mag(1, 8),
        mag(257, 0),
        mag(u32::MAX as u64, 0),
        mag(1, 32),
        mag((u32::MAX as u64) + 2, 0),
        mag(u64::MAX, 0),
        mag(1, 64),
        mag(1, 1000),
        mag(u64::MAX, 1000),
        mag(1, 1065),
        mag(1, EXP_INFINITE - 65),
        mag(u64::MAX, EXP_INFINITE - 65),
    ];
    out.push(Magnitude::Infinite);
    out
}

/// What a magnitude denotes, as a pair the trials can compare with arithmetic
/// rather than with bytes: where the top bit sits, and the significand aligned
/// to it. `None` is the point above every finite one.
fn denotation(m: &Magnitude) -> Option<(u64, u128)> {
    match m {
        Magnitude::Infinite => None,
        Magnitude::Finite(f) => {
            let significand = f.significand();
            let mut bits = 0u32;
            let mut x = significand;
            while x > 0 {
                bits += 1;
                x /= 2;
            }
            Some((
                bits as u64 + f.scale() as u64,
                (significand as u128) << (64 - bits),
            ))
        }
    }
}

fn cmp_denotation(a: &Magnitude, b: &Magnitude) -> Ordering {
    match (denotation(a), denotation(b)) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(&y),
    }
}

/// Every number the trials sweep, in the order the line puts them.
fn ascending_numbers() -> Vec<CanonicalBytes> {
    let mut out: Vec<CanonicalBytes> = Vec::new();
    let mags = ascending_magnitudes();
    for m in mags.iter().rev() {
        out.push(seal_num_negative(m, Repr::Int).into_value());
        out.push(seal_num_negative(m, Repr::Float).into_value());
    }
    out.push(seal_num_zero(Repr::Int).into_value());
    out.push(seal_num_zero(Repr::Float).into_value());
    for m in mags.iter() {
        out.push(seal_num_positive(m, Repr::Int).into_value());
        out.push(seal_num_positive(m, Repr::Float).into_value());
    }
    out.push(seal_num_nan().into_value());
    out
}

fn numeric_classes_sort_negative_zero_positive_nan(t: &mut Trials) {
    let neg = seal_num_negative(&mag_min(), Repr::Int).into_value();
    let zero = seal_num_zero(Repr::Int).into_value();
    let pos = seal_num_positive(&mag_min(), Repr::Int).into_value();
    let nan = seal_num_nan().into_value();
    t.check("negative below zero", neg.as_bytes() < zero.as_bytes());
    t.check("zero below positive", zero.as_bytes() < pos.as_bytes());
    t.check("positive below nan", pos.as_bytes() < nan.as_bytes());
    t.check("the class byte carries the order", neg.as_bytes()[1] < zero.as_bytes()[1]);
    t.check("the class byte carries the order", zero.as_bytes()[1] < pos.as_bytes()[1]);
    t.check("the class byte carries the order", pos.as_bytes()[1] < nan.as_bytes()[1]);
}

fn zero_int_sorts_before_zero_float(t: &mut Trials) {
    let int = seal_num_zero(Repr::Int).into_value();
    let float = seal_num_zero(Repr::Float).into_value();
    t.check("integer zero sorts before float zero", int.as_bytes() < float.as_bytes());
    t.check("the two zeroes differ only in the tie-break", int.as_bytes()[..2] == float.as_bytes()[..2]);
    t.check("zero carries no magnitude", int.as_bytes().len() == 3);
}

fn equal_magnitude_int_sorts_before_float(t: &mut Trials) {
    for m in ascending_magnitudes() {
        let pos_int = seal_num_positive(&m, Repr::Int).into_value();
        let pos_float = seal_num_positive(&m, Repr::Float).into_value();
        t.check(
            "at one positive magnitude the integer sorts first",
            pos_int.as_bytes() < pos_float.as_bytes(),
        );
        let neg_int = seal_num_negative(&m, Repr::Int).into_value();
        let neg_float = seal_num_negative(&m, Repr::Float).into_value();
        t.check(
            "at one negative magnitude the integer still sorts first",
            neg_int.as_bytes() < neg_float.as_bytes(),
        );
    }
}

fn tie_break_is_consulted_only_after_magnitude(t: &mut Trials) {
    let mags = ascending_magnitudes();
    for (i, a) in mags.iter().enumerate() {
        for (j, b) in mags.iter().enumerate() {
            if i == j {
                continue;
            }
            // The lower magnitude as a float against the higher as an integer:
            // if the tie-break were read first, the float would win.
            let low = seal_num_positive(a, Repr::Float).into_value();
            let high = seal_num_positive(b, Repr::Int).into_value();
            t.check(
                "the magnitude decides before the tie-break is read",
                (low.as_bytes() < high.as_bytes()) == (i < j),
            );
        }
    }
}

fn magnitude_is_exactly_released_width(t: &mut Trials) {
    for m in ascending_magnitudes() {
        for k in 0..2usize {
            let pos = seal_num_positive(&m, tie(k)).into_value();
            let neg = seal_num_negative(&m, tie(k)).into_value();
            t.check(
                "a signed number is tag, class, magnitude, tie-break",
                pos.as_bytes().len() == 2 + MAG_BYTES + 1,
            );
            t.check(
                "the negative class is the same width",
                neg.as_bytes().len() == 2 + MAG_BYTES + 1,
            );
        }
    }
}

fn magnitude_exponent_is_big_endian(t: &mut Trials) {
    // The exponent is the top 16 bits of the payload: raising it must change
    // the first payload byte before it changes any other.
    for scale in [0u32, 1, 255, 256, 4096] {
        let m = mag(1, scale);
        let sealed = seal_num_positive(&m, Repr::Int).into_value();
        let payload = &sealed.as_bytes()[2..2 + MAG_BYTES];
        let exponent = u16::from_be_bytes([payload[0], payload[1]]);
        t.check(
            "the exponent is where the top bit sits",
            exponent as u32 == scale + 1,
        );
    }
    for scale in 0u32..64 {
        let low = seal_num_positive(&mag(1, scale), Repr::Int).into_value();
        let high = seal_num_positive(&mag(1, scale + 1), Repr::Int).into_value();
        t.check(
            "a higher exponent sorts higher",
            low.as_bytes() < high.as_bytes(),
        );
    }
}

fn magnitude_fraction_is_big_endian(t: &mut Trials) {
    // At one exponent, the fraction is left-aligned below it: the significand's
    // top bit is implicit in the exponent and the rest descends byte by byte.
    let sealed = seal_num_positive(&mag(0xFF, 0), Repr::Int).into_value();
    let payload = &sealed.as_bytes()[2..2 + MAG_BYTES];
    t.check("the exponent leads", payload[0] == 0x00 && payload[1] == 0x08);
    t.check("the fraction follows it, most significant byte first", payload[2] == 0xFF);
    for k in 3..MAG_BYTES {
        t.check("and the rest of the fraction is zero", payload[k] == 0x00);
    }
    let higher = seal_num_positive(&mag(0xFF, 1), Repr::Int).into_value();
    t.check(
        "shifting the significand shifts the exponent, not the fraction",
        higher.as_bytes()[2 + 2..] == sealed.as_bytes()[2 + 2..],
    );
}

fn magnitude_all_input_bits_affect_output(t: &mut Trials) {
    // Every bit of the significand reaches the payload: flipping one changes it.
    let base = u64::MAX;
    let sealed = seal_num_positive(&mag(base, 0), Repr::Int).into_value();
    for bit in 0..64u32 {
        let flipped = base ^ (1u64 << bit);
        if flipped == 0 {
            continue;
        }
        let other = seal_num_positive(&mag(flipped, 0), Repr::Int).into_value();
        t.check(
            "every significand bit reaches the payload",
            other.as_bytes() != sealed.as_bytes(),
        );
    }
    // And every bit of the scale, within the range the door admits.
    let scale_base = 1024u32;
    let at_scale = seal_num_positive(&mag(1, scale_base), Repr::Int).into_value();
    for bit in 0..12u32 {
        let flipped = scale_base ^ (1u32 << bit);
        let other = seal_num_positive(&mag(1, flipped), Repr::Int).into_value();
        t.check(
            "every scale bit reaches the payload",
            other.as_bytes() != at_scale.as_bytes(),
        );
    }
}

fn magnitude_finite_constructor_is_injective(t: &mut Trials) {
    // Two magnitudes encode alike exactly when they denote the same number:
    // 2x2^0 and 1x2^1 ARE one number, and the encoder is right to agree.
    let candidates: Vec<Magnitude> = vec![
        mag(1, 0), mag(2, 0), mag(1, 1), mag(4, 0), mag(2, 1), mag(1, 2),
        mag(3, 0), mag(6, 0), mag(3, 1), mag(u64::MAX, 0), mag(u64::MAX, 1),
    ];
    for a in &candidates {
        for b in &candidates {
            let same_number = cmp_denotation(a, b) == Ordering::Equal;
            let same_bytes = seal_num_positive(a, Repr::Int).into_value().as_bytes()
                == seal_num_positive(b, Repr::Int).into_value().as_bytes();
            t.check("one number, one payload", same_number == same_bytes);
        }
    }
}

fn magnitude_infinite_constructor_is_unique(t: &mut Trials) {
    let one = seal_num_positive(&Magnitude::Infinite, Repr::Int).into_value();
    let two = seal_num_positive(&Magnitude::Infinite, Repr::Int).into_value();
    t.check("infinity has one encoding", one.as_bytes() == two.as_bytes());
    let payload = &one.as_bytes()[2..2 + MAG_BYTES];
    t.check(
        "its exponent is the reserved one",
        u16::from_be_bytes([payload[0], payload[1]]) as u32 == EXP_INFINITE,
    );
    for k in 2..MAG_BYTES {
        t.check("and its fraction is saturated", payload[k] == 0xFF);
    }
}

fn finite_domain_excludes_infinity_sentinel(t: &mut Trials) {
    let infinite = seal_num_positive(&Magnitude::Infinite, Repr::Int).into_value();
    for m in ascending_magnitudes() {
        match m {
            Magnitude::Infinite => {}
            finite => {
                let sealed = seal_num_positive(&finite, Repr::Int).into_value();
                let payload = &sealed.as_bytes()[2..2 + MAG_BYTES];
                let exponent = u16::from_be_bytes([payload[0], payload[1]]) as u32;
                t.check("no finite magnitude reaches the reserved exponent", exponent < EXP_INFINITE);
                t.check(
                    "and so sorts below infinity",
                    sealed.as_bytes() < infinite.as_bytes(),
                );
            }
        }
    }
}

fn positive_magnitude_order_matches_semantic_order(t: &mut Trials) {
    let mags = ascending_magnitudes();
    for a in &mags {
        for b in &mags {
            let arithmetic = cmp_denotation(a, b);
            let bytes = seal_num_positive(a, Repr::Int)
                .into_value()
                .as_bytes()
                .cmp(seal_num_positive(b, Repr::Int).into_value().as_bytes());
            t.check("positive order is magnitude order", bytes == arithmetic);
        }
    }
}

fn negative_magnitude_order_is_reversed_correctly(t: &mut Trials) {
    let mags = ascending_magnitudes();
    for a in &mags {
        for b in &mags {
            let arithmetic = cmp_denotation(a, b);
            let bytes = seal_num_negative(a, Repr::Int)
                .into_value()
                .as_bytes()
                .cmp(seal_num_negative(b, Repr::Int).into_value().as_bytes());
            t.check("negative order is magnitude order reversed", bytes == arithmetic.reverse());
        }
    }
}

/// Either side of a binade edge, where the exponent changes and the fraction
/// resets: the order must not notice the seam.
fn exponent_carry_transition_preserves_order(t: &mut Trials) {
    for bits in 1u32..63 {
        let below = mag((1u64 << bits) - 1, 0);
        let at = mag(1u64 << bits, 0);
        let above = mag((1u64 << bits) + 1, 0);
        let a = seal_num_positive(&below, Repr::Int).into_value();
        let b = seal_num_positive(&at, Repr::Int).into_value();
        let c = seal_num_positive(&above, Repr::Int).into_value();
        t.check("the binade edge ascends", a.as_bytes() < b.as_bytes());
        t.check("and keeps ascending past it", b.as_bytes() < c.as_bytes());
        let na = seal_num_negative(&below, Repr::Int).into_value();
        let nb = seal_num_negative(&at, Repr::Int).into_value();
        t.check("negatives descend across the same edge", nb.as_bytes() < na.as_bytes());
    }
}

/// Inside one binade, where only the fraction moves.
fn fraction_carry_transition_preserves_order(t: &mut Trials) {
    for bits in 8u32..40 {
        let base = 1u64 << bits;
        for delta in [1u64, 2, 3, 255, 256] {
            let low = mag(base + delta - 1, 0);
            let high = mag(base + delta, 0);
            let a = seal_num_positive(&low, Repr::Int).into_value();
            let b = seal_num_positive(&high, Repr::Int).into_value();
            t.check("the fraction ascends inside a binade", a.as_bytes() < b.as_bytes());
            let na = seal_num_negative(&low, Repr::Int).into_value();
            let nb = seal_num_negative(&high, Repr::Int).into_value();
            t.check("and descends for negatives", nb.as_bytes() < na.as_bytes());
        }
    }
}

fn negative_exponent_boundary_orders_correctly(t: &mut Trials) {
    let least = mag(1, 0);
    let greatest = mag(u64::MAX, EXP_INFINITE - 65);
    let a = seal_num_negative(&greatest, Repr::Int).into_value();
    let b = seal_num_negative(&least, Repr::Int).into_value();
    t.check("the greatest negative magnitude sorts lowest", a.as_bytes() < b.as_bytes());
    let infinite = seal_num_negative(&Magnitude::Infinite, Repr::Int).into_value();
    t.check("and negative infinity below even that", infinite.as_bytes() < a.as_bytes());
}

fn negative_fraction_boundary_orders_correctly(t: &mut Trials) {
    let saturated = mag(u64::MAX, 0);
    let one_less = mag(u64::MAX - 1, 0);
    let a = seal_num_negative(&saturated, Repr::Int).into_value();
    let b = seal_num_negative(&one_less, Repr::Int).into_value();
    t.check("a fuller fraction is a smaller negative", a.as_bytes() < b.as_bytes());
}

fn positive_exponent_boundary_orders_correctly(t: &mut Trials) {
    let least = seal_num_positive(&mag(1, 0), Repr::Int).into_value();
    let greatest = seal_num_positive(&mag(u64::MAX, EXP_INFINITE - 65), Repr::Int).into_value();
    let infinite = seal_num_positive(&Magnitude::Infinite, Repr::Int).into_value();
    t.check("the least positive sorts below the greatest", least.as_bytes() < greatest.as_bytes());
    t.check("and the greatest below infinity", greatest.as_bytes() < infinite.as_bytes());
}

fn positive_fraction_boundary_orders_correctly(t: &mut Trials) {
    let a = seal_num_positive(&mag(u64::MAX - 1, 0), Repr::Int).into_value();
    let b = seal_num_positive(&mag(u64::MAX, 0), Repr::Int).into_value();
    t.check("a fuller fraction is a larger positive", a.as_bytes() < b.as_bytes());
}

fn negative_infinity_is_global_numeric_minimum(t: &mut Trials) {
    let least = seal_num_negative(&Magnitude::Infinite, Repr::Int).into_value();
    for other in ascending_numbers() {
        t.check(
            "negative infinity is at or below every number",
            least.as_bytes() <= other.as_bytes(),
        );
    }
}

fn positive_infinity_sorts_below_nan(t: &mut Trials) {
    let infinite = seal_num_positive(&Magnitude::Infinite, Repr::Float).into_value();
    let nan = seal_num_nan().into_value();
    t.check("infinity sorts below nan", infinite.as_bytes() < nan.as_bytes());
    t.check("and they are different values", infinite.as_bytes() != nan.as_bytes());
}

fn nan_sorts_above_every_numeric_value(t: &mut Trials) {
    let nan = seal_num_nan().into_value();
    for other in ascending_numbers() {
        t.check(
            "nan is at or above every number",
            other.as_bytes() <= nan.as_bytes(),
        );
    }
}

fn nan_has_exactly_one_encoding(t: &mut Trials) {
    let a = seal_num_nan().into_value();
    let b = seal_num_nan().into_value();
    t.check("nan has one encoding", a.as_bytes() == b.as_bytes());
    t.check("nan is tag, class, tie-break", a.as_bytes().len() == 3);
    t.check("its tie-break is the float one", a.as_bytes()[2] == 0x01);
}

fn numeric_encoding_is_injective_across_classes(t: &mut Trials) {
    let all = ascending_numbers();
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            t.check(
                "one number, one byte string",
                (a.as_bytes() == b.as_bytes()) == (i == j),
            );
        }
    }
}

fn numeric_semantic_equality_implies_identical_bytes(t: &mut Trials) {
    // Written two ways, denoting one number.
    let pairs: Vec<(Magnitude, Magnitude)> = vec![
        (mag(2, 0), mag(1, 1)),
        (mag(4, 0), mag(1, 2)),
        (mag(6, 0), mag(3, 1)),
        (mag(1 << 40, 0), mag(1, 40)),
        (mag(u32::MAX as u64 + 1, 0), mag(1, 32)),
    ];
    for (a, b) in &pairs {
        t.check("the two writings denote one number", cmp_denotation(a, b) == Ordering::Equal);
        for k in 0..2usize {
            t.check(
                "and encode to one byte string",
                seal_num_positive(a, tie(k)).into_value().as_bytes()
                    == seal_num_positive(b, tie(k)).into_value().as_bytes(),
            );
            t.check(
                "in the negative class too",
                seal_num_negative(a, tie(k)).into_value().as_bytes()
                    == seal_num_negative(b, tie(k)).into_value().as_bytes(),
            );
        }
    }
}

fn numeric_semantic_order_matches_bytes_property(t: &mut Trials) {
    let all = ascending_numbers();
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            t.check(
                "the number line is the byte order",
                a.as_bytes().cmp(b.as_bytes()) == i.cmp(&j),
            );
        }
    }
}

/// The whole line at once, held against the reference's independent number
/// order rather than against the encoder's own.
fn numeric_total_order_matches_database_number_order(t: &mut Trials) {
    use reference::{Mag, Num, Repr as R, Sem};
    let mut values: Vec<Sem> = Vec::new();
    for (sig, scale) in [(1u64, 0u32), (3, 0), (1, 8), (u64::MAX, 0), (1, 1000)] {
        for tie in [R::Int, R::Float] {
            match Mag::finite(sig, scale) {
                Some(m) => {
                    values.push(Sem::Number(Num::Negative(m, tie)));
                    values.push(Sem::Number(Num::Positive(m, tie)));
                }
                None => t.check("a magnitude in range is a magnitude", false),
            }
        }
    }
    for tie in [R::Int, R::Float] {
        values.push(Sem::Number(Num::Zero(tie)));
        values.push(Sem::Number(Num::Negative(Mag::Infinite, tie)));
        values.push(Sem::Number(Num::Positive(Mag::Infinite, tie)));
    }
    values.push(Sem::Number(Num::NotANumber));
    for a in &values {
        for b in &values {
            t.check(
                "the reference's number order is the encoder's byte order",
                a.cmp_sem(b) == built(a).as_bytes().cmp(built(b).as_bytes()),
            );
        }
    }
}

fn numeric_golden_vectors_cover_every_boundary(t: &mut Trials) {
    let cases: Vec<(CanonicalBytes, Vec<u8>)> = vec![
        (seal_num_zero(Repr::Int).into_value(), vec![0x10, 0x02, 0x00]),
        (seal_num_zero(Repr::Float).into_value(), vec![0x10, 0x02, 0x01]),
        (seal_num_nan().into_value(), vec![0x10, 0x04, 0x01]),
        (
            seal_num_positive(&mag(1, 0), Repr::Int).into_value(),
            vec![0x10, 0x03, 0x00, 0x01, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0x00],
        ),
        (
            seal_num_positive(&mag(1, 0), Repr::Float).into_value(),
            vec![0x10, 0x03, 0x00, 0x01, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        ),
        (
            seal_num_negative(&mag(1, 0), Repr::Int).into_value(),
            vec![0x10, 0x01, 0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
        ),
        (
            seal_num_positive(&Magnitude::Infinite, Repr::Float).into_value(),
            vec![0x10, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
        ),
        (
            seal_num_negative(&Magnitude::Infinite, Repr::Float).into_value(),
            vec![0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        ),
    ];
    for (sealed, expected) in &cases {
        t.check(
            "a number encodes to its pinned bytes",
            sealed.as_bytes() == expected.as_slice(),
        );
    }
}

/// The raw set door is `pub(crate)`, and inside the encoder's own crate it has
/// exactly one caller: the type whose constructor normalises. This reads the
/// encoder's source at compile time and counts, because "who calls it" is a
/// fact about the source and not about any byte string.
fn raw_set_sealer_has_only_canonical_set_callers(t: &mut Trials) {
    const CANONICAL: &str = include_str!("../../kyzo-model/src/value/canonical.rs");
    const CODEC: &str = include_str!("../../kyzo-model/src/value/codec.rs");

    t.check(
        "the raw set door is crate-private where it is declared",
        CANONICAL.contains("pub(crate) fn seal_set"),
    );
    t.check(
        "and is declared once",
        CANONICAL.matches("fn seal_set").count() == 1,
    );
    let callers = CODEC.matches("seal_set(").count();
    t.check("the codec calls it exactly once", callers == 1);
    t.check(
        "and that call is the normalising type's own",
        CODEC.contains("canonical::seal_set(&self.0)"),
    );
    // No other file in the encoder's value module reaches it.
    const CELL: &str = include_str!("../../kyzo-model/src/value/cell.rs");
    t.check("no other value file calls it", !CELL.contains("seal_set("));
}

/// The public surface hands out no way to name a tag, a shape, or a branch
/// table. Every one of those is a forgery in `canonical-forgery`, which is
/// compiled by `xtask/compile-fail.sh` and must be rejected; what runs here is
/// the other half — that the doors which ARE public take no such argument.
fn public_api_does_not_expose_raw_grammar_authority(t: &mut Trials) {
    const CANONICAL: &str = include_str!("../../kyzo-model/src/value/canonical.rs");
    for private in [
        "fn seal(tag: u8",
        "struct Body {",
        "fn shape_scan",
        "fn sum_scan",
        "fn delim_scan",
    ] {
        let at = CANONICAL.find(private);
        match at {
            None => t.check("the declaration this trial names still exists", false),
            Some(index) => {
                let before = &CANONICAL[index.saturating_sub(12)..index];
                t.check(
                    "no grammar-level door is public",
                    !before.ends_with("pub ") || before.contains("pub(crate)"),
                );
            }
        }
    }
    t.check(
        "the tag constants are the format, not a door taking one",
        !CANONICAL.contains("pub fn seal(tag"),
    );
}
