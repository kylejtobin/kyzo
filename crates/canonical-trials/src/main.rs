/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

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

#[path = "../../kyzo-model/src/value/canonical.rs"]
mod canonical;

use canonical::{
    Bound, Branches, grammar_exec, CanonicalBytes, Shape, escape, scan_value, seal_bool, seal_bytes,
    seal_geometry, seal_interval, seal_interval_empty, seal_json, seal_list, seal_null,
    seal_num_negative, seal_num_positive, seal_num_zero, seal_regex, seal_set, seal_str,
    seal_uuid, seal_validity, seal_vector, shape_scan,
};

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

struct Trials {
    run: usize,
    failed: Vec<String>,
}

impl Trials {
    fn new() -> Trials {
        Trials { run: 0, failed: Vec::new() }
    }

    fn check(&mut self, name: &str, ok: bool) {
        self.run += 1;
        if !ok {
            self.failed.push(name.to_string());
        }
    }

    fn report(&self, section: &str) {
        println!("  {section}: {} checks", self.run);
    }
}

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
    let one = seal_list(&vec![str_val(&[0x01, 0x41])]);
    let two = seal_list(&vec![str_val(&[0x01, 0x41]), str_val(&[0x41])]);

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
    let seq_of_empty = seal_list(&vec![str_val(&[])]);

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
    let str_lo = seal_str(&[]);
    let bytes_lo = seal_bytes(&[]);

    t.check("null < bool", lex_le_independent(null.as_bytes(), bool_hi.as_bytes()));
    t.check("bool < str", lex_le_independent(bool_hi.as_bytes(), str_lo.as_bytes()));
    t.check("str < bytes", lex_le_independent(str_lo.as_bytes(), bytes_lo.as_bytes()));
    // A Str whose content is all 0xFF still sorts under Bytes: the tag decides,
    // and no payload reaches across it.
    let str_hi = seal_str(&[0xFF; 8]);
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
        let short = seal_list(&vec![str_val(b"a")]);
        let long = seal_list(&vec![str_val(b"a"), str_val(&[byte])]);
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
    let mut inner = str_val(b"leaf");
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
    t.check("unmarked: empty row reads as 1", shape_scan(&g, &hostile, &empty_row, 0) == Some(1));
    t.check(
        "unmarked: row holding 0x01 reads as the EMPTY row",
        shape_scan(&g, &hostile, &row_of_one, 0) == Some(1),
    );
    t.check(
        "unmarked: two different rows, one reading — this is the defect",
        shape_scan(&g, &hostile, &empty_row, 0) == shape_scan(&g, &hostile, &row_of_one, 0),
    );

    // Marked: every element opens with a key above the terminator.
    let marked = Shape::Row(Box::new(Shape::Sum(Box::new(Branches::Alt(
        0x18,
        Box::new(Shape::Fixed(1)),
        Box::new(Branches::End),
    )))));
    let marked_empty: Vec<u8> = vec![0x01];
    let marked_one: Vec<u8> = vec![0x18, 0x01, 0x01]; // marker, hostile content, end
    t.check("marked: empty row reads as 1", shape_scan(&g, &marked, &marked_empty, 0) == Some(1));
    t.check(
        "marked: row holding 0x01 reads as 3",
        shape_scan(&g, &marked, &marked_one, 0) == Some(3),
    );
    t.check(
        "marked: the two rows have different readings",
        shape_scan(&g, &marked, &marked_empty, 0) != shape_scan(&g, &marked, &marked_one, 0),
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
        (seal_num_zero(0x00), 3, "Num zero: tag, class, repr tie-break"),
        (seal_num_negative(&[0x00; 12]), 14, "Num negative: tag, class, 12"),
        (seal_num_positive(&[0x00; 12]), 14, "Num positive: tag, class, 12"),
        (seal_str(b"hello"), 8, "Str: tag, content, terminator"),
        (seal_bytes(&[0x00, 0xFF]), 6, "Bytes: tag, escaped content, terminator"),
        (seal_uuid(&[0x00; 16]), 17, "Uuid: tag, 16"),
        (seal_regex(b"ab", 0x07), 6, "Regex: tag, pattern, terminator, flags"),
        (seal_json(&seal_null()), 2, "Json: tag, a value"),
        (seal_vector(&[0x00; 32]), 33, "Vector: tag, 32"),
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
        t.check(label, scan_value(bytes) == Some(bytes.len()));
        // One byte short is refused, never guessed at.
        if bytes.len() > 1 {
            let short = &bytes[..bytes.len() - 1];
            t.check(label, shape_scan(&g, &Shape::Tagged, short, 0) != Some(short.len()));
        }
    }

    // The lead byte each door writes IS the released tag.
    let leads: Vec<(CanonicalBytes, u8, &str)> = vec![
        (seal_null(), TAG_NULL, "Null tag"),
        (seal_bool(false), TAG_FALSE, "False tag"),
        (seal_bool(true), TAG_TRUE, "True tag"),
        (seal_num_zero(0), TAG_NUM, "Num tag"),
        (seal_str(b""), TAG_STR, "Str tag"),
        (seal_bytes(b""), TAG_BYTES, "Bytes tag"),
        (seal_uuid(&[0; 16]), TAG_UUID, "Uuid tag"),
        (seal_regex(b"", 0), TAG_REGEX, "Regex tag"),
        (seal_json(&seal_null()), TAG_JSON, "Json tag"),
        (seal_vector(&[0; 32]), TAG_VECTOR, "Vector tag"),
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
        seal_str(&[]),
        seal_str(&[0x00, 0x01, 0xFF]),
        seal_num_zero(0x00),
        seal_json(&seal_bool(true)),
        seal_list(&Vec::new()),
        seal_list(&vec![str_val(&[0x01]), str_val(&[0x00])]),
        seal_list(&vec![seal_list(&vec![str_val(b"x")])]),
    ];
    for v in &values {
        let bytes = v.as_bytes();
        t.check("reader measures the writer exactly", scan_value(bytes) == Some(bytes.len()));

        for trailer in [vec![0x00u8], vec![0x01], vec![0xFF; 4], vec![TAG_NULL]] {
            let mut extended = bytes.to_vec();
            extended.extend_from_slice(&trailer);
            t.check(
                "trailing bytes cannot move the reading",
                scan_value(&extended) == Some(bytes.len()),
            );
        }

        // Every proper prefix is incomplete: it may be refused, but it may
        // never be accepted as the whole value.
        for cut in 0..bytes.len() {
            t.check("no proper prefix is complete", scan_value(&bytes[..cut]) != Some(cut));
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
            Some(n) => t.check("reader never claims more than it was given", n <= p.len()),
            None => t.check("reader refuses rather than guesses", true),
        }
    }

    // Nesting past the bound is refused, never followed.
    let mut deep = str_val(b"leaf");
    for _ in 0..40 {
        deep = seal_list(&vec![deep]);
    }
    t.check("nesting within the bound is read", scan_value(deep.as_bytes()).is_some());
    for _ in 0..512 {
        deep = seal_list(&vec![deep]);
    }
    t.check("nesting past the bound is refused", scan_value(deep.as_bytes()).is_none());
}

/// ATTACK: JSON is not a second grammar. A JSON value is a value, so the same
/// bytes read the same way whether or not a Json tag sits in front of them.
fn attack_json_is_the_value_grammar(t: &mut Trials) {
    let inner: Vec<CanonicalBytes> = vec![
        seal_null(),
        seal_bool(true),
        seal_num_zero(0x00),
        seal_str(b"k"),
        seal_list(&Vec::new()),
    ];
    for v in &inner {
        let bare = v.as_bytes().to_vec();
        let mut wrapped = vec![TAG_JSON];
        wrapped.extend_from_slice(&bare);
        t.check("a json body IS a value", scan_value(&wrapped) == Some(bare.len() + 1));
        t.check(
            "and it is the same reading as the bare value",
            scan_value(&bare) == Some(bare.len()),
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
fn str_val(s: &[u8]) -> CanonicalBytes {
    seal_str(s)
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
    attack_interval_infinities(&mut t);
    attack_reader_agrees_with_writer(&mut t);
    attack_reader_totality(&mut t);
    attack_json_is_the_value_grammar(&mut t);
    attack_high_bytes(&mut t);
    t.report("total");

    if t.failed.is_empty() {
        println!("\nall {} checks passed", t.run);
    } else {
        println!("\n{} FAILURES:", t.failed.len());
        let mut seen: Vec<&String> = Vec::new();
        for f in &t.failed {
            if !seen.contains(&f) {
                seen.push(f);
                println!("  {f}");
            }
        }
        std::process::exit(1);
    }
}
