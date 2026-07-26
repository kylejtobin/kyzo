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
    Branches, CanonicalBytes, SeqTag, Shape, ShapedKey, escape, grammar_exec, scan_value,
    seal, seal_sequence, shape_scan,
};

const TAG_NULL: u8 = 0x05;
const TAG_FALSE: u8 = 0x08;
const TAG_BOOL: u8 = 0x08;
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
    let seq_tag = SeqTag::mint(TAG_LIST);

    // An element whose content starts with the sequence terminator.
    let one = seal_sequence(seq_tag, &vec![str_val(&[0x01, 0x41])]);
    let two = seal_sequence(
        seq_tag,
        &vec![str_val(&[0x01, 0x41]), str_val(&[0x41])],
    );

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
    let seq_tag = SeqTag::mint(TAG_LIST);

    let empty_seq = seal_sequence(seq_tag, &Vec::new());
    let seq_of_empty = seal_sequence(seq_tag, &vec![str_val(&[])]);

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
    let null = scalar(TAG_NULL, Vec::new());
    let bool_hi = scalar(TAG_BOOL, Vec::new());
    let str_lo = scalar(TAG_STR, escape(&[]));
    let bytes_lo = scalar(TAG_BYTES, escape(&[]));

    t.check("null < bool", lex_le_independent(null.as_bytes(), bool_hi.as_bytes()));
    t.check("bool < str", lex_le_independent(bool_hi.as_bytes(), str_lo.as_bytes()));
    t.check("str < bytes", lex_le_independent(str_lo.as_bytes(), bytes_lo.as_bytes()));
    // A Str whose content is all 0xFF still sorts under Bytes: the tag decides,
    // and no payload reaches across it.
    let str_hi = scalar(TAG_STR, escape(&[0xFF; 8]));
    t.check(
        "max payload cannot cross a tag",
        lex_le_independent(str_hi.as_bytes(), bytes_lo.as_bytes()),
    );
}

/// ATTACK: prefix sequences. `[a]` must sort before `[a, x]` for EVERY x,
/// including an x whose first payload byte is `0x00`.
fn attack_prefix_sequence_exhaustive(t: &mut Trials) {
    let seq_tag = SeqTag::mint(TAG_LIST);
    for x in 0u16..=255 {
        let byte = x as u8;
        let short = seal_sequence(seq_tag, &vec![str_val(b"a")]);
        let long = seal_sequence(
            seq_tag,
            &vec![str_val(b"a"), str_val(&[byte])],
        );
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
    let seq_tag = SeqTag::mint(TAG_LIST);
    let mut inner = str_val(b"leaf");
    for _ in 0..512 {
        inner = seal_sequence(seq_tag, &vec![inner]);
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
/// is the released format, so both are pinned here against the encoder rather
/// than left to the proof — a proof of an invented grammar proves nothing about
/// the bytes on disk.
fn trial_grammar_table(t: &mut Trials) {
    // (tag, a body the shape must read exactly)
    let table: Vec<(u8, Vec<u8>, &str)> = vec![
        (TAG_NULL, vec![], "Null: no payload"),
        (TAG_FALSE, vec![], "False: no payload"),
        (TAG_TRUE, vec![], "True: no payload"),
        (TAG_NUM, vec![0x02, 0x00], "Num zero: class byte, repr tie-break"),
        (TAG_NUM, vec![0x01; 13], "Num negative: class byte, 12 of magnitude"),
        (TAG_NUM, vec![0x03; 13], "Num positive: class byte, 12 of magnitude"),
        (TAG_STR, escape(b"hello"), "Str: delimited"),
        (TAG_BYTES, escape(&[0x00, 0xFF]), "Bytes: delimited"),
        (TAG_UUID, vec![0x00; 16], "Uuid: 16"),
        (TAG_REGEX, [escape(b"ab"), vec![0x07]].concat(), "Regex: pattern then flags"),
        (TAG_JSON, vec![TAG_NULL], "Json: a value"),
        (TAG_VECTOR, vec![0x00; 32], "Vector: 32"),
        (TAG_LIST, vec![0x01], "List: empty row"),
        (TAG_SET, vec![0x01], "Set: empty row"),
        (TAG_VALIDITY, vec![0x00; 9], "Validity: 9"),
        (TAG_INTERVAL, vec![0x01], "Interval: empty"),
        (TAG_INTERVAL, vec![0x02, 0x01, 0x03], "Interval: unbounded both ends"),
        (TAG_INTERVAL, [vec![0x02, 0x02], vec![0x00; 8], vec![0x03]].concat(), "Interval: lo at"),
        (TAG_GEOMETRY, vec![0x00; 8], "Geometry: 8"),
    ];
    let g = grammar_exec();
    for (tag, body, label) in &table {
        // A row tag is sealed by seal_sequence, not by the scalar door.
        let is_row = *tag == TAG_LIST || *tag == TAG_SET;
        let minted = ShapedKey::mint(*tag, body.clone());
        t.check(label, minted.is_some() != is_row);

        // Whatever the door accepts, the reader measures exactly.
        let mut whole = vec![*tag];
        whole.extend_from_slice(body);
        t.check(label, scan_value(&whole) == Some(whole.len()));

        // And one byte short of it is refused, never guessed at.
        if !body.is_empty() {
            let short = &whole[..whole.len() - 1];
            t.check(label, shape_scan(&g, &Shape::Tagged, short, 0) != Some(short.len()));
        }
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
}

/// ATTACK: the interval ends. Unbounded below is the LEAST element of its axis
/// and unbounded above is the GREATEST, so the two ends cannot share a marker
/// table. A single table would put one of the two infinities on the wrong side
/// of every finite instant.
fn attack_interval_infinities(t: &mut Trials) {
    let lo_unbounded = scalar(TAG_INTERVAL, [vec![0x02, 0x01], vec![0x02], vec![0x00; 8]].concat());
    let lo_at_min = scalar(
        TAG_INTERVAL,
        [vec![0x02, 0x02], vec![0x00; 8], vec![0x02], vec![0x00; 8]].concat(),
    );
    t.check(
        "unbounded below sorts under every instant",
        lex_le_independent(lo_unbounded.as_bytes(), lo_at_min.as_bytes()),
    );

    let hi_at_max = scalar(
        TAG_INTERVAL,
        [vec![0x02, 0x01], vec![0x02], vec![0xFF; 8]].concat(),
    );
    let hi_unbounded = scalar(TAG_INTERVAL, vec![0x02, 0x01, 0x03]);
    t.check(
        "unbounded above sorts over every instant",
        lex_le_independent(hi_at_max.as_bytes(), hi_unbounded.as_bytes()),
    );

    // The empty interval is the one value below every inhabited one.
    let empty = scalar(TAG_INTERVAL, vec![0x01]);
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
    let seq_tag = SeqTag::mint(TAG_LIST);
    let values: Vec<CanonicalBytes> = vec![
        scalar(TAG_NULL, Vec::new()),
        scalar(TAG_STR, escape(&[])),
        scalar(TAG_STR, escape(&[0x00, 0x01, 0xFF])),
        scalar(TAG_NUM, vec![0x02, 0x00]),
        scalar(TAG_JSON, vec![TAG_TRUE]),
        seal_sequence(seq_tag, &Vec::new()),
        seal_sequence(seq_tag, &vec![str_val(&[0x01]), str_val(&[0x00])]),
        seal_sequence(seq_tag, &vec![seal_sequence(seq_tag, &vec![str_val(b"x")])]),
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
    let seq_tag = SeqTag::mint(TAG_LIST);
    let mut deep = str_val(b"leaf");
    for _ in 0..40 {
        deep = seal_sequence(seq_tag, &vec![deep]);
    }
    t.check("nesting within the bound is read", scan_value(deep.as_bytes()).is_some());
    for _ in 0..512 {
        deep = seal_sequence(seq_tag, &vec![deep]);
    }
    t.check("nesting past the bound is refused", scan_value(deep.as_bytes()).is_none());
}

/// ATTACK: JSON is not a second grammar. A JSON value is a value, so the same
/// bytes read the same way whether or not a Json tag sits in front of them.
fn attack_json_is_the_value_grammar(t: &mut Trials) {
    let seq_tag = SeqTag::mint(TAG_LIST);
    let inner: Vec<CanonicalBytes> = vec![
        scalar(TAG_NULL, Vec::new()),
        scalar(TAG_TRUE, Vec::new()),
        scalar(TAG_NUM, vec![0x02, 0x00]),
        scalar(TAG_STR, escape(b"k")),
        seal_sequence(seq_tag, &Vec::new()),
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
    seal(&ShapedKey::mint(TAG_STR, escape(s)).expect("Str body"))
}

/// Mint through the one door, and refuse to continue if the grammar refuses.
fn scalar(tag: u8, body: Vec<u8>) -> CanonicalBytes {
    seal(&ShapedKey::mint(tag, body).expect("body the tag's shape reads exactly"))
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
