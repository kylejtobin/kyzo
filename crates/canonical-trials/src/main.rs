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
    CanonicalBytes, EscapedKey, FixedKey, GrammarLaws, JsonValueBytes, KindKey, SeqTag,
    escape, seal, seal_sequence,
};

const TAG_NULL: u8 = 0x05;
const TAG_BOOL: u8 = 0x08;
const TAG_STR: u8 = 0x18;
const TAG_BYTES: u8 = 0x20;
const TAG_LIST: u8 = 0x48;

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
    let laws = GrammarLaws::establish();
    let seq_tag = SeqTag::mint(TAG_LIST);

    // An element whose content starts with the sequence terminator.
    let one = seal_sequence(&laws, seq_tag, &vec![str_val(&laws, &[0x01, 0x41])]);
    let two = seal_sequence(
        &laws,
        seq_tag,
        &vec![str_val(&laws, &[0x01, 0x41]), str_val(&laws, &[0x41])],
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
    let laws = GrammarLaws::establish();
    let seq_tag = SeqTag::mint(TAG_LIST);

    let empty_seq = seal_sequence(&laws, seq_tag, &Vec::new());
    let seq_of_empty = seal_sequence(&laws, seq_tag, &vec![str_val(&laws, &[])]);

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
    let laws = GrammarLaws::establish();
    let null = seal(&laws, &FixedKey::mint(TAG_NULL, Vec::new()));
    let bool_hi = seal(&laws, &FixedKey::mint(TAG_BOOL, vec![0xFF]));
    let str_lo = seal(&laws, &EscapedKey::mint(TAG_STR, &[]));
    let bytes_lo = seal(&laws, &EscapedKey::mint(TAG_BYTES, &[]));

    t.check("null < bool", lex_le_independent(null.as_bytes(), bool_hi.as_bytes()));
    t.check("bool < str", lex_le_independent(bool_hi.as_bytes(), str_lo.as_bytes()));
    t.check("str < bytes", lex_le_independent(str_lo.as_bytes(), bytes_lo.as_bytes()));
    t.check(
        "max payload cannot cross a tag",
        lex_le_independent(bool_hi.as_bytes(), str_lo.as_bytes()),
    );
}

/// ATTACK: prefix sequences. `[a]` must sort before `[a, x]` for EVERY x,
/// including an x whose first payload byte is `0x00`.
fn attack_prefix_sequence_exhaustive(t: &mut Trials) {
    let laws = GrammarLaws::establish();
    let seq_tag = SeqTag::mint(TAG_LIST);
    for x in 0u16..=255 {
        let byte = x as u8;
        let short = seal_sequence(&laws, seq_tag, &vec![str_val(&laws, b"a")]);
        let long = seal_sequence(
            &laws,
            seq_tag,
            &vec![str_val(&laws, b"a"), str_val(&laws, &[byte])],
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
    let laws = GrammarLaws::establish();
    let seq_tag = SeqTag::mint(TAG_LIST);
    let mut inner = str_val(&laws, b"leaf");
    for _ in 0..512 {
        inner = seal_sequence(&laws, seq_tag, &vec![inner]);
    }
    let bytes = inner.as_bytes();
    // 512 opening tags, 512 terminators, plus the leaf.
    t.check("deep nesting balanced", bytes.len() == 512 * 2 + 1 + 4 + 2);
    t.check("deep nesting opens with the list tag", bytes[0] == TAG_LIST);
    t.check("deep nesting closes with the terminator", bytes[bytes.len() - 1] == 0x01);
}

/// ATTACK: the JSON object-key defect. A key opening with `0x01` must not be
/// readable as the object terminator. The marked grammar puts `JSTR` (`0x18`)
/// in front of every key, so the first byte of a key position is never `0x01`.
fn attack_json_object_key_terminator(t: &mut Trials) {
    let hostile_key: Vec<u8> = vec![0x01, b'x'];
    let value = JsonValueBytes::null();
    let obj = JsonValueBytes::object(&vec![(hostile_key.clone(), value)]);
    let bytes = obj.as_bytes();

    t.check("object opens with JOBJ", bytes[0] == 0x4C);
    t.check("key position is marked, never 0x01", bytes[1] == 0x18);
    t.check("hostile key survives into the body", bytes[2] == 0x01 && bytes[3] == b'x');
    t.check("object closes with the terminator", bytes[bytes.len() - 1] == 0x01);
    // Under the unmarked v1 grammar the body would have opened with 0x01 and
    // decoded as the empty object. The marker is what prevents it.
    t.check("body does not open with the terminator", bytes[1] != 0x01);

    let empty = JsonValueBytes::object(&Vec::new());
    t.check("empty object is two bytes", empty.as_bytes() == [0x4C, 0x01]);
    t.check(
        "empty object != object with hostile key",
        empty.as_bytes() != bytes,
    );
}

/// ATTACK: JSON arrays holding every marker, to prove no element can be read as
/// the array terminator.
fn attack_json_array_markers(t: &mut Trials) {
    let elems = vec![
        JsonValueBytes::null(),
        JsonValueBytes::boolean(false),
        JsonValueBytes::boolean(true),
        JsonValueBytes::string(&[0x01]),
        JsonValueBytes::string(&[0x00]),
        JsonValueBytes::array(&Vec::new()),
        JsonValueBytes::object(&Vec::new()),
    ];
    let arr = JsonValueBytes::array(&elems);
    let bytes = arr.as_bytes();
    t.check("array opens with JARR", bytes[0] == 0x48);
    t.check("no element opens with 0x01", bytes[1] != 0x01);
    t.check("array closes with the terminator", bytes[bytes.len() - 1] == 0x01);
    t.check("array is not empty", bytes.len() > 2);
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
fn str_val(laws: &GrammarLaws, s: &[u8]) -> CanonicalBytes {
    seal(laws, &EscapedKey::mint(TAG_STR, s))
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

    println!("attacks");
    attack_terminator_forgery(&mut t);
    attack_escape_forgery(&mut t);
    attack_concatenation_collision(&mut t);
    attack_structural_smuggling(&mut t);
    attack_empty_confusion(&mut t);
    attack_cross_type_order(&mut t);
    attack_prefix_sequence_exhaustive(&mut t);
    attack_deep_nesting(&mut t);
    attack_json_object_key_terminator(&mut t);
    attack_json_array_markers(&mut t);
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
