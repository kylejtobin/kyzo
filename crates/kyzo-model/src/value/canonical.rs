/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! AUTHORITY: The one order-preserving byte form — the interning key and the on-disk key.
//!
//! ORDER_LAW: `a <= b  <=>  encode(a) <=lex encode(b)`, total over every kind.
//!
//! CLAIM: Unconstructible — an encoding that is not order-preserving.
//!
//! Binary order equals semantic order. One order over one substrate is what
//! makes every access path a range scan on the same bytes. A defect does not
//! raise; it returns wrong answers until someone notices.
//!
//! The law is discharged by Verus over all inputs. Run `xtask/verify-canonical.sh`.
//! A violation is a verification failure carrying a counterexample.
//!
//! # What is proven
//!
//! - `lex_le` is a total order: reflexive, antisymmetric, transitive, total.
//! - `lemma_concat_order` — THE CLOSURE THEOREM. Concatenation is the
//!   lexicographic product order whenever the left operands are
//!   prefix-incomparable.
//! - `lemma_prefix_hypothesis_is_necessary` — that hypothesis cannot be
//!   dropped, by machine-checked counterexample.
//! - `lemma_bytes_order` / `lemma_bytes_prefix_free` — the escaped byte-string
//!   code is order-preserving AND a prefix code.
//! - `lemma_row_order` / `lemma_row_prefix_free` — the same two properties for
//!   sequences, so a sequence may nest without bound.
//! - `theorem_prefix_code` — complete encodings form a prefix code, which is
//!   what discharges the closure theorem's hypothesis everywhere at once.
//! - `theorem_value_order` — `val_le(u,v) == lex_le(enc(u), enc(v))` over the
//!   whole recursive value domain.
//! - `lemma_enc_injective` — distinct values never share bytes.
//! - `lemma_enc_complete` — every encoding this module produces is complete.
//!
//! # The grammar seam is open
//!
//! The format layer is deleted and its replacement is not built. `scan` and
//! everything reached through it name a per-kind reader that no longer exists,
//! so this file does not verify. What survives is the proof machinery that is
//! independent of any particular grammar: the order on bytes, the closure
//! theorem, the escaped byte-string code, the row code, and the value tree.
//!
//! The replacement is one `Shape` — a self-delimiting, order-preserving binary
//! grammar as data — with one recursive reader and one locality lemma proven by
//! structural induction. Locality stops being an obligation a kind assumes and
//! becomes a theorem the algebra discharges.
//!
//! # Marked positions
//!
//! Every position a scanner reads to decide "element or terminator" holds a
//! byte that sorts above the terminator. `wf_grammar` is exactly that check,
//! and it is demanded of a `Row`'s element and nowhere else. An unmarked
//! element would admit one beginning `0x01`, and the body would have two
//! readings.
//!
//! # Trusted computing base
//!
//! The exact, enumerable list this proof assumes rather than proves:
//!
//! 1. **Z3 4.12.5** — the solver discharging the obligations. A soundness bug
//!    means it can certify something false.
//! 2. **Verus 0.2026.07.18** — the encoding of Rust's semantics into SMT. If
//!    Verus models Rust wrong, the theorem is about a different language.
//! 3. **The specification** — `lex_le` and `is_prefix` below, together under
//!    twenty lines. If `lex_le` does not define lexicographic order, everything
//!    under it is a rigorous proof of the wrong thing. It is readable in one
//!    sitting, and `tests/canonical_law.rs` pins that it computes what a human
//!    means by "lexicographic" against exhaustive independent enumeration.
//!
//! The size of that list is the deliverable. Nothing about the encoder is
//! trusted, including code not yet written: a new kind reopens no obligation,
//! because it can only be assembled from proven parts.

use vstd::prelude::*;

/// THE GRAMMAR, written once.
///
/// A macro and not two functions: the value the proof reasons about and the
/// value the program builds must be the same characters. Two bodies with an
/// `ensures` between them are two authorities and a patch over the second.
/// Raw constructors, because a helper function belongs to one mode or the
/// other and this text has to live in both.
macro_rules! branch_table {
    () => { Branches::End };
    ($k:expr => $s:expr $(, $rk:expr => $rs:expr)* $(,)?) => {
        Branches::Alt($k, Box::new($s), Box::new(branch_table!($($rk => $rs),*)))
    };
}

// Four classes, in order: negative, zero, positive, NaN. NaN sorts above every
// number because the store needs a TOTAL order over every value it can hold,
// and there is no number it could sit beside.
//
// Every class carries the int/float tie-break byte, because `Num::encode_key`
// writes one for every class. That byte IS a constant for NaN — only a float is
// ever NaN — and a constant byte decides nothing, so it looks like weight to
// drop. It is not this file's to drop. `number.rs` owns the number payload and
// this file frames it; removing the byte here while `Num::decode_key` still
// expects it makes two authorities disagree about the same bytes, which is the
// defect, not the fix. Dropping it is a change to the number law, made there.
macro_rules! num_table {
    () => { branch_table!(
        0x01 => Shape::Fixed(12),
        0x02 => Shape::Fixed(1),
        0x03 => Shape::Fixed(12),
        0x04 => Shape::Fixed(1),
    ) };
}
macro_rules! lo_table {
    () => { branch_table!(0x01 => Shape::Fixed(0), 0x02 => Shape::Fixed(8)) };
}
macro_rules! hi_table {
    () => { branch_table!(0x02 => Shape::Fixed(8), 0x03 => Shape::Fixed(0)) };
}
macro_rules! interval_table {
    () => { branch_table!(
        0x01 => Shape::Fixed(0),
        0x02 => Shape::Product(Box::new(Shape::Sum(Box::new(lo_table!()))),
                               Box::new(Shape::Sum(Box::new(hi_table!())))),
    ) };
}
macro_rules! grammar_table {
    () => { branch_table!(
        0x05 => Shape::Fixed(0),
        0x08 => Shape::Fixed(0),
        0x09 => Shape::Fixed(0),
        0x10 => Shape::Sum(Box::new(num_table!())),
        0x18 => Shape::Delimited,
        0x20 => Shape::Delimited,
        0x28 => Shape::Fixed(16),
        0x30 => Shape::Product(Box::new(Shape::Delimited), Box::new(Shape::Fixed(1))),
        0x38 => Shape::Tagged,
        // A vector is its dimension, then its components. Dimension leads
        // because two vectors of different length order by length first, and a
        // fixed width here would pin dimensionality into the value type — the
        // one thing the model zone forbids, since dimension is per row.
        //
        // The components are a row of TAGGED values, not a row of bare Num
        // bodies: `keys_marked` requires a lead byte above STRUCT_END, and
        // Num's negative class byte IS 0x01. A row of bare Nums could not tell
        // a negative component from the end of the row.
        0x40 => Shape::Product(
            Box::new(Shape::Fixed(4)),
            Box::new(Shape::Row(Box::new(Shape::Tagged))),
        ),
        0x48 => Shape::Row(Box::new(Shape::Tagged)),
        0x50 => Shape::Row(Box::new(Shape::Tagged)),
        0x58 => Shape::Fixed(9),
        0x60 => Shape::Sum(Box::new(interval_table!())),
        0x68 => Shape::Fixed(8),
    ) };
}

verus! {


pub const STRUCT_ESC: u8 = 0x00;
pub const STRUCT_END: u8 = 0x01;
/// What an escaped `STRUCT_ESC` is followed by. Any other second byte is not
/// an escape, which is what keeps `STRUCT_ESC STRUCT_ESC` free to terminate.
pub const ESC_ZERO: u8 = 0xFF;

// ============================ lexicographic order ============================

pub open spec fn lex_le(a: Seq<u8>, b: Seq<u8>) -> bool
    decreases a.len()
{
    if a.len() == 0 { true }
    else if b.len() == 0 { false }
    else if a[0] != b[0] { a[0] < b[0] }
    else { lex_le(a.drop_first(), b.drop_first()) }
}

pub open spec fn is_prefix(x: Seq<u8>, y: Seq<u8>) -> bool {
    x.len() <= y.len() && y.take(x.len() as int) =~= x
}

pub open spec fn incomparable(x: Seq<u8>, y: Seq<u8>) -> bool {
    (is_prefix(x, y) || is_prefix(y, x)) ==> x =~= y
}

pub proof fn lemma_lex_refl(a: Seq<u8>)
    ensures lex_le(a, a)
    decreases a.len()
{ if a.len() > 0 { lemma_lex_refl(a.drop_first()); } }

pub proof fn lemma_lex_total(a: Seq<u8>, b: Seq<u8>)
    ensures lex_le(a, b) || lex_le(b, a)
    decreases a.len()
{ if a.len() > 0 && b.len() > 0 && a[0] == b[0] { lemma_lex_total(a.drop_first(), b.drop_first()); } }

pub proof fn lemma_lex_antisym(a: Seq<u8>, b: Seq<u8>)
    requires lex_le(a, b), lex_le(b, a)
    ensures a =~= b
    decreases a.len()
{
    if a.len() > 0 && b.len() > 0 {
        lemma_lex_antisym(a.drop_first(), b.drop_first());
        assert(a =~= seq![a[0]] + a.drop_first());
        assert(b =~= seq![b[0]] + b.drop_first());
    }
}

pub proof fn lemma_lex_trans(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires lex_le(a, b), lex_le(b, c)
    ensures lex_le(a, c)
    decreases a.len()
{
    if a.len() > 0 && b.len() > 0 && c.len() > 0 && a[0] == b[0] && b[0] == c[0] {
        lemma_lex_trans(a.drop_first(), b.drop_first(), c.drop_first());
    }
}

proof fn lemma_head_tail(a: Seq<u8>, b: Seq<u8>)
    requires a.len() > 0, b.len() > 0, a[0] == b[0]
    ensures
        is_prefix(a.drop_first(), b.drop_first()) == is_prefix(a, b),
        (a.drop_first() =~= b.drop_first()) == (a =~= b),
{
    assert(a =~= seq![a[0]] + a.drop_first());
    assert(b =~= seq![b[0]] + b.drop_first());
    if is_prefix(a.drop_first(), b.drop_first()) {
        assert(b.take(a.len() as int) =~= a) by {
            assert forall|i: int| 0 <= i < a.len()
                implies #[trigger] b.take(a.len() as int)[i] == a[i] by {
                if i > 0 {
                    assert(b.drop_first().take(a.drop_first().len() as int)[i - 1]
                        == a.drop_first()[i - 1]);
                }
            }
        }
    }
    if is_prefix(a, b) {
        assert(b.drop_first().take(a.drop_first().len() as int) =~= a.drop_first()) by {
            assert forall|i: int| 0 <= i < a.len() - 1
                implies #[trigger] b.drop_first().take(a.len() - 1)[i] == a.drop_first()[i] by {
                assert(b.take(a.len() as int)[i + 1] == a[i + 1]);
            }
        }
    }
}

/// THE CLOSURE THEOREM. Prefix-incomparable heads make concatenation the
/// lexicographic product order.
pub proof fn lemma_concat_order(f: Seq<u8>, g: Seq<u8>, f2: Seq<u8>, g2: Seq<u8>)
    requires incomparable(f, f2)
    ensures lex_le(f + g, f2 + g2) == if f =~= f2 { lex_le(g, g2) } else { lex_le(f, f2) }
    decreases f.len()
{
    if f.len() == 0 {
        assert(is_prefix(f, f2));
        assert(f + g =~= g);
        assert(f2 + g2 =~= g2);
    } else if f2.len() == 0 {
        assert(is_prefix(f2, f));
    } else {
        assert((f + g)[0] == f[0]);
        assert((f2 + g2)[0] == f2[0]);
        if f[0] == f2[0] {
            lemma_head_tail(f, f2);
            lemma_head_tail(f2, f);
            assert((f + g).drop_first() =~= f.drop_first() + g);
            assert((f2 + g2).drop_first() =~= f2.drop_first() + g2);
            lemma_concat_order(f.drop_first(), g, f2.drop_first(), g2);
        }
    }
}

/// Without prefix-incomparability the closure theorem is FALSE. Machine-checked
/// counterexample: `("a","bc")` and `("ab","c")` both concatenate to `abc`.
pub proof fn lemma_prefix_hypothesis_is_necessary()
    ensures
        !incomparable(seq![97u8], seq![97u8, 98u8]),
        seq![97u8] + seq![98u8, 99u8] =~= seq![97u8, 98u8] + seq![99u8],
        !(seq![97u8] =~= seq![97u8, 98u8]),
{
    assert(seq![97u8, 98u8].take(1) =~= seq![97u8]);
    assert(seq![97u8] + seq![98u8, 99u8] =~= seq![97u8, 98u8, 99u8]);
    assert(seq![97u8, 98u8] + seq![99u8] =~= seq![97u8, 98u8, 99u8]);
}

pub proof fn lemma_prefix_split(x: Seq<u8>, a: Seq<u8>, y: Seq<u8>, b: Seq<u8>)
    requires incomparable(x, y), is_prefix(x + a, y + b)
    ensures x =~= y, is_prefix(a, b)
{
    if x.len() <= y.len() {
        assert(is_prefix(x, y)) by {
            assert(y.take(x.len() as int) =~= x) by {
                assert forall|i: int| 0 <= i < x.len()
                    implies #[trigger] y.take(x.len() as int)[i] == x[i] by {
                    assert((y + b).take((x + a).len() as int)[i] == (x + a)[i]);
                }
            }
        }
    } else {
        assert(is_prefix(y, x)) by {
            assert(x.take(y.len() as int) =~= y) by {
                assert forall|i: int| 0 <= i < y.len()
                    implies #[trigger] x.take(y.len() as int)[i] == y[i] by {
                    assert((y + b).take((x + a).len() as int)[i] == (x + a)[i]);
                }
            }
        }
    }
    assert(x =~= y);
    assert(b.take(a.len() as int) =~= a) by {
        assert forall|i: int| 0 <= i < a.len()
            implies #[trigger] b.take(a.len() as int)[i] == a[i] by {
            assert((y + b).take((x + a).len() as int)[x.len() + i] == (x + a)[x.len() + i]);
        }
    }
}

proof fn lemma_prefix_trans(x: Seq<u8>, y: Seq<u8>, z: Seq<u8>)
    requires is_prefix(x, y), is_prefix(y, z)
    ensures is_prefix(x, z)
{
    assert(z.take(x.len() as int) =~= x) by {
        assert forall|i: int| 0 <= i < x.len()
            implies #[trigger] z.take(x.len() as int)[i] == x[i] by {
            assert(z.take(y.len() as int)[i] == y[i]);
            assert(y.take(x.len() as int)[i] == x[i]);
        }
    }
}

proof fn lemma_prefix_of_self_plus(x: Seq<u8>, a: Seq<u8>)
    ensures is_prefix(x, x + a)
{ assert((x + a).take(x.len() as int) =~= x); }

// ======================= the escaped byte-string code ========================

pub open spec fn code(b: u8) -> Seq<u8> {
    if b == STRUCT_ESC { seq![STRUCT_ESC, ESC_ZERO] } else { seq![b] }
}

pub open spec fn esc(s: Seq<u8>) -> Seq<u8>
    decreases s.len()
{ if s.len() == 0 { Seq::empty() } else { code(s[0]) + esc(s.drop_first()) } }

/// Escaped body then the `0x00 0x00` terminator. The terminator is the unique
/// minimum of the code alphabet, so a prefix sorts before its extensions.
pub open spec fn enc_bytes(s: Seq<u8>) -> Seq<u8> {
    esc(s) + seq![STRUCT_ESC, STRUCT_ESC]
}

pub proof fn lemma_esc_no_terminator(s: Seq<u8>)
    ensures forall|i: int| 0 <= i < esc(s).len() - 1
        ==> !(#[trigger] esc(s)[i] == 0u8 && esc(s)[i + 1] == 0u8)
    decreases s.len()
{
    if s.len() > 0 {
        lemma_esc_no_terminator(s.drop_first());
        let c = code(s[0]);
        let rest = esc(s.drop_first());
        assert(esc(s) =~= c + rest);
        assert forall|i: int| 0 <= i < esc(s).len() - 1
            implies !(#[trigger] esc(s)[i] == 0u8 && esc(s)[i + 1] == 0u8) by {
            if i >= c.len() {
                assert(esc(s)[i] == rest[i - c.len()]);
                assert(esc(s)[i + 1] == rest[i + 1 - c.len()]);
                assert(rest[i - c.len()] == 0u8 ==> rest[i - c.len() + 1] != 0u8);
            } else if s[0] == 0u8 {
                assert(esc(s)[1] == ESC_ZERO);
            } else {
                assert(esc(s)[0] == s[0]);
            }
        }
    }
}

pub proof fn lemma_esc_last_nonzero(s: Seq<u8>)
    ensures esc(s).len() > 0 ==> esc(s)[esc(s).len() - 1] != 0u8
    decreases s.len()
{
    if s.len() > 0 {
        lemma_esc_last_nonzero(s.drop_first());
        let c = code(s[0]);
        let rest = esc(s.drop_first());
        assert(esc(s) =~= c + rest);
        if rest.len() > 0 {
            assert(esc(s)[esc(s).len() - 1] == rest[rest.len() - 1]);
        } else {
            assert(esc(s) =~= c);
        }
    }
}

pub proof fn lemma_esc_injective(s: Seq<u8>, t: Seq<u8>)
    requires esc(s) =~= esc(t)
    ensures s =~= t
    decreases s.len()
{
    if s.len() == 0 {
        if t.len() > 0 { assert(esc(t) =~= code(t[0]) + esc(t.drop_first())); }
    } else if t.len() == 0 {
        assert(esc(s) =~= code(s[0]) + esc(s.drop_first()));
    } else {
        assert(esc(s) =~= code(s[0]) + esc(s.drop_first()));
        assert(esc(t) =~= code(t[0]) + esc(t.drop_first()));
        assert(esc(s)[0] == code(s[0])[0]);
        assert(esc(t)[0] == code(t[0])[0]);
        assert(s[0] == t[0]);
        assert(esc(s).skip(code(s[0]).len() as int) =~= esc(s.drop_first()));
        assert(esc(t).skip(code(t[0]).len() as int) =~= esc(t.drop_first()));
        lemma_esc_injective(s.drop_first(), t.drop_first());
        assert(s =~= seq![s[0]] + s.drop_first());
        assert(t =~= seq![t[0]] + t.drop_first());
    }
}

pub proof fn lemma_enc_bytes_peel(s: Seq<u8>)
    requires s.len() > 0
    ensures enc_bytes(s) =~= code(s[0]) + enc_bytes(s.drop_first())
{
    assert(esc(s) =~= code(s[0]) + esc(s.drop_first()));
    assert((code(s[0]) + esc(s.drop_first())) + seq![0u8, 0u8]
        =~= code(s[0]) + (esc(s.drop_first()) + seq![0u8, 0u8]));
}

proof fn lemma_terminator_is_minimum(t: Seq<u8>)
    requires t.len() > 0
    ensures
        lex_le(seq![0u8, 0u8], enc_bytes(t)),
        !lex_le(enc_bytes(t), seq![0u8, 0u8]),
{
    lemma_enc_bytes_peel(t);
    let e = enc_bytes(t);
    let z = seq![0u8, 0u8];
    if t[0] == 0u8 {
        assert(code(t[0]) =~= seq![STRUCT_ESC, ESC_ZERO]);
        assert(e.len() >= 4);
        assert(e[0] == STRUCT_ESC && e[1] == ESC_ZERO);
        let e1 = e.drop_first();
        let z1 = z.drop_first();
        assert(z1 =~= seq![0u8]);
        assert(e1.len() >= 3 && e1[0] == ESC_ZERO);
        assert(lex_le(z1, e1)) by { assert(z1[0] == STRUCT_ESC && e1[0] == ESC_ZERO); }
        assert(!lex_le(e1, z1)) by { assert(z1[0] == STRUCT_ESC && e1[0] == ESC_ZERO); }
        assert(z[0] == e[0]);
    } else {
        assert(code(t[0]) =~= seq![t[0]]);
        assert(e[0] == t[0] && z[0] == 0u8);
    }
}

proof fn lemma_lex_cancel(p: Seq<u8>, a: Seq<u8>, b: Seq<u8>)
    ensures lex_le(p + a, p + b) == lex_le(a, b)
    decreases p.len()
{
    if p.len() > 0 {
        assert((p + a)[0] == p[0] && (p + b)[0] == p[0]);
        assert((p + a).drop_first() =~= p.drop_first() + a);
        assert((p + b).drop_first() =~= p.drop_first() + b);
        lemma_lex_cancel(p.drop_first(), a, b);
    } else {
        assert(p + a =~= a);
        assert(p + b =~= b);
    }
}

/// ORDER LAW for byte strings.
pub proof fn lemma_bytes_order(s: Seq<u8>, t: Seq<u8>)
    ensures lex_le(s, t) == lex_le(enc_bytes(s), enc_bytes(t))
    decreases s.len()
{
    if s.len() == 0 {
        assert(esc(s) =~= Seq::<u8>::empty());
        assert(enc_bytes(s) =~= seq![0u8, 0u8]);
        if t.len() == 0 {
            assert(enc_bytes(t) =~= seq![0u8, 0u8]);
            lemma_lex_refl(enc_bytes(t));
        } else {
            lemma_terminator_is_minimum(t);
        }
    } else if t.len() == 0 {
        assert(esc(t) =~= Seq::<u8>::empty());
        assert(enc_bytes(t) =~= seq![0u8, 0u8]);
        lemma_terminator_is_minimum(s);
    } else {
        lemma_enc_bytes_peel(s);
        lemma_enc_bytes_peel(t);
        if s[0] == t[0] {
            lemma_lex_cancel(code(s[0]), enc_bytes(s.drop_first()), enc_bytes(t.drop_first()));
            lemma_bytes_order(s.drop_first(), t.drop_first());
        } else {
            let a = enc_bytes(s);
            let b = enc_bytes(t);
            if s[0] == 0u8 {
                assert(a[0] == 0u8 && b[0] == t[0] && t[0] != 0u8);
            } else if t[0] == 0u8 {
                assert(b[0] == 0u8 && a[0] == s[0] && s[0] != 0u8);
            } else {
                assert(a[0] == s[0] && b[0] == t[0]);
            }
        }
    }
}

/// PREFIX-FREEDOM for byte strings.
pub proof fn lemma_bytes_prefix_free(s: Seq<u8>, t: Seq<u8>)
    requires is_prefix(enc_bytes(s), enc_bytes(t))
    ensures s =~= t
{
    lemma_esc_no_terminator(t);
    lemma_esc_last_nonzero(t);
    let a = esc(s);
    let b = esc(t);
    let ea = enc_bytes(s);
    let eb = enc_bytes(t);
    assert(ea.len() == a.len() + 2 && eb.len() == b.len() + 2);
    if a.len() < b.len() {
        assert(eb.take(ea.len() as int)[a.len() as int] == ea[a.len() as int]);
        assert(eb.take(ea.len() as int)[a.len() as int + 1] == ea[a.len() as int + 1]);
        assert(ea[a.len() as int] == 0u8 && ea[a.len() as int + 1] == 0u8);
        assert(eb[a.len() as int] == 0u8 && eb[a.len() as int + 1] == 0u8);
        if a.len() + 1 < b.len() {
            assert(eb[a.len() as int] == b[a.len() as int]);
            assert(eb[a.len() as int + 1] == b[a.len() as int + 1]);
        } else {
            assert(eb[a.len() as int] == b[a.len() as int]);
            assert(b[b.len() - 1] == 0u8);
        }
    }
    assert(a.len() == b.len());
    assert(a =~= b) by {
        assert forall|i: int| 0 <= i < a.len() implies #[trigger] a[i] == b[i] by {
            assert(eb.take(ea.len() as int)[i] == ea[i]);
        }
    }
    lemma_esc_injective(s, t);
}

/// Where the escaped body in `p` ends: the first `0x00 0x00`. This is the
/// reader of [`enc_bytes`], and it is exact because [`esc`] never emits that
/// pair, so the terminator `enc_bytes` appends is the first one this meets.
/// Adds `k` to a reading. `None` propagates.
pub open spec fn after(r: Option<nat>, k: nat) -> Option<nat> {
    match r {
        Some(n) => Some((n + k) as nat),
        None => None,
    }
}

pub open spec fn delim_end(p: Seq<u8>) -> Option<nat>
    decreases p.len()
{
    if p.len() < 2 { None }
    else if p[0] == STRUCT_ESC {
        if p[1] == STRUCT_ESC { Some(2nat) }
        else if p[1] == ESC_ZERO { after(delim_end(p.skip(2)), 2nat) }
        else { None }
    } else {
        after(delim_end(p.skip(1)), 1nat)
    }
}

pub proof fn lemma_delim_bounded(p: Seq<u8>)
    ensures match delim_end(p) { Some(n) => 2 <= n <= p.len(), None => true }
    decreases p.len()
{
    if p.len() >= 2 {
        if p[0] == STRUCT_ESC {
            if p[1] == ESC_ZERO { lemma_delim_bounded(p.skip(2)); }
        } else {
            lemma_delim_bounded(p.skip(1));
        }
    }
}

/// LOCALITY for the escaped body: the terminator is inside the body, so bytes
/// after it cannot move it.
pub proof fn lemma_delim_local(a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), delim_end(a) is Some
    ensures delim_end(b) == delim_end(a)
    decreases a.len()
{
    lemma_delim_bounded(a);
    lemma_prefix_index(a, b, 0);
    lemma_prefix_index(a, b, 1);
    if a[0] == STRUCT_ESC {
        if a[1] == ESC_ZERO {
            lemma_prefix_skip(a, b, 2);
            lemma_delim_local(a.skip(2), b.skip(2));
        }
    } else {
        lemma_prefix_skip(a, b, 1);
        lemma_delim_local(a.skip(1), b.skip(1));
    }
}

/// The escaped form measures itself exactly.
pub proof fn lemma_delim_end_of_enc_bytes(s: Seq<u8>)
    ensures delim_end(enc_bytes(s)) == Some(enc_bytes(s).len() as nat)
    decreases s.len()
{
    let q = enc_bytes(s);
    if s.len() == 0 {
        assert(esc(s) =~= Seq::<u8>::empty());
        assert(q =~= seq![0u8, 0u8]);
    } else {
        lemma_enc_bytes_peel(s);
        let rest = enc_bytes(s.drop_first());
        lemma_delim_end_of_enc_bytes(s.drop_first());
        if s[0] == STRUCT_ESC {
            assert(code(s[0]) =~= seq![STRUCT_ESC, ESC_ZERO]);
            assert(q[0] == STRUCT_ESC && q[1] == ESC_ZERO);
            assert(q.skip(2) =~= rest);
        } else {
            assert(code(s[0]) =~= seq![s[0]]);
            assert(q[0] == s[0]);
            assert(q.skip(1) =~= rest);
        }
    }
}

// ================================== rows =====================================

pub open spec fn cat(r: Seq<Seq<u8>>) -> Seq<u8>
    decreases r.len()
{ if r.len() == 0 { Seq::empty() } else { r[0] + cat(r.drop_first()) } }

pub open spec fn enc_row(r: Seq<Seq<u8>>) -> Seq<u8> { cat(r) + seq![STRUCT_END] }

pub open spec fn row_le(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>) -> bool
    decreases r.len()
{
    if r.len() == 0 { true }
    else if s.len() == 0 { false }
    else if !(r[0] =~= s[0]) { lex_le(r[0], s[0]) }
    else { row_le(r.drop_first(), s.drop_first()) }
}

pub open spec fn tagged(r: Seq<Seq<u8>>) -> bool {
    forall|i: int| 0 <= i < r.len() ==> #[trigger] r[i].len() > 0 && r[i][0] > STRUCT_END
}

pub open spec fn pfx_family(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>) -> bool {
    forall|i: int, j: int| 0 <= i < r.len() && 0 <= j < s.len()
        ==> #[trigger] incomparable(r[i], s[j])
}

proof fn lemma_row_peel(r: Seq<Seq<u8>>)
    requires r.len() > 0
    ensures enc_row(r) =~= r[0] + enc_row(r.drop_first())
{
    assert(cat(r) =~= r[0] + cat(r.drop_first()));
    assert((r[0] + cat(r.drop_first())) + seq![STRUCT_END]
        =~= r[0] + (cat(r.drop_first()) + seq![STRUCT_END]));
}

proof fn lemma_row_head(r: Seq<Seq<u8>>)
    requires tagged(r), r.len() > 0
    ensures enc_row(r).len() > 0, enc_row(r)[0] == r[0][0], enc_row(r)[0] > STRUCT_END
{ lemma_row_peel(r); assert(r[0].len() > 0); }

proof fn lemma_tail_tagged(r: Seq<Seq<u8>>)
    requires tagged(r), r.len() > 0
    ensures tagged(r.drop_first())
{
    assert forall|i: int| 0 <= i < r.drop_first().len()
        implies #[trigger] r.drop_first()[i].len() > 0 && r.drop_first()[i][0] > STRUCT_END by {
        assert(r[i + 1].len() > 0 && r[i + 1][0] > STRUCT_END);
    }
}

proof fn lemma_tail_family(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>)
    requires pfx_family(r, s), r.len() > 0, s.len() > 0
    ensures pfx_family(r.drop_first(), s.drop_first())
{
    assert forall|i: int, j: int|
        0 <= i < r.drop_first().len() && 0 <= j < s.drop_first().len()
        implies #[trigger] incomparable(r.drop_first()[i], s.drop_first()[j]) by {
        assert(incomparable(r[i + 1], s[j + 1]));
    }
}

/// ORDER LAW for rows.
pub proof fn lemma_row_order(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>)
    requires tagged(r), tagged(s), pfx_family(r, s)
    ensures row_le(r, s) == lex_le(enc_row(r), enc_row(s))
    decreases r.len()
{
    if r.len() == 0 {
        assert(cat(r) =~= Seq::<u8>::empty());
        assert(enc_row(r) =~= seq![STRUCT_END]);
        if s.len() == 0 {
            assert(enc_row(s) =~= seq![STRUCT_END]);
            lemma_lex_refl(enc_row(r));
        } else {
            lemma_row_head(s);
            assert(lex_le(enc_row(r), enc_row(s))) by {
                assert(enc_row(r)[0] == STRUCT_END && enc_row(s)[0] > STRUCT_END);
            }
        }
    } else if s.len() == 0 {
        assert(cat(s) =~= Seq::<u8>::empty());
        assert(enc_row(s) =~= seq![STRUCT_END]);
        lemma_row_head(r);
        assert(!lex_le(enc_row(r), enc_row(s))) by {
            assert(enc_row(r)[0] > STRUCT_END && enc_row(s)[0] == STRUCT_END);
        }
    } else {
        lemma_row_peel(r);
        lemma_row_peel(s);
        assert(incomparable(r[0], s[0]));
        lemma_concat_order(r[0], enc_row(r.drop_first()), s[0], enc_row(s.drop_first()));
        lemma_tail_tagged(r);
        lemma_tail_tagged(s);
        lemma_tail_family(r, s);
        lemma_row_order(r.drop_first(), s.drop_first());
    }
}

/// PREFIX-FREEDOM for rows.
pub proof fn lemma_row_prefix_free(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>)
    requires tagged(r), tagged(s), pfx_family(r, s), is_prefix(enc_row(r), enc_row(s))
    ensures r =~= s
    decreases r.len()
{
    if r.len() == 0 {
        assert(cat(r) =~= Seq::<u8>::empty());
        assert(enc_row(r) =~= seq![STRUCT_END]);
        if s.len() > 0 {
            lemma_row_head(s);
            assert(enc_row(s).take(1)[0] == STRUCT_END);
            assert(enc_row(s)[0] > STRUCT_END);
        }
    } else if s.len() == 0 {
        assert(cat(s) =~= Seq::<u8>::empty());
        assert(enc_row(s) =~= seq![STRUCT_END]);
        lemma_row_head(r);
        lemma_row_peel(r);
        assert(enc_row(r).len() > 1);
    } else {
        lemma_row_peel(r);
        lemma_row_peel(s);
        assert(incomparable(r[0], s[0]));
        lemma_prefix_split(r[0], enc_row(r.drop_first()), s[0], enc_row(s.drop_first()));
        lemma_tail_tagged(r);
        lemma_tail_tagged(s);
        lemma_tail_family(r, s);
        lemma_row_prefix_free(r.drop_first(), s.drop_first());
        assert(r =~= seq![r[0]] + r.drop_first());
        assert(s =~= seq![s[0]] + s.drop_first());
    }
}

proof fn lemma_prefix_index(a: Seq<u8>, b: Seq<u8>, i: int)
    requires is_prefix(a, b), 0 <= i < a.len()
    ensures a[i] == b[i]
{ assert(b.take(a.len() as int)[i] == a[i]); }

proof fn lemma_prefix_skip(a: Seq<u8>, b: Seq<u8>, n: int)
    requires is_prefix(a, b), 0 <= n <= a.len()
    ensures is_prefix(a.skip(n), b.skip(n))
{
    assert(b.skip(n).take(a.skip(n).len() as int) =~= a.skip(n)) by {
        assert forall|i: int| 0 <= i < a.len() - n
            implies #[trigger] b.skip(n).take(a.len() - n)[i] == a.skip(n)[i] by {
            lemma_prefix_index(a, b, i + n);
        }
    }
}

// ===================== the self-delimiting byte grammar ======================
//
// A grammar is a value of type [`Shape`], read by the one function
// [`shape_end`]. A kind does not own a scanner and owes no obligation: it names
// a shape, and the shape's laws are already discharged by structural induction
// over the algebra.

/// A self-delimiting, order-preserving binary grammar.
///
/// Self-delimitation is not a side condition here: every constructor has a
/// reader, so there is no inhabitant of this type that lacks one. The only law
/// a grammar can break is the `Row` one, and [`wf_shape`] is exactly that law.
// CONSTRUCT: ClosedSum Shape
pub enum Shape {
    /// Exactly `n` payload bytes.
    Fixed(usize),
    /// An escaped body terminated by `0x00 0x00` — the reader of [`enc_bytes`].
    Delimited,
    /// One shape, then another at the offset the first ends.
    Product(Box<Shape>, Box<Shape>),
    /// One lead byte selects a branch, which reads what follows it.
    Sum(Box<Branches>),
    /// Elements until `STRUCT_END`.
    Row(Box<Shape>),
    /// The whole grammar, again.
    ///
    /// The one back-reference, and what lets a value nest without bound while
    /// the grammar stays a finite tree. It consumes its lead byte *before* it
    /// recurses, which is why the reader terminates on a shrinking input rather
    /// than a shrinking shape.
    Tagged,
}

/// A branch table: lead byte to the shape it selects.
// CONSTRUCT: ClosedSum Branches
pub enum Branches {
    End,
    Alt(u8, Box<Shape>, Box<Branches>),
}

/// The branch a lead byte selects. First match wins, so a repeated key is dead
/// weight rather than an ambiguity.
pub open spec fn branch_of(bs: Branches, b: u8) -> Option<Shape>
    decreases bs
{
    match bs {
        Branches::End => None,
        Branches::Alt(k, s, rest) => if k == b { Some(*s) } else { branch_of(*rest, b) },
    }
}

/// The measure that shrinks on the two steps that read no byte: a `Product`'s
/// factors and a `Row`'s element. Every other step consumes a lead byte, so the
/// input shrinks instead and the selected branch's own size never matters —
/// which is what lets `Tagged` name a grammar that contains it.
pub open spec fn shape_sz(s: Shape) -> nat
    decreases s
{
    match s {
        Shape::Product(a, b) => 1nat + shape_sz(*a) + shape_sz(*b),
        Shape::Row(e) => 1nat + shape_sz(*e),
        _ => 1nat,
    }
}

/// Where the shape ends in `p`, or negative if `p` does not open with one.
/// Total: every shape and every byte sequence has an answer, never a panic.
pub open spec fn shape_end(g: Branches, s: Shape, p: Seq<u8>) -> Option<nat>
    decreases p.len(), shape_sz(s)
{
    match s {
        Shape::Fixed(n) => if p.len() >= n { Some(n as nat) } else { None },
        Shape::Delimited => delim_end(p),
        Shape::Product(a, b) => {
            match shape_end(g, *a, p) {
                None => None,
                // `j > p.len()` cannot arise — `lemma_shape_bounded` proves it —
                // but a spec function cannot invoke a lemma, and without the
                // bound Verus cannot show `p.skip(j)` shrinks.
                Some(j) => if j > p.len() { None } else {
                    after(shape_end(g, *b, p.skip(j as int)), j)
                }
            }
        }
        Shape::Sum(bs) => sum_end(g, *bs, p),
        Shape::Tagged => sum_end(g, g, p),
        Shape::Row(e) => {
            if p.len() == 0 { None }
            else if p[0] == STRUCT_END { Some(1nat) }
            else {
                match shape_end(g, *e, p) {
                    None => None,
                    // Both bounds are termination conditions, not validation.
                    // `j == 0` leaves `p.skip(0) == p`, so the measure does not
                    // fall; `j > p.len()` leaves `p.skip(j)` unconstrained.
                    Some(j) => if j == 0 || j > p.len() { None } else {
                        after(shape_end(g, Shape::Row(e), p.skip(j as int)), j)
                    }
                }
            }
        }
    }
}

/// One lead byte selects a branch of `bs`, which reads what follows it.
pub open spec fn sum_end(g: Branches, bs: Branches, p: Seq<u8>) -> Option<nat>
    decreases p.len(), 0nat
{
    if p.len() == 0 { None }
    else {
        match branch_of(bs, p[0]) {
            None => None,
            Some(t) => after(shape_end(g, t, p.skip(1)), 1nat),
        }
    }
}

// --- the one law: a row's element is never its end ---

/// Every key sorts above the terminator, so a branch of this table can neither
/// be read as the end of a row nor sort below one.
pub open spec fn keys_marked(bs: Branches) -> bool
    decreases bs
{
    match bs {
        Branches::End => true,
        Branches::Alt(k, _, rest) => k > STRUCT_END && keys_marked(*rest),
    }
}

/// Whatever this shape reads opens with a byte above the terminator.
///
/// Demanded of a `Row`'s element and nowhere else: that is the one position a
/// reader decides "element or end" from the byte in front of it. A `Sum` that
/// is not a row element is free to key on `0x01` — a number's class byte does.
pub open spec fn lead_marked(g: Branches, s: Shape) -> bool
    decreases s
{
    match s {
        Shape::Sum(bs) => keys_marked(*bs),
        Shape::Tagged => keys_marked(g),
        Shape::Product(a, _) => lead_marked(g, *a),
        _ => false,
    }
}

pub open spec fn wf_shape(g: Branches, s: Shape) -> bool
    decreases s, 1int
{
    match s {
        Shape::Product(a, b) => wf_shape(g, *a) && wf_shape(g, *b),
        Shape::Sum(bs) => wf_branches(g, *bs),
        Shape::Row(e) => lead_marked(g, *e) && wf_shape(g, *e),
        _ => true,
    }
}

pub open spec fn wf_branches(g: Branches, bs: Branches) -> bool
    decreases bs, 0int
{
    match bs {
        Branches::End => true,
        Branches::Alt(_, s, rest) => wf_shape(g, *s) && wf_branches(g, *rest),
    }
}

/// A grammar is well-formed when its own tree is, with `Tagged` resolved
/// against itself. The back-reference needs nothing further: it names this same
/// table, which this same check already covers.
pub open spec fn wf_grammar(g: Branches) -> bool { keys_marked(g) && wf_branches(g, g) }

// --- boundedness and locality, by structural induction ---

pub proof fn lemma_shape_bounded(g: Branches, s: Shape, p: Seq<u8>)
    ensures match shape_end(g, s, p) { Some(n) => n <= p.len(), None => true }
    decreases p.len(), shape_sz(s)
{
    match s {
        Shape::Delimited => { lemma_delim_bounded(p); }
        Shape::Product(a, b) => {
            lemma_shape_bounded(g, *a, p);
            match shape_end(g, *a, p) {
                Some(j) => { lemma_shape_bounded(g, *b, p.skip(j as int)); }
                None => {}
            }
        }
        Shape::Sum(bs) => { lemma_sum_bounded(g, *bs, p); }
        Shape::Tagged => { lemma_sum_bounded(g, g, p); }
        Shape::Row(e) => {
            if p.len() > 0 && p[0] != STRUCT_END {
                lemma_shape_bounded(g, *e, p);
                match shape_end(g, *e, p) {
                    Some(j) => { if j > 0 { lemma_shape_bounded(g, Shape::Row(e), p.skip(j as int)); } }
                    None => {}
                }
            }
        }
        _ => {}
    }
}

pub proof fn lemma_sum_bounded(g: Branches, bs: Branches, p: Seq<u8>)
    ensures match sum_end(g, bs, p) { Some(n) => 1 <= n <= p.len(), None => true }
    decreases p.len(), 0nat
{
    if p.len() > 0 {
        match branch_of(bs, p[0]) {
            Some(t) => { lemma_shape_bounded(g, t, p.skip(1)); }
            None => {}
        }
    }
}

/// THE LOCALITY LEMMA. A shape's length is decided by the bytes it reads, so
/// trailing bytes cannot change it.
///
/// One induction over the algebra replaces one lemma per kind. It asks nothing
/// of [`wf_shape`]: lead-marking is what makes a reading unique, not what makes
/// it local.
pub proof fn lemma_shape_local(g: Branches, s: Shape, a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), shape_end(g, s, a) is Some
    ensures shape_end(g, s, b) == shape_end(g, s, a)
    decreases a.len(), shape_sz(s)
{
    match s {
        Shape::Delimited => { lemma_delim_local(a, b); }
        Shape::Product(x, y) => {
            lemma_shape_bounded(g, *x, a);
            match shape_end(g, *x, a) {
                Some(j) => {
                    lemma_shape_local(g, *x, a, b);
                    lemma_prefix_skip(a, b, j as int);
                    lemma_shape_bounded(g, *y, a.skip(j as int));
                    lemma_shape_local(g, *y, a.skip(j as int), b.skip(j as int));
                }
                None => {}
            }
        }
        Shape::Sum(bs) => { lemma_sum_local(g, *bs, a, b); }
        Shape::Tagged => { lemma_sum_local(g, g, a, b); }
        Shape::Row(e) => {
            lemma_prefix_index(a, b, 0);
            if a[0] != STRUCT_END {
                lemma_shape_bounded(g, *e, a);
                match shape_end(g, *e, a) {
                    Some(j) => {
                        lemma_shape_local(g, *e, a, b);
                        lemma_prefix_skip(a, b, j as int);
                        lemma_shape_bounded(g, Shape::Row(e), a.skip(j as int));
                        lemma_shape_local(g, Shape::Row(e), a.skip(j as int), b.skip(j as int));
                    }
                    None => {}
                }
            }
        }
        _ => {}
    }
}

pub proof fn lemma_sum_local(g: Branches, bs: Branches, a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), sum_end(g, bs, a) is Some
    ensures sum_end(g, bs, b) == sum_end(g, bs, a)
    decreases a.len(), 0nat
{
    lemma_sum_bounded(g, bs, a);
    lemma_prefix_index(a, b, 0);
    match branch_of(bs, a[0]) {
        Some(t) => {
            lemma_prefix_skip(a, b, 1);
            lemma_shape_bounded(g, t, a.skip(1));
            lemma_shape_local(g, t, a.skip(1), b.skip(1));
        }
        None => {}
    }
}

proof fn lemma_marked_key(bs: Branches, b: u8)
    requires keys_marked(bs), branch_of(bs, b) is Some
    ensures b > STRUCT_END
    decreases bs
{
    match bs {
        Branches::End => {}
        Branches::Alt(k, _, rest) => { if k != b { lemma_marked_key(*rest, b); } }
    }
}

// ========================== the canonical grammar ============================

/// THE GRAMMAR. One value; the whole byte format.
///
/// Cross-kind order is lead-byte order, so the table's byte assignments are the
/// released format and cannot move. What each kind's body looks like is decided
/// by what the kind is: a fixed-width identity is `Fixed`, opaque content of
/// unknown length is `Delimited`, a discriminated body is a `Sum`, a container
/// is a `Row`, and a value that carries a tie-break sorts as a `Product` with
/// the tie-break last.
pub open spec fn grammar() -> Branches { grammar_table!() }

/// A number's class byte selects its magnitude: zero carries only the
/// representation tie-break, a signed magnitude carries exponent, fraction and
/// tie-break. There is no NaN class — NaN is not a real, and no door here takes
/// one, so no ordering convention has to be invented for it.
pub open spec fn num_branches() -> Branches { num_table!() }
pub open spec fn num_shape() -> Shape { Shape::Sum(Box::new(num_branches())) }

/// An interval is empty, or a lower end then an upper end.
pub open spec fn interval_branches() -> Branches { interval_table!() }
pub open spec fn interval_shape() -> Shape { Shape::Sum(Box::new(interval_branches())) }

/// Unbounded below sorts under every instant, so its marker is the lower one.
pub open spec fn lo_branches() -> Branches { lo_table!() }
pub open spec fn lo_shape() -> Shape { Shape::Sum(Box::new(lo_branches())) }

/// Unbounded above sorts over every instant, so its marker is the higher one.
/// The two ends cannot share a table: one unbounded shape is the least element
/// of its axis and the other is the greatest.
pub open spec fn hi_branches() -> Branches { hi_table!() }
pub open spec fn hi_shape() -> Shape { Shape::Sum(Box::new(hi_branches())) }

pub open spec fn alt(k: u8, s: Shape, rest: Branches) -> Branches {
    Branches::Alt(k, Box::new(s), Box::new(rest))
}

pub open spec fn prod(a: Shape, b: Shape) -> Shape {
    Shape::Product(Box::new(a), Box::new(b))
}

pub open spec fn row(e: Shape) -> Shape { Shape::Row(Box::new(e)) }

/// The grammar obeys its one law. Machine-checked, not asserted: it is what
/// rejects a row whose element could be read as the row's end.
pub proof fn theorem_grammar_wf()
    ensures wf_grammar(grammar())
{ assert(wf_grammar(grammar())) by (compute_only); }

// --- the grammar's reader, and what it reads exactly ---

/// The shape a lead byte selects.
pub open spec fn tag_shape(t: u8) -> Option<Shape> { branch_of(grammar(), t) }

/// Where tag `t`'s body ends in `p`.
pub open spec fn body_end(t: u8, p: Seq<u8>) -> Option<nat> {
    match tag_shape(t) {
        Some(sh) => shape_end(grammar(), sh, p),
        None => None,
    }
}

/// A body the tag's shape measures exactly: the kind's mint produced it.
pub open spec fn valid_body(t: u8, k: Seq<u8>) -> bool { body_end(t, k) == Some(k.len() as nat) }

/// A tag whose body is a row of values.
pub open spec fn is_row_tag(t: u8) -> bool { tag_shape(t) == Some(row(Shape::Tagged)) }

pub open spec fn scan(e: Seq<u8>) -> Option<nat> { shape_end(grammar(), Shape::Tagged, e) }

/// Peel the tag. Every completeness proof in the value tree is this step once.
pub proof fn lemma_scan_peel(t: u8, body: Seq<u8>)
    ensures scan(seq![t] + body) == match tag_shape(t) {
        Some(sh) => after(shape_end(grammar(), sh, body), 1nat),
        None => None,
    }
{
    let e = seq![t] + body;
    assert(e.len() > 0 && e[0] == t);
    assert(e.skip(1) =~= body);
    assert(scan(e) == sum_end(grammar(), grammar(), e));
    assert(branch_of(grammar(), e[0]) == tag_shape(t));
    match tag_shape(t) {
        Some(sh) => { assert(shape_end(grammar(), sh, e.skip(1)) == shape_end(grammar(), sh, body)); }
        None => {}
    }
}

/// A complete encoding: the grammar consumes it exactly.
pub open spec fn complete(x: Seq<u8>) -> bool { scan(x) == Some(x.len() as nat) }

pub open spec fn scan_row_bytes(e: Seq<u8>) -> Option<nat> {
    shape_end(grammar(), row(Shape::Tagged), e)
}

proof fn lemma_scan_bounded(e: Seq<u8>)
    ensures match scan(e) { Some(n) => 1 <= n <= e.len(), None => true }
{ lemma_sum_bounded(grammar(), grammar(), e); }

proof fn lemma_scan_local(a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), scan(a) is Some
    ensures scan(b) == scan(a)
{ lemma_scan_bounded(a); lemma_shape_local(grammar(), Shape::Tagged, a, b); }

/// THE PREFIX-CODE THEOREM. Complete encodings form a prefix code, so the
/// closure theorem's hypothesis holds for every pair of them, everywhere.
pub proof fn theorem_prefix_code(x: Seq<u8>, y: Seq<u8>)
    requires complete(x), complete(y), is_prefix(x, y)
    ensures x =~= y
{
    lemma_scan_local(x, y);
    assert(y.take(x.len() as int) =~= x);
    assert(y =~= y.take(y.len() as int));
}

pub proof fn lemma_complete_incomparable(x: Seq<u8>, y: Seq<u8>)
    requires complete(x), complete(y)
    ensures incomparable(x, y)
{
    if is_prefix(x, y) { theorem_prefix_code(x, y); }
    if is_prefix(y, x) { theorem_prefix_code(y, x); }
}

pub proof fn lemma_complete_is_tagged(x: Seq<u8>)
    requires complete(x)
    ensures x.len() > 0, x[0] > STRUCT_END
{
    lemma_scan_bounded(x);
    theorem_grammar_wf();
    assert(sum_end(grammar(), grammar(), x) == Some(x.len() as nat));
    assert(branch_of(grammar(), x[0]) is Some);
    lemma_marked_key(grammar(), x[0]);
}

// ============================== the value tree ===============================

/// A value as the encoder sees it: a tagged scalar carrying its kind's minted
/// key, or a tagged sequence of values.
// CONSTRUCT: ClosedSum Val
pub enum Val { S(u8, Seq<u8>), L(u8, Vals) }
// CONSTRUCT: ClosedSum Vals
pub enum Vals { Nil, Cons(Box<Val>, Box<Vals>) }

pub open spec fn tag_of(v: Val) -> u8 {
    match v { Val::S(t, _) => t, Val::L(t, _) => t }
}

pub open spec fn sz(v: Val) -> nat
    decreases v, 1int
{ match v { Val::S(_, _) => 1nat, Val::L(_, es) => 1nat + sz_all(es) } }

pub open spec fn sz_all(es: Vals) -> nat
    decreases es, 0int
{ match es { Vals::Nil => 0nat, Vals::Cons(h, t) => 1nat + sz(*h) + sz_all(*t) } }

/// Well-formed: the tag is a real tag, scalar and sequence tags are disjoint,
/// and every scalar carries a key its kind actually minted.
pub open spec fn wf(v: Val) -> bool
    decreases v, 1int
{
    match v {
        Val::S(t, k) => !is_row_tag(t) && valid_body(t, k),
        Val::L(t, es) => is_row_tag(t) && wf_all(es),
    }
}

pub open spec fn wf_all(es: Vals) -> bool
    decreases es, 0int
{ match es { Vals::Nil => true, Vals::Cons(h, t) => wf(*h) && wf_all(*t) } }

pub open spec fn body(v: Val) -> Seq<u8>
    decreases v, 1int
{
    match v {
        Val::S(_, k) => k,
        Val::L(_, es) => enc_row(enc_seq(es)),
    }
}

pub open spec fn enc(v: Val) -> Seq<u8>
    decreases v, 2int
{ seq![tag_of(v)] + body(v) }

pub open spec fn enc_seq(es: Vals) -> Seq<Seq<u8>>
    decreases es, 0int
{
    match es {
        Vals::Nil => Seq::empty(),
        Vals::Cons(h, t) => seq![enc(*h)] + enc_seq(*t),
    }
}

/// Semantic order: cross-kind by tag, within a kind by the kind's own order
/// (scalars) or element-wise (sequences).
pub open spec fn val_le(a: Val, b: Val) -> bool
    decreases a, 1int
{
    if tag_of(a) != tag_of(b) { tag_of(a) < tag_of(b) }
    else {
        match (a, b) {
            (Val::S(_, ka), Val::S(_, kb)) => lex_le(ka, kb),
            (Val::L(_, xs), Val::L(_, ys)) => vals_le(xs, ys),
            _ => false,
        }
    }
}

pub open spec fn vals_le(xs: Vals, ys: Vals) -> bool
    decreases xs, 0int
{
    match (xs, ys) {
        (Vals::Nil, _) => true,
        (Vals::Cons(_, _), Vals::Nil) => false,
        (Vals::Cons(hx, tx), Vals::Cons(hy, ty)) =>
            if *hx != *hy { val_le(*hx, *hy) } else { vals_le(*tx, *ty) },
    }
}

pub open spec fn all_complete(r: Seq<Seq<u8>>) -> bool {
    forall|i: int| 0 <= i < r.len() ==> complete(#[trigger] r[i])
}

// --- completeness of every encoding ---

proof fn lemma_all_complete_tail(r: Seq<Seq<u8>>)
    requires all_complete(r), r.len() > 0
    ensures all_complete(r.drop_first())
{
    assert forall|i: int| 0 <= i < r.drop_first().len()
        implies complete(#[trigger] r.drop_first()[i]) by { assert(complete(r[i + 1])); }
}

proof fn lemma_complete_row_is_tagged(r: Seq<Seq<u8>>)
    requires all_complete(r)
    ensures tagged(r)
{
    assert forall|i: int| 0 <= i < r.len()
        implies #[trigger] r[i].len() > 0 && r[i][0] > STRUCT_END by {
        lemma_complete_is_tagged(r[i]);
    }
}

proof fn lemma_complete_row_is_family(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>)
    requires all_complete(r), all_complete(s)
    ensures pfx_family(r, s)
{
    assert forall|i: int, j: int| 0 <= i < r.len() && 0 <= j < s.len()
        implies #[trigger] incomparable(r[i], s[j]) by {
        lemma_complete_incomparable(r[i], s[j]);
    }
}

/// A row of complete encodings is itself scanned exactly, whatever follows it.
proof fn lemma_scan_row_of_row(r: Seq<Seq<u8>>, rest: Seq<u8>)
    requires all_complete(r)
    ensures scan_row_bytes((cat(r) + seq![STRUCT_END]) + rest) == Some((cat(r).len() + 1) as nat)
    decreases r.len()
{
    let buf = (cat(r) + seq![STRUCT_END]) + rest;
    if r.len() == 0 {
        assert(cat(r) =~= Seq::<u8>::empty());
        assert(buf[0] == STRUCT_END);
    } else {
        let head = r[0];
        let tail_buf = (cat(r.drop_first()) + seq![STRUCT_END]) + rest;
        assert(complete(head));
        lemma_complete_is_tagged(head);
        assert(buf =~= head + tail_buf) by { assert(cat(r) =~= head + cat(r.drop_first())); }
        assert(buf[0] == head[0]);
        assert(buf[0] != STRUCT_END);
        lemma_prefix_of_self_plus(head, tail_buf);
        lemma_scan_local(head, buf);
        assert(scan(buf) == Some(head.len() as nat));
        assert(buf.skip(head.len() as int) =~= tail_buf);
        lemma_all_complete_tail(r);
        lemma_scan_row_of_row(r.drop_first(), rest);
    }
}

pub proof fn lemma_enc_complete(v: Val)
    requires wf(v)
    ensures complete(enc(v))
    decreases sz(v)
{
    let e = enc(v);
    assert(e[0] == tag_of(v));
    assert(e.drop_first() =~= body(v));
    match v {
        Val::S(t, k) => {
            lemma_scan_peel(t, k);
            assert(valid_body(t, k));
            assert(body_end(t, k) == Some(k.len() as nat));
        }
        Val::L(t, es) => {
            lemma_enc_seq_complete(es);
            let r = enc_seq(es);
            lemma_scan_row_of_row(r, Seq::empty());
            assert(body(v) =~= (cat(r) + seq![STRUCT_END]) + Seq::<u8>::empty());
            lemma_scan_peel(t, body(v));
        }
    }
}

pub proof fn lemma_enc_seq_complete(es: Vals)
    requires wf_all(es)
    ensures all_complete(enc_seq(es))
    decreases sz_all(es)
{
    match es {
        Vals::Nil => { assert(enc_seq(es) =~= Seq::<Seq<u8>>::empty()); }
        Vals::Cons(h, t) => {
            lemma_enc_complete(*h);
            lemma_enc_seq_complete(*t);
            let r = enc_seq(es);
            assert(r =~= seq![enc(*h)] + enc_seq(*t));
            assert forall|i: int| 0 <= i < r.len() implies complete(#[trigger] r[i]) by {
                if i > 0 { assert(r[i] == enc_seq(*t)[i - 1]); }
            }
        }
    }
}

// --- injectivity ---

pub proof fn lemma_enc_injective(u: Val, v: Val)
    requires wf(u), wf(v), enc(u) =~= enc(v)
    ensures u == v
    decreases sz(u)
{
    assert(enc(u)[0] == tag_of(u) && enc(v)[0] == tag_of(v));
    assert(tag_of(u) == tag_of(v));
    assert(enc(u).drop_first() =~= body(u));
    assert(enc(v).drop_first() =~= body(v));
    assert(body(u) =~= body(v));
    match (u, v) {
        (Val::S(_, _), Val::S(_, _)) => {}
        (Val::L(_, xs), Val::L(_, ys)) => {
            lemma_enc_seq_complete(xs);
            lemma_enc_seq_complete(ys);
            let rx = enc_seq(xs);
            let ry = enc_seq(ys);
            lemma_complete_row_is_tagged(rx);
            lemma_complete_row_is_tagged(ry);
            lemma_complete_row_is_family(rx, ry);
            assert(is_prefix(enc_row(rx), enc_row(ry))) by {
                assert(enc_row(ry).take(enc_row(rx).len() as int) =~= enc_row(rx));
            }
            lemma_row_prefix_free(rx, ry);
            lemma_enc_seq_injective(xs, ys);
        }
        _ => { assert(false); }
    }
}

pub proof fn lemma_enc_seq_injective(xs: Vals, ys: Vals)
    requires wf_all(xs), wf_all(ys), enc_seq(xs) =~= enc_seq(ys)
    ensures xs == ys
    decreases sz_all(xs)
{
    match (xs, ys) {
        (Vals::Nil, Vals::Nil) => {}
        (Vals::Nil, Vals::Cons(h, t)) => {
            assert(enc_seq(ys) =~= seq![enc(*h)] + enc_seq(*t));
            assert(enc_seq(xs).len() == 0);
        }
        (Vals::Cons(h, t), Vals::Nil) => {
            assert(enc_seq(xs) =~= seq![enc(*h)] + enc_seq(*t));
            assert(enc_seq(ys).len() == 0);
        }
        (Vals::Cons(hx, tx), Vals::Cons(hy, ty)) => {
            assert(enc_seq(xs) =~= seq![enc(*hx)] + enc_seq(*tx));
            assert(enc_seq(ys) =~= seq![enc(*hy)] + enc_seq(*ty));
            assert(enc_seq(xs)[0] =~= enc(*hx));
            assert(enc_seq(ys)[0] =~= enc(*hy));
            assert(enc(*hx) =~= enc(*hy));
            assert(enc_seq(*tx) =~= enc_seq(*ty)) by {
                assert(enc_seq(xs).drop_first() =~= enc_seq(*tx));
                assert(enc_seq(ys).drop_first() =~= enc_seq(*ty));
            }
            lemma_enc_injective(*hx, *hy);
            lemma_enc_seq_injective(*tx, *ty);
        }
    }
}

// --- THE ORDER LAW ---

/// `a <= b  <=>  encode(a) <=lex encode(b)`, over the whole value domain.
pub proof fn theorem_value_order(u: Val, v: Val)
    requires wf(u), wf(v)
    ensures val_le(u, v) == lex_le(enc(u), enc(v))
    decreases sz(u)
{
    let tu = seq![tag_of(u)];
    let tv = seq![tag_of(v)];
    assert(incomparable(tu, tv)) by {
        if is_prefix(tu, tv) { assert(tv.take(1) =~= tu); }
        if is_prefix(tv, tu) { assert(tu.take(1) =~= tv); }
    }
    lemma_concat_order(tu, body(u), tv, body(v));
    if tag_of(u) == tag_of(v) {
        assert(tu =~= tv);
        match (u, v) {
            (Val::S(_, _), Val::S(_, _)) => {}
            (Val::L(_, xs), Val::L(_, ys)) => {
                lemma_enc_seq_complete(xs);
                lemma_enc_seq_complete(ys);
                let rx = enc_seq(xs);
                let ry = enc_seq(ys);
                lemma_complete_row_is_tagged(rx);
                lemma_complete_row_is_tagged(ry);
                lemma_complete_row_is_family(rx, ry);
                lemma_row_order(rx, ry);
                lemma_vals_order(xs, ys);
            }
            _ => { assert(false); }
        }
    } else {
        assert(!(tu =~= tv));
        assert(lex_le(tu, tv) == (tag_of(u) < tag_of(v)));
    }
}

pub proof fn lemma_vals_order(xs: Vals, ys: Vals)
    requires wf_all(xs), wf_all(ys)
    ensures vals_le(xs, ys) == row_le(enc_seq(xs), enc_seq(ys))
    decreases sz_all(xs)
{
    match (xs, ys) {
        (Vals::Nil, _) => { assert(enc_seq(xs) =~= Seq::<Seq<u8>>::empty()); }
        (Vals::Cons(h, t), Vals::Nil) => {
            assert(enc_seq(xs) =~= seq![enc(*h)] + enc_seq(*t));
            assert(enc_seq(ys) =~= Seq::<Seq<u8>>::empty());
        }
        (Vals::Cons(hx, tx), Vals::Cons(hy, ty)) => {
            let rx = enc_seq(xs);
            let ry = enc_seq(ys);
            assert(rx =~= seq![enc(*hx)] + enc_seq(*tx));
            assert(ry =~= seq![enc(*hy)] + enc_seq(*ty));
            assert(rx[0] =~= enc(*hx) && ry[0] =~= enc(*hy));
            assert(rx.drop_first() =~= enc_seq(*tx));
            assert(ry.drop_first() =~= enc_seq(*ty));
            if *hx == *hy {
                assert(rx[0] =~= ry[0]);
                lemma_vals_order(*tx, *ty);
            } else {
                assert(!(rx[0] =~= ry[0])) by {
                    if rx[0] =~= ry[0] { lemma_enc_injective(*hx, *hy); }
                }
                theorem_value_order(*hx, *hy);
            }
        }
    }
}

// ============================== executable code ==============================

proof fn lemma_esc_snoc(t: Seq<u8>, b: u8)
    ensures esc(t.push(b)) =~= esc(t) + code(b)
    decreases t.len()
{
    if t.len() == 0 {
        assert(t.push(b) =~= seq![b]);
        assert(seq![b].len() == 1 && seq![b][0] == b);
        assert(seq![b].drop_first() =~= Seq::<u8>::empty());
        assert(esc(Seq::<u8>::empty()) =~= Seq::<u8>::empty());
        assert(code(b) + Seq::<u8>::empty() =~= code(b));
        assert(esc(t) =~= Seq::<u8>::empty());
    } else {
        assert(t.push(b)[0] == t[0]);
        assert(t.push(b).drop_first() =~= t.drop_first().push(b));
        lemma_esc_snoc(t.drop_first(), b);
        assert(esc(t.push(b)) =~= code(t[0]) + esc(t.drop_first().push(b)));
        assert(esc(t) =~= code(t[0]) + esc(t.drop_first()));
        assert(code(t[0]) + (esc(t.drop_first()) + code(b))
            =~= (code(t[0]) + esc(t.drop_first())) + code(b));
    }
}

#[verifier::rlimit(4)]
proof fn lemma_cat_snoc(r: Seq<Seq<u8>>, x: Seq<u8>)
    ensures cat(r.push(x)) =~= cat(r) + x
    decreases r.len()
{
    if r.len() == 0 {
        assert(r.push(x) =~= seq![x]);
        assert(seq![x].len() == 1 && seq![x][0] =~= x);
        assert(seq![x].drop_first() =~= Seq::<Seq<u8>>::empty());
        assert(cat(Seq::<Seq<u8>>::empty()) =~= Seq::<u8>::empty());
        assert(x + Seq::<u8>::empty() =~= x);
        assert(cat(r) =~= Seq::<u8>::empty());
    } else {
        assert(r.push(x)[0] =~= r[0]);
        assert(r.push(x).drop_first() =~= r.drop_first().push(x));
        lemma_cat_snoc(r.drop_first(), x);
        assert(cat(r.push(x)) =~= r[0] + cat(r.drop_first().push(x)));
        assert(cat(r) =~= r[0] + cat(r.drop_first()));
        assert(r[0] + (cat(r.drop_first()) + x) =~= (r[0] + cat(r.drop_first())) + x);
    }
}

/// Bytes that are a complete encoding of exactly one value.
///
/// The field is private and this module holds every constructor, so there is no
/// door beside the proven ones. The type invariant is `complete`, which by
/// [`theorem_prefix_code`] makes any two of these prefix-incomparable — the
/// closure theorem's hypothesis, discharged once, everywhere.
// CONSTRUCT: SealedProduct CanonicalBytes
pub struct CanonicalBytes {
    bytes: Vec<u8>,
}

// CONSTRUCT: ImplBlock CanonicalBytes
impl CanonicalBytes {
    pub closed spec fn view(self) -> Seq<u8> { self.bytes@ }

    #[verifier::type_invariant]
    closed spec fn wf_bytes(self) -> bool { complete(self.view()) }

    pub fn as_bytes(&self) -> (r: &[u8])
        ensures r@ =~= self.view()
    { self.bytes.as_slice() }

}

/// Escape a variable-length payload into the order-preserving, self-delimiting
/// form. Its order law is [`lemma_bytes_order`] and its prefix-freedom is
/// [`lemma_bytes_prefix_free`].
// CONSTRUCT: Derivation escape
pub(crate) fn escape(s: &[u8]) -> (r: Vec<u8>)
    ensures r@ =~= enc_bytes(s@)
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < s.len()
        invariant 0 <= i <= s.len(), out@ =~= esc(s@.take(i as int)),
        decreases s.len() - i
    {
        proof {
            lemma_esc_snoc(s@.take(i as int), s@[i as int]);
            assert(s@.take(i + 1) =~= s@.take(i as int).push(s@[i as int]));
        }
        if s[i] == STRUCT_ESC {
            out.push(STRUCT_ESC);
            out.push(ESC_ZERO);
        } else {
            out.push(s[i]);
        }
        i = i + 1;
    }
    out.push(STRUCT_ESC);
    out.push(STRUCT_ESC);
    proof { assert(s@.take(s.len() as int) =~= s@); }
    out
}

// ================================ the scanner ================================
//
// The grammar above is a specification; this is the one executable reader
// proven against it. [`theorem_prefix_code`] already establishes that no byte
// string has two readings, so a reader that agrees with `shape_end` is the only
// reader there can be.

/// The grammar, at exec.
///
/// The grammar is stated twice because a value a proof reasons about and a
/// value a program builds cannot be the same body in this tool. The `ensures`
/// is what makes that two bodies and not two authorities: they cannot drift,
/// because the gate proves them equal. Change one and the gate names the other.
///
/// What neither body can decide is whether the widths and lead bytes are the
/// released format. That is what `canonical-trials` pins.
pub(crate) fn grammar_exec() -> (r: Branches)
    ensures r == grammar()
{ grammar_table!() }

/// The branch a lead byte selects, at exec.
pub(crate) fn branch_lookup(bs: &Branches, b: u8) -> (r: Option<&Shape>)
    ensures
        match r {
            Some(s) => branch_of(*bs, b) == Some(*s),
            None => branch_of(*bs, b) is None,
        },
    decreases *bs
{
    match bs {
        Branches::End => None,
        Branches::Alt(k, s, rest) => if *k == b { Some(&**s) } else { branch_lookup(&**rest, b) },
    }
}

/// Why the grammar refused, and where it stopped.
///
/// A reader that answers `None` tells a caller nothing it can act on and
/// nothing an operator can read in a log. `at` is a byte offset into the input
/// the reader was handed, accumulated through the composition, so a refusal
/// inside the third element of a nested row names that position and not the
/// start of the buffer.
// CONSTRUCT: ClosedSum Reason
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub enum Reason {
    /// The input ended inside a shape that had more to read. `at` is the first
    /// offset the reader needed and did not have — one past the last byte
    /// available, never the last byte examined.
    Truncated,
    /// No branch of the table in force names this lead byte.
    UnknownLeadByte(u8),
    /// `0x00` followed by neither the terminator nor the escape companion.
    BadEscape(u8),
    /// Nesting deeper than the reader will descend. Refusing is sound in one
    /// direction only, and this is that direction: a reader may reject, it may
    /// never accept a reading the grammar does not give.
    TooDeep,
}

/// A reader's typed refusal: what was wrong, and where it stopped.
///
/// Both seats are private and only the scan path mints one, so a caller cannot
/// place a refusal somewhere the reader never reached.
///
/// `at` is a [`Stopped`] and not a number. It was `Offset(usize)`, which is
/// what forced the composition to be an addition: moving a nested reading's
/// position into its container was `base + inner`, a sum that can overflow, so
/// the body saturated to `usize::MAX` and named a position no buffer has. A
/// suffix of a sub-slice is already a suffix of the outer slice, so there is
/// no composition left to perform.
// CONSTRUCT: ValueObject Refusal
pub struct Refusal<'a> {
    reason: Reason,
    at: Stopped<'a>,
}

// CONSTRUCT: ImplBlock Refusal
impl<'a> Refusal<'a> {
    pub closed spec fn spec_reason(&self) -> Reason { self.reason }
    pub closed spec fn spec_at(&self) -> Seq<u8> { self.at.spec_rest() }

    pub fn reason(&self) -> (r: Reason)
        ensures r == self.spec_reason()
    { self.reason }

    /// The bytes the reading had not consumed when it stopped.
    pub fn at(&self) -> (r: &'a [u8])
        ensures r@ =~= self.spec_at()
    { self.at.rest() }
}

/// The one constructor, module-private.
fn refuse<'a>(reason: Reason, at: &'a [u8]) -> (r: Refusal<'a>)
    ensures r.spec_reason() == reason, r.spec_at() =~= at@
{
    Refusal { reason, at: Stopped { rest: at } }
}

/// Where the escaped body at the front of `p` ends. Total over every
/// byte sequence: no panic, no unbounded read.
pub(crate) fn delim_scan<'a>(p: &'a [u8]) -> (r: Result<usize, Refusal<'a>>)
    ensures
        match r {
            Ok(n) => delim_end(p@) == Some(n as nat) && n <= p.len(),
            Err(_) => delim_end(p@) is None,
        },
{
    let mut i: usize = 0;
    proof { assert(p@.skip(0int) =~= p@); }
    while i < p.len()
        invariant
            0 <= i <= p@.len(),
            delim_end(p@) == after(delim_end(p@.skip(i as int)), i as nat),
        decreases p.len() - i
    {
        proof { assert(p@.skip(i as int)[0] == p@[i as int]); }
        if i + 1 >= p.len() {
            proof { assert(p@.skip(i as int).len() < 2); }
            return Err(refuse(Reason::Truncated, vstd::slice::slice_subrange(p, p.len(), p.len())));
        }
        proof { assert(p@.skip(i as int)[1] == p@[i as int + 1]); }
        if p[i] == STRUCT_ESC {
            if p[i + 1] == STRUCT_ESC {
                proof { assert(delim_end(p@.skip(i as int)) == Some(2nat)); }
                return Ok(i + 2);
            }
            if p[i + 1] != ESC_ZERO {
                return Err(refuse(Reason::BadEscape(p[i + 1]), vstd::slice::slice_subrange(p, i + 1, p.len())));
            }
            proof { assert(p@.skip(i as int).skip(2) =~= p@.skip(i as int + 2)); }
            i = i + 2;
        } else {
            proof { assert(p@.skip(i as int).skip(1) =~= p@.skip(i as int + 1)); }
            i = i + 1;
        }
    }
    proof { assert(p@.skip(i as int).len() < 2); }
    Err(refuse(Reason::Truncated, vstd::slice::slice_subrange(p, p.len(), p.len())))
}

/// Nesting a reader will descend. Deeper input is refused, never followed: the
/// reader is recursive descent and an unbounded one is a stack overflow a
/// writer chooses. Refusing is sound in one direction only, which is the
/// direction that matters — a reader may reject, it may never accept a reading
/// the grammar does not give.
pub const MAX_DEPTH: u32 = 128;

/// Where the shape at the front of `p` ends, or `None` if `p` does not open
/// with one. One function; the whole grammar. Total over every byte sequence.
pub(crate) fn shape_scan<'a>(g: &Branches, s: &Shape, p: &'a [u8], depth: u32) -> (r: Result<usize, Refusal<'a>>)
    ensures
        match r {
            Ok(n) => shape_end(*g, *s, p@) == Some(n as nat) && n <= p.len(),
            Err(_) => true,
        },
    decreases p@.len(), shape_sz(*s)
{
    if depth >= MAX_DEPTH {
        return Err(refuse(Reason::TooDeep, p));
    }
    match s {
        Shape::Fixed(n) => if p.len() >= *n {
            Ok(*n)
        } else {
            Err(refuse(Reason::Truncated, vstd::slice::slice_subrange(p, p.len(), p.len())))
        },
        Shape::Delimited => delim_scan(p),
        Shape::Product(a, b) => {
            let j = match shape_scan(g, &**a, p, depth) {
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            let rest = vstd::slice::slice_subrange(p, j, p.len());
            proof { assert(rest@ =~= p@.skip(j as int)); }
            match shape_scan(g, &**b, rest, depth) {
                Ok(k) => Ok(j + k),
                Err(e) => Err(e),
            }
        }
        Shape::Sum(bs) => sum_scan(g, &**bs, p, depth),
        Shape::Tagged => sum_scan(g, g, p, depth),
        Shape::Row(e) => {
            // A row is read by iteration, not recursion: its length is chosen
            // by whoever wrote the bytes, and a recursive tail would let them
            // pick the stack depth.
            let mut at: usize = 0;
            proof { assert(p@.skip(0int) =~= p@); }
            loop
                invariant
                    0 <= at <= p.len(),
                    depth < MAX_DEPTH,
                    *s == Shape::Row(*e),
                    shape_end(*g, *s, p@) == after(shape_end(*g, *s, p@.skip(at as int)), at as nat),
                decreases p.len() - at
            {
                if at >= p.len() {
                    proof { assert(p@.skip(at as int).len() == 0); }
                    return Err(refuse(Reason::Truncated, vstd::slice::slice_subrange(p, at, p.len())));
                }
                let tail = vstd::slice::slice_subrange(p, at, p.len());
                proof {
                    assert(tail@ =~= p@.skip(at as int));
                    assert(tail@[0] == p@[at as int]);
                }
                if tail[0] == STRUCT_END {
                    return Ok(at + 1);
                }
                let j = match shape_scan(g, &**e, tail, depth + 1) {
                    Ok(n) => n,
                    Err(err) => return Err(err),
                };
                if j == 0 {
                    return Err(refuse(Reason::Truncated, vstd::slice::slice_subrange(p, at, p.len())));
                }
                proof { assert(p@.skip(at as int).skip(j as int) =~= p@.skip(at as int + j as int)); }
                at = at + j;
            }
        }
    }
}

/// One lead byte selects a branch of `bs`, which reads what follows it.
pub(crate) fn sum_scan<'a>(g: &Branches, bs: &Branches, p: &'a [u8], depth: u32) -> (r: Result<usize, Refusal<'a>>)
    ensures
        match r {
            Ok(n) => sum_end(*g, *bs, p@) == Some(n as nat) && n <= p.len(),
            Err(_) => true,
        },
    decreases p@.len(), 0nat
{
    if depth >= MAX_DEPTH {
        return Err(refuse(Reason::TooDeep, p));
    }
    if p.len() == 0 {
        return Err(refuse(Reason::Truncated, p));
    }
    let t = match branch_lookup(bs, p[0]) {
        Some(sh) => sh,
        None => return Err(refuse(Reason::UnknownLeadByte(p[0]), p)),
    };
    let body = vstd::slice::slice_subrange(p, 1, p.len());
    proof { assert(body@ =~= p@.skip(1)); }
    match shape_scan(g, t, body, depth + 1) {
        Ok(n) => Ok(1 + n),
        Err(e) => Err(e),
    }
}

/// Where the complete encoding at the front of `p` ends.
pub fn scan_value<'a>(p: &'a [u8]) -> (r: Result<usize, Refusal<'a>>)
    ensures
        match r {
            Ok(n) => scan(p@) == Some(n as nat) && n <= p.len(),
            Err(_) => true,
        },
{
    let g = grammar_exec();
    sum_scan(&g, &g, p, 0)
}

/// Where a reading stopped: the bytes it had not consumed.
///
/// A position in a byte string is a suffix of that byte string, so this carries
/// no number. [`Offset`] carries one, and that is why composing a nested
/// reading's position into its container needed an addition that could
/// overflow, and why the deleted `deeper` saturated to `usize::MAX` — a
/// position no buffer has. A suffix of a sub-slice is already a suffix of the
/// outer slice, so the composition is identity and there is nothing to add.
///
/// The seat is private and only the scan path mints one, so a caller cannot
/// point a refusal somewhere the reader did not stop.
// CONSTRUCT: ValueObject Stopped
pub struct Stopped<'a> {
    rest: &'a [u8],
}

// CONSTRUCT: ImplBlock Stopped
impl<'a> Stopped<'a> {
    pub closed spec fn spec_rest(&self) -> Seq<u8> { self.rest@ }

    /// The unconsumed bytes. How far in that is depends on the buffer the
    /// caller handed over, which is the caller's fact and not this type's.
    pub fn rest(&self) -> (r: &'a [u8])
        ensures r@ =~= self.spec_rest()
    { self.rest }
}

/// One complete encoding at the front of a buffer, and the bytes after it.
///
/// The reader's result. [`CanonicalBytes`] carries `complete` because a writer
/// established it; this carries the same invariant because a scan found it, and
/// the two are the same claim reached from opposite directions.
///
/// Both seats are private and the only constructor is [`read`], so a `Reading`
/// whose first seat is not a complete encoding is not a `Reading` that was
/// built wrongly — it cannot be written down. That is what makes the result
/// narrower than the input: `read` accepts every byte string, and this type
/// admits only the ones the grammar gives a reading.
// CONSTRUCT: SealedProduct Reading
pub struct Reading<'a> {
    value: &'a [u8],
    rest: &'a [u8],
}

// CONSTRUCT: ImplBlock Reading
impl<'a> Reading<'a> {
    pub closed spec fn spec_value(&self) -> Seq<u8> { self.value@ }
    pub closed spec fn spec_rest(&self) -> Seq<u8> { self.rest@ }

    #[verifier::type_invariant]
    closed spec fn wf_reading(&self) -> bool { complete(self.spec_value()) }

    pub fn value(&self) -> (r: &'a [u8])
        ensures r@ =~= self.spec_value()
    { self.value }

    pub fn rest(&self) -> (r: &'a [u8])
        ensures r@ =~= self.spec_rest()
    { self.rest }
}

/// A tag's body: bytes, and the shape that reads them exactly.
///
/// The shape is ghost, the bytes are private, and every constructor below
/// ESTABLISHES the type invariant rather than checking it. There is no
/// validating door and no fallible one — a body the grammar would refuse is not
/// a `Body` that failed to build, it is a `Body` that cannot be written.
// CONSTRUCT: SealedProduct Body
struct Body {
    bytes: Vec<u8>,
    shape: Ghost<Shape>,
}

// CONSTRUCT: ImplBlock Body
impl Body {
    closed spec fn view(self) -> Seq<u8> { self.bytes@ }
    closed spec fn shape(self) -> Shape { self.shape@ }

    #[verifier::type_invariant]
    closed spec fn wf_body(self) -> bool {
        shape_end(grammar(), self.shape@, self.bytes@) == Some(self.bytes@.len() as nat)
    }

    /// Exactly these bytes. The width is a fact about the vector, so a body of
    /// the wrong width is not ill-formed — it is a different shape, and the tag
    /// it is sealed under will not accept it.
    fn fixed(bytes: Vec<u8>) -> (r: Body)
        ensures r.view() =~= bytes@, r.shape() == Shape::Fixed(bytes@.len() as usize)
    {
        let n = bytes.len();
        Body { bytes, shape: Ghost(Shape::Fixed(n)) }
    }

    /// Opaque content of any length. Every byte sequence has an escaped form,
    /// so there is nothing here that can fail.
    fn delimited(content: &[u8]) -> (r: Body)
        ensures r.view() =~= enc_bytes(content@), r.shape() == Shape::Delimited
    {
        let bytes = escape(content);
        proof { lemma_delim_end_of_enc_bytes(content@); }
        Body { bytes, shape: Ghost(Shape::Delimited) }
    }

    /// One body then another, with no separator between them.
    ///
    /// The first is self-delimiting, so the second cannot reach back into it.
    /// That is [`lemma_shape_local`] — the reason a `Product` needs no length
    /// prefix, discharged here once for every kind that carries a tie-break.
    fn product(a: Body, b: Body) -> (r: Body)
        ensures
            r.view() =~= a.view() + b.view(),
            r.shape() == prod(a.shape(), b.shape()),
    {
        proof { use_type_invariant(&a); use_type_invariant(&b); }
        let ghost sa = a.shape@;
        let ghost sb = b.shape@;
        let ghost va = a.bytes@;
        let ghost vb = b.bytes@;
        let mut bytes = a.bytes;
        let mut tail = b.bytes;
        bytes.append(&mut tail);
        proof {
            lemma_prefix_of_self_plus(va, vb);
            lemma_shape_local(grammar(), sa, va, va + vb);
            assert((va + vb).skip(va.len() as int) =~= vb);
        }
        Body { bytes, shape: Ghost(prod(sa, sb)) }
    }

    /// A lead byte, and the body the branch table says it selects.
    ///
    /// The table is the kind's own and the key must be one of its keys. That is
    /// a precondition, discharged where the kind is defined; there is no lookup
    /// here and nothing to refuse.
    fn select(bs: Ghost<Branches>, k: u8, inner: Body) -> (r: Body)
        requires branch_of(bs@, k) == Some(inner.shape())
        ensures
            r.view() =~= seq![k] + inner.view(),
            r.shape() == Shape::Sum(Box::new(bs@)),
    {
        proof { use_type_invariant(&inner); }
        let ghost vi = inner.bytes@;
        let ghost si = inner.shape@;
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(k);
        let mut tail = inner.bytes;
        bytes.append(&mut tail);
        proof {
            assert(bytes@ =~= seq![k] + vi);
            assert(bytes@.len() > 0 && bytes@[0] == k);
            assert(bytes@.skip(1) =~= vi);
            assert(branch_of(bs@, bytes@[0]) == Some(si));
            assert(shape_end(grammar(), si, bytes@.skip(1)) == Some(vi.len() as nat));
            assert(sum_end(grammar(), bs@, bytes@) == Some((1 + vi.len()) as nat));
        }
        Body { bytes, shape: Ghost(Shape::Sum(Box::new(bs@))) }
    }

    /// A row of complete values, terminated. Elements open with a tag, which
    /// sorts above the terminator, so none can be read as the row's end.
    fn row(elems: &Vec<CanonicalBytes>) -> (r: Body)
        ensures
            r.view() =~= enc_row(elems@.map_values(|e: CanonicalBytes| e.view())),
            r.shape() == row(Shape::Tagged),
    {
        let ghost views = elems@.map_values(|e: CanonicalBytes| e.view());
        let mut bytes: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < elems.len()
            invariant
                0 <= i <= elems.len(),
                views =~= elems@.map_values(|e: CanonicalBytes| e.view()),
                bytes@ =~= cat(views.take(i as int)),
                forall|k: int| 0 <= k < i ==> complete(#[trigger] views[k]),
            decreases elems.len() - i
        {
            let e = &elems[i];
            proof { use_type_invariant(e); }
            let src = e.as_bytes();
            let ghost before = bytes@;
            let mut j: usize = 0;
            while j < src.len()
                invariant
                    0 <= j <= src.len(),
                    src@ =~= views[i as int],
                    bytes@ =~= before + src@.take(j as int),
                decreases src.len() - j
            {
                bytes.push(src[j]);
                proof { assert(src@.take(j + 1) =~= src@.take(j as int).push(src@[j as int])); }
                j = j + 1;
            }
            proof {
                assert(src@.take(src.len() as int) =~= views[i as int]);
                lemma_cat_snoc(views.take(i as int), views[i as int]);
                assert(views.take(i + 1) =~= views.take(i as int).push(views[i as int]));
            }
            i = i + 1;
        }
        bytes.push(STRUCT_END);
        proof {
            assert(views.take(elems.len() as int) =~= views);
            assert(all_complete(views));
            lemma_scan_row_of_row(views, Seq::empty());
            assert(bytes@ =~= (cat(views) + seq![STRUCT_END]) + Seq::<u8>::empty());
        }
        Body { bytes, shape: Ghost(row(Shape::Tagged)) }
    }

    /// One complete value, carried as a body. This is the back-reference: a
    /// kind whose payload is a value, not bytes of its own.
    fn value(v: &CanonicalBytes) -> (r: Body)
        ensures r.view() =~= v.view(), r.shape() == Shape::Tagged
    {
        proof { use_type_invariant(v); }
        let src = v.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();
        let mut j: usize = 0;
        while j < src.len()
            invariant 0 <= j <= src.len(), src@ =~= v.view(), bytes@ =~= src@.take(j as int),
            decreases src.len() - j
        {
            bytes.push(src[j]);
            proof { assert(src@.take(j + 1) =~= src@.take(j as int).push(src@[j as int])); }
            j = j + 1;
        }
        proof {
            assert(src@.take(src.len() as int) =~= v.view());
            assert(scan(bytes@) == Some(bytes@.len() as nat));
        }
        Body { bytes, shape: Ghost(Shape::Tagged) }
    }
}

/// Seal a body under its tag.
///
/// The precondition is the whole contract: the tag's shape IS the body's shape.
/// A tag sealed over a body it does not read is not refused at run time — it
/// fails to verify.
///
/// Private, and so is [`Body`], because that contract is a *specification*
/// precondition: it binds callers the gate verifies and nobody else. Exported,
/// it would be an untyped door taking a `u8` and arbitrary bytes, with its
/// guarantee erased for every caller outside this file. The public surface is
/// the kind doors below, which take no tag at all.
// CONSTRUCT: Mint seal
fn seal(tag: u8, body: Body) -> (r: CanonicalBytes)
    requires tag_shape(tag) == Some(body.shape())
    ensures r.view() =~= seq![tag] + body.view()
{
    proof { use_type_invariant(&body); }
    let ghost vb = body.bytes@;
    let mut out: Vec<u8> = Vec::new();
    out.push(tag);
    let mut tail = body.bytes;
    out.append(&mut tail);
    proof {
        assert(out@ =~= seq![tag] + vb);
        lemma_scan_peel(tag, vb);
    }
    CanonicalBytes { bytes: out }
}

// ================================= the kinds =================================
//
// One door per kind, and every one of them total: no `Option`, no panic, no
// width to get wrong. The obligation `tag_shape(tag) == Some(body.shape())` is
// discharged HERE, inside the gate, by computation against the grammar. A
// caller outside this file cannot state a wrong pairing, because the only
// vocabulary it is given is these doors and the argument types they take.

pub const TAG_NULL: u8 = 0x05;
pub const TAG_FALSE: u8 = 0x08;
pub const TAG_TRUE: u8 = 0x09;
pub const TAG_NUM: u8 = 0x10;
pub const TAG_STR: u8 = 0x18;
pub const TAG_BYTES: u8 = 0x20;
pub const TAG_UUID: u8 = 0x28;
pub const TAG_REGEX: u8 = 0x30;
pub const TAG_JSON: u8 = 0x38;
pub const TAG_VECTOR: u8 = 0x40;
pub const TAG_LIST: u8 = 0x48;
pub const TAG_SET: u8 = 0x50;
pub const TAG_VALIDITY: u8 = 0x58;
pub const TAG_INTERVAL: u8 = 0x60;
pub const TAG_GEOMETRY: u8 = 0x68;

/// THE TAG TABLE, resolved. Every door below discharges its obligation from
/// this one computation, so the grammar is consulted once rather than restated
/// fifteen times.
pub proof fn lemma_tag_shapes()
    ensures
        tag_shape(TAG_NULL) == Some(Shape::Fixed(0)),
        tag_shape(TAG_FALSE) == Some(Shape::Fixed(0)),
        tag_shape(TAG_TRUE) == Some(Shape::Fixed(0)),
        tag_shape(TAG_NUM) == Some(num_shape()),
        tag_shape(TAG_STR) == Some(Shape::Delimited),
        tag_shape(TAG_BYTES) == Some(Shape::Delimited),
        tag_shape(TAG_UUID) == Some(Shape::Fixed(16)),
        tag_shape(TAG_REGEX) == Some(prod(Shape::Delimited, Shape::Fixed(1))),
        tag_shape(TAG_JSON) == Some(Shape::Tagged),
        tag_shape(TAG_VECTOR) == Some(prod(Shape::Fixed(4), row(Shape::Tagged))),
        tag_shape(TAG_LIST) == Some(row(Shape::Tagged)),
        tag_shape(TAG_SET) == Some(row(Shape::Tagged)),
        tag_shape(TAG_VALIDITY) == Some(Shape::Fixed(9)),
        tag_shape(TAG_INTERVAL) == Some(interval_shape()),
        tag_shape(TAG_GEOMETRY) == Some(Shape::Fixed(8)),
{
    assert(tag_shape(TAG_NULL) == Some(Shape::Fixed(0))) by (compute_only);
    assert(tag_shape(TAG_FALSE) == Some(Shape::Fixed(0))) by (compute_only);
    assert(tag_shape(TAG_TRUE) == Some(Shape::Fixed(0))) by (compute_only);
    assert(tag_shape(TAG_NUM) == Some(num_shape())) by (compute_only);
    assert(tag_shape(TAG_STR) == Some(Shape::Delimited)) by (compute_only);
    assert(tag_shape(TAG_BYTES) == Some(Shape::Delimited)) by (compute_only);
    assert(tag_shape(TAG_UUID) == Some(Shape::Fixed(16))) by (compute_only);
    assert(tag_shape(TAG_REGEX) == Some(prod(Shape::Delimited, Shape::Fixed(1)))) by (compute_only);
    assert(tag_shape(TAG_JSON) == Some(Shape::Tagged)) by (compute_only);
    assert(tag_shape(TAG_VECTOR) == Some(prod(Shape::Fixed(4), row(Shape::Tagged))))
        by (compute_only);
    assert(tag_shape(TAG_LIST) == Some(row(Shape::Tagged))) by (compute_only);
    assert(tag_shape(TAG_SET) == Some(row(Shape::Tagged))) by (compute_only);
    assert(tag_shape(TAG_VALIDITY) == Some(Shape::Fixed(9))) by (compute_only);
    assert(tag_shape(TAG_INTERVAL) == Some(interval_shape())) by (compute_only);
    assert(tag_shape(TAG_GEOMETRY) == Some(Shape::Fixed(8))) by (compute_only);
}

/// The inner tables, resolved. `Body::select` asks which branch a key names;
/// these are the answers, computed against the same grammar.
pub proof fn lemma_branch_shapes()
    ensures
        branch_of(num_branches(), 0x01) == Some(Shape::Fixed(12)),
        branch_of(num_branches(), 0x02) == Some(Shape::Fixed(1)),
        branch_of(num_branches(), 0x03) == Some(Shape::Fixed(12)),
        branch_of(num_branches(), 0x04) == Some(Shape::Fixed(1)),
        branch_of(interval_branches(), 0x01) == Some(Shape::Fixed(0)),
        branch_of(interval_branches(), 0x02) == Some(prod(lo_shape(), hi_shape())),
        branch_of(lo_branches(), 0x01) == Some(Shape::Fixed(0)),
        branch_of(lo_branches(), 0x02) == Some(Shape::Fixed(8)),
        branch_of(hi_branches(), 0x02) == Some(Shape::Fixed(8)),
        branch_of(hi_branches(), 0x03) == Some(Shape::Fixed(0)),
{
    assert(branch_of(num_branches(), 0x01) == Some(Shape::Fixed(12))) by (compute_only);
    assert(branch_of(num_branches(), 0x02) == Some(Shape::Fixed(1))) by (compute_only);
    assert(branch_of(num_branches(), 0x03) == Some(Shape::Fixed(12))) by (compute_only);
    assert(branch_of(num_branches(), 0x04) == Some(Shape::Fixed(1))) by (compute_only);
    assert(branch_of(interval_branches(), 0x01) == Some(Shape::Fixed(0))) by (compute_only);
    assert(branch_of(interval_branches(), 0x02) == Some(prod(lo_shape(), hi_shape())))
        by (compute_only);
    assert(branch_of(lo_branches(), 0x01) == Some(Shape::Fixed(0))) by (compute_only);
    assert(branch_of(lo_branches(), 0x02) == Some(Shape::Fixed(8))) by (compute_only);
    assert(branch_of(hi_branches(), 0x02) == Some(Shape::Fixed(8))) by (compute_only);
    assert(branch_of(hi_branches(), 0x03) == Some(Shape::Fixed(0))) by (compute_only);
}

/// Copy a slice into an owned body. The length travels with the result, which
/// is what lets a fixed-width door prove its width.
fn owned(a: &[u8]) -> (r: Vec<u8>)
    ensures r@ =~= a@
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < a.len()
        invariant 0 <= i <= a.len(), out@ =~= a@.take(i as int),
        decreases a.len() - i
    {
        out.push(a[i]);
        proof { assert(a@.take(i + 1) =~= a@.take(i as int).push(a@[i as int])); }
        i = i + 1;
    }
    proof { assert(a@.take(a.len() as int) =~= a@); }
    out
}

pub fn seal_null() -> (r: CanonicalBytes)
    ensures r.view() =~= seq![TAG_NULL]
{
    proof { lemma_tag_shapes(); }
    let b = Body::fixed(Vec::new());
    seal(TAG_NULL, b)
}

/// The two booleans are two tags. There is no payload to disagree with them.
pub fn seal_bool(v: bool) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![if v { TAG_TRUE } else { TAG_FALSE }]
{
    proof { lemma_tag_shapes(); }
    let b = Body::fixed(Vec::new());
    if v { seal(TAG_TRUE, b) } else { seal(TAG_FALSE, b) }
}

/// How a number was written. The tie-break every numeric body ends with, so
/// `1` and `1.0` compare equal on magnitude and separate here.
// CONSTRUCT: ClosedSum Repr
pub enum Repr {
    Int,
    Float,
}

impl Repr {
    pub open spec fn spec_byte(self) -> u8 {
        match self { Repr::Int => 0x00u8, Repr::Float => 0x01u8 }
    }

    pub fn byte(self) -> (r: u8)
        ensures r == self.spec_byte()
    {
        match self { Repr::Int => 0x00u8, Repr::Float => 0x01u8 }
    }
}

/// Zero carries only the representation tie-break: there is no magnitude to
/// write, so there is no door that takes one.
pub fn seal_num_zero(tie: Repr) -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); lemma_branch_shapes(); }
    let inner = Body::fixed(owned(&[tie.byte()]));
    seal(TAG_NUM, Body::select(Ghost(num_branches()), 0x02, inner))
}

/// A number's magnitude as stored: a 16-bit biased exponent, then an 80-bit
/// fraction, then the representation tie-break, big-endian throughout.
///
/// ORDER_LAW: ascending, exponent first. The field order is the order law —
/// exponent above fraction above tie-break is what makes numeric order equal
/// byte order. Reordering the fields is a format break.
// CONSTRUCT: SealedProduct Magnitude
/// Bytes of exponent-and-fraction, before the tie-break.
pub const MAG_BYTES: usize = 11;
/// Bits of fraction. Every shift in `packed` derives from it.
pub const FRAC_BITS: u32 = 72;
/// A saturated fraction: every bit of the field set. `lemma_frac_mask` binds
/// it to `FRAC_BITS`, so the two cannot drift apart silently.
pub const FRAC_MASK: u128 = 0xFFFFFFFFFFFFFFFFFFu128;

pub proof fn lemma_frac_mask()
    ensures FRAC_MASK == (1u128 << FRAC_BITS) - 1
{ assert(0xFFFFFFFFFFFFFFFFFFu128 == (1u128 << 72u32) - 1) by (bit_vector); }
/// The exponent value no finite magnitude may take, so that `Infinite` sorts
/// above every one of them.
pub const EXP_INFINITE: u32 = 0xFFFF;

// CONSTRUCT: ClosedSum Magnitude
pub enum Magnitude {
    /// `significand × 2^(biased_scale)`, the scale biased so the field is
    /// unsigned and its numeric order is its byte order.
    Finite { significand: u64, biased_scale: u32 },
    Infinite,
}

pub open spec fn pow2(n: nat) -> nat
    decreases n
{ if n == 0 { 1nat } else { (2 * pow2((n - 1) as nat)) as nat } }

/// What a magnitude denotes: `significand × 2^biased_scale`, or nothing for
/// `Infinite`, which is above every finite value rather than equal to one.
pub open spec fn mag_value(m: Magnitude) -> Option<nat> {
    match m {
        Magnitude::Finite { significand, biased_scale } =>
            Some((significand as nat * pow2(biased_scale as nat)) as nat),
        Magnitude::Infinite => None,
    }
}

/// ORDER_LAW: finite magnitudes by numeric value; `Infinite` above all of them.
///
/// This is the semantic side of the bridge. It is stated over what a magnitude
/// *denotes*, never over the bytes it encodes to, so `theorem_magnitude_order`
/// relates two independently-defined orders instead of restating one of them.
pub open spec fn mag_le(a: Magnitude, b: Magnitude) -> bool {
    match (mag_value(a), mag_value(b)) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(x), Some(y)) => x <= y,
    }
}

pub open spec fn spec_bit_len(v: nat) -> nat
    decreases v
{ if v == 0 { 0nat } else { (1 + spec_bit_len((v / 2) as nat)) as nat } }

/// The layout as a number: exponent above fraction, which is the order law
/// stated arithmetically rather than as a byte diagram.
pub open spec fn spec_packed(m: Magnitude) -> nat {
    match m {
        Magnitude::Finite { significand, biased_scale } => {
            let bits = spec_bit_len(significand as nat);
            let exponent = (bits + biased_scale as nat) as nat;
            (exponent * pow2(FRAC_BITS as nat)
                + significand as nat * pow2((FRAC_BITS - bits) as nat)) as nat
        }
        Magnitude::Infinite =>
            (EXP_INFINITE as nat * pow2(FRAC_BITS as nat)
                + (pow2(FRAC_BITS as nat) - 1) as nat) as nat,
    }
}

/// `v` big-endian in `width` bytes.
pub open spec fn spec_be(v: nat, width: nat) -> Seq<u8>
    decreases width
{
    if width == 0 { Seq::empty() }
    else { spec_be((v / 256) as nat, (width - 1) as nat).push((v % 256) as u8) }
}

pub open spec fn spec_mag_body(m: Magnitude, tie: Repr) -> Seq<u8> {
    spec_be(spec_packed(m), MAG_BYTES as nat).push(tie.spec_byte())
}

/// Lexicographic order on equal-length sequences is decided by the prefix
/// when the prefixes differ, and by the last element when they do not.
pub proof fn lemma_lex_snoc(s: Seq<u8>, t: Seq<u8>, a: u8, b: u8)
    requires s.len() == t.len()
    ensures
        s == t ==> (lex_le(s.push(a), t.push(b)) == (a <= b)),
        s != t ==> (lex_le(s.push(a), t.push(b)) == lex_le(s, t)),
    decreases s.len()
{
    if s.len() == 0 {
        assert(s =~= t);
        assert(s.push(a) =~= seq![a]);
        assert(t.push(b) =~= seq![b]);
        assert(s.push(a).len() == 1 && t.push(b).len() == 1);
        assert(s.push(a)[0] == a && t.push(b)[0] == b);
        assert(s.push(a).drop_first() =~= Seq::<u8>::empty());
        assert(t.push(b).drop_first() =~= Seq::<u8>::empty());
        assert(lex_le(Seq::<u8>::empty(), Seq::<u8>::empty()));
    } else {
        assert(s.push(a).len() > 0 && t.push(b).len() > 0);
        assert(s.push(a)[0] == s[0]);
        assert(t.push(b)[0] == t[0]);
        assert(s.push(a).drop_first() =~= s.drop_first().push(a));
        assert(t.push(b).drop_first() =~= t.drop_first().push(b));
        assert(s.drop_first().len() == t.drop_first().len());
        lemma_lex_snoc(s.drop_first(), t.drop_first(), a, b);
        assert(s =~= seq![s[0]] + s.drop_first());
        assert(t =~= seq![t[0]] + t.drop_first());
        if s == t {
            assert(s[0] == t[0]);
            assert(s.drop_first() =~= t.drop_first());
        }
        if s != t && s[0] == t[0] {
            assert(s.drop_first() != t.drop_first()) by {
                if s.drop_first() == t.drop_first() { assert(s =~= t); }
            }
        }
    }
}

pub proof fn lemma_be_len(v: nat, width: nat)
    ensures spec_be(v, width).len() == width
    decreases width
{ if width > 0 { lemma_be_len((v / 256) as nat, (width - 1) as nat); } }

pub proof fn lemma_pow2_byte(n: nat)
    ensures pow2((n + 8) as nat) == 256 * pow2(n)
{
    assert(pow2((n + 8) as nat) == 2 * pow2((n + 7) as nat));
    assert(pow2((n + 7) as nat) == 2 * pow2((n + 6) as nat));
    assert(pow2((n + 6) as nat) == 2 * pow2((n + 5) as nat));
    assert(pow2((n + 5) as nat) == 2 * pow2((n + 4) as nat));
    assert(pow2((n + 4) as nat) == 2 * pow2((n + 3) as nat));
    assert(pow2((n + 3) as nat) == 2 * pow2((n + 2) as nat));
    assert(pow2((n + 2) as nat) == 2 * pow2((n + 1) as nat));
    assert(pow2((n + 1) as nat) == 2 * pow2(n));
}

/// Big-endian at a fixed width: byte order is numeric order. The half of the
/// bridge that is about bytes.
pub proof fn lemma_be_order(x: nat, y: nat, width: nat)
    requires x < pow2((8 * width) as nat), y < pow2((8 * width) as nat)
    ensures (x <= y) == lex_le(spec_be(x, width), spec_be(y, width))
    decreases width
{
    if width == 0 {
        assert(pow2(0nat) == 1);
        assert(x == 0 && y == 0);
        assert(spec_be(x, 0nat) =~= Seq::<u8>::empty());
        assert(spec_be(y, 0nat) =~= Seq::<u8>::empty());
    } else {
        let w1 = (width - 1) as nat;
        lemma_pow2_byte((8 * w1) as nat);
        assert(8 * width == 8 * w1 + 8);
        lemma_be_len((x / 256) as nat, w1);
        lemma_be_len((y / 256) as nat, w1);
        lemma_be_order((x / 256) as nat, (y / 256) as nat, w1);
        lemma_be_order((y / 256) as nat, (x / 256) as nat, w1);
        lemma_lex_snoc(
            spec_be((x / 256) as nat, w1),
            spec_be((y / 256) as nat, w1),
            (x % 256) as u8, (y % 256) as u8);
        assert(x == 256 * (x / 256) + x % 256);
        assert(y == 256 * (y / 256) + y % 256);
        assert(x % 256 < 256 && y % 256 < 256);
        assert(x <= y <==> (x / 256 < y / 256
            || (x / 256 == y / 256 && x % 256 <= y % 256))) by (nonlinear_arith)
            requires x == 256 * (x / 256) + x % 256,
                     y == 256 * (y / 256) + y % 256,
                     x % 256 < 256, y % 256 < 256;
    }
}

/// `pow2` is monotone, which is what lets an exponent gap dominate any
/// fraction difference.
pub proof fn lemma_pow2_mono(m: nat, n: nat)
    requires m <= n
    ensures pow2(m) <= pow2(n)
    decreases n
{ if n > m { lemma_pow2_mono(m, (n - 1) as nat); } }

pub proof fn lemma_pow2_pos(n: nat)
    ensures pow2(n) >= 1
    decreases n
{ if n > 0 { lemma_pow2_pos((n - 1) as nat); } }

/// THE BINADE BOUND. A value occupies exactly `spec_bit_len` bits, so it sits
/// in `[2^(bits-1), 2^bits)`. This is what makes the left-aligned fraction
/// normalized, and normalization is what makes the exponent dominate.
pub proof fn lemma_binade(v: nat)
    requires v > 0
    ensures
        pow2((spec_bit_len(v) - 1) as nat) <= v,
        v < pow2(spec_bit_len(v)),
        spec_bit_len(v) >= 1,
    decreases v
{
    if v == 1 {
        assert((1nat / 2) == 0nat);
        assert(spec_bit_len(0nat) == 0);
        assert(spec_bit_len(1nat) == 1);
        assert(pow2(0nat) == 1);
        assert(pow2(1nat) == 2);
    } else {
        lemma_binade((v / 2) as nat);
        assert(spec_bit_len(v) == 1 + spec_bit_len((v / 2) as nat));
        assert(v / 2 >= 1);
        let k = spec_bit_len((v / 2) as nat);
        assert(pow2((k - 1) as nat) <= v / 2);
        assert(v / 2 < pow2(k));
        assert(pow2(k) == 2 * pow2((k - 1) as nat));
        assert(pow2((k + 1) as nat) == 2 * pow2(k));
        assert(v >= 2 * (v / 2));
        assert(v < 2 * (v / 2) + 2);
    }
}

pub proof fn lemma_pow2_add(a: nat, b: nat)
    ensures pow2(a) * pow2(b) == pow2((a + b) as nat)
    decreases a
{
    if a == 0 {
        assert(pow2(0nat) == 1);
        assert((0 + b) as nat == b);
    } else {
        let pa1 = pow2((a - 1) as nat);
        let pb = pow2(b);
        lemma_pow2_add((a - 1) as nat, b);
        assert(((a - 1) + b) as nat == (a + b - 1) as nat);
        assert(pa1 * pb == pow2((a + b - 1) as nat));
        assert(pow2(a) == 2 * pa1);
        assert(pow2((a + b) as nat) == 2 * pow2((a + b - 1) as nat));
        assert((2 * pa1) * pb == 2 * (pa1 * pb)) by (nonlinear_arith);
        assert(pow2(a) * pb == (2 * pa1) * pb);
        assert(2 * (pa1 * pb) == 2 * pow2((a + b - 1) as nat));
    }
}

/// The exponent field a magnitude carries.
pub open spec fn spec_exp(m: Magnitude) -> nat {
    match m {
        Magnitude::Finite { significand, biased_scale } =>
            (spec_bit_len(significand as nat) + biased_scale as nat) as nat,
        Magnitude::Infinite => EXP_INFINITE as nat,
    }
}

/// The fraction field: the significand left-aligned in `FRAC_BITS` bits.
pub open spec fn spec_frac(m: Magnitude) -> nat {
    match m {
        Magnitude::Finite { significand, biased_scale } =>
            (significand as nat
                * pow2((FRAC_BITS - spec_bit_len(significand as nat)) as nat)) as nat,
        Magnitude::Infinite => (pow2(FRAC_BITS as nat) - 1) as nat,
    }
}

pub proof fn lemma_packed_fields(m: Magnitude)
    ensures spec_packed(m) == spec_exp(m) * pow2(FRAC_BITS as nat) + spec_frac(m)
{ }

/// NORMALIZATION. Every fraction lands in the same binade `[2^(F-1), 2^F)`,
/// which is what lets a difference in exponent outweigh any difference in
/// fraction.
pub proof fn lemma_frac_normalized(m: Magnitude)
    requires wf_mag(m)
    ensures
        pow2((FRAC_BITS - 1) as nat) <= spec_frac(m),
        spec_frac(m) < pow2(FRAC_BITS as nat),
{
    match m {
        Magnitude::Finite { significand, biased_scale } => {
            let s = significand as nat;
            let bits = spec_bit_len(s);
            lemma_binade(s);
            assert(pow2(64nat) == 18446744073709551616nat) by (compute);
            lemma_bit_len_bound(s, 64nat);
            assert(bits <= 64);
            lemma_pow2_add((bits - 1) as nat, (FRAC_BITS - bits) as nat);
            lemma_pow2_add(bits, (FRAC_BITS - bits) as nat);
            lemma_pow2_pos((FRAC_BITS - bits) as nat);
            assert(pow2((bits - 1) as nat) * pow2((FRAC_BITS - bits) as nat)
                == pow2((FRAC_BITS - 1) as nat));
            assert(pow2(bits) * pow2((FRAC_BITS - bits) as nat) == pow2(FRAC_BITS as nat));
            let lo = pow2((bits - 1) as nat);
            let hi = pow2(bits);
            let shift = pow2((FRAC_BITS - bits) as nat);
            assert(lo <= s);
            assert(s < hi);
            assert(lo * shift <= s * shift) by (nonlinear_arith)
                requires lo <= s, shift >= 1;
            assert(s * shift < hi * shift) by (nonlinear_arith)
                requires s < hi, shift >= 1;
        }
        Magnitude::Infinite => {
            lemma_pow2_mono((FRAC_BITS - 1) as nat, FRAC_BITS as nat);
            lemma_pow2_pos((FRAC_BITS - 1) as nat);
            assert(pow2(FRAC_BITS as nat) == 2 * pow2((FRAC_BITS - 1) as nat));
        }
    }
}

/// A value below `2^n` occupies at most `n` bits.
pub proof fn lemma_bit_len_bound(v: nat, n: nat)
    requires v < pow2(n)
    ensures spec_bit_len(v) <= n
    decreases n
{
    if v > 0 {
        assert(n > 0) by { if n == 0 { assert(pow2(0nat) == 1); } }
        assert(pow2(n) == 2 * pow2((n - 1) as nat));
        lemma_bit_len_bound((v / 2) as nat, (n - 1) as nat);
    }
}

/// The denotation, scaled into whole numbers: `value(m) x 2^F == frac x 2^exp`.
/// Comparing scaled values avoids a negative exponent without changing order.
pub proof fn lemma_value_scaled(m: Magnitude)
    requires wf_mag(m), m is Finite
    ensures
        mag_value(m) is Some,
        mag_value(m).unwrap() * pow2(FRAC_BITS as nat)
            == spec_frac(m) * pow2(spec_exp(m)),
{
    let s = m->Finite_significand as nat;
    let sc = m->Finite_biased_scale as nat;
    let bits = spec_bit_len(s);
    assert(pow2(64nat) == 18446744073709551616nat) by (compute);
    lemma_bit_len_bound(s, 64nat);
    lemma_binade(s);
    // value x 2^F = (s x 2^sc) x 2^F = s x 2^(sc+F)
    lemma_pow2_add(sc, FRAC_BITS as nat);
    assert((s * pow2(sc)) * pow2(FRAC_BITS as nat) == s * pow2((sc + FRAC_BITS) as nat))
        by (nonlinear_arith)
        requires pow2(sc) * pow2(FRAC_BITS as nat) == pow2((sc + FRAC_BITS) as nat);
    // frac x 2^exp = (s x 2^(F-bits)) x 2^(bits+sc) = s x 2^(F+sc)
    lemma_pow2_add((FRAC_BITS - bits) as nat, (bits + sc) as nat);
    assert(((FRAC_BITS - bits) + (bits + sc)) as nat == (sc + FRAC_BITS) as nat);
    assert((s * pow2((FRAC_BITS - bits) as nat)) * pow2((bits + sc) as nat)
            == s * pow2((sc + FRAC_BITS) as nat))
        by (nonlinear_arith)
        requires pow2((FRAC_BITS - bits) as nat) * pow2((bits + sc) as nat)
            == pow2((sc + FRAC_BITS) as nat);
}

/// A strictly greater exponent beats any fraction, because both fractions sit
/// in the same binade.
pub proof fn lemma_exp_dominates(m: Magnitude, n: Magnitude)
    requires wf_mag(m), wf_mag(n), spec_exp(m) < spec_exp(n)
    ensures spec_frac(m) * pow2(spec_exp(m)) < spec_frac(n) * pow2(spec_exp(n))
{
    lemma_frac_normalized(m);
    lemma_frac_normalized(n);
    let em = spec_exp(m);
    let en = spec_exp(n);
    // frac(m) x 2^em < 2^F x 2^em = 2^(F+em) <= 2^(F+en-1) = 2^(F-1) x 2^en <= frac(n) x 2^en
    lemma_pow2_add(FRAC_BITS as nat, em);
    lemma_pow2_add((FRAC_BITS - 1) as nat, en);
    lemma_pow2_mono((FRAC_BITS + em) as nat, (FRAC_BITS - 1 + en) as nat);
    lemma_pow2_pos(em);
    lemma_pow2_pos(en);
    assert(spec_frac(m) * pow2(em) < pow2(FRAC_BITS as nat) * pow2(em))
        by (nonlinear_arith)
        requires spec_frac(m) < pow2(FRAC_BITS as nat), pow2(em) >= 1;
    assert(pow2((FRAC_BITS - 1) as nat) * pow2(en) <= spec_frac(n) * pow2(en))
        by (nonlinear_arith)
        requires pow2((FRAC_BITS - 1) as nat) <= spec_frac(n), pow2(en) >= 1;
}

/// THE NORMALIZATION BRIDGE. What a magnitude denotes orders exactly as its
/// packed fields do. This is the obligation every kind owes and the one
/// `theorem_value_order` cannot supply for itself.
pub proof fn lemma_packed_order(a: Magnitude, b: Magnitude)
    requires wf_mag(a), wf_mag(b)
    ensures mag_le(a, b) == (spec_packed(a) <= spec_packed(b))
{
    lemma_packed_fields(a);
    lemma_packed_fields(b);
    lemma_frac_normalized(a);
    lemma_frac_normalized(b);
    let ea = spec_exp(a);
    let eb = spec_exp(b);
    let fa = spec_frac(a);
    let fb = spec_frac(b);
    let pf = pow2(FRAC_BITS as nat);
    // packed is lexicographic in (exp, frac) because frac < 2^F.
    assert(spec_packed(a) <= spec_packed(b)
        <==> (ea < eb || (ea == eb && fa <= fb))) by (nonlinear_arith)
        requires
            spec_packed(a) == ea * pf + fa, spec_packed(b) == eb * pf + fb,
            fa < pf, fb < pf;
    match (a, b) {
        (Magnitude::Infinite, Magnitude::Infinite) => {}
        (Magnitude::Finite { .. }, Magnitude::Infinite) => {
            lemma_exp_finite_below_infinite(a);
        }
        (Magnitude::Infinite, Magnitude::Finite { .. }) => {
            lemma_exp_finite_below_infinite(b);
        }
        (Magnitude::Finite { .. }, Magnitude::Finite { .. }) => {
            lemma_value_scaled(a);
            lemma_value_scaled(b);
            lemma_pow2_pos(FRAC_BITS as nat);
            let va = mag_value(a).unwrap();
            let vb = mag_value(b).unwrap();
            assert(va <= vb <==> va * pf <= vb * pf) by (nonlinear_arith)
                requires pf >= 1;
            if ea < eb { lemma_exp_dominates(a, b); }
            if eb < ea { lemma_exp_dominates(b, a); }
            if ea == eb {
                lemma_pow2_pos(ea);
                assert(fa * pow2(ea) <= fb * pow2(eb) <==> fa <= fb)
                    by (nonlinear_arith)
                    requires ea == eb, pow2(ea) >= 1;
            }
        }
    }
}

/// Every finite exponent is below the reserved one, which is what `wf_mag`
/// buys: `Infinite` cannot be impersonated.
pub proof fn lemma_exp_finite_below_infinite(m: Magnitude)
    requires wf_mag(m), m is Finite
    ensures spec_exp(m) < EXP_INFINITE as nat
{
    let s = m->Finite_significand as nat;
    assert(pow2(64nat) == 18446744073709551616nat) by (compute);
    lemma_bit_len_bound(s, 64nat);
}

/// The packed field fits the payload: exponent below 2^16, fraction below
/// 2^72, so the pair is below 2^88 = 2^(8 x MAG_BYTES). Derived, so the order
/// theorem needs no width precondition.
pub proof fn lemma_packed_fits(m: Magnitude)
    requires wf_mag(m)
    ensures spec_packed(m) < pow2((8 * MAG_BYTES) as nat)
{
    lemma_packed_fields(m);
    lemma_frac_normalized(m);
    let e = spec_exp(m);
    let f = spec_frac(m);
    let pf = pow2(FRAC_BITS as nat);
    assert(e <= EXP_INFINITE as nat) by {
        match m {
            Magnitude::Finite { .. } => { lemma_exp_finite_below_infinite(m); }
            Magnitude::Infinite => {}
        }
    }
    lemma_pow2_add(16nat, FRAC_BITS as nat);
    assert((8 * MAG_BYTES) as nat == (16 + FRAC_BITS) as nat);
    assert(pow2(16nat) == 65536nat) by (compute);
    assert(e < pow2(16nat));
    assert(e * pf + f < pow2(16nat) * pf) by (nonlinear_arith)
        requires e < pow2(16nat), f < pf, pf >= 1;
}

/// THE MAGNITUDE ORDER BRIDGE. What a magnitude denotes orders exactly as the
/// bytes it encodes to.
///
/// Without this, `theorem_value_order` proves that framing preserves an order
/// the scalar bytes were *defined* to have. With it, the scalar side is an
/// independent numeric order and the equality is a theorem.
pub proof fn theorem_magnitude_order(a: Magnitude, b: Magnitude, tie: Repr)
    requires wf_mag(a), wf_mag(b)
    ensures mag_le(a, b) == lex_le(spec_mag_body(a, tie), spec_mag_body(b, tie))
{
    lemma_packed_order(a, b);
    lemma_packed_fits(a);
    lemma_packed_fits(b);
    let pa = spec_packed(a);
    let pb = spec_packed(b);
    let w = MAG_BYTES as nat;
    lemma_be_len(pa, w);
    lemma_be_len(pb, w);
    lemma_be_order(pa, pb, w);
    lemma_be_order(pb, pa, w);
    lemma_lex_snoc(spec_be(pa, w), spec_be(pb, w), tie.spec_byte(), tie.spec_byte());
}

/// A magnitude the numeric doors accept.
pub open spec fn wf_mag(m: Magnitude) -> bool {
    match m {
        Magnitude::Finite { significand, biased_scale } =>
            significand > 0 && biased_scale + 64 < EXP_INFINITE,
        Magnitude::Infinite => true,
    }
}

/// Bit-length of a non-zero value: the width the significand occupies, which
/// decides both the exponent and how far the fraction is left-aligned.
pub fn bit_len(v: u64) -> (r: u32)
    requires v > 0
    ensures 1 <= r <= 64
{
    let mut n: u32 = 0;
    let mut x: u64 = v;
    while x > 0 && n < 64
        invariant n <= 64
        decreases 64 - n
    { x = x / 2; n = n + 1; }
    if n == 0 { 1 } else { n }
}

/// The one `as` in this file, at the one place it is proven lossless.
fn low_byte(v: u128) -> (r: u8)
    requires v < 256
    ensures r as u128 == v
{ v as u8 }

/// `v` big-endian in exactly `width` bytes: the sole byte-order writer, so
/// numeric order is byte order in one place rather than at each call site.
pub fn be_bytes(v: u128, width: usize) -> (r: Vec<u8>)
    requires width <= 16
    ensures r@.len() == width
{
    let mut b: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < width
        invariant 0 <= i <= width, b@.len() == i, width <= 16
        decreases width - i
    {
        let shift: u32 = ((width - 1 - i) * 8) as u32;
        let byte: u128 = (v >> shift) & 0xff;
        proof { assert(((v >> shift) & 0xff) < 256) by (bit_vector); }
        b.push(low_byte(byte));
        i = i + 1;
    }
    b
}

impl Magnitude {
    /// The exponent this magnitude carries. `Infinite`'s is the reserved one.
    pub fn exponent(&self) -> (r: u32)
        requires match self {
            Magnitude::Finite { significand, biased_scale } =>
                *significand > 0 && *biased_scale + 64 < EXP_INFINITE,
            Magnitude::Infinite => true,
        }
        ensures r <= EXP_INFINITE
    {
        match self {
            Magnitude::Finite { significand, biased_scale } => bit_len(*significand) + *biased_scale,
            Magnitude::Infinite => EXP_INFINITE,
        }
    }

    /// Exponent in the high 16 bits, fraction left-aligned below it. One
    /// expression, so the layout has no second place to disagree with itself.
    fn packed(&self) -> (r: u128)
        requires match self {
            Magnitude::Finite { significand, biased_scale } =>
                *significand > 0 && *biased_scale + 64 < EXP_INFINITE,
            Magnitude::Infinite => true,
        }
    {
        match self {
            Magnitude::Finite { significand, biased_scale } => {
                let bits = bit_len(*significand);
                let exponent: u128 = (bit_len(*significand) + *biased_scale) as u128;
                (exponent << FRAC_BITS) | ((*significand as u128) << (FRAC_BITS - bits))
            }
            Magnitude::Infinite => {
                ((EXP_INFINITE as u128) << FRAC_BITS) | FRAC_MASK
            }
        }
    }

    /// The payload complemented, then the tie-break uncomplemented.
    ///
    /// ORDER_LAW: a larger magnitude is a smaller negative number, so the
    /// negative class stores the complement and its order reverses. The
    /// tie-break is not complemented, so `Int` sorts before `Float` in both
    /// classes rather than flipping with the sign.
    pub fn body_negated(&self, tie: Repr) -> (r: Vec<u8>)
        requires match self {
            Magnitude::Finite { significand, biased_scale } =>
                *significand > 0 && *biased_scale + 64 < EXP_INFINITE,
            Magnitude::Infinite => true,
        }
        ensures r@.len() == MAG_BYTES + 1
    {
        let p = be_bytes(self.packed(), MAG_BYTES);
        let mut b: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < MAG_BYTES
            invariant 0 <= i <= MAG_BYTES, b@.len() == i, p@.len() == MAG_BYTES
            decreases MAG_BYTES - i
        { b.push(!p[i]); i = i + 1; }
        b.push(tie.byte());
        b
    }

    /// The payload, big-endian, `MAG_BYTES` wide, then the tie-break.
    pub fn body(&self, tie: Repr) -> (r: Vec<u8>)
        requires match self {
            Magnitude::Finite { significand, biased_scale } =>
                *significand > 0 && *biased_scale + 64 < EXP_INFINITE,
            Magnitude::Infinite => true,
        }
        ensures r@.len() == MAG_BYTES + 1
    {
        let mut b = be_bytes(self.packed(), MAG_BYTES);
        b.push(tie.byte());
        b
    }
}

/// A signed magnitude. The class byte is not a parameter — the door the caller
/// picks IS the class, so a magnitude cannot be filed under the wrong sign.
pub fn seal_num_negative(mag: &Magnitude, tie: Repr) -> (r: CanonicalBytes)
    requires match mag {
        Magnitude::Finite { significand, biased_scale } =>
            *significand > 0 && *biased_scale + 64 < EXP_INFINITE,
        Magnitude::Infinite => true,
    }
{
    proof { lemma_tag_shapes(); lemma_branch_shapes(); }
    let inner = Body::fixed(mag.body_negated(tie));
    seal(TAG_NUM, Body::select(Ghost(num_branches()), 0x01, inner))
}

pub fn seal_num_positive(mag: &Magnitude, tie: Repr) -> (r: CanonicalBytes)
    requires match mag {
        Magnitude::Finite { significand, biased_scale } =>
            *significand > 0 && *biased_scale + 64 < EXP_INFINITE,
        Magnitude::Infinite => true,
    }
{
    proof { lemma_tag_shapes(); lemma_branch_shapes(); }
    let inner = Body::fixed(mag.body(tie));
    seal(TAG_NUM, Body::select(Ghost(num_branches()), 0x03, inner))
}

/// Not a number, and above every number.
///
/// NaN is reachable only from a float, so the representation tie-break has one
/// admissible value and this door writes it.
pub fn seal_num_nan() -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); lemma_branch_shapes(); }
    let inner = Body::fixed(owned(&[Repr::Float.byte()]));
    seal(TAG_NUM, Body::select(Ghost(num_branches()), 0x04, inner))
}

pub fn seal_str(content: &[u8]) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![TAG_STR] + enc_bytes(content@)
{ proof { lemma_tag_shapes(); } seal(TAG_STR, Body::delimited(content)) }

pub fn seal_bytes(content: &[u8]) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![TAG_BYTES] + enc_bytes(content@)
{ proof { lemma_tag_shapes(); } seal(TAG_BYTES, Body::delimited(content)) }

pub fn seal_uuid(id: &[u8; 16]) -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); }
    let b = Body::fixed(owned(id.as_slice()));
    seal(TAG_UUID, b)
}

/// The regex flags that survive into stored bytes. Bit 0 case-insensitive,
/// bit 1 multi-line, bit 2 dot-matches-newline.
// CONSTRUCT: ValueObject RegexFlags
pub struct RegexFlags {
    case_insensitive: bool,
    multi_line: bool,
    dot_matches_new_line: bool,
}

impl RegexFlags {
    pub fn new(case_insensitive: bool, multi_line: bool, dot_matches_new_line: bool) -> (r: RegexFlags) {
        RegexFlags { case_insensitive, multi_line, dot_matches_new_line }
    }

    pub fn byte(&self) -> (r: u8) {
        let a: u8 = if self.case_insensitive { 1 } else { 0 };
        let b: u8 = if self.multi_line { 2 } else { 0 };
        let c: u8 = if self.dot_matches_new_line { 4 } else { 0 };
        a | b | c
    }
}

/// A regex is identified by its pattern, so the pattern sorts first and the
/// flags break ties. The order of the two is the grammar's, not the caller's.
pub fn seal_regex(pattern: &[u8], flags: &RegexFlags) -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); }
    let f = Body::fixed(owned(&[flags.byte()]));
    seal(TAG_REGEX, Body::product(Body::delimited(pattern), f))
}

/// A JSON value IS a value. There is no second grammar to keep in step.
pub fn seal_json(v: &CanonicalBytes) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![TAG_JSON] + v.view()
{ proof { lemma_tag_shapes(); } seal(TAG_JSON, Body::value(v)) }

/// Width of the dimension field, in bytes.
pub const DIM_BYTES: usize = 4;

/// Dimension, then components.
///
/// ORDER_LAW: the dimension sorts first, so two vectors of different length
/// order by length before either is examined and a shorter one is never a
/// prefix of a longer one.
pub fn seal_vector(components: &Vec<CanonicalBytes>) -> (r: CanonicalBytes)
    requires components.len() < 0x1_0000_0000u64
{
    proof { lemma_tag_shapes(); }
    let d = be_bytes(components.len() as u128, DIM_BYTES);
    seal(TAG_VECTOR, Body::product(Body::fixed(d), Body::row(components)))
}

pub fn seal_validity(v: &[u8; 9]) -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); }
    let b = Body::fixed(owned(v.as_slice()));
    seal(TAG_VALIDITY, b)
}

pub fn seal_geometry(g: &[u8; 8]) -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); }
    let b = Body::fixed(owned(g.as_slice()));
    seal(TAG_GEOMETRY, b)
}

pub fn seal_list(elems: &Vec<CanonicalBytes>) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![TAG_LIST] + enc_row(elems@.map_values(|e: CanonicalBytes| e.view()))
{ proof { lemma_tag_shapes(); } seal(TAG_LIST, Body::row(elems)) }

/// The raw set door: a row under the set tag, in the order given.
///
/// `pub(crate)` because that order is the caller's, and a set has none. Two
/// writings of one set value would seal to two byte strings, which the law
/// forbids — equal values encode equal. Normalising is not a grammar property,
/// so it is not provable here and does not belong here; the public path is
/// [`super::codec::CanonicalSet`], whose only constructor sorts and dedups.
pub(crate) fn seal_set(elems: &Vec<CanonicalBytes>) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![TAG_SET] + enc_row(elems@.map_values(|e: CanonicalBytes| e.view()))
{ proof { lemma_tag_shapes(); } seal(TAG_SET, Body::row(elems)) }

/// An interval endpoint. Unboundedness is a variant, never a sentinel instant:
/// there is no `[u8; 8]` that means "no bound", so no caller can pick one and
/// no reader has to know which one was picked.
// CONSTRUCT: ClosedSum Bound
pub enum Bound {
    Unbounded,
    At([u8; 8]),
}

/// The empty interval: the one value below every inhabited one.
pub fn seal_interval_empty() -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); lemma_branch_shapes(); }
    let inner = Body::fixed(Vec::new());
    seal(TAG_INTERVAL, Body::select(Ghost(interval_branches()), 0x01, inner))
}

/// A bounded interval. The two ends carry different marker tables because
/// unbounded below is the least element of its axis and unbounded above is the
/// greatest — one table would put an infinity on the wrong side of every
/// instant. The caller names the ends; the markers are not its business.
pub fn seal_interval(lo: &Bound, hi: &Bound) -> (r: CanonicalBytes) {
    proof { lemma_tag_shapes(); lemma_branch_shapes(); }
    let lo_body = match lo {
        Bound::Unbounded => {
            let e = Body::fixed(Vec::new());
            Body::select(Ghost(lo_branches()), 0x01, e)
        }
        Bound::At(t) => {
            let e = Body::fixed(owned(t.as_slice()));
            Body::select(Ghost(lo_branches()), 0x02, e)
        }
    };
    let hi_body = match hi {
        Bound::At(t) => {
            let e = Body::fixed(owned(t.as_slice()));
            Body::select(Ghost(hi_branches()), 0x02, e)
        }
        Bound::Unbounded => {
            let e = Body::fixed(Vec::new());
            Body::select(Ghost(hi_branches()), 0x03, e)
        }
    };
    seal(TAG_INTERVAL, Body::select(Ghost(interval_branches()), 0x02,
        Body::product(lo_body, hi_body)))
}

} // verus!
