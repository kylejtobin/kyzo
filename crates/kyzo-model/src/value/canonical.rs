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
//! # The two obligations a kind must discharge
//!
//! `key_end` and `valid_key` are uninterpreted: this module proves nothing
//! about any particular kind's key, and assumes nothing either. A kind enters
//! through [`KindKey`], whose `law_key` is the proof that its key belongs to
//! the family. `kind_local` and `kind_complete` state the two properties every
//! kind owes. There is no third.
//!
//! # Marked positions
//!
//! Every position a scanner reads to decide "element or terminator" holds a
//! byte that cannot be the terminator. Sequence elements open with a tag
//! (`>= 0x05`), and `STRUCT_END` is `0x01`, so no element can be read as the
//! end of the row it sits in. An unmarked element position would admit an
//! element beginning `0x01` and the body would have two readings.
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

verus! {


pub const STRUCT_ESC: u8 = 0x00;
pub const STRUCT_END: u8 = 0x01;
pub const TAG_MIN: u8 = 0x05;

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
    if b == STRUCT_ESC { seq![STRUCT_ESC, 0xFFu8] } else { seq![b] }
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
                assert(esc(s)[1] == 0xFFu8);
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
        assert(code(t[0]) =~= seq![0u8, 0xFFu8]);
        assert(e.len() >= 4);
        assert(e[0] == 0u8 && e[1] == 0xFFu8);
        let e1 = e.drop_first();
        let z1 = z.drop_first();
        assert(z1 =~= seq![0u8]);
        assert(e1.len() >= 3 && e1[0] == 0xFFu8);
        assert(lex_le(z1, e1)) by { assert(z1[0] == 0u8 && e1[0] == 0xFFu8); }
        assert(!lex_le(e1, z1)) by { assert(z1[0] == 0u8 && e1[0] == 0xFFu8); }
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
    forall|i: int| 0 <= i < r.len() ==> #[trigger] r[i].len() > 0 && r[i][0] >= TAG_MIN
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
    ensures enc_row(r).len() > 0, enc_row(r)[0] == r[0][0], enc_row(r)[0] >= TAG_MIN
{ lemma_row_peel(r); assert(r[0].len() > 0); }

proof fn lemma_tail_tagged(r: Seq<Seq<u8>>)
    requires tagged(r), r.len() > 0
    ensures tagged(r.drop_first())
{
    assert forall|i: int| 0 <= i < r.drop_first().len()
        implies #[trigger] r.drop_first()[i].len() > 0 && r.drop_first()[i][0] >= TAG_MIN by {
        assert(r[i + 1].len() > 0 && r[i + 1][0] >= TAG_MIN);
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
                assert(enc_row(r)[0] == STRUCT_END && enc_row(s)[0] >= TAG_MIN);
            }
        }
    } else if s.len() == 0 {
        assert(cat(s) =~= Seq::<u8>::empty());
        assert(enc_row(s) =~= seq![STRUCT_END]);
        lemma_row_head(r);
        assert(!lex_le(enc_row(r), enc_row(s))) by {
            assert(enc_row(r)[0] >= TAG_MIN && enc_row(s)[0] == STRUCT_END);
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
            assert(enc_row(s)[0] >= TAG_MIN);
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

// ===================== the self-delimiting byte grammar ======================
//
// `key_end` and `is_seq_tag` are the two seams a value kind fills. Everything
// below is proven from the two obligations `kind_local` and `kind_complete`.

/// What a tag's payload looks like. Closed: a tag outside this table has no
/// encoding at all, which is why `scan` refuses it rather than guessing.
///
/// This table IS canonical format v1. It is transcribed from the released
/// format, not invented: changing any entry changes the on-disk order.
// CONSTRUCT: ClosedSum KeyShape
pub enum KeyShape {
    /// Exactly `n` payload bytes. Prefix-free because the width is constant.
    Fixed(nat),
    /// Escaped form: `0x00 -> 0x00 0xFF`, terminated `0x00 0x00`.
    Escaped,
    /// Escaped content, then one flags byte. A regex is identified by its
    /// pattern, so the pattern sorts first and the flags are the tie-break.
    EscapedThenFlags,
    /// The first payload byte selects the remaining width. Num.
    ClassLed,
    /// The bounded-interval grammar.
    IntervalShape,
    /// A row of complete encodings, terminated by `STRUCT_END`.
    Sequence,
}

/// THE TAG TABLE. Byte order is cross-kind order; the shape is the grammar.
/// `0x00` and `0x01` are structural and never tags, which is what lets a
/// sequence terminator sort below every element.
pub open spec fn shape_of(t: u8) -> Option<KeyShape> {
    if t == 0x05u8 { Some(KeyShape::Fixed(0nat)) }           // Null
    else if t == 0x08u8 { Some(KeyShape::Fixed(0nat)) }      // False
    else if t == 0x09u8 { Some(KeyShape::Fixed(0nat)) }      // True
    else if t == 0x10u8 { Some(KeyShape::ClassLed) }         // Num
    else if t == 0x18u8 { Some(KeyShape::Escaped) }          // Str
    else if t == 0x20u8 { Some(KeyShape::Escaped) }          // Bytes
    else if t == 0x28u8 { Some(KeyShape::Fixed(16nat)) }     // Uuid
    else if t == 0x30u8 { Some(KeyShape::EscapedThenFlags) } // Regex
    else if t == 0x40u8 { Some(KeyShape::Fixed(32nat)) }     // Vector
    else if t == 0x48u8 { Some(KeyShape::Sequence) }         // List
    else if t == 0x50u8 { Some(KeyShape::Sequence) }         // Set
    else if t == 0x58u8 { Some(KeyShape::Fixed(9nat)) }      // Validity
    else if t == 0x60u8 { Some(KeyShape::IntervalShape) }    // Interval
    else if t == 0x68u8 { Some(KeyShape::Fixed(8nat)) }      // Geometry
    else { None }
}

pub open spec fn is_seq_tag(t: u8) -> bool {
    shape_of(t) == Some(KeyShape::Sequence)
}

// --- the per-shape scanners ---

/// Width selected by a number's class byte: zero and NaN carry only the repr
/// tie-break; a signed magnitude carries exponent, fraction, and tie-break.
/// Zero carries only the representation tie-break; a signed magnitude carries
/// exponent, fraction, and tie-break. There is no NaN class: NaN is not a real
/// and the mint refuses it, so no ordering convention has to be invented for it.
pub open spec fn class_led_width(first: u8) -> int {
    if first == 0x02u8 { 2 }
    else if first == 0x01u8 || first == 0x03u8 { 13 }
    else { -1 }
}

pub open spec fn num_end(p: Seq<u8>) -> int {
    if p.len() == 0 { -1 }
    else {
        let w = class_led_width(p[0]);
        if w < 0 || p.len() < w { -1 } else { w }
    }
}

/// End of an escaped payload: the first unescaped `0x00 0x00`.
pub open spec fn esc_end(p: Seq<u8>) -> int
    decreases p.len()
{
    if p.len() == 0 { -1 }
    else if p[0] == 0x00u8 {
        if p.len() < 2 { -1 }
        else if p[1] == 0x00u8 { 2 }
        else if p[1] == 0xFFu8 {
            let r = esc_end(p.skip(2)); if r < 0 { -1 } else { 2 + r }
        } else { -1 }
    } else {
        let r = esc_end(p.skip(1)); if r < 0 { -1 } else { 1 + r }
    }
}

/// The empty interval, the one value below every inhabited one.
pub const IV_EMPTY: u8 = 0x01;
/// A bounded interval: a lower end then an upper end.
pub const IV_BOUNDED: u8 = 0x02;
/// Lower end, negative infinity: below every instant.
pub const LO_UNBOUNDED: u8 = 0x01;
/// Lower end at an instant.
pub const LO_AT: u8 = 0x02;
/// Upper end at an instant.
pub const HI_AT: u8 = 0x02;
/// Upper end, positive infinity: above every instant.
pub const HI_UNBOUNDED: u8 = 0x03;

/// The lower end: unbounded is negative infinity, the minimum, so its marker
/// sorts below every bounded one.
pub open spec fn lo_bound_end(p: Seq<u8>, at: int) -> int {
    if at < 0 || at >= p.len() { -1 }
    else if p[at] == LO_UNBOUNDED { at + 1 }
    else if p[at] == LO_AT { if p.len() < at + 9 { -1 } else { at + 9 } }
    else { -1 }
}

/// The upper end: unbounded is positive infinity, the MAXIMUM, so its marker
/// sorts above every bounded one. The two ends cannot share a marker table —
/// one unbounded shape is the least element of its axis and the other is the
/// greatest.
pub open spec fn hi_bound_end(p: Seq<u8>, at: int) -> int {
    if at < 0 || at >= p.len() { -1 }
    else if p[at] == HI_AT { if p.len() < at + 9 { -1 } else { at + 9 } }
    else if p[at] == HI_UNBOUNDED { at + 1 }
    else { -1 }
}

pub open spec fn interval_end(p: Seq<u8>) -> int {
    if p.len() == 0 { -1 }
    else if p[0] == IV_EMPTY { 1 }
    else if p[0] == IV_BOUNDED {
        let a = lo_bound_end(p, 1);
        if a < 0 { -1 } else {
            let b = hi_bound_end(p, a);
            if b < 0 { -1 } else { b }
        }
    } else { -1 }
}

/// Length of the kind's key at the front of `payload`, or negative if the
/// payload does not open with a complete key of that kind. Total: every tag
/// and every byte sequence has an answer, and the answer is never a panic.
pub open spec fn key_end(t: u8, payload: Seq<u8>) -> int {
    match shape_of(t) {
        Some(KeyShape::Fixed(n)) => if payload.len() >= n { n as int } else { -1 },
        Some(KeyShape::Escaped) => esc_end(payload),
        Some(KeyShape::EscapedThenFlags) => {
            let r = esc_end(payload);
            if r <= 0 || payload.len() < r + 1 { -1 } else { r + 1 }
        }
        Some(KeyShape::ClassLed) => num_end(payload),
        Some(KeyShape::IntervalShape) => interval_end(payload),
        Some(KeyShape::Sequence) => -1,
        None => -1,
    }
}

/// A key that measures itself exactly: the kind's mint produced it.
pub open spec fn valid_key(t: u8, k: Seq<u8>) -> bool {
    key_end(t, k) == k.len()
}

// --- the two obligations, PROVEN for every shape in the table ---

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

proof fn lemma_esc_end_local(a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), 0 <= esc_end(a) <= a.len()
    ensures esc_end(b) == esc_end(a)
    decreases a.len()
{
    lemma_prefix_index(a, b, 0);
    if a[0] == 0x00u8 {
        if a.len() >= 2 {
            lemma_prefix_index(a, b, 1);
            if a[1] == 0xFFu8 {
                lemma_prefix_skip(a, b, 2);
                lemma_esc_end_local(a.skip(2), b.skip(2));
            }
        }
    } else {
        lemma_prefix_skip(a, b, 1);
        lemma_esc_end_local(a.skip(1), b.skip(1));
    }
}

proof fn lemma_num_end_local(a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), 0 <= num_end(a) <= a.len()
    ensures num_end(b) == num_end(a)
{ lemma_prefix_index(a, b, 0); }

proof fn lemma_interval_end_local(a: Seq<u8>, b: Seq<u8>)
    requires is_prefix(a, b), 0 <= interval_end(a) <= a.len()
    ensures interval_end(b) == interval_end(a)
{
    lemma_prefix_index(a, b, 0);
    if a[0] == IV_BOUNDED {
        lemma_prefix_index(a, b, 1);
        let x = lo_bound_end(a, 1);
        if x >= 0 && x < a.len() { lemma_prefix_index(a, b, x); }
    }
}

/// OBLIGATION 1 — locality: a key's length is decided by the key, so trailing
/// bytes cannot change it. Discharged for every shape in the table.
pub proof fn lemma_kind_local()
    ensures kind_local()
{
    assert forall|t: u8, a: Seq<u8>, b: Seq<u8>|
        is_prefix(a, b) && 0 <= key_end(t, a) <= a.len()
        implies #[trigger] key_end(t, b) == #[trigger] key_end(t, a) by {
        match shape_of(t) {
            Some(KeyShape::Escaped) => { lemma_esc_end_local(a, b); }
            Some(KeyShape::EscapedThenFlags) => { lemma_esc_end_local(a, b); }
            Some(KeyShape::ClassLed) => { lemma_num_end_local(a, b); }
            Some(KeyShape::IntervalShape) => { lemma_interval_end_local(a, b); }
            _ => {}
        }
    }
}

/// OBLIGATION 2 — completeness: a minted key measures itself exactly. True by
/// the definition of [`valid_key`]; stated so the obligation stays named.
pub proof fn lemma_kind_complete()
    ensures kind_complete()
{}

pub open spec fn kind_local() -> bool {
    forall|t: u8, a: Seq<u8>, b: Seq<u8>|
        #![trigger is_prefix(a, b), key_end(t, a)]
        is_prefix(a, b) && 0 <= key_end(t, a) <= a.len()
            ==> key_end(t, b) == key_end(t, a)
}

pub open spec fn kind_complete() -> bool {
    forall|t: u8, k: Seq<u8>| #[trigger] valid_key(t, k) ==> key_end(t, k) == k.len()
}

pub open spec fn kind_laws() -> bool { kind_local() && kind_complete() }

pub open spec fn scan(e: Seq<u8>) -> int
    decreases e.len(), 0int
{
    if e.len() == 0 { -1 }
    else if e[0] < TAG_MIN { -1 }
    else if is_seq_tag(e[0]) {
        let r = scan_row_bytes(e.drop_first());
        if r < 0 { -1 } else { 1 + r }
    } else {
        let k = key_end(e[0], e.drop_first());
        if k < 0 || k > e.len() - 1 { -1 } else { 1 + k }
    }
}

pub open spec fn scan_row_bytes(e: Seq<u8>) -> int
    decreases e.len(), 1int
{
    if e.len() == 0 { -1 }
    else if e[0] == STRUCT_END { 1 }
    else {
        let j = scan(e);
        if j <= 0 || j > e.len() { -1 }
        else {
            let r = scan_row_bytes(e.skip(j));
            if r < 0 { -1 } else { j + r }
        }
    }
}

/// A complete encoding: the grammar consumes it exactly.
pub open spec fn complete(x: Seq<u8>) -> bool { scan(x) == x.len() }

proof fn lemma_prefix_index(a: Seq<u8>, b: Seq<u8>, i: int)
    requires is_prefix(a, b), 0 <= i < a.len()
    ensures a[i] == b[i]
{ assert(b.take(a.len() as int)[i] == a[i]); }

proof fn lemma_scan_bounded(e: Seq<u8>)
    ensures scan(e) >= 0 ==> 1 <= scan(e) <= e.len()
    decreases e.len(), 0int
{ if e.len() > 0 && e[0] >= TAG_MIN && is_seq_tag(e[0]) { lemma_scan_row_bounded(e.drop_first()); } }

proof fn lemma_scan_row_bounded(e: Seq<u8>)
    ensures scan_row_bytes(e) >= 0 ==> 1 <= scan_row_bytes(e) <= e.len()
    decreases e.len(), 1int
{
    if e.len() > 0 && e[0] != STRUCT_END {
        lemma_scan_bounded(e);
        let j = scan(e);
        if 0 < j <= e.len() { lemma_scan_row_bounded(e.skip(j)); }
    }
}

proof fn lemma_scan_local(a: Seq<u8>, b: Seq<u8>)
    requires kind_local(), is_prefix(a, b), scan(a) >= 0
    ensures scan(b) == scan(a)
    decreases a.len(), 0int
{
    lemma_scan_bounded(a);
    lemma_prefix_index(a, b, 0);
    if is_seq_tag(a[0]) {
        assert(is_prefix(a.drop_first(), b.drop_first())) by {
            assert(b.drop_first().take(a.drop_first().len() as int) =~= a.drop_first()) by {
                assert forall|i: int| 0 <= i < a.len() - 1
                    implies #[trigger] b.drop_first().take(a.len() - 1)[i] == a.drop_first()[i] by {
                    lemma_prefix_index(a, b, i + 1);
                }
            }
        }
        lemma_scan_row_local(a.drop_first(), b.drop_first());
    } else {
        assert(is_prefix(a.drop_first(), b.drop_first())) by {
            assert(b.drop_first().take(a.drop_first().len() as int) =~= a.drop_first()) by {
                assert forall|i: int| 0 <= i < a.len() - 1
                    implies #[trigger] b.drop_first().take(a.len() - 1)[i] == a.drop_first()[i] by {
                    lemma_prefix_index(a, b, i + 1);
                }
            }
        }
        assert(key_end(a[0], b.drop_first()) == key_end(a[0], a.drop_first()));
    }
}

proof fn lemma_scan_row_local(a: Seq<u8>, b: Seq<u8>)
    requires kind_local(), is_prefix(a, b), scan_row_bytes(a) >= 0
    ensures scan_row_bytes(b) == scan_row_bytes(a)
    decreases a.len(), 1int
{
    lemma_scan_row_bounded(a);
    lemma_prefix_index(a, b, 0);
    if a[0] != STRUCT_END {
        lemma_scan_bounded(a);
        lemma_scan_local(a, b);
        let j = scan(a);
        assert(is_prefix(a.skip(j), b.skip(j))) by {
            assert(b.skip(j).take(a.skip(j).len() as int) =~= a.skip(j)) by {
                assert forall|i: int| 0 <= i < a.len() - j
                    implies #[trigger] b.skip(j).take(a.len() - j)[i] == a.skip(j)[i] by {
                    lemma_prefix_index(a, b, i + j);
                }
            }
        }
        lemma_scan_row_local(a.skip(j), b.skip(j));
    }
}

/// THE PREFIX-CODE THEOREM. Complete encodings form a prefix code, so the
/// closure theorem's hypothesis holds for every pair of them, everywhere.
pub proof fn theorem_prefix_code(x: Seq<u8>, y: Seq<u8>)
    requires kind_local(), complete(x), complete(y), is_prefix(x, y)
    ensures x =~= y
{
    lemma_scan_local(x, y);
    assert(y.take(x.len() as int) =~= x);
    assert(y =~= y.take(y.len() as int));
}

pub proof fn lemma_complete_incomparable(x: Seq<u8>, y: Seq<u8>)
    requires kind_local(), complete(x), complete(y)
    ensures incomparable(x, y)
{
    if is_prefix(x, y) { theorem_prefix_code(x, y); }
    if is_prefix(y, x) { theorem_prefix_code(y, x); }
}

pub proof fn lemma_complete_is_tagged(x: Seq<u8>)
    requires complete(x)
    ensures x.len() > 0, x[0] >= TAG_MIN
{ lemma_scan_bounded(x); }

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
        Val::S(t, k) => t >= TAG_MIN && !is_seq_tag(t) && valid_key(t, k),
        Val::L(t, es) => t >= TAG_MIN && is_seq_tag(t) && wf_all(es),
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
        implies #[trigger] r[i].len() > 0 && r[i][0] >= TAG_MIN by {
        lemma_complete_is_tagged(r[i]);
    }
}

proof fn lemma_complete_row_is_family(r: Seq<Seq<u8>>, s: Seq<Seq<u8>>)
    requires kind_local(), all_complete(r), all_complete(s)
    ensures pfx_family(r, s)
{
    assert forall|i: int, j: int| 0 <= i < r.len() && 0 <= j < s.len()
        implies #[trigger] incomparable(r[i], s[j]) by {
        lemma_complete_incomparable(r[i], s[j]);
    }
}

/// A row of complete encodings is itself scanned exactly, whatever follows it.
proof fn lemma_scan_row_of_row(r: Seq<Seq<u8>>, rest: Seq<u8>)
    requires kind_local(), all_complete(r)
    ensures scan_row_bytes((cat(r) + seq![STRUCT_END]) + rest) == cat(r).len() + 1
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
        assert(scan(buf) == head.len());
        assert(buf.skip(head.len() as int) =~= tail_buf);
        lemma_all_complete_tail(r);
        lemma_scan_row_of_row(r.drop_first(), rest);
    }
}

pub proof fn lemma_enc_complete(v: Val)
    requires kind_laws(), wf(v)
    ensures complete(enc(v))
    decreases sz(v)
{
    let e = enc(v);
    assert(e[0] == tag_of(v));
    assert(e.drop_first() =~= body(v));
    match v {
        Val::S(t, k) => {
            assert(valid_key(t, k));
            assert(key_end(t, k) == k.len());
        }
        Val::L(t, es) => {
            lemma_enc_seq_complete(es);
            let r = enc_seq(es);
            lemma_scan_row_of_row(r, Seq::empty());
            assert(body(v) =~= (cat(r) + seq![STRUCT_END]) + Seq::<u8>::empty());
        }
    }
}

pub proof fn lemma_enc_seq_complete(es: Vals)
    requires kind_laws(), wf_all(es)
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
    requires kind_laws(), wf(u), wf(v), enc(u) =~= enc(v)
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
    requires kind_laws(), wf_all(xs), wf_all(ys), enc_seq(xs) =~= enc_seq(ys)
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
    requires kind_laws(), wf(u), wf(v)
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
    requires kind_laws(), wf_all(xs), wf_all(ys)
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

    pub fn len(&self) -> (n: usize)
        ensures n == self.view().len(), n > 0
    { proof { use_type_invariant(self); lemma_complete_is_tagged(self.view()); } self.bytes.len() }

    pub fn tag_byte(&self) -> (b: u8)
        ensures b == self.view()[0], b >= TAG_MIN
    {
        proof { use_type_invariant(self); lemma_complete_is_tagged(self.view()); }
        self.bytes[0]
    }
}

/// A kind's key: the type-level seam. A kind cannot be encoded until it proves
/// its key belongs to a prefix-free, self-measuring family.
// CONSTRUCT: SealedTrait KindKey
pub trait KindKey: Sized {
    spec fn tag(self) -> u8;
    spec fn key(self) -> Seq<u8>;

    /// The implementor's own invariant. A type invariant holds of exec values
    /// only, so it is recovered at exec by [`KindKey::tag_byte`] and carried
    /// into the two laws as a precondition. This is what stops a ghost value of
    /// the type from being handed to `law_key`.
    spec fn wf(self) -> bool;

    proof fn law_tag(self)
        requires self.wf()
        ensures self.tag() >= TAG_MIN, !is_seq_tag(self.tag());

    proof fn law_key(self)
        requires self.wf()
        ensures valid_key(self.tag(), self.key());

    /// The tag byte, at exec. Also attests the invariant.
    fn tag_byte(&self) -> (t: u8)
        ensures t == self.tag(), self.wf();

    fn emit(&self) -> (r: Vec<u8>)
        ensures r@ =~= self.key();
}

/// The grammar's two obligations, as a value.
///
/// A `requires kind_laws()` can be forgotten at a call site; a value cannot.
/// [`GrammarLaws::establish`] is the sole mint and it discharges both laws, so
/// every sealing entry point below takes the token rather than restating the
/// hypothesis. There is no way to encode anything without holding it.
// CONSTRUCT: Marker GrammarLaws
pub struct GrammarLaws {
    seal: bool,
}

// CONSTRUCT: ImplBlock GrammarLaws
impl GrammarLaws {
    #[verifier::type_invariant]
    closed spec fn holds(self) -> bool { kind_laws() && self.seal }

    /// Mint the token by discharging both obligations.
    pub fn establish() -> (r: GrammarLaws) {
        proof { lemma_kind_local(); lemma_kind_complete(); }
        GrammarLaws { seal: true }
    }
}

/// A tag that opens a sequence. A `u8` is not a tag: the invariant travels with
/// the value, so no site re-checks and no site can pass a scalar tag here.
// CONSTRUCT: Newtype SeqTag
#[derive(Clone, Copy)]
pub struct SeqTag {
    byte: u8,
}

impl View for SeqTag {
    type V = u8;
    closed spec fn view(&self) -> u8 { self.byte }
}

// CONSTRUCT: ImplBlock SeqTag
impl SeqTag {
    #[verifier::type_invariant]
    closed spec fn wf_tag(self) -> bool { self@ >= TAG_MIN && is_seq_tag(self@) }

    pub fn mint(b: u8) -> (r: SeqTag)
        requires b >= TAG_MIN, is_seq_tag(b)
        ensures r@ == b
    { SeqTag { byte: b } }

    pub fn byte(&self) -> (b: u8)
        ensures b == self@, b >= TAG_MIN, is_seq_tag(b)
    { proof { use_type_invariant(*self); } self.byte }
}

/// Seal a scalar. The result is a complete encoding by construction.
// CONSTRUCT: Mint seal
pub fn seal<K: KindKey>(laws: &GrammarLaws, k: &K) -> (r: CanonicalBytes)
    ensures r.view() =~= seq![k.tag()] + k.key()
{
    proof { use_type_invariant(laws); }
    let mut out: Vec<u8> = Vec::new();
    let t = k.tag_byte();
    proof { k.law_tag(); k.law_key(); }
    out.push(t);
    let mut payload = k.emit();
    out.append(&mut payload);
    proof {
        let v = Val::S(k.tag(), k.key());
        assert(wf(v));
        assert(enc(v) =~= out@);
        lemma_enc_complete(v);
    }
    CanonicalBytes { bytes: out }
}

/// Seal a sequence of already-sealed values.
// CONSTRUCT: Mint seal_sequence
pub fn seal_sequence(laws: &GrammarLaws, tag: SeqTag, elems: &Vec<CanonicalBytes>)
    -> (r: CanonicalBytes)
    ensures
        r.view() =~= seq![tag@] + enc_row(elems@.map_values(|e: CanonicalBytes| e.view())),
{
    proof { use_type_invariant(laws); use_type_invariant(tag); }
    let tag = tag.byte();
    let ghost views = elems@.map_values(|e: CanonicalBytes| e.view());
    let mut out: Vec<u8> = Vec::new();
    out.push(tag);
    let mut i: usize = 0;
    while i < elems.len()
        invariant
            0 <= i <= elems.len(),
            views =~= elems@.map_values(|e: CanonicalBytes| e.view()),
            out@ =~= seq![tag] + cat(views.take(i as int)),
            forall|k: int| 0 <= k < i ==> complete(#[trigger] views[k]),
        decreases elems.len() - i
    {
        let e = &elems[i];
        proof { use_type_invariant(e); }
        let bs = e.as_bytes();
        let mut j: usize = 0;
        let ghost before = out@;
        while j < bs.len()
            invariant
                0 <= j <= bs.len(),
                bs@ =~= views[i as int],
                out@ =~= before + bs@.take(j as int),
            decreases bs.len() - j
        {
            out.push(bs[j]);
            proof { assert(bs@.take(j + 1) =~= bs@.take(j as int).push(bs@[j as int])); }
            j = j + 1;
        }
        proof {
            assert(bs@.take(bs.len() as int) =~= views[i as int]);
            lemma_cat_snoc(views.take(i as int), views[i as int]);
            assert(views.take(i + 1) =~= views.take(i as int).push(views[i as int]));
        }
        i = i + 1;
    }
    out.push(STRUCT_END);
    proof {
        assert(all_complete(views));
        assert(views.take(elems.len() as int) =~= views);
        lemma_scan_row_of_row(views, Seq::empty());
        assert(out@ =~= seq![tag] + ((cat(views) + seq![STRUCT_END]) + Seq::<u8>::empty()));
        assert(out@[0] == tag);
        assert(out@.drop_first() =~= (cat(views) + seq![STRUCT_END]) + Seq::<u8>::empty());
    }
    CanonicalBytes { bytes: out }
}

/// The escaped form measures itself exactly: [`esc`] never emits `0x00 0x00`,
/// so the terminator this appends is the first one the scanner meets.
pub proof fn lemma_esc_end_of_enc_bytes(s: Seq<u8>)
    ensures esc_end(enc_bytes(s)) == enc_bytes(s).len()
    decreases s.len()
{
    let p = enc_bytes(s);
    if s.len() == 0 {
        assert(esc(s) =~= Seq::<u8>::empty());
        assert(p =~= seq![0u8, 0u8]);
    } else {
        lemma_enc_bytes_peel(s);
        let rest = enc_bytes(s.drop_first());
        lemma_esc_end_of_enc_bytes(s.drop_first());
        if s[0] == 0x00u8 {
            assert(code(s[0]) =~= seq![0x00u8, 0xFFu8]);
            assert(p[0] == 0x00u8 && p[1] == 0xFFu8);
            assert(p.skip(2) =~= rest);
        } else {
            assert(code(s[0]) =~= seq![s[0]]);
            assert(p[0] == s[0]);
            assert(p.skip(1) =~= rest);
        }
    }
}

/// A variable-length key: opaque content in the escaped form. Every kind whose
/// payload is bytes or text mints through this and inherits both obligations.
// CONSTRUCT: SealedProduct EscapedKey
pub struct EscapedKey {
    tag: u8,
    encoded: Vec<u8>,
}

// CONSTRUCT: ImplBlock EscapedKey
impl EscapedKey {
    #[verifier::type_invariant]
    closed spec fn wf_key(self) -> bool {
        self.tag >= TAG_MIN
        && shape_of(self.tag) == Some(KeyShape::Escaped)
        && exists|s: Seq<u8>| self.encoded@ =~= enc_bytes(s)
    }

    /// Mint from raw content. The content is arbitrary: every byte sequence has
    /// an escaped form, so this cannot fail.
    pub fn mint(tag: u8, content: &[u8]) -> (r: EscapedKey)
        requires tag >= TAG_MIN, shape_of(tag) == Some(KeyShape::Escaped)
        ensures r.key() =~= enc_bytes(content@), r.tag() == tag
    {
        let encoded = escape(content);
        proof { assert(exists|s: Seq<u8>| encoded@ =~= enc_bytes(s)) by { assert(encoded@ =~= enc_bytes(content@)); } }
        EscapedKey { tag, encoded }
    }
}

impl KindKey for EscapedKey {
    closed spec fn tag(self) -> u8 { self.tag }
    closed spec fn key(self) -> Seq<u8> { self.encoded@ }
    closed spec fn wf(self) -> bool { self.wf_key() }

    proof fn law_tag(self) { assert(!is_seq_tag(self.tag)); }

    proof fn law_key(self) {
        let s = choose|s: Seq<u8>| self.encoded@ =~= enc_bytes(s);
        lemma_esc_end_of_enc_bytes(s);
        assert(self.encoded@ =~= enc_bytes(s));
    }

    fn tag_byte(&self) -> (t: u8) { proof { use_type_invariant(self); } self.tag }

    fn emit(&self) -> (r: Vec<u8>) { self.encoded.clone() }
}

/// A fixed-width key. Prefix-free because the width is constant, so the
/// obligations fall out of the tag table with nothing left to prove.
// CONSTRUCT: SealedProduct FixedKey
pub struct FixedKey {
    tag: u8,
    bytes: Vec<u8>,
}

// CONSTRUCT: ImplBlock FixedKey
impl FixedKey {
    #[verifier::type_invariant]
    closed spec fn wf_key(self) -> bool {
        self.tag >= TAG_MIN && shape_of(self.tag) == Some(KeyShape::Fixed(self.bytes@.len() as nat))
    }

    /// Mint at a tag whose declared width matches these bytes. A width mismatch
    /// does not fail at run time; it fails to verify.
    pub fn mint(tag: u8, bytes: Vec<u8>) -> (r: FixedKey)
        requires
            tag >= TAG_MIN,
            shape_of(tag) == Some(KeyShape::Fixed(bytes@.len() as nat)),
        ensures r.key() =~= bytes@, r.tag() == tag
    { FixedKey { tag, bytes } }
}

impl KindKey for FixedKey {
    closed spec fn tag(self) -> u8 { self.tag }
    closed spec fn key(self) -> Seq<u8> { self.bytes@ }
    closed spec fn wf(self) -> bool { self.wf_key() }

    proof fn law_tag(self) { assert(!is_seq_tag(self.tag)); }

    proof fn law_key(self) {}

    fn tag_byte(&self) -> (t: u8) { proof { use_type_invariant(self); } self.tag }

    fn emit(&self) -> (r: Vec<u8>) { self.bytes.clone() }
}

/// A class-led key: the first byte selects the remaining width. Num mints here.
// CONSTRUCT: SealedProduct ClassLedKey
pub struct ClassLedKey {
    tag: u8,
    bytes: Vec<u8>,
}

// CONSTRUCT: ImplBlock ClassLedKey
impl ClassLedKey {
    #[verifier::type_invariant]
    closed spec fn wf_key(self) -> bool {
        self.tag >= TAG_MIN
        && shape_of(self.tag) == Some(KeyShape::ClassLed)
        && self.bytes@.len() > 0
        && class_led_width(self.bytes@[0]) == self.bytes@.len()
    }

    /// Mint from a class-led byte string. A width that disagrees with the class
    /// byte does not fail at run time; it fails to verify.
    pub fn mint(tag: u8, bytes: Vec<u8>) -> (r: ClassLedKey)
        requires
            tag >= TAG_MIN,
            shape_of(tag) == Some(KeyShape::ClassLed),
            bytes@.len() > 0,
            class_led_width(bytes@[0]) == bytes@.len(),
        ensures r.key() =~= bytes@, r.tag() == tag
    { ClassLedKey { tag, bytes } }
}

impl KindKey for ClassLedKey {
    closed spec fn tag(self) -> u8 { self.tag }
    closed spec fn key(self) -> Seq<u8> { self.bytes@ }
    closed spec fn wf(self) -> bool { self.wf_key() }
    proof fn law_tag(self) { assert(!is_seq_tag(self.tag)); }
    proof fn law_key(self) {}
    fn tag_byte(&self) -> (t: u8) { proof { use_type_invariant(self); } self.tag }
    fn emit(&self) -> (r: Vec<u8>) { self.bytes.clone() }
}

/// One flags byte, then escaped content. Regex mints here.
// CONSTRUCT: SealedProduct EscapedFlagsKey
pub struct EscapedFlagsKey {
    tag: u8,
    bytes: Vec<u8>,
}

// CONSTRUCT: ImplBlock EscapedFlagsKey
impl EscapedFlagsKey {
    #[verifier::type_invariant]
    closed spec fn wf_key(self) -> bool {
        self.tag >= TAG_MIN
        && shape_of(self.tag) == Some(KeyShape::EscapedThenFlags)
        && self.bytes@.len() > 0
        && exists|c: Seq<u8>| self.bytes@ =~= enc_bytes(c) + seq![self.bytes@.last()]
    }

    /// Mint from pattern and flags. The pattern sorts first because a regex is
    /// identified by its pattern; flags break ties.
    pub fn mint(tag: u8, content: &[u8], flags: u8) -> (r: EscapedFlagsKey)
        requires tag >= TAG_MIN, shape_of(tag) == Some(KeyShape::EscapedThenFlags)
        ensures r.key() =~= enc_bytes(content@) + seq![flags], r.tag() == tag
    {
        let mut bytes = escape(content);
        bytes.push(flags);
        proof {
            assert(bytes@.last() == flags);
            assert(bytes@ =~= enc_bytes(content@) + seq![flags]);
            assert(exists|c: Seq<u8>| bytes@ =~= enc_bytes(c) + seq![bytes@.last()]);
        }
        EscapedFlagsKey { tag, bytes }
    }
}

impl KindKey for EscapedFlagsKey {
    closed spec fn tag(self) -> u8 { self.tag }
    closed spec fn key(self) -> Seq<u8> { self.bytes@ }
    closed spec fn wf(self) -> bool { self.wf_key() }
    proof fn law_tag(self) { assert(!is_seq_tag(self.tag)); }
    proof fn law_key(self) {
        let c = choose|c: Seq<u8>| self.bytes@ =~= enc_bytes(c) + seq![self.bytes@.last()];
        lemma_esc_end_of_enc_bytes(c);
        lemma_prefix_of_self_plus(enc_bytes(c), seq![self.bytes@.last()]);
        lemma_esc_end_local(enc_bytes(c), self.bytes@);
    }
    fn tag_byte(&self) -> (t: u8) { proof { use_type_invariant(self); } self.tag }
    fn emit(&self) -> (r: Vec<u8>) { self.bytes.clone() }
}

/// The bounded-interval grammar: `0x01` for the one empty value, or `0x02`
/// followed by two ends, each `0x01` (unbounded) or `0x02` plus eight bytes.
// CONSTRUCT: SealedProduct IntervalKey
pub struct IntervalKey {
    tag: u8,
    bytes: Vec<u8>,
}

// CONSTRUCT: ImplBlock IntervalKey
impl IntervalKey {
    #[verifier::type_invariant]
    closed spec fn wf_key(self) -> bool {
        self.tag >= TAG_MIN
        && shape_of(self.tag) == Some(KeyShape::IntervalShape)
        && interval_end(self.bytes@) == self.bytes@.len()
    }

    /// The one empty interval.
    pub fn mint_empty(tag: u8) -> (r: IntervalKey)
        requires tag >= TAG_MIN, shape_of(tag) == Some(KeyShape::IntervalShape)
        ensures r.key() =~= seq![0x01u8], r.tag() == tag
    {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(0x01u8);
        proof { assert(interval_end(bytes@) == 1); }
        IntervalKey { tag, bytes }
    }

    /// A bounded interval. Each end is `None` for unbounded, or eight bytes of
    /// the ascending timestamp key.
    /// A bounded interval. `None` at the lower end is negative infinity and
    /// sorts below every instant; `None` at the upper end is positive infinity
    /// and sorts above every instant. The two ends therefore carry different
    /// marker tables — one unbounded shape is the least element of its axis and
    /// the other is the greatest.
    pub fn mint_bounded(tag: u8, lo: Option<[u8; 8]>, hi: Option<[u8; 8]>) -> (r: IntervalKey)
        requires tag >= TAG_MIN, shape_of(tag) == Some(KeyShape::IntervalShape)
        ensures r.tag() == tag
    {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(IV_BOUNDED);
        push_bound(&mut bytes, lo, LO_UNBOUNDED, LO_AT);
        let ghost after_lo = bytes@;
        push_bound(&mut bytes, hi, HI_UNBOUNDED, HI_AT);
        proof {
            assert(bytes@[0] == IV_BOUNDED);
            assert(after_lo =~= bytes@.take(after_lo.len() as int));
            assert(bytes@[1] == after_lo[1]);
            assert(lo_bound_end(bytes@, 1) == after_lo.len());
            assert(bytes@[after_lo.len() as int] == HI_UNBOUNDED
                || bytes@[after_lo.len() as int] == HI_AT);
            assert(hi_bound_end(bytes@, after_lo.len() as int) == bytes@.len());
        }
        IntervalKey { tag, bytes }
    }
}

/// Append one interval end. Unboundedness is a marker, never a sentinel
/// instant, and the caller supplies the marker pair for its axis.
fn push_bound(out: &mut Vec<u8>, end: Option<[u8; 8]>, unbounded: u8, at: u8)
    ensures
        match end {
            None => final(out)@ =~= old(out)@ + seq![unbounded],
            Some(t) => final(out)@ =~= (old(out)@ + seq![at]) + t@,
        },
{
    match end {
        None => { out.push(unbounded); }
        Some(t) => {
            out.push(at);
            let mut i: usize = 0;
            let ghost base = out@;
            while i < 8
                invariant 0 <= i <= 8, out@ =~= base + t@.take(i as int),
                decreases 8 - i
            {
                out.push(t[i]);
                proof { assert(t@.take(i + 1) =~= t@.take(i as int).push(t@[i as int])); }
                i = i + 1;
            }
            proof { assert(t@.take(8int) =~= t@); }
        }
    }
}

impl KindKey for IntervalKey {
    closed spec fn tag(self) -> u8 { self.tag }
    closed spec fn key(self) -> Seq<u8> { self.bytes@ }
    closed spec fn wf(self) -> bool { self.wf_key() }
    proof fn law_tag(self) { assert(!is_seq_tag(self.tag)); }
    proof fn law_key(self) {}
    fn tag_byte(&self) -> (t: u8) { proof { use_type_invariant(self); } self.tag }
    fn emit(&self) -> (r: Vec<u8>) { self.bytes.clone() }
}

// ================================ the scanner ================================
//
// The grammar above is a specification; these are the executable readers proven
// against it. `theorem_prefix_code` already establishes that no byte string has
// two readings, so a scanner that agrees with `scan` is the only scanner there
// can be.

/// How many bytes the escaped payload at the front of `p` occupies, or `None`
/// if it does not hold a complete one. Total over every byte sequence.
pub fn scan_escaped(p: &[u8]) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => esc_end(p@) == n as int && n <= p.len(),
            None => esc_end(p@) < 0,
        },
{
    let mut i: usize = 0;
    proof { assert(p@.skip(0int) =~= p@); }
    while i < p.len()
        invariant
            0 <= i <= p@.len(),
            esc_end(p@) == if esc_end(p@.skip(i as int)) < 0 { -1int }
                           else { i + esc_end(p@.skip(i as int)) },
        decreases p.len() - i
    {
        proof { assert(p@.skip(i as int)[0] == p@[i as int]); }
        if p[i] == 0x00 {
            if i + 1 >= p.len() {
                proof { assert(p@.skip(i as int).len() < 2); }
                return None;
            }
            proof { assert(p@.skip(i as int)[1] == p@[i as int + 1]); }
            if p[i + 1] == 0x00 {
                proof { assert(esc_end(p@.skip(i as int)) == 2); }
                return Some(i + 2);
            }
            if p[i + 1] != 0xFF {
                return None;
            }
            proof { assert(p@.skip(i as int).skip(2) =~= p@.skip(i as int + 2)); }
            i = i + 2;
        } else {
            proof { assert(p@.skip(i as int).skip(1) =~= p@.skip(i as int + 1)); }
            i = i + 1;
        }
    }
    proof { assert(p@.skip(i as int).len() == 0); }
    None
}

/// Bytes the number at the front of `p` occupies. The class byte selects it.
pub fn scan_num(p: &[u8]) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => num_end(p@) == n as int && n <= p.len(),
            None => num_end(p@) < 0,
        },
{
    if p.len() == 0 {
        return None;
    }
    let c = p[0];
    let w: usize = if c == 0x02 {
        2
    } else if c == 0x01 || c == 0x03 {
        13
    } else {
        return None;
    };
    if p.len() < w { None } else { Some(w) }
}

/// Nesting a reader will descend. Deeper input is refused, never followed: the
/// scanners are recursive descent and an unbounded one is a stack overflow a
/// writer chooses. Refusing is sound in one direction only, which is the
/// direction that matters — a scanner may reject, it may never accept a reading
/// the grammar does not give.
pub const MAX_DEPTH: u32 = 128;

/// Bytes the vector payload at the front of `p` occupies: a `u32` big-endian
/// component count, then that many number keys.
/// Bytes the interval payload at the front of `p` occupies.
pub fn scan_interval(p: &[u8]) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => interval_end(p@) == n as int && n <= p.len(),
            None => interval_end(p@) < 0,
        },
{
    if p.len() == 0 {
        return None;
    }
    if p[0] == IV_EMPTY {
        return Some(1);
    }
    if p[0] != IV_BOUNDED {
        return None;
    }
    let a = match lo_end(p, 1) {
        Some(n) => n,
        None => return None,
    };
    hi_end(p, a)
}

/// The lower end. Unbounded is negative infinity, below every instant.
fn lo_end(p: &[u8], at: usize) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => lo_bound_end(p@, at as int) == n as int && n <= p.len(),
            None => lo_bound_end(p@, at as int) < 0,
        },
{
    if at >= p.len() {
        return None;
    }
    if p[at] == LO_UNBOUNDED {
        Some(at + 1)
    } else if p[at] == LO_AT {
        if p.len() < 9 || at > p.len() - 9 { None } else { Some(at + 9) }
    } else {
        None
    }
}

/// The upper end. Unbounded is positive infinity, above every instant.
fn hi_end(p: &[u8], at: usize) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => hi_bound_end(p@, at as int) == n as int && n <= p.len(),
            None => hi_bound_end(p@, at as int) < 0,
        },
{
    if at >= p.len() {
        return None;
    }
    if p[at] == HI_AT {
        if p.len() < 9 || at > p.len() - 9 { None } else { Some(at + 9) }
    } else if p[at] == HI_UNBOUNDED {
        Some(at + 1)
    } else {
        None
    }
}

/// Bytes the complete encoding at the front of `p` occupies, or `None` if `p`
/// does not open with one. Total over every byte sequence: no panic, no
/// unbounded read, and by [`theorem_prefix_code`] no second reading.
pub fn scan_value(p: &[u8], depth: u32) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => scan(p@) == n as int && n <= p.len(),
            None => true,
        },
    decreases p.len(), 2int
{
    if p.len() == 0 || depth >= MAX_DEPTH {
        return None;
    }
    let t = p[0];
    if t < TAG_MIN {
        return None;
    }
    let body = vstd::slice::slice_subrange(p, 1, p.len());
    proof { assert(body@ =~= p@.skip(1)); }

    let payload: Option<usize> = if t == 0x05 {
        Some(0)
    } else if t == 0x08 || t == 0x09 {
        Some(0)
    } else if t == 0x10 {
        scan_num(body)
    } else if t == 0x18 || t == 0x20 {
        scan_escaped(body)
    } else if t == 0x28 {
        if body.len() >= 16 { Some(16) } else { None }
    } else if t == 0x30 {
        match scan_escaped(body) {
            Some(n) => if n == 0 || n >= body.len() { None } else { Some(n + 1) },
            None => None,
        }
    } else if t == 0x40 {
        if body.len() >= 32 { Some(32) } else { None }
    } else if t == 0x48 || t == 0x50 {
        return match scan_seq(body, depth + 1) {
            Some(n) => Some(1 + n),
            None => None,
        };
    } else if t == 0x58 {
        if body.len() >= 9 { Some(9) } else { None }
    } else if t == 0x60 {
        scan_interval(body)
    } else if t == 0x68 {
        if body.len() >= 8 { Some(8) } else { None }
    } else {
        None
    };

    match payload {
        Some(n) => Some(1 + n),
        None => None,
    }
}

/// Bytes the sequence body at the front of `p` occupies, terminator included.
pub fn scan_seq(p: &[u8], depth: u32) -> (r: Option<usize>)
    ensures
        match r {
            Some(n) => scan_row_bytes(p@) == n as int && n <= p.len(),
            None => true,
        },
    decreases p.len(), 3int
{
    if p.len() == 0 || depth >= MAX_DEPTH {
        return None;
    }
    if p[0] == STRUCT_END {
        return Some(1);
    }
    let j = match scan_value(p, depth) {
        Some(n) => n,
        None => return None,
    };
    if j == 0 || j > p.len() {
        return None;
    }
    let rest = vstd::slice::slice_subrange(p, j, p.len());
    proof { assert(rest@ =~= p@.skip(j as int)); }
    match scan_seq(rest, depth) {
        Some(n) => Some(j + n),
        None => None,
    }
}

/// Escape a variable-length payload into the order-preserving, self-delimiting
/// form. A kind with variable-length content builds its key with this and
/// discharges [`KindKey::law_key`] from [`lemma_bytes_order`] and
/// [`lemma_bytes_prefix_free`].
// CONSTRUCT: Derivation escape
pub fn escape(s: &[u8]) -> (r: Vec<u8>)
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
        if s[i] == 0 {
            out.push(0u8);
            out.push(0xFFu8);
        } else {
            out.push(s[i]);
        }
        i = i + 1;
    }
    out.push(0u8);
    out.push(0u8);
    proof { assert(s@.take(s.len() as int) =~= s@); }
    out
}

} // verus!
