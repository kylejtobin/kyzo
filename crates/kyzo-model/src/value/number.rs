/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! `Num`: the unified sortable int/float space (the `Num` tag's inline realization).
//!
//! ## The numeric identity law (format v1, ruled before any byte)
//!
//! Seats: **14a** (one law + identity-first float divergence), **98**
//! (future Decimal/BigInt tag encoding — not this layout).
//!
//! The domain is `i64 ∪ f64` under **one** top-level tag, totally ordered
//! by **exact real value**, with a representation tie-break:
//!
//! - Order: real-number order, computed exactly (never through a lossy
//!   cast) — every integer interleaves correctly with every float,
//!   including beyond 2^53 where floats cannot represent them.
//! - Identity is representation-faithful: `Int(1)` and `Float(1.0)` are
//!   *adjacent, not equal* — equal reals order `Int < Float`, uniformly,
//!   both signs. (Unifying them would make round-trip lossy: aggregates
//!   producing `2.0` must not come back as `2`.)
//! - **Identity-first (law, not a defect):** `-0.0` normalizes to `+0.0`
//!   at construction; all NaN bit patterns collapse to one canonical NaN
//!   (`Float`, equal to itself, **greatest** — above `+∞`). Float order
//!   authority is IEEE 754-2019 totalOrder; Kyzo’s ruled divergence from
//!   strict totalOrder *payload fidelity* is this collapse — **prior art
//!   matching CockroachDB/TiDB** (decisions.md seat 14a, locked again in
//!   seat 98). Do **not** “fix” toward preserving distinct NaN payloads
//!   or signed zero as distinct stored identities: that splits equal
//!   things under dedup forever.
//! - `±∞` order as the finite extremes' neighbors.
//!
//! Consequence: equivalence = dedup identity = code identity, and numeric
//! *order* crosses representations while numeric *identity* does not.
//!
//! Two durable laws riding on this identity:
//! - `Int(1) != Float(1.0)` is **query-layer semantics forever**, not an
//!   encoding detail — the expression layer's oracle differentials verify
//!   that the semantics agree across all consumers.
//! - The v1 numeric domain is **closed**: exactly `i64 ∪ f64`. This
//!   fixed-width key is permanent. Decimal / BigInt, when they earn Tag
//!   membership, are **new kinds** under seat 98 — SQLite4/CockroachDB
//!   `E(exp)` + base-100 self-terminating-mantissa (ELEN §7 production
//!   form) — **never** an extension or widen of this `Num` layout.
//!   Named blocker until then: those Tag variants are not in the Tag
//!   enum yet (research-open encode; do not invent a Decimal type here).
//!
//! ## The order-preserving key (format v1)
//!
//! `[class][exponent 2B][fraction 9B][repr]`, where class is `NEG=0x01 <
//! ZERO=0x02 < POS=0x03 < NAN=0x04` (zero: `[0x02][repr]`; NaN:
//! `[0x04][0x01]`). A nonzero finite magnitude is written normalized as
//! `f × 2^E` with `f ∈ [0.5, 1)`: the exponent as `E + 1080` big-endian
//! (covering subnormal 2^-1074 through 2^1024 and every i64), the
//! fraction as 72 big-endian bits with the leading 1 at the top (64 bits
//! hold any i64 exactly, 53 any f64 significand). `±∞` is the sentinel
//! `exp=0xFFFF, fraction=0xFF…`. Negative keys complement exponent and
//! fraction bytes so order reverses; the trailing repr byte (`0=Int`,
//! `1=Float`) is never complemented — the tie-break is type order, not
//! value order. Lexicographic byte order of keys equals the semantic
//! order above; the law is property-tested against an independent exact
//! comparator, both directions.

use std::cmp::Ordering;
use std::num::NonZeroU64;

/// Repr tie-break bytes.
const REPR_INT: u8 = 0x00;
const REPR_FLOAT: u8 = 0x01;

/// Which representation a number was written as, as the tie-break between two
/// equal reals.
///
/// ORDER_LAW: `Int < Float`, which is the order of the bytes they encode to
/// (`0x00 < 0x01`). The tie-break is type order, not value order: it separates
/// `1` from `1.0` in storage, and says nothing about which is the larger number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ReprTag {
    Int,
    Float,
}

/// The eleven payload bytes of a magnitude: two of exponent, nine of fraction.

const MAG_BYTES: usize = 11;

/// Exponent offset: a finite `E` runs from -1073 to 1024, and biased by this
/// the whole range is [7, 2104], which is below `0xFFFF`.
const EXP_OFFSET: u32 = 1080;

/// Bits of fraction a magnitude carries.
const FRAC_BITS: u32 = 72;

/// How far above zero a number is, and nothing about which side of zero.
///
/// ORDER_LAW: `Finite < Infinite`, from `0xFFFF` being above every biased
/// exponent a finite magnitude carries.
#[derive(Clone, Copy, Debug)]
enum Mag {
    /// `significand × 2^(scale - EXP_OFFSET)`, biased so the field is unsigned.
    Finite(NonZeroU64, u32),
    Infinite,
}

impl Mag {
    /// The eleven payload bytes: biased exponent, then the fraction.
    fn bytes(self) -> [u8; MAG_BYTES] {
        let packed: u128 = match self {
            Mag::Finite(significand, biased_scale) => {
                let bits = significand.ilog2() + 1;
                let exponent = bits + biased_scale;
                (u128::from(exponent) << FRAC_BITS)
                    | (u128::from(significand.get()) << (FRAC_BITS - bits))
            }
            Mag::Infinite => (u128::from(u16::MAX) << FRAC_BITS) | ((1u128 << FRAC_BITS) - 1),
        };
        let be = packed.to_be_bytes();
        std::array::from_fn(|i| be[i + (16 - MAG_BYTES)])
    }
}

/// The eleven payload bytes of a magnitude, oriented so that `derive(Ord)` on
/// the class that holds them is that class's order.

///
/// ORDER_LAW: `[u8; MAG_BYTES]`'s own `Ord`, which is `memcmp`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Payload([u8; MAG_BYTES]);

/// A number in key form: which of the four classes it falls in, and the payload
/// that class carries.
///
/// The class is not a field. The variant *is* the class, so a magnitude cannot
/// be filed under the wrong sign — there is no byte to set incorrectly. The four
/// variants are the four branches of `num_table!()` in
/// [`crate::value::canonical`], which owns the selector bytes `0x01..=0x04`;
/// this type names them and nothing here repeats them.
///
/// `Nan` carries no payload. An integer is never NaN, so the representation byte
/// under that class has exactly one legal value, and a payload with one legal
/// value is a constant rather than a field. The grammar still writes its byte.
///
/// ORDER_LAW: declaration order across variants — `Negative < Zero < Positive <
/// Nan` — then the payload's own order. This is not *matched to* the encoded
/// order, it *is* the encoded order: the payloads are the bytes canonical
/// writes, so the derived `Ord` compares exactly what a `memcmp` of the encoding
/// compares. `key_order_is_byte_order` holds the variant order against the
/// selector bytes, which are the one part this type does not carry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Real {
    /// A magnitude, complemented — which is what being negative is. XOR
    /// reverses lexicographic order, so `derive(Ord)` on these bytes gives the
    /// backwards order directly; there is no hand-written `.reverse()` and no
    /// `Complement` wrapper to hold one.
    Negative(Payload),
    /// No magnitude at all.
    Zero,
    /// A magnitude.
    Positive(Payload),
    /// Not a number, and above every number.
    Nan,
}

impl Real {
    /// The complement is the class: applied here and nowhere else.
    fn negative(m: Mag) -> Real {
        Real::Negative(Payload(m.bytes().map(|b| !b)))
    }

    fn positive(m: Mag) -> Real {
        Real::Positive(Payload(m.bytes()))
    }
}

/// A number in key form: the real it names, then how it was written.
///
/// The two are separate fields because the two orders this engine needs differ
/// in exactly one of them. Storage order is the pair; query-semantic numeric
/// order is [`Real`] alone. Both are `derive`d — the numeric order does not
/// compute the storage order and then remove the tie-break, it never adds it.
///
/// That is why `1` and `1.0` need no special case anywhere. Normalization
/// already gives them the same [`Real`] (exponent 1081, fraction 2^71), so
/// `Real`'s own `Ord` answers `Equal` with nothing written to make it.
///
/// ORDER_LAW: field order — `real`, then `repr`. That is the order of the bytes:
/// canonical writes the class selector and magnitude first and the
/// representation byte last, so the derived `Ord` compares exactly what a
/// `memcmp` of the encoding compares. The four [`Real`] variants are the four
/// branches of `num_table!()` in [`crate::value::canonical`], which owns the
/// selector bytes `0x01..=0x04`; this type names them and nothing here repeats
/// them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct NumKey {
    real: Real,
    repr: ReprTag,
}

/// One canonical NaN bit pattern (positive quiet NaN).
const CANON_NAN_BITS: u64 = 0x7FF8_0000_0000_0000;

/// A number of the unified domain: exactly an `i64` or an `f64`, held in
/// normalized identity form (no `-0.0`, one NaN). Construct through
/// [`Num::int`] / [`Num::float`]; `Ord` is the **storage** law (exact real
/// order, `Int < Float` on equal reals, NaN greatest) — lawful as a trait
/// here because `Num` is fully inline: no deref, no context. Query-semantic
/// numeric order (ties equal: `1 == 1.0`) lives on [`NumericOrd`], never
/// as a second method on this type.
#[derive(Clone, Copy, Debug)]
pub struct Num(Repr);

/// The representation a [`Num`] holds: exactly an `i64` or an `f64`.
///
/// Public for pattern matching, and that costs nothing: `Num`'s field is
/// private and there is no constructor from this type, so the identity law
/// (`-0.0` collapsed, one NaN) cannot be bypassed by naming a variant. There
/// used to be a second copy of this enum, `NumRepr`, existing only to be the
/// public one — the same constructor list twice with an identity mapping
/// between them.
#[derive(Clone, Copy, Debug)]
pub enum Repr {
    Int(i64),
    Float(f64),
}

impl Num {
    pub fn int(v: i64) -> Num {
        Num(Repr::Int(v))
    }

    /// Construct a float under the identity-first law (seats 14a / 98):
    /// `-0.0 → +0.0`, any NaN → the canonical NaN. Not payload-faithful
    /// IEEE totalOrder — Cockroach/TiDB prior art; do not "restore" distinct
    /// NaN payloads or signed zero.
    pub fn float(v: f64) -> Num {
        if v.is_nan() {
            return Num(Repr::Float(f64::from_bits(CANON_NAN_BITS)));
        }
        if v == 0.0 {
            return Num(Repr::Float(0.0));
        }
        Num(Repr::Float(v))
    }

    /// The numeric value as f64: ints promote by IEEE sitofp. A NUMERIC read
    /// for math kernels, never an identity claim (beyond 2^53 the conversion
    /// rounds).
    pub fn to_f64(self) -> f64 {
        match self.0 {
            Repr::Int(i) => i64_to_f64(i),
            Repr::Float(f) => f,
        }
    }

    /// The read-only representation view: pattern-matching ergonomics
    /// WITHOUT construction authority — `Repr` cannot be turned back
    /// into a `Num` except through the normalizing constructors, so the
    /// identity law (`-0.0` collapsed, one NaN) cannot be bypassed by a
    /// public variant.
    pub fn repr(self) -> Repr {
        self.0
    }

    pub fn as_int(self) -> Option<i64> {
        match self.0 {
            Repr::Int(v) => Some(v),
            Repr::Float(_) => None,
        }
    }

    /// The integer VALUE via numeric coercion: an int, or an integral float
    /// inside i64's exact range. This is DISTINCT from [`Num::as_int`],
    /// which reads only the `Int` representation — coercion (e.g. a `3.0`
    /// literal written into an `Int` column) goes through here.
    ///
    /// The bound is the exact power of two, not a rounded `i64::MAX`
    /// float: the true max (2^63 - 1) is not exactly representable in f64,
    /// so promoting `i64::MAX` to f64 rounds UP to 2^63 and would admit
    /// 2^63 itself — one past the boundary, which then saturates to
    /// `i64::MAX` on conversion, silently fabricating a different index key.
    pub fn to_int_coerced(self) -> Option<i64> {
        match self.0 {
            Repr::Int(v) => Some(v),
        }
    }

    pub fn as_float(self) -> Option<f64> {
        match self.0 {
            Repr::Float(v) => Some(v),
            Repr::Int(_) => None,
        }
    }

    fn repr_tag(self) -> ReprTag {
        match self.0 {
            Repr::Int(_) => ReprTag::Int,
            Repr::Float(_) => ReprTag::Float,
        }
    }

    /// This number in key form.
    ///
    /// Total: every `Num` has a key, so there is nothing here to refuse.
    /// Produces the payload; the class selector and the frame are
    /// [`crate::value::canonical`]'s, which is why no byte of either appears
    /// here. `Num::encode_key` used to write both, so the tag bytes existed in
    /// two files that had to agree.
    ///
    /// The three finite forms — an integer, a normal double, a subnormal double
    /// — are one derivation, not three. Each is `significand × 2^scale` for some
    /// nonzero significand, which is [`Mag::Finite`]; the arms below differ only
    /// in which significand and scale they name, and the normalizing shift and
    /// the exponent bias are written once, in [`Mag::bytes`].
    ///
    /// Zero is not tested for. It is the significand being zero, so it arrives
    /// as the `None` arm of the same `NonZeroU64` that the derivation needs —
    /// which is also why [`Real::Zero`] carries no exponent and no fraction.
    pub fn key(self) -> NumKey {
        NumKey {
            real: self.real(),
            repr: self.repr_tag(),
        }
    }

}


impl PartialEq for Num {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Num {}

impl PartialOrd for Num {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Num {
    /// ORDER_LAW: exact real order, `Int < Float` on equal reals, NaN greatest.
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// Exact real-value order for query/expression semantics.
///
/// Law: real-number order with ties EQUAL — `Int(1)` and `Float(1.0)`
/// compare `Equal` here. Distinct from [`Num`]'s storage `Ord`, which
/// places `Int < Float` on equal reals. Two total orders = two types;
/// expression compare/eq/min/max must go through this newtype, never
/// through a second method on [`Num`].
///
/// Private field: the only mint is [`NumericOrd::of`].
#[derive(Clone, Copy, Debug)]
pub struct NumericOrd(Num);

impl NumericOrd {
    /// Wrap a [`Num`] for query-semantic numeric order.
    #[inline]
    pub const fn of(n: Num) -> NumericOrd {
        NumericOrd(n)
    }

    /// The wrapped number (read-only; construction stays at [`of`]).
    #[inline]
    pub const fn get(self) -> Num {
        self.0
    }
}

impl Ord for NumericOrd {
    /// ORDER_LAW: [`Real`] alone, so equal reals are `Equal` whatever they were
    /// written as.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.key().real.cmp(&other.0.key().real)
    }
}

impl PartialEq for NumericOrd {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for NumericOrd {}

impl PartialOrd for NumericOrd {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Bit-exact IEEE `i64 → f64` (sitofp), without a numeric `as` cast.
fn i64_to_f64(n: i64) -> f64 {
    if let Ok(v) = i32::try_from(n) {
        return f64::from(v);
    }
    let neg = n < 0;
    let abs = n.unsigned_abs();
    let f = u64_to_f64(abs);
    if neg { -f } else { f }
}

/// Bit-exact IEEE `u64 → f64` with round-to-nearest-even.
fn u64_to_f64(n: u64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let lz = n.leading_zeros();
    let msb = 63 - lz;
    if msb < 52 {
        let lo = super::convert::u32_from_u64_low(n);
        let hi = super::convert::u32_from_u64_low(n >> 32);
        return f64::from(hi).mul_add(4294967296.0, f64::from(lo));
    }
    let shift = msb - 52;
    let significand = n >> shift;
    let round_bit = if shift >= 1 {
        (n >> (shift - 1)) & 1
    } else {
        0
    };
    let sticky = if shift >= 2 {
        n & ((1u64 << (shift - 1)) - 1)
    } else {
        0
    };
    let mut mant = significand;
    if round_bit == 1 && (sticky != 0 || (mant & 1) == 1) {
        mant += 1;
    }
    let (final_exp_add, final_mant) = if mant == (1u64 << 53) {
        (1u32, 1u64 << 52)
    } else {
        (0u32, mant)
    };
    let exp = u64::from(msb + final_exp_add) + 1023;
    let frac = final_mant & ((1u64 << 52) - 1);
    f64::from_bits((exp << 52) | frac)
}

impl std::hash::Hash for Num {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self.0 {
            Repr::Int(v) => {
                state.write_u8(REPR_INT);
                state.write_i64(v);
            }
            Repr::Float(v) => {
                state.write_u8(REPR_FLOAT);
                state.write_u64(v.to_bits());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use miette::{Result, miette};

    use super::*;

    // ---- GUARDIAN ONE-LAW HUNT: independent true-numeric-order oracle ----
    // The edge-corpus one-law test checks byte order == Num::cmp, and its
    // "semantic" leg delegates to Num::cmp -- so nothing independently checks
    // Num::cmp against TRUE numeric order. encode_key AND Num::cmp both derive
    // from sign_magnitude(), so a magnitude bug at the int/float boundary or a
    // subnormal would agree across byte-order, Num::cmp, and the semantic leg
    // and stay green. This oracle computes the storage order from exact reals
    // WITHOUT sign_magnitude and drives the boundary cases the corpus omits.
    #[derive(Clone, Copy, Debug)]
    enum HuntV {
        I(i64),
        F(f64),
    }

    fn hunt_num(v: HuntV) -> Num {
        match v {
            HuntV::I(i) => Num::int(i),
            HuntV::F(f) => Num::float(f),
        }
    }

    /// The bytes canonical writes for a key: selector, then payload.
    ///
    /// The selectors are restated here on purpose. `NumKey`'s `Ord` claims to be
    /// the encoded order; a test that took the selectors from the same place the
    /// encoder does could not catch that claim being false. This is the oracle,
    /// so it says independently what the bytes are, and every order law below
    /// runs against it rather than against another derivation.
    fn key_bytes(n: Num) -> Vec<u8> {
        let k = n.key();
        // Restated, never read back from `ReprTag`: an oracle that asks the
        // encoder what the tie-break byte is cannot catch the encoder
        // answering wrong. Same reason the four selectors are literals here.
        let repr = match k.repr {
            ReprTag::Int => 0x00,
            ReprTag::Float => 0x01,
        };
        let mut v = Vec::new();
        // Selector, then the payload the class carries — and the tie-break
        // last, for every class alike. It is not complemented under
        // `Negative`: the tie-break is type order, not value order, so
        // reversing it would sort `-1` and `-1.0` backwards from `1` and `1.0`.
        match k.real {
            Real::Negative(m) => {
                v.push(0x01);
                v.extend_from_slice(&m.0);
            }
            Real::Zero => v.push(0x02),
            Real::Positive(m) => {
                v.push(0x03);
                v.extend_from_slice(&m.0);
            }
            Real::Nan => v.push(0x04),
        }
        v.push(repr);
        v
    }

    fn hunt_enc(v: HuntV) -> Vec<u8> {
        key_bytes(hunt_num(v))
    }

    fn hunt_is_nan(v: HuntV) -> bool {
        matches!(v, HuntV::F(f) if f.is_nan())
    }

    /// Exact compare i64 vs (finite or infinite, non-NaN) f64.
    fn hunt_cmp_i_f(i: i64, f: f64) -> Ordering {
        if f.is_infinite() {
            return if f > 0.0 {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        if f >= 9223372036854775808.0 {
            return Ordering::Less; // f >= 2^63 > i64::MAX
        }
        if f < -9223372036854775808.0 {
            return Ordering::Greater; // f < -2^63 <= i64::MIN
        }
        let fl = f.floor();
        let fli = f64_integral_in_i64_range_to_i64(fl); // exact: fl integral, in [-2^63, 2^63)
        match i128::from(i).cmp(&i128::from(fli)) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => {
                if f == fl {
                    Ordering::Equal
                } else {
                    Ordering::Less // floor(f) < f, so i == floor < f
                }
            }
        }
    }

    /// Independent STORAGE order: exact real order, NaN greatest and equal to
    /// itself, ties broken Int < Float (REPR_INT < REPR_FLOAT). -0.0 == +0.0.
    fn hunt_true_order(a: HuntV, b: HuntV) -> Result<Ordering> {
        match (hunt_is_nan(a), hunt_is_nan(b)) {
            (true, true) => return Ok(Ordering::Equal),
            (true, false) => return Ok(Ordering::Greater),
            (false, true) => return Ok(Ordering::Less),
            (false, false) => {}
        }
        let real = match (a, b) {
            (HuntV::I(x), HuntV::I(y)) => x.cmp(&y),
            (HuntV::F(x), HuntV::F(y)) => {
                x.partial_cmp(&y).ok_or_else(|| miette!("no NaN in this arm"))?
            }
            (HuntV::I(x), HuntV::F(y)) => hunt_cmp_i_f(x, y),
            (HuntV::F(x), HuntV::I(y)) => hunt_cmp_i_f(y, x).reverse(),
        };
        if real != Ordering::Equal {
            return Ok(real);
        }
        let rank = |v: HuntV| u8::from(matches!(v, HuntV::F(_)));
        Ok(rank(a).cmp(&rank(b)))
    }

    #[test]
    fn one_law_holds_at_int_float_boundary_and_ugly_floats() -> Result<()> {
        let corpus = [
            HuntV::I(0),
            HuntV::F(0.0),
            HuntV::F(-0.0),
            HuntV::I(1),
            HuntV::F(1.0),
            HuntV::I(-1),
            HuntV::F(-1.0),
            HuntV::I(i64::MAX),
            HuntV::I(i64::MIN),
            HuntV::F(9223372036854775808.0),  // 2^63 == i64::MAX + 1
            HuntV::F(9223372036854774784.0),  // largest f64 strictly below 2^63
            HuntV::F(-9223372036854775808.0), // -2^63 == i64::MIN
            HuntV::I(9007199254740993),       // 2^53 + 1 (not f64-representable)
            HuntV::F(9007199254740992.0),     // 2^53
            HuntV::F(9007199254740994.0),     // 2^53 + 2
            HuntV::F(f64::from_bits(1)),      // smallest positive subnormal
            HuntV::F(-f64::from_bits(1)),     // smallest negative subnormal
            HuntV::F(f64::MIN_POSITIVE),
            HuntV::F(1e-300),
            HuntV::F(-1e-300),
            HuntV::F(f64::NEG_INFINITY),
            HuntV::F(f64::INFINITY),
            HuntV::F(f64::NAN),
            HuntV::F(f64::MIN),
            HuntV::F(f64::MAX),
        ];
        for &a in &corpus {
            for &b in &corpus {
                let byte = hunt_enc(a).cmp(&hunt_enc(b));
                let truth = hunt_true_order(a, b)?;
                assert_eq!(
                    byte, truth,
                    "ONE-LAW VIOLATION: byte order {byte:?} != true numeric order {truth:?} for {a:?} vs {b:?}"
                );
                assert_eq!(
                    hunt_num(a).cmp(&hunt_num(b)),
                    byte,
                    "Num::cmp != byte order for {a:?} vs {b:?}"
                );
            }
        }
        Ok(())
    }

    use crate::value::test_rng::Rng;

    // ------------------------------------------------------------------
    // Independent exact comparator: the oracle. Implemented by floor
    // comparison, sharing NOTHING with the decomposition the encoder and
    // Ord use — two independent derivations of the same law, cross-checked.
    // ------------------------------------------------------------------

    fn oracle_int_float(i: i64, f: f64) -> Ordering {
        if f.is_nan() {
            return Ordering::Less; // every number < NaN
        }
        if f == f64::INFINITY {
            return Ordering::Less;
        }
        if f == f64::NEG_INFINITY {
            return Ordering::Greater;
        }
        if f >= 9_223_372_036_854_775_808.0 {
            return Ordering::Less; // f >= 2^63 > any i64
        }
        if f < -9_223_372_036_854_775_808.0 {
            return Ordering::Greater;
        }
        let fl = f.floor();
        let fi = f64_integral_in_i64_range_to_i64(fl); // exact: fl ∈ [-2^63, 2^63)
        match i.cmp(&fi) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            // i == floor(f): if f has a fraction, i < f; if equal reals,
            // the tie-break says Int < Float. Both ways: Less.
            Ordering::Equal => Ordering::Less,
        }
    }

    fn oracle_cmp(a: Num, b: Num) -> Result<Ordering> {
        Ok(match (a.0, b.0) {
            (Repr::Int(x), Repr::Int(y)) => x.cmp(&y),
            (Repr::Float(x), Repr::Float(y)) => match (x.is_nan(), y.is_nan()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => x.partial_cmp(&y).ok_or_else(|| miette!("no NaN here"))?,
            },
            (Repr::Int(x), Repr::Float(y)) => oracle_int_float(x, y),
            (Repr::Float(x), Repr::Int(y)) => oracle_int_float(y, x).reverse(),
        })
    }

    // ------------------------------------------------------------------
    // Corpus: every boundary that has ever broken a numeric encoding,
    // plus seeded randoms over the full bit space.
    // ------------------------------------------------------------------

    fn corpus() -> Vec<Num> {
        let mut c = Vec::new();
        for i in [
            0i64,
            1,
            -1,
            2,
            -2,
            9,
            10,
            i64::MAX,
            i64::MIN,
            i64::MAX - 1,
            i64::MIN + 1,
            (1i64 << 52) - 1,
            1i64 << 52,
            (1i64 << 52) + 1,
            (1i64 << 53) - 1,
            1i64 << 53,
            (1i64 << 53) + 1,
            (1i64 << 62) + 12345,
            -((1i64 << 53) + 1),
        ] {
            c.push(Num::int(i));
        }
        for f in [
            0.0f64,
            -0.0,
            1.0,
            -1.0,
            1.5,
            -1.5,
            0.5,
            -0.5,
            2.0,
            f64::MAX,
            f64::MIN,
            f64::MIN_POSITIVE,
            5e-324, // smallest subnormal
            f64::MIN_POSITIVE / 2.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            9_007_199_254_740_992.0,      // 2^53
            9_007_199_254_740_994.0,      // 2^53 + 2
            9_223_372_036_854_775_808.0,  // 2^63
            -9_223_372_036_854_775_808.0, // -2^63
            1e308,
            -1e308,
            1e-300,
            std::f64::consts::PI,
        ] {
            c.push(Num::float(f));
        }
        c
    }

    fn extend_random(c: &mut Vec<Num>, n: usize, seed: u64) {
        let mut rng = Rng(seed);
        for _ in 0..n {
            if rng.next().is_multiple_of(2) {
                c.push(Num::int(rng.next().cast_signed()));
            } else {
                c.push(Num::float(f64::from_bits(rng.next())));
            }
        }
    }

    #[test]
    fn law_semantic_order_matches_independent_oracle() -> Result<()> {
        let mut c = corpus();
        extend_random(&mut c, 400, 0xA11CE);
        for &a in &c {
            for &b in &c {
                assert_eq!(
                    a.cmp(&b),
                    oracle_cmp(a, b)?,
                    "cmp diverged from oracle for {a:?} vs {b:?}"
                );
            }
        }
        Ok(())
    }

    /// Key byte order equals semantic order on every pair.
    #[test]
    fn numeric_ord_is_value_order_with_ties_equal() {
        assert_eq!(
            NumericOrd::of(Num::int(1)).cmp(&NumericOrd::of(Num::float(1.0))),
            Ordering::Equal
        );
        assert_eq!(
            NumericOrd::of(Num::float(1.0)).cmp(&NumericOrd::of(Num::int(1))),
            Ordering::Equal
        );
        assert_eq!(NumericOrd::of(Num::int(1)), NumericOrd::of(Num::float(1.0)));
        assert_eq!(
            NumericOrd::of(Num::int(1)).cmp(&NumericOrd::of(Num::float(1.5))),
            Ordering::Less
        );
        assert_eq!(
            NumericOrd::of(Num::float(2.5)).cmp(&NumericOrd::of(Num::int(2))),
            Ordering::Greater
        );
        // Beyond 2^53: floats cannot represent the int; NOT equal.
        assert_ne!(
            NumericOrd::of(Num::int((1 << 53) + 1))
                .cmp(&NumericOrd::of(Num::float(9_007_199_254_740_992.0))),
            Ordering::Equal
        );
        // Storage keeps its tie-break; NumericOrd drops it. Both named.
        assert_eq!(Num::int(1).cmp(&Num::float(1.0)), Ordering::Less);
        // Differential vs storage over the corpus: equal reals are the
        // ONLY places the two authorities differ.
        let mut c = corpus();
        extend_random(&mut c, 300, 0xACE);
        for &a in &c {
            for &b in &c {
                let num = NumericOrd::of(a).cmp(&NumericOrd::of(b));
                let sto = a.cmp(&b);
                if num != sto {
                    assert_eq!(num, Ordering::Equal, "authorities may differ only on ties");
                }
            }
        }
    }

    /// Identity-first pin (seats 14a / 98): NaN-collapse and `-0` normalize
    /// are construction law matching Cockroach/TiDB — not a hole to fill
    /// toward strict IEEE 754-2019 totalOrder payload fidelity.
    #[test]
    fn identity_law_edges() -> Result<()> {
        // -0.0 collapses at construction (not a distinct stored identity).
        assert_eq!(Num::float(-0.0), Num::float(0.0));
        assert_eq!(key_bytes(Num::float(-0.0)), key_bytes(Num::float(0.0)));
        assert_eq!(
            Num::float(-0.0)
                .as_float()
                .ok_or_else(|| miette!("as_float"))?
                .to_bits(),
            0.0f64.to_bits()
        );
        // All NaN payloads are one canonical NaN, equal to itself, greatest.
        let weird_nan = f64::from_bits(0xFFF8_DEAD_BEEF_0001);
        assert_eq!(Num::float(weird_nan), Num::float(f64::NAN));
        assert_eq!(key_bytes(Num::float(weird_nan)), key_bytes(Num::float(f64::NAN)));
        assert!(Num::float(f64::NAN) > Num::float(f64::INFINITY));
        // Int and Float of equal real are adjacent, Int first, both signs.
        assert!(Num::int(1) < Num::float(1.0));
        assert!(Num::int(-1) < Num::float(-1.0));
        assert!(Num::int(0) < Num::float(0.0));
        assert!(Num::float(1.0) < Num::int(2));
        // Beyond 2^53: floats cannot represent every int; order stays exact.
        assert!(Num::int((1 << 53) + 1) > Num::float(9_007_199_254_740_992.0));
        assert!(Num::int(i64::MAX) < Num::float(9_223_372_036_854_775_808.0));
        assert!(Num::float(f64::INFINITY) > Num::int(i64::MAX));
        assert!(Num::float(f64::NEG_INFINITY) < Num::int(i64::MIN));
        Ok(())
    }

    /// `Num`'s order is total: `PartialOrd` never returns `None` — the
    /// IEEE NaN hole is closed at construction (one canonical NaN).
    #[test]
    fn law_num_partial_ord_is_total_no_nan_hole() {
        let mut c = corpus();
        extend_random(&mut c, 200, 0x0BAD_70E1);
        // Inject many raw NaN bit patterns; construction collapses them.
        for bits in [
            0x7FF8_0000_0000_0000u64,
            0xFFF8_0000_0000_0001,
            0x7FF0_DEAD_BEEF_0001,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            c.push(Num::float(f64::from_bits(bits)));
        }
        for &a in &c {
            for &b in &c {
                let p = a.partial_cmp(&b);
                assert!(p.is_some(), "Num PartialOrd hole (NaN?): {a:?} vs {b:?}");
                assert_eq!(p, Some(a.cmp(&b)));
            }
        }
        // Canonical NaN is greatest and equal to every other NaN mint.
        let nan = Num::float(f64::NAN);
        assert_eq!(nan.partial_cmp(&nan), Some(Ordering::Equal));
        assert_eq!(
            nan.partial_cmp(&Num::float(f64::INFINITY)),
            Some(Ordering::Greater)
        );
    }

    /// Format v1 golden vectors: these bytes are permanent. A failure here
    /// means the on-disk numeric key moved, which is forbidden.
    #[test]
    fn format_v1_golden_vectors() {
        let cases: [(Num, &str); 12] = [
            (Num::int(0), "0200"),
            (Num::float(0.0), "0201"),
            (Num::int(1), "03043980000000000000000000"),
            (Num::float(1.0), "03043980000000000000000001"),
            (Num::int(-1), "01fbc67fffffffffffffffff00"),
            (Num::float(-1.0), "01fbc67fffffffffffffffff01"),
            (Num::int(2), "03043a80000000000000000000"),
            (Num::float(0.5), "03043880000000000000000001"),
            (Num::int(i64::MAX), "030477fffffffffffffffe0000"),
            (Num::int(i64::MIN), "01fb877fffffffffffffffff00"),
            (Num::float(f64::INFINITY), "03ffffffffffffffffffffff01"),
            (Num::float(f64::NAN), "0401"),
        ];
        for (n, hex) in cases {
            let k = key_bytes(n);
            let got: String = k.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, hex, "golden vector moved for {n:?}");
        }
    }

    /// Decode totality: arbitrary bytes are Ok or a typed error, never a
    /// panic; truncations of valid keys are errors.

    /// Adversary, staged ahead of Wave 3's `as_cast` sweep on this file:
    /// `to_int_coerced` has NO other test anywhere in the tree (checked:
    /// only two non-test call sites exist). Its own doc comment names the
    /// exact bug a naive "just satisfy the meter" rewrite would reintroduce
    /// — using `i64::MAX as f64` (which rounds UP to 2^63) as the bound
    /// instead of the exact power-of-two `I64_MAX_BOUND_EXCLUSIVE` — which
    /// would wrongly ADMIT `2^63` as `Some(i64::MAX)` (silent index-key
    /// fabrication) instead of refusing it. Pinned at the exact boundary in
    /// both directions so a regression here is a coerced-value mismatch,
    /// not a vague "changed behavior": nothing about this test can pass by
    /// construction — it must observe the real return value at the exact
    /// ULP either side of 2^63.
    #[test]
    fn to_int_coerced_refuses_two_pow_63_and_admits_the_float_just_below_it() {
        let two_pow_63 = 9223372036854775808.0_f64; // exactly i64::MAX + 1
        assert_eq!(
            Num::float(two_pow_63).to_int_coerced(),
            None,
            "2^63 is one past i64::MAX and must be refused, not saturated to Some(i64::MAX)"
        );

        // The largest f64 strictly below 2^63 — an exact integer at this
        // magnitude (ULP is 2^11 here), so round() == itself and the value
        // legitimately fits i64.
        let just_below = f64::from_bits(two_pow_63.to_bits() - 1);
        assert!(just_below < two_pow_63);
        let coerced = Num::float(just_below).to_int_coerced();
        assert_eq!(
            coerced,
            Some(9223372036854774784_i64),
            "the largest representable f64 strictly below 2^63 must coerce, not refuse"
        );
        assert!(
            coerced.is_some_and(|n| n > 0),
            "must not have wrapped/saturated to a negative or zero garbage value"
        );

        // -2^63 == i64::MIN is the exact opposite boundary and must be admitted.
        assert_eq!(
            Num::float(-9223372036854775808.0).to_int_coerced(),
            Some(i64::MIN),
            "-2^63 is exactly i64::MIN and must coerce, not refuse"
        );

        // A non-integral float must never coerce, at any magnitude.
        assert_eq!(Num::float(3.5).to_int_coerced(), None);
    }
}
