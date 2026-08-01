/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! An independent statement of the format: a semantic value, its order, its
//! encoding, and its reading.
//!
//! AUTHORITY: to disagree with `canonical`. Nothing here calls it, imports from
//! it, or shares a line with it. Every constant below is written out from the
//! released format rather than read from the encoder, because a reference that
//! asks the thing under test what the answer is checks nothing.
//!
//! ORDER_LAW: [`Sem`] orders by what a value MEANS — kind first, then the
//! kind's own semantics — and never by looking at an encoding. That is the
//! whole point: [`encode`] must map this order onto lexicographic byte order,
//! and a test can only detect the failure if the two orders were defined
//! apart.
//!
//! Deliberately naive. It builds vectors, it re-scans from the front, it does
//! not share the grammar table. Slow and obviously correct beats fast and
//! agreeing for the wrong reason.

use std::cmp::Ordering;

// The released format. These are the reference's own copy; they are not
// imported, and a divergence between these and the encoder's is exactly the
// failure the differential trials exist to catch.
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

const ESC: u8 = 0x00;
const END: u8 = 0x01;
const ESC_ZERO: u8 = 0xFF;

const CLASS_NEG: u8 = 0x01;
const CLASS_ZERO: u8 = 0x02;
const CLASS_POS: u8 = 0x03;
const CLASS_NAN: u8 = 0x04;

const LO_UNBOUNDED: u8 = 0x01;
const LO_AT: u8 = 0x02;
const HI_AT: u8 = 0x02;
const HI_UNBOUNDED: u8 = 0x03;
const INTERVAL_EMPTY: u8 = 0x01;
const INTERVAL_BOUNDED: u8 = 0x02;

const MAG_BYTES: usize = 11;
const FRAC_BITS: u32 = 72;
const EXP_INFINITE: u128 = 0xFFFF;
const DIM_BYTES: usize = 4;

/// The deepest value the format admits: a leaf spends one level, and every
/// enclosing tag spends another.
pub const MAX_VALUE_DESCENT: u32 = 127;

/// A number spends a level on its class byte, above the tag's own.
const NUM_DESCENT: u32 = 2;

/// Which representation a number was written as. It breaks ties between
/// numbers of equal value and orders below nothing else.
///
/// ORDER_LAW: `Int` before `Float`, in every class, including the negative one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Repr {
    Int,
    Float,
}

impl Repr {
    fn byte(self) -> u8 {
        match self {
            Repr::Int => 0x00,
            Repr::Float => 0x01,
        }
    }
}

/// A magnitude as a number, not as a layout: `significand × 2^scale`, or the
/// point above every finite one.
///
/// ORDER_LAW: by denotation, `Infinite` above all. Two magnitudes denoting the
/// same number ARE the same magnitude, which is why the constructor normalises
/// — `2 × 2^0` and `1 × 2^1` are one value and must encode to one byte string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mag {
    Finite { significand: u64, scale: u32 },
    Infinite,
}

impl Mag {
    /// Strip the trailing zero bits into the scale, so equal numbers have equal
    /// fields. A zero significand is not a magnitude: zero is its own class.
    pub fn finite(significand: u64, scale: u32) -> Option<Mag> {
        match significand {
            0 => None,
            mut s => {
                let mut k = scale;
                while s % 2 == 0 {
                    s /= 2;
                    k += 1;
                }
                match k + 64 < EXP_INFINITE as u32 {
                    true => Some(Mag::Finite {
                        significand: s,
                        scale: k,
                    }),
                    false => None,
                }
            }
        }
    }

    /// The exponent field: where the significand's top bit sits.
    fn exponent(self) -> u128 {
        match self {
            Mag::Finite { significand, scale } => bit_len(significand) as u128 + scale as u128,
            Mag::Infinite => EXP_INFINITE,
        }
    }

    /// The payload as one number: exponent above a left-aligned fraction.
    fn packed(self) -> u128 {
        match self {
            Mag::Finite { significand, .. } => {
                let bits = bit_len(significand);
                (self.exponent() << FRAC_BITS) | ((significand as u128) << (FRAC_BITS - bits))
            }
            Mag::Infinite => (EXP_INFINITE << FRAC_BITS) | ((1u128 << FRAC_BITS) - 1),
        }
    }

    /// Ascending by what the magnitude denotes. Computed on the numbers, so it
    /// owes nothing to the layout above.
    fn cmp_value(self, other: Mag) -> Ordering {
        match (self, other) {
            (Mag::Infinite, Mag::Infinite) => Ordering::Equal,
            (Mag::Infinite, Mag::Finite { .. }) => Ordering::Greater,
            (Mag::Finite { .. }, Mag::Infinite) => Ordering::Less,
            (
                Mag::Finite {
                    significand: a,
                    scale: sa,
                },
                Mag::Finite {
                    significand: b,
                    scale: sb,
                },
            ) => {
                // a·2^sa against b·2^sb, exactly and without a big integer.
                // Where the top bit lands decides first: a number whose highest
                // set bit is higher IS the larger number. Only when the two
                // land on the same bit does anything below it matter, and then
                // the significands compared from that bit down decide it.
                let top_a = bit_len(a) as u64 + sa as u64;
                let top_b = bit_len(b) as u64 + sb as u64;
                let aligned_a = (a as u128) << (64 - bit_len(a));
                let aligned_b = (b as u128) << (64 - bit_len(b));
                top_a.cmp(&top_b).then(aligned_a.cmp(&aligned_b))
            }
        }
    }
}

fn bit_len(v: u64) -> u32 {
    let mut n = 0u32;
    let mut x = v;
    while x > 0 {
        n += 1;
        x /= 2;
    }
    n
}

/// A number as a value on the line, with the tie-break that survives into the
/// bytes.
///
/// ORDER_LAW: negatives descending by magnitude, then zero, then positives
/// ascending, then NaN — which is not a point on the line and is placed above
/// every one of them so that the order is total. Within one point, `Int` before
/// `Float`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Num {
    Negative(Mag, Repr),
    Zero(Repr),
    Positive(Mag, Repr),
    NotANumber,
}

impl Num {
    fn class(self) -> u8 {
        match self {
            Num::Negative(..) => CLASS_NEG,
            Num::Zero(_) => CLASS_ZERO,
            Num::Positive(..) => CLASS_POS,
            Num::NotANumber => CLASS_NAN,
        }
    }

    fn cmp_num(self, other: Num) -> Ordering {
        match self.class().cmp(&other.class()) {
            Ordering::Equal => match (self, other) {
                (Num::Negative(a, ta), Num::Negative(b, tb)) => {
                    b.cmp_value(a).then(ta.cmp(&tb))
                }
                (Num::Positive(a, ta), Num::Positive(b, tb)) => {
                    a.cmp_value(b).then(ta.cmp(&tb))
                }
                (Num::Zero(ta), Num::Zero(tb)) => ta.cmp(&tb),
                (Num::NotANumber, Num::NotANumber) => Ordering::Equal,
                _ => Ordering::Equal,
            },
            other_way => other_way,
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut out = vec![TAG_NUM, self.class()];
        match self {
            Num::Negative(m, t) => {
                for b in be(m.packed(), MAG_BYTES) {
                    out.push(!b);
                }
                out.push(t.byte());
            }
            Num::Positive(m, t) => {
                out.extend_from_slice(&be(m.packed(), MAG_BYTES));
                out.push(t.byte());
            }
            Num::Zero(t) => out.push(t.byte()),
            Num::NotANumber => out.push(Repr::Float.byte()),
        }
        out
    }
}

/// An interval endpoint.
///
/// ORDER_LAW: on the lower axis, unbounded is the least point; on the upper
/// axis, unbounded is the greatest. One end's order is not the other's, which
/// is why the two are compared by axis and never by a shared rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bound {
    Unbounded,
    At([u8; 8]),
}

impl Bound {
    fn cmp_low(self, other: Bound) -> Ordering {
        match (self, other) {
            (Bound::Unbounded, Bound::Unbounded) => Ordering::Equal,
            (Bound::Unbounded, Bound::At(_)) => Ordering::Less,
            (Bound::At(_), Bound::Unbounded) => Ordering::Greater,
            (Bound::At(a), Bound::At(b)) => a.cmp(&b),
        }
    }

    fn cmp_high(self, other: Bound) -> Ordering {
        match (self, other) {
            (Bound::Unbounded, Bound::Unbounded) => Ordering::Equal,
            (Bound::Unbounded, Bound::At(_)) => Ordering::Greater,
            (Bound::At(_), Bound::Unbounded) => Ordering::Less,
            (Bound::At(a), Bound::At(b)) => a.cmp(&b),
        }
    }

    fn encode_low(self) -> Vec<u8> {
        match self {
            Bound::Unbounded => vec![LO_UNBOUNDED],
            Bound::At(t) => {
                let mut v = vec![LO_AT];
                v.extend_from_slice(&t);
                v
            }
        }
    }

    fn encode_high(self) -> Vec<u8> {
        match self {
            Bound::Unbounded => vec![HI_UNBOUNDED],
            Bound::At(t) => {
                let mut v = vec![HI_AT];
                v.extend_from_slice(&t);
                v
            }
        }
    }
}

/// A value, as meaning.
///
/// ORDER_LAW: by kind in the order the kinds are listed here, which is the
/// order of their tags; then within a kind by that kind's own semantics. The
/// listing order is the law and is written out in [`Sem::rank`] rather than
/// derived, so that reordering the variants cannot silently reorder the domain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Sem {
    Null,
    Bool(bool),
    Number(Num),
    Text(String),
    Blob(Vec<u8>),
    Uuid([u8; 16]),
    Regex { pattern: String, flags: RefFlags },
    Json(Box<Sem>),
    Vector(Vec<Num>),
    List(Vec<Sem>),
    Set(Vec<Sem>),
    Validity {
        ts_micros: i64,
        is_assert: bool,
    },
    Interval(Option<(Bound, Bound)>),
    Geometry(u64),
}

impl Sem {
    /// The kind's place in the domain order, equal to its tag's place. Written
    /// out because it is a claim about the format, not about this file.
    fn rank(&self) -> u8 {
        match self {
            Sem::Null => TAG_NULL,
            Sem::Bool(false) => TAG_FALSE,
            Sem::Bool(true) => TAG_TRUE,
            Sem::Number(_) => TAG_NUM,
            Sem::Text(_) => TAG_STR,
            Sem::Blob(_) => TAG_BYTES,
            Sem::Uuid(_) => TAG_UUID,
            Sem::Regex { .. } => TAG_REGEX,
            Sem::Json(_) => TAG_JSON,
            Sem::Vector(_) => TAG_VECTOR,
            Sem::List(_) => TAG_LIST,
            Sem::Set(_) => TAG_SET,
            Sem::Validity { .. } => TAG_VALIDITY,
            Sem::Interval(_) => TAG_INTERVAL,
            Sem::Geometry(_) => TAG_GEOMETRY,
        }
    }

    /// A set has no order of its own, so its members are put in one before
    /// anything is asked of them. Two writings of one set are one value.
    pub fn normalized(&self) -> Sem {
        match self {
            Sem::Set(members) => {
                let mut m: Vec<Sem> = members.iter().map(|e| e.normalized()).collect();
                m.sort_by(|a, b| a.cmp_sem(b));
                m.dedup_by(|a, b| a.cmp_sem(b) == Ordering::Equal);
                Sem::Set(m)
            }
            Sem::List(elems) => Sem::List(elems.iter().map(|e| e.normalized()).collect()),
            Sem::Json(inner) => Sem::Json(Box::new(inner.normalized())),
            other => other.clone(),
        }
    }

    /// How many levels the reader spends on this value. A leaf spends one; a
    /// value carried whole adds its own; a row adds one for the row and then
    /// the deepest member's.
    pub fn descent(&self) -> u32 {
        match self {
            Sem::Json(inner) => 1 + inner.descent(),
            Sem::List(elems) | Sem::Set(elems) => {
                2 + elems.iter().map(|e| e.descent()).max().unwrap_or(0)
            }
            // A vector's components are numbers, and a number spends a level
            // on its class before its payload.
            Sem::Vector(components) => {
                2 + components.iter().map(|_| NUM_DESCENT).max().unwrap_or(0)
            }
            // The class byte and the interval marker are each a level.
            Sem::Number(_) => NUM_DESCENT,
            Sem::Interval(None) => 2,
            Sem::Interval(Some(_)) => 3,
            _ => 1,
        }
    }

    /// The whole order law, stated over meaning.
    pub fn cmp_sem(&self, other: &Sem) -> Ordering {
        match self.rank().cmp(&other.rank()) {
            Ordering::Equal => self.cmp_within(other),
            decided => decided,
        }
    }

    fn cmp_within(&self, other: &Sem) -> Ordering {
        match (self, other) {
            (Sem::Null, Sem::Null) => Ordering::Equal,
            (Sem::Bool(_), Sem::Bool(_)) => Ordering::Equal,
            (Sem::Number(a), Sem::Number(b)) => a.cmp_num(*b),
            (Sem::Text(a), Sem::Text(b)) => a.as_bytes().cmp(b.as_bytes()),
            (Sem::Blob(a), Sem::Blob(b)) => a.cmp(b),
            (Sem::Uuid(a), Sem::Uuid(b)) => a.cmp(b),
            (
                Sem::Regex { pattern: pa, flags: fa },
                Sem::Regex { pattern: pb, flags: fb },
            ) => pa.as_bytes().cmp(pb.as_bytes()).then(fa.byte().cmp(&fb.byte())),
            (Sem::Json(a), Sem::Json(b)) => a.cmp_sem(b),
            (Sem::Vector(a), Sem::Vector(b)) => a
                .len()
                .cmp(&b.len())
                .then_with(|| cmp_seq(a, b, |x, y| x.cmp_num(*y))),
            (Sem::List(a), Sem::List(b)) => cmp_seq(a, b, |x, y| x.cmp_sem(y)),
            (Sem::Set(a), Sem::Set(b)) => cmp_seq(a, b, |x, y| x.cmp_sem(y)),
            (
                Sem::Validity {
                    ts_micros: ta,
                    is_assert: aa,
                },
                Sem::Validity {
                    ts_micros: tb,
                    is_assert: ab,
                },
            ) => tb.cmp(ta).then(ab.cmp(aa)),
            (Sem::Interval(a), Sem::Interval(b)) => match (a, b) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some((la, ha)), Some((lb, hb))) => {
                    la.cmp_low(*lb).then(ha.cmp_high(*hb))
                }
            },
            (Sem::Geometry(a), Sem::Geometry(b)) => a.cmp(b),
            _ => Ordering::Equal,
        }
    }
}

/// Element by element; a sequence that runs out first is the lesser one.
fn cmp_seq<T>(a: &[T], b: &[T], each: impl Fn(&T, &T) -> Ordering) -> Ordering {
    let mut i = 0usize;
    while i < a.len() && i < b.len() {
        match each(&a[i], &b[i]) {
            Ordering::Equal => i += 1,
            decided => return decided,
        }
    }
    a.len().cmp(&b.len())
}

/// The flag set as this file states it: the six bits KyzoRegexV1 has, written
/// out from the format rather than imported from the encoder.
///
/// The reserved bits are 0xC0, and a byte holding one is not a flag set. The
/// mint is what makes that true here, exactly as it is over there — but nothing
/// is shared, which is the point of this file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RefFlags(u8);

impl RefFlags {
    pub const RESERVED: u8 = 0xC0;

    pub fn of(bits: u8) -> Option<RefFlags> {
        match bits & RefFlags::RESERVED == 0 {
            true => Some(RefFlags(bits)),
            false => None,
        }
    }

    pub fn byte(self) -> u8 {
        self.0
    }
}

/// `v` in `width` bytes, most significant first.
fn be(v: u128, width: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = width;
    while i > 0 {
        i -= 1;
        out.push(((v >> (i * 8)) & 0xFF) as u8);
    }
    out
}

/// Opaque content, self-delimiting and order-preserving: `0x00` doubles into
/// `0x00 0xFF`, and `0x00 0x00` ends it.
fn escaped(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in content {
        out.push(*b);
        if *b == ESC {
            out.push(ESC_ZERO);
        }
    }
    out.push(ESC);
    out.push(ESC);
    out
}

/// The encoding, written from the format.
pub fn encode(v: &Sem) -> Vec<u8> {
    match v {
        Sem::Null => vec![TAG_NULL],
        Sem::Bool(false) => vec![TAG_FALSE],
        Sem::Bool(true) => vec![TAG_TRUE],
        Sem::Number(n) => n.encode(),
        Sem::Text(s) => {
            let mut out = vec![TAG_STR];
            out.extend_from_slice(&escaped(s.as_bytes()));
            out
        }
        Sem::Blob(b) => {
            let mut out = vec![TAG_BYTES];
            out.extend_from_slice(&escaped(b));
            out
        }
        Sem::Uuid(id) => {
            let mut out = vec![TAG_UUID];
            out.extend_from_slice(id);
            out
        }
        Sem::Regex { pattern, flags } => {
            let mut out = vec![TAG_REGEX];
            out.extend_from_slice(&escaped(pattern.as_bytes()));
            out.push(flags.byte());
            out
        }
        Sem::Json(inner) => {
            let mut out = vec![TAG_JSON];
            out.extend_from_slice(&encode(inner));
            out
        }
        Sem::Vector(components) => {
            let mut out = vec![TAG_VECTOR];
            out.extend_from_slice(&be(components.len() as u128, DIM_BYTES));
            for c in components {
                out.extend_from_slice(&c.encode());
            }
            out.push(END);
            out
        }
        Sem::List(elems) => {
            let mut out = vec![TAG_LIST];
            for e in elems {
                out.extend_from_slice(&encode(e));
            }
            out.push(END);
            out
        }
        Sem::Set(_) => {
            let normal = v.normalized();
            let members = match &normal {
                Sem::Set(m) => m.clone(),
                _ => Vec::new(),
            };
            let mut out = vec![TAG_SET];
            for e in &members {
                out.extend_from_slice(&encode(e));
            }
            out.push(END);
            out
        }
        Sem::Validity {
            ts_micros,
            is_assert,
        } => {
            let biased = (*ts_micros as u64) ^ 0x8000_0000_0000_0000u64;
            let mut out = vec![TAG_VALIDITY];
            out.extend_from_slice(&be(!biased as u128, 8));
            out.push(if *is_assert { 0x00 } else { 0x01 });
            out
        }
        Sem::Interval(None) => vec![TAG_INTERVAL, INTERVAL_EMPTY],
        Sem::Interval(Some((lo, hi))) => {
            let mut out = vec![TAG_INTERVAL, INTERVAL_BOUNDED];
            out.extend_from_slice(&lo.encode_low());
            out.extend_from_slice(&hi.encode_high());
            out
        }
        Sem::Geometry(curve_index) => {
            let mut out = vec![TAG_GEOMETRY];
            out.extend_from_slice(&be(*curve_index as u128, 8));
            out
        }
    }
}

/// Why a reading stopped. The reference names its refusals for the same reason
/// the encoder does: a refusal that says nothing cannot be compared with one
/// that says something.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefRefusal {
    Truncated,
    UnknownLeadByte(u8),
    BadEscape(u8),
    TooDeep,
}

/// What a reading found: where the value ended, and how far the reader went to
/// find it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reading {
    pub end: usize,
    pub descent: u32,
}

/// Read one value from the front of `p`.
///
/// Recursive descent, written from the format rather than from a table, and
/// bounded the way the format is bounded: a value whose descent would exceed
/// [`MAX_VALUE_DESCENT`] is refused rather than followed.
pub fn scan(p: &[u8]) -> Result<Reading, RefRefusal> {
    let r = scan_at(p)?;
    match r.descent > MAX_VALUE_DESCENT {
        true => Err(RefRefusal::TooDeep),
        false => Ok(r),
    }
}

fn scan_at(p: &[u8]) -> Result<Reading, RefRefusal> {
    let tag = *p.first().ok_or(RefRefusal::Truncated)?;
    let body = &p[1..];
    match tag {
        TAG_NULL | TAG_FALSE | TAG_TRUE => leaf(1),
        TAG_NUM => scan_num(body),
        TAG_STR | TAG_BYTES => leaf(1 + scan_escaped(body)?),
        TAG_UUID => leaf(1 + fixed(body, 16)?),
        TAG_REGEX => {
            let n = scan_escaped(body)?;
            leaf(1 + n + fixed(&body[n..], 1)?)
        }
        TAG_JSON => {
            let inner = scan_at(body)?;
            deeper(1 + inner.end, inner.descent)
        }
        TAG_VECTOR => {
            let dim = fixed(body, DIM_BYTES)?;
            let row = scan_row(&body[dim..])?;
            deeper(1 + dim + row.end, row.descent)
        }
        TAG_LIST | TAG_SET => {
            let row = scan_row(body)?;
            deeper(1 + row.end, row.descent)
        }
        TAG_VALIDITY => leaf(1 + fixed(body, 9)?),
        TAG_GEOMETRY => leaf(1 + fixed(body, 8)?),
        TAG_INTERVAL => scan_interval(body),
        unknown => Err(RefRefusal::UnknownLeadByte(unknown)),
    }
}

/// A value with nothing inside it: one level, and no deeper reading to fold in.
fn leaf(end: usize) -> Result<Reading, RefRefusal> {
    Ok(Reading { end, descent: 1 })
}

/// A value carrying a reading: this tag's level, above what was inside it.
fn deeper(end: usize, inner: u32) -> Result<Reading, RefRefusal> {
    match 1 + inner > MAX_VALUE_DESCENT {
        true => Err(RefRefusal::TooDeep),
        false => Ok(Reading {
            end,
            descent: 1 + inner,
        }),
    }
}

fn fixed(p: &[u8], width: usize) -> Result<usize, RefRefusal> {
    match p.len() >= width {
        true => Ok(width),
        false => Err(RefRefusal::Truncated),
    }
}

fn scan_num(p: &[u8]) -> Result<Reading, RefRefusal> {
    let class = *p.first().ok_or(RefRefusal::Truncated)?;
    let width = match class {
        CLASS_NEG | CLASS_POS => MAG_BYTES + 1,
        CLASS_ZERO | CLASS_NAN => 1,
        other => return Err(RefRefusal::UnknownLeadByte(other)),
    };
    Ok(Reading {
        end: 2 + fixed(&p[1..], width)?,
        descent: NUM_DESCENT,
    })
}

fn scan_interval(p: &[u8]) -> Result<Reading, RefRefusal> {
    let marker = *p.first().ok_or(RefRefusal::Truncated)?;
    let rest = &p[1..];
    match marker {
        INTERVAL_EMPTY => Ok(Reading {
            end: 2,
            descent: 2,
        }),
        INTERVAL_BOUNDED => {
            let lo = match rest.first().ok_or(RefRefusal::Truncated)? {
                &LO_UNBOUNDED => 1,
                &LO_AT => 1 + fixed(&rest[1..], 8)?,
                &other => return Err(RefRefusal::UnknownLeadByte(other)),
            };
            let after = &rest[lo..];
            let hi = match after.first().ok_or(RefRefusal::Truncated)? {
                &HI_UNBOUNDED => 1,
                &HI_AT => 1 + fixed(&after[1..], 8)?,
                &other => return Err(RefRefusal::UnknownLeadByte(other)),
            };
            Ok(Reading {
                end: 2 + lo + hi,
                descent: 3,
            })
        }
        other => Err(RefRefusal::UnknownLeadByte(other)),
    }
}

/// An escaped payload: how many bytes it occupies, terminator included.
fn scan_escaped(p: &[u8]) -> Result<usize, RefRefusal> {
    let mut i = 0usize;
    loop {
        let b = *p.get(i).ok_or(RefRefusal::Truncated)?;
        match b {
            ESC => {
                let second = *p.get(i + 1).ok_or(RefRefusal::Truncated)?;
                match second {
                    ESC => return Ok(i + 2),
                    ESC_ZERO => i += 2,
                    bad => return Err(RefRefusal::BadEscape(bad)),
                }
            }
            _ => i += 1,
        }
    }
}

/// A terminated row of whole values: where it ends, and the deepest member.
fn scan_row(p: &[u8]) -> Result<Reading, RefRefusal> {
    let mut at = 0usize;
    let mut deepest = 0u32;
    loop {
        let b = *p.get(at).ok_or(RefRefusal::Truncated)?;
        match b {
            END => {
                return Ok(Reading {
                    end: at + 1,
                    descent: 1 + deepest,
                })
            }
            _ => {
                let e = scan_at(&p[at..])?;
                at += e.end;
                deepest = deepest.max(e.descent);
            }
        }
    }
}
