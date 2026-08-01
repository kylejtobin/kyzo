/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! AUTHORITY: carrying values across the proved boundary, and nothing else.
//!
//! ORDER_LAW: `a <= b  <=>  a.seal() <=lex b.seal()`, and `a == b  <=>  equal
//! bytes`. [`super::canonical`] proves the byte form is unambiguous and
//! order-preserving over the grammar. This file decides which grammar shape a
//! value takes, which is a different question and is not provable there.
//!
//! Why it is a separate file. `canonical` lives inside `verus!`, and the value
//! kinds are `String`/`Vec`/`BTreeSet`-shaped — Verus cannot reason about them,
//! so they cannot cross into that module. The alternative was to re-export
//! these names from `canonical` and let callers import them from the proved
//! module. That would put unproved glue behind a proved module's name. Here the
//! boundary is in the import line: `value::canonical::` is discharged by Z3,
//! `value::codec::` is discharged by trials and tests.
//!
//! What lives here is the part of encoding that is semantic rather than
//! grammatical. The clearest case is a set. `canonical::seal_set` writes a row
//! in the order it is handed, because a row's order is all the grammar knows
//! about. A set has no order, so two writings of one set value sealed to two
//! byte strings — equal values with unequal bytes, which the foundational
//! invariant forbids outright. Normalising to canonical set form is not a
//! property Verus can state about the grammar; it is a property of what a set
//! IS. So the raw door is `pub(crate)` and the only public way to seal a set is
//! [`CanonicalSet`], whose one constructor sorts and dedups.

use super::canonical::{self, CanonicalBytes, RowItem};

/// A set's elements in canonical form: ascending by their sealed bytes, no
/// duplicates.
///
/// The invariant is established by the only constructor and cannot be
/// disturbed afterwards, because nothing hands out the inner `Vec`. There is
/// deliberately no `from_sorted` fast path: a caller claiming its input is
/// already sorted is a claim nothing checks, and the sort it saves is not worth
/// a door that can be told a lie.
pub struct CanonicalSet(Vec<RowItem>);

impl CanonicalSet {
    /// Sort by sealed bytes and drop duplicates.
    ///
    /// Sorting is part of encoding a set, not a precondition on the caller —
    /// which is why this normalises rather than refusing an unsorted input.
    /// There is no wrong argument to reject: every multiset of values denotes
    /// exactly one set, and this computes its one encoding.
    pub fn of<I: IntoIterator<Item = RowItem>>(elems: I) -> CanonicalSet {
        let mut v: Vec<RowItem> = elems.into_iter().collect();
        v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        v.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
        CanonicalSet(v)
    }

    /// How many distinct elements survived normalisation.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Seal the set. One value, one byte string, whatever order it arrived in.
    pub fn seal(&self) -> CanonicalBytes {
        canonical::seal_set(&self.0)
    }
}

impl FromIterator<RowItem> for CanonicalSet {
    fn from_iter<I: IntoIterator<Item = RowItem>>(iter: I) -> CanonicalSet {
        CanonicalSet::of(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::canonical::{seal_null, seal_str, Utf8};

    /// A member built from a leaf value. The mint is fallible because a deep
    /// value is not a member; a leaf never is one.
    fn member(v: CanonicalBytes) -> RowItem {
        RowItem::of(v).expect("a leaf value is shallow enough to be a member")
    }

    fn text(s: &str) -> RowItem {
        member(seal_str(&Utf8::of(s)))
    }

    /// The breach this file exists to close: one set value, one byte string,
    /// regardless of the order the elements were written in.
    #[test]
    fn a_set_has_one_encoding_whatever_order_it_arrives_in() {
        let ab = CanonicalSet::of([text("a"), text("b")]).seal();
        let ba = CanonicalSet::of([text("b"), text("a")]).seal();
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }

    #[test]
    fn duplicates_are_not_members_twice() {
        let once = CanonicalSet::of([text("a")]).seal();
        let twice = CanonicalSet::of([text("a"), text("a")]).seal();
        assert_eq!(once.as_bytes(), twice.as_bytes());
        assert_eq!(CanonicalSet::of([text("a"), text("a")]).len(), 1);
    }

    /// Distinct elements are not silently merged: dedup is by whole bytes, not
    /// by a prefix or a hash.
    #[test]
    fn distinct_elements_all_survive() {
        let s = CanonicalSet::of([text("a"), text("ab"), member(seal_null())]);
        assert_eq!(s.len(), 3);
    }

    /// Members come out ascending, which is what makes the sealed row's order
    /// the same order a reader would sort them into.
    #[test]
    fn members_are_ascending_by_their_bytes() {
        let s = CanonicalSet::of([text("c"), text("a"), text("b")]);
        let sealed = s.seal();
        let a = seal_str(&Utf8::of("a"));
        let c = seal_str(&Utf8::of("c"));
        let body = sealed.as_bytes();
        let first = body
            .windows(a.as_bytes().len())
            .position(|w| w == a.as_bytes());
        let last = body
            .windows(c.as_bytes().len())
            .position(|w| w == c.as_bytes());
        assert!(first < last, "elements are not ascending in the sealed row");
    }
}
