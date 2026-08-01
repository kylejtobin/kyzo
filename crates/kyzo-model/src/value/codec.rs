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

use super::canonical::{self, CanonicalBytes, JsonEntry, JsonValue, RowItem};

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

/// A canonical JSON object: entries sorted by key bytes, keys unique.
///
/// The law is stated in [`super::kind::json`] and it is not the grammar's: two
/// writings of one object would seal to two byte strings unless the entries are
/// put in one order, and a document with a repeated key is not one value at all.
/// So this sorts, and it REFUSES a duplicate rather than choosing last-wins or
/// first-wins — an ambiguous document is not a value, and the refusal names the
/// key that made it ambiguous.
///
/// Keys sort by their raw UTF-8 bytes. The grammar's escape is order-preserving
/// over raw bytes, so the sealed entries are in the same order as the keys.
pub struct CanonicalJsonObject(Vec<JsonEntry>);

/// The typed refusal for an ambiguous document, carrying the key that appeared
/// twice. A refusal is a finding about a document that was examined, so the
/// only thing that mints one is the constructor that found the duplicate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DuplicateKey(Vec<u8>);

impl DuplicateKey {
    pub fn key_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The typed refusal for a document the reader could not descend into.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TooDeepForJson;

impl CanonicalJsonObject {
    /// Sort by key bytes and refuse a repeated key.
    ///
    /// Sorting is part of encoding an object, not a precondition on the caller.
    /// Uniqueness is not: a document with two "a" keys denotes nothing, and
    /// there is no order this could put it in that would make it denote
    /// something.
    pub fn of(mut entries: Vec<JsonEntry>) -> Result<CanonicalJsonObject, DuplicateKey> {
        entries.sort_by(|a, b| a.key_bytes().cmp(b.key_bytes()));
        for pair in entries.windows(2) {
            if pair[0].key_bytes() == pair[1].key_bytes() {
                return Err(DuplicateKey(pair[0].key_bytes().to_vec()));
            }
        }
        Ok(CanonicalJsonObject(entries))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The object as a JSON value: a set of key-value pairs. One object, one
    /// byte string, whatever order the entries arrived in.
    pub fn into_value(self) -> Result<JsonValue, TooDeepForJson> {
        let mut pairs: Vec<JsonValue> = Vec::new();
        for entry in self.0 {
            match entry.into_pair() {
                Ok(pair) => pairs.push(pair),
                Err(_) => return Err(TooDeepForJson),
            }
        }
        canonical::seal_json_object(pairs).map_err(|_| TooDeepForJson)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::canonical::{seal_null, seal_str, Utf8};

    /// Members from leaf values. The mint is fallible because a deep value is
    /// not a member and a leaf never is one, so a refusal here drops a member
    /// and every test below counts its members before it compares bytes.
    fn members(values: Vec<CanonicalBytes>) -> Vec<RowItem> {
        values.into_iter().filter_map(|v| RowItem::of(v).ok()).collect()
    }

    fn texts(strings: &[&str]) -> Vec<RowItem> {
        members(strings.iter().map(|s| seal_str(&Utf8::of(s))).collect())
    }

    /// The breach this file exists to close: one set value, one byte string,
    /// regardless of the order the elements were written in.
    #[test]
    fn a_set_has_one_encoding_whatever_order_it_arrives_in() {
        assert_eq!(CanonicalSet::of(texts(&["a", "b"])).len(), 2);
        let ab = CanonicalSet::of(texts(&["a", "b"])).seal();
        let ba = CanonicalSet::of(texts(&["b", "a"])).seal();
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }

    #[test]
    fn duplicates_are_not_members_twice() {
        assert_eq!(texts(&["a", "a"]).len(), 2);
        let once = CanonicalSet::of(texts(&["a"])).seal();
        let twice = CanonicalSet::of(texts(&["a", "a"])).seal();
        assert_eq!(once.as_bytes(), twice.as_bytes());
        assert_eq!(CanonicalSet::of(texts(&["a", "a"])).len(), 1);
    }

    /// Distinct elements are not silently merged: dedup is by whole bytes, not
    /// by a prefix or a hash.
    #[test]
    fn distinct_elements_all_survive() {
        let mut given = texts(&["a", "ab"]);
        given.extend(members(vec![seal_null()]));
        assert_eq!(given.len(), 3);
        assert_eq!(CanonicalSet::of(given).len(), 3);
    }

    /// Members come out ascending, which is what makes the sealed row's order
    /// the same order a reader would sort them into.
    #[test]
    fn members_are_ascending_by_their_bytes() {
        let given = texts(&["c", "a", "b"]);
        assert_eq!(given.len(), 3);
        let sealed = CanonicalSet::of(given).seal();
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
