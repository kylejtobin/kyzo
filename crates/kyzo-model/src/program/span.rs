/*
 * Copyright 2022, The Cozo Project Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */
/*
 * Copyright 2026, The KyzoDB Authors. Modified from the CozoDB original
 * (MPL-2.0): SourceSpan relocated from parse into the data layer;
 * Serialize/Deserialize dropped as never persisted; Display and merge
 * return with the parse tier. Tuple fields deleted — sealed named fields
 * are the only lawful shape (grammar sealed-struct).
 */

//! Source location: where in the query text a thing came from.
//!
//! A span is data-layer vocabulary, not a parser detail: every substance
//! that originates in user text (symbols, atoms, rules, expressions) carries
//! one, and every diagnostic points back through it. Errors that cannot say
//! *where* are not finished errors.

/// A byte range into the query text: offset and length.
///
/// Spans survive every pipeline stage — a compiled plan can still point at
/// the exact characters responsible for a runtime error.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceSpan {
    offset: usize,
    length: usize,
}

impl SourceSpan {
    /// Construct a span from byte offset and length.
    pub const fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    /// The empty span at offset 0 — used when no source location is known.
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            length: 0,
        }
    }

    pub const fn offset(self) -> usize {
        self.offset
    }

    pub const fn length(self) -> usize {
        self.length
    }

    /// The smallest span covering both `self` and `other`: diagnostics that
    /// implicate two places label the whole stretch between them.
    pub fn merge(self, other: Self) -> Self {
        let s1 = self.offset;
        let e1 = self.offset + self.length;
        let s2 = other.offset;
        let e2 = other.offset + other.length;
        let s = s1.min(s2);
        let e = e1.max(e2);
        Self::new(s, e - s)
    }
}

impl std::fmt::Debug for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.offset, self.offset + self.length)
    }
}

impl From<SourceSpan> for miette::SourceSpan {
    fn from(s: SourceSpan) -> Self {
        (s.offset, s.length).into()
    }
}

impl From<&SourceSpan> for miette::SourceSpan {
    fn from(s: &SourceSpan) -> Self {
        (s.offset, s.length).into()
    }
}

impl std::fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.offset, self.offset + self.length)
    }
}
