/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The four detection surfaces. Exactly four — this mirrors the ontology of
//! how a claim/reality mismatch becomes visible, not a historical file
//! count:
//! - [`shape`]: the lie is a construct at one site in source text.
//! - [`graph`]: the lie is relational — no single site is wrong.
//! - [`behavior`]: the lie only exists when executed.
//! - [`meta`]: the lie is in the detector itself.

pub mod graph;
pub mod meta;
pub mod shape;

/// One detector hit, before waiver filtering: where and what.
///
/// Fields are private (TRUTH item 9). Sole admission is [`Hit::admit`].
#[derive(Clone, Debug)]
pub struct Hit {
    file: String,
    line: usize,
    /// The construct name as waivers must swear to it.
    construct: String,
}

impl Hit {
    /// Sole admission constructor.
    pub fn admit(file: impl Into<String>, line: usize, construct: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line,
            construct: construct.into(),
        }
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn line(&self) -> usize {
        self.line
    }

    pub fn construct(&self) -> &str {
        &self.construct
    }
}
