/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Gate engines that live under this module — the tree as it is, not a
//! planned ontology.
//!
//! Crate seats outside this folder (named so the map is complete):
//! - `grammar` — grammar.toml load / construct seats (unbuilt seats named
//!   in that file stay unbuilt until declared).
//! - `classify` — item classifier onto seated constructs or unclassified.
//!
//! Engines here:
//! - [`shape`]: banned-shape predicates (named matchers over one site).
//! - [`graph`]: relational passes (no single site is the whole lie).
//! - [`meta`]: meta passes (the detector policing its own run).
//! - [`behavior`]: execution checks and campaigns (TRUTH item 10).

use crate::boundary::{Label, RelPath};

pub mod behavior;
pub mod graph;
pub mod meta;
pub mod shape;

/// One detector hit, before waiver filtering: where and what.
///
/// Fields are private (TRUTH item 9). Sole admission is [`Hit::admit`].
/// No `String`/`str` terminals — file is [`RelPath`], construct is [`Label`].
#[derive(Clone, Debug)]
pub struct Hit {
    file: RelPath,
    line: usize,
    /// The construct name as waivers must swear to it.
    construct: Label,
}

impl Hit {
    /// Sole admission constructor.
    pub fn admit(file: impl Into<RelPath>, line: usize, construct: impl Into<Label>) -> Self {
        Self {
            file: file.into(),
            line,
            construct: construct.into(),
        }
    }

    pub fn file(&self) -> &RelPath {
        &self.file
    }

    pub fn line(&self) -> usize {
        self.line
    }

    pub fn construct(&self) -> &str {
        self.construct.as_str()
    }
}
