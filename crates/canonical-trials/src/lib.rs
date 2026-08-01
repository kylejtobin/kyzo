/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![forbid(unsafe_code)]

//! AUTHORITY: to show the encoder's public surface to another crate, and only
//! that surface.
//!
//! `canonical-forgery` compiles against this. It has to be a separate crate:
//! `pub(crate)` doors — the raw set sealer, the shape and delimiter scanners —
//! are visible to everything inside this one, so "not public" is a claim only
//! an outside caller can put to the compiler.
//!
//! The trials binary keeps its own mount of the same source, because it is an
//! inside caller by design: it drives the crate-private doors on purpose.

pub mod value;
