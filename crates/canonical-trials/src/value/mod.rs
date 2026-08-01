/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The encoder's own source, mounted under the module path `codec.rs` expects.
//! `codec` names `super::canonical`, so both live under one parent here.

#[path = "../../../kyzo-model/src/value/canonical.rs"]
pub mod canonical;

#[path = "../../../kyzo-model/src/value/codec.rs"]
pub mod codec;
