/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![forbid(unsafe_code)]

//! AUTHORITY: to fail to compile, for the one reason `forge.rs` cannot hold.
//!
//! rustc reports at most one privacy error per struct, so a file that already
//! reads a private field never reaches the struct literal below. Alone, it is
//! tested.

use canonical_trials::value;

fn main() {
    // FORGERY: build a sealed value out of bytes of the forger's choosing,
    // skipping every door and the grammar behind them.
    // EXPECT: E0451 fields `bytes` and `descent` of struct `CanonicalBytes` are private
    let _ = value::canonical::CanonicalBytes {
        bytes: vec![0x05],
        descent: 1,
    };

    // FORGERY: build a magnitude out of a significand and a scale of the
    // forger's choosing, skipping the mint that decides whether the pair is one
    // -- here, a zero significand at a scale that carries the exponent out of
    // its field, which is two different numbers with one encoding.
    // EXPECT: E0451 fields `significand` and `biased_scale` of struct `FiniteMagnitude` are private
    let _ = value::canonical::FiniteMagnitude {
        significand: 0,
        biased_scale: u32::MAX,
    };
}
