/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![forbid(unsafe_code)]

//! AUTHORITY: to fail to compile, and to fail for the stated reason.
//!
//! Every statement below is a forgery: a way to reach the grammar's authority
//! without going through a door. None of them compiles, and `xtask/compile-
//! fail.sh` runs the compiler over this file and holds its output against the
//! list in that script — a forgery that starts compiling is a hole in the
//! encoder's construction authority, and a forgery that fails for a DIFFERENT
//! reason (a typo, a renamed item) is a test that stopped testing.
//!
//! It lives in its own crate because `pub(crate)` is not `pub`: the raw set
//! sealer and the scanners are visible to everything inside `canonical-trials`,
//! so only an outside caller can put "not public" to the compiler. It is behind
//! `required-features = ["compile-fail"]`, so an ordinary build never sees it. Nothing here is dead code to be deleted; it is the negative
//! space of the public API, written down.
//!
//! `forge_literal.rs` holds one forgery of its own, because rustc reports at
//! most one privacy error per struct: with the field read below in the same
//! file, the struct-literal forgery is never reached and would look rejected
//! without being tested.

use canonical_trials::value;
use value::canonical::{seal_null, seal_num_zero, seal_regex, RegexFlags, Repr, Validity};

fn main() {
    // FORGERY: reach inside a sealed value and read its bytes directly.
    // EXPECT: E0616 field `bytes` of struct `CanonicalBytes` is private
    let sealed = seal_null();
    let _ = sealed.bytes;

    // FORGERY: name the body type at all.
    // EXPECT: E0603 struct `Body` is private
    let _: value::canonical::Body;

    // FORGERY: build a body out of arbitrary bytes.
    // EXPECT: E0603 struct `Body` is private
    // EXPECT: E0624 associated function `fixed` is private
    let _ = value::canonical::Body::fixed(vec![0xFF]);

    // FORGERY: name a body's fields, which is what a forged body would need.
    // EXPECT: E0603 struct `Body` is private
    // EXPECT: E0308 mismatched types
    //
    // Two codes because rustc type-checks the field expressions before it gives
    // up on the private type. The rejection is the E0603: a field of a type no
    // caller can name is a field no caller can set.
    let _ = value::canonical::Body {
        bytes: vec![0x05u8],
        shape: 0u8,
        descent: 0u32,
    };

    // FORGERY: seal a body under a tag of the forger's choosing.
    // EXPECT: E0603 function `seal` is private
    // EXPECT: E0624 associated function `fixed` is private
    let _ = value::canonical::seal(0x05, value::canonical::Body::fixed(Vec::new()));

    // FORGERY: read the magnitude's stored fields.
    // EXPECT: E0616 field `significand` of struct `FiniteMagnitude` is private
    if let Some(f) = value::canonical::FiniteMagnitude::of(1, 0) {
        let _ = f.significand;
    }

    // FORGERY: read the flags byte's bits as a field.
    // EXPECT: E0616 field `case_insensitive` of struct `RegexFlags` is private
    let flags = RegexFlags::new(true, false, false);
    let _ = flags.case_insensitive;

    // FORGERY: set a flag bit the type has no field for.
    // EXPECT: E0061 this function takes 3 arguments but 4 arguments were supplied
    let _ = RegexFlags::new(true, true, true, true);

    // FORGERY: name a representation that is neither integer nor float.
    // EXPECT: E0599 no variant or associated item named `Decimal` found for enum `Repr`
    let _ = Repr::Decimal;

    // FORGERY: choose the byte that says "not a number".
    // EXPECT: E0061 this function takes 0 arguments but 1 argument was supplied
    let _ = value::canonical::seal_num_nan(0x04);

    // FORGERY: choose the class byte a number is filed under.
    // EXPECT: E0061 this function takes 1 argument but 2 arguments were supplied
    let _ = seal_num_zero(Repr::Int, 0x02);

    // FORGERY: choose the marker byte an interval end is written with.
    // EXPECT: E0599 no variant named `Marker` found for enum `Bound`
    let _ = value::canonical::Bound::Marker(0x01);

    // FORGERY: write a row under the Set tag in the caller's own order.
    // EXPECT: E0603 function `seal_set` is private
    let _ = value::canonical::seal_set(&Vec::new());

    // FORGERY: hand the regex door a pattern that is not text.
    // EXPECT: E0308 mismatched types
    let _ = seal_regex(b"not text", &RegexFlags::new(false, false, false));

    // FORGERY: assert a validity without asking whether it is one.
    // EXPECT: E0308 mismatched types
    let _: Validity = Validity::new(0, true);

    // FORGERY: reach the grammar table and rewrite a shape.
    // EXPECT: E0433 cannot find `grammar` in `canonical`
    //
    // There is no grammar module to make private: the table is a macro the
    // shapes are built from, and nothing exports it under a name a caller
    // could reach. Failing to resolve IS the rejection.
    let _ = value::canonical::grammar::TAGS;

    // FORGERY: scan with a depth counter of the forger's choosing.
    // EXPECT: E0603 function `sum_scan` is private
    let _ = value::canonical::sum_scan;
}
