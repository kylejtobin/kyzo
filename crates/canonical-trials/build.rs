/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! AUTHORITY: Declare the cfgs Verus sets so a plain `cargo build` does not warn.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(verus_only)");
    println!("cargo::rustc-check-cfg=cfg(verus_keep_ghost)");
    println!("cargo::rustc-check-cfg=cfg(verus_keep_ghost_body)");
    println!("cargo::rustc-check-cfg=cfg(verus_verify_core)");
    println!("cargo::rerun-if-changed=build.rs");
}
