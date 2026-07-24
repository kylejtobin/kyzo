/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The xtask host-env seat: the only `std::env` read in this crate.
//! Callers consume strings/paths as data — never `std::env` path idents.

fn read(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

/// Optional runtime override for the workspace root (`GATE_ROOT`).
pub(crate) fn gate_root() -> Option<String> {
    read("GATE_ROOT")
}

/// Cargo's manifest dir for this package, when the process was launched by cargo.
pub(crate) fn cargo_manifest_dir() -> Option<String> {
    read("CARGO_MANIFEST_DIR")
}

/// Optional `RUST_TEST_THREADS` fingerprint for the env-report verb.
pub(crate) fn rust_test_threads() -> Option<String> {
    read("RUST_TEST_THREADS")
}
