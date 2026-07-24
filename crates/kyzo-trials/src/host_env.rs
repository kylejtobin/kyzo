/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Trials host-env seat: the only `std::env` read in campaign binaries.

fn read(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

/// Optional `RAYON_NUM_THREADS` report string for the determinism digest probe.
pub fn rayon_num_threads() -> Option<String> {
    read("RAYON_NUM_THREADS")
}

/// Optional `KYZO_DST_QUERY_SEEDS` campaign scale knob.
pub fn dst_query_seeds() -> Option<String> {
    read("KYZO_DST_QUERY_SEEDS")
}

/// Optional campaign u64 knob by variable name.
pub fn knob(var: &str) -> Option<String> {
    read(var)
}
