/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The bs-detector host-env seat: the only `std::env` read in this crate.
//! Callers consume argv as data — never `std::env` path idents outside this door.

/// Host-env authority — tip 806/914 + config-once seat.
pub struct HostEnvLaw;

/// The one production door for argv observation.
pub const HOST_ENV: HostEnvLaw = HostEnvLaw;

impl HostEnvLaw {
    /// The one lawful argv observation for the detector binary (config-once seat).
    pub fn args(&self) -> std::env::Args {
        std::env::args()
    }
}
