/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The engine's one host-clock seat.
//!
//! Every other module consumes [`MonoMillis`] / wall-micros as data. Wall
//! and monotonic OS reads live here and nowhere else in the value or
//! evaluation planes — campaigns replay stamps; budgets and telemetry arm
//! from [`mono_millis`].

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use miette::{Diagnostic, Result};
use thiserror::Error;

/// Process-local monotonic milliseconds since the first seat read.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MonoMillis(u64);

impl MonoMillis {
    /// Elapsed duration since `earlier`; zero if clocks moved backwards
    /// within the process (should not happen for a mono Instant).
    pub(crate) fn saturating_elapsed_since(self, earlier: MonoMillis) -> Duration {
        match self.0.checked_sub(earlier.0) {
            Some(ms) => Duration::from_millis(ms),
            None => Duration::ZERO,
        }
    }

    /// Whole milliseconds since the process anchor.
    pub(crate) fn as_millis(self) -> u64 {
        self.0
    }
}

/// Named refusals for the wall-clock seat.
#[derive(Debug, Error, Diagnostic)]
pub(crate) enum HostClockRefuse {
    #[error("system clock reads earlier than the Unix epoch")]
    #[diagnostic(code(session::host_clock::before_epoch))]
    #[diagnostic(help("Fix the host clock; timestamps are microseconds since 1970-01-01T00:00:00Z"))]
    BeforeEpoch,
    #[error("system clock beyond i64 microseconds")]
    #[diagnostic(code(session::host_clock::past_i64))]
    PastI64,
}

fn elapsed_since_anchor() -> Duration {
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    let start = ANCHOR.get_or_init(|| Instant::now());
    start.elapsed()
}

/// Finite ceiling when `as_millis` exceeds `u64` — still a mono reading, not an Err→MAX costume.
const MONO_MILLIS_CEILING: u64 = u64::MAX;

/// Monotonic milliseconds since the first call in this process.
pub(crate) fn mono_millis() -> MonoMillis {
    let ms = elapsed_since_anchor().as_millis();
    let ms = match u64::try_from(ms) {
        Ok(v) => v,
        Err(_past_u64) => MONO_MILLIS_CEILING,
    };
    MonoMillis(ms)
}

/// Monotonic nanoseconds since the process anchor — bench SLA instrument.
pub(crate) fn mono_nanos() -> u128 {
    elapsed_since_anchor().as_nanos()
}

/// Wall-clock microseconds since the Unix epoch.
pub(crate) fn wall_micros() -> Result<i64, HostClockRefuse> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostClockRefuse::BeforeEpoch)?
        .as_micros();
    i64::try_from(micros).map_err(|_| HostClockRefuse::PastI64)
}
