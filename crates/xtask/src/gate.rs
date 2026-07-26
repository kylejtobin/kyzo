/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The `gate` verb: the one-command seal. Runs env-report, check, fmt,
//! clippy, the bs-detector conduct gate (twelve forbidden shapes, each
//! decidable from syntax alone), test, and test-release-checked — cheapest
//! first, stopping at the first failure.

use std::fmt;

use crate::proc::ProcessFailure;
use crate::verbs;

/// Every way `gate` can refuse, one variant per step it runs.
#[derive(Debug)]
pub enum GateError {
    EnvReport(ProcessFailure),
    Check(ProcessFailure),
    Fmt(ProcessFailure),
    Clippy(ProcessFailure),
    BsDetector(ProcessFailure),
    Test(ProcessFailure),
    TestReleaseChecked(ProcessFailure),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::EnvReport(e) => write!(f, "env-report step failed: {e}"),
            GateError::Check(e) => write!(f, "check step failed: {e}"),
            GateError::Fmt(e) => write!(f, "fmt step failed: {e}"),
            GateError::Clippy(e) => write!(f, "clippy step failed: {e}"),
            GateError::BsDetector(e) => write!(f, "bs-detector step failed: {e}"),
            GateError::Test(e) => write!(f, "test step failed: {e}"),
            GateError::TestReleaseChecked(e) => {
                write!(f, "test-release-checked step failed: {e}")
            }
        }
    }
}

impl std::error::Error for GateError {}

pub fn run() -> Result<(), GateError> {
    verbs::env_report().map_err(GateError::EnvReport)?;
    verbs::check().map_err(GateError::Check)?;
    verbs::fmt().map_err(GateError::Fmt)?;
    verbs::clippy().map_err(GateError::Clippy)?;
    verbs::bs_detector().map_err(GateError::BsDetector)?;
    verbs::test().map_err(GateError::Test)?;
    verbs::test_release_checked().map_err(GateError::TestReleaseChecked)?;

    println!("=== GATE PASSED ===");
    Ok(())
}
