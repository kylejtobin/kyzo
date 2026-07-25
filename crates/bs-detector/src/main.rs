/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The Bullshit Detector CLI — the one door, and the ONLY writer of the
//! gate log. Verdict contract (frozen; the Stop hook, the watcher, and CI
//! all parse it): line 1 of the log is `GATE: ACKNOWLEDGE` or
//! `GATE: ALARM <check, check, …>`; the counts artifact is one line,
//! `name:N …  = TOTAL violations`. All detection lives in the library;
//! this binary is a one-call composition root over [`bs_detector::cli`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    bs_detector::cli::CLI.run_from_env()
}
