/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Execution surface (TRUTH item 10): live supply-chain checks and
//! campaigns whose truth only exists when run. A check outside the
//! laws.toml registry does not exist.

use std::path::Path;

use crate::engines::Hit;

pub mod build_script_sandbox;
pub mod campaign;
pub mod pure_rust;
pub mod unsafe_check;

/// Live pure-Rust tree scan → hits (empty = clean).
pub fn pure_rust_hits(repo_root: &Path) -> Vec<Hit> {
    match pure_rust::PureRustGate.check_at(repo_root) {
        Ok(_) => vec![],
        Err(pure_rust::PureRustError::BannedCratesFound(hits)) => hits
            .into_iter()
            .map(|line| {
                Hit::admit(
                    "Cargo.toml".to_string(),
                    1,
                    format!("pure_rust_banned:{line}"),
                )
            })
            .collect(),
        Err(e) => vec![Hit::admit(
            "Cargo.toml".to_string(),
            1,
            format!("pure_rust_refuse:{e}"),
        )],
    }
}

/// Live unsafe-law scan → hits (empty = clean).
pub fn unsafe_check_hits(repo_root: &Path) -> Vec<Hit> {
    match unsafe_check::UnsafeCheckGate.check_at(repo_root) {
        Ok(_) => vec![],
        Err(unsafe_check::UnsafeCheckError::MissingForbid { root }) => {
            vec![Hit::admit(root, 1, "unsafe_missing_forbid".to_string())]
        }
        Err(unsafe_check::UnsafeCheckError::AllowFound { offenders }) => offenders
            .into_iter()
            .map(|f| Hit::admit(f, 1, "unsafe_allow_found".to_string()))
            .collect(),
        Err(unsafe_check::UnsafeCheckError::LyingDoc { offenders }) => offenders
            .into_iter()
            .map(|f| Hit::admit(f, 1, "unsafe_lying_doc".to_string()))
            .collect(),
        Err(e) => vec![Hit::admit(
            "Cargo.toml".to_string(),
            1,
            format!("unsafe_refuse:{e}"),
        )],
    }
}
