/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Workspace-root discovery — the one fsutil surface still owned by
//! xtask's remaining verbs. Tree scanning moved wholesale to the
//! bs-detector crate's Boundary.

use std::path::PathBuf;

use anyhow::{Context, Result};

pub fn repo_root() -> Result<PathBuf> {
    if let Some(r) = crate::host_env::gate_root() {
        return Ok(PathBuf::from(r));
    }
    let manifest_dir = crate::host_env::cargo_manifest_dir()
        .context("CARGO_MANIFEST_DIR not set (run via `cargo run -p xtask`)")?;
    let mut dir = PathBuf::from(manifest_dir);
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            let text = std::fs::read_to_string(&candidate)
                .with_context(|| format!("reading {}", candidate.display()))?;
            if text.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            return Err(anyhow::anyhow!(
                "no workspace root (Cargo.toml with [workspace]) found above xtask's manifest dir"
            ));
        }
    }
}
