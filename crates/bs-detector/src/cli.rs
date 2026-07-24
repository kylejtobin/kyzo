/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! CLI composition surface — tip 806/914: no free helpers in the binary door.
//! `main` is a one-call composition root; all argv/IO lives on [`CLI`].

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::boundary::Label;

/// CLI-door authority — tip 806/914: no free helpers.
pub struct CliLaw;

/// The one production door for the detector binary.
pub const CLI: CliLaw = CliLaw;

/// CLI door — fields private (TRUTH item 9). Sole admission is [`Cli::parse`]
/// (clap). `only` is [`Label`] via [`std::str::FromStr`], never `String`.
#[derive(Parser)]
#[command(about = "the bullshit detector: default deny, one door, zero baseline")]
struct Cli {
    /// Repo root (defaults to the working directory).
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Run only this check (a ban name or pass name).
    #[arg(long)]
    only: Option<Label>,
    /// Gate log path (line 1 is the verdict header).
    #[arg(long, default_value = "crates/xtask/gate.log")]
    log: PathBuf,
    /// Counts artifact path (the [GATE] banner's source).
    #[arg(long, default_value = "crates/xtask/gate-counts.txt")]
    counts: PathBuf,
    /// Print findings without writing the log/counts artifacts.
    #[arg(long)]
    dry_run: bool,
    /// Host observation instant (unix seconds) for campaign freshness.
    /// Required — the detector never reads the wall clock.
    #[arg(long)]
    now_unix: u64,
}

impl CliLaw {
    /// Binary composition target: parse argv, run, print, write, exit.
    pub fn run_from_env(&self) -> ExitCode {
        match self.try_run() {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e:?}");
                ExitCode::FAILURE
            }
        }
    }

    fn try_run(&self) -> Result<ExitCode> {
        // argv enters only through HOST_ENV.args (config-once seat).
        let cli = Cli::parse_from(crate::host_env::HOST_ENV.args());
        let root = cli
            .root
            .canonicalize()
            .with_context(|| format!("resolving root {}", cli.root.display()))?;

        let only = cli.only.as_ref().map(|l| l.as_str());
        let v = crate::run::RUN.run(&root, only, cli.now_unix)?;

        println!("{}", v.header());
        print!("{}", v.report());
        println!("[GATE] {}", v.counts_line());

        // A partial (--only) run NEVER writes the verdict artifacts: a
        // one-check log wearing the full-tree header is a scope lie the hooks
        // would believe.
        if !cli.dry_run && cli.only.is_none() {
            std::fs::write(root.join(&cli.log), format!("{}\n{}", v.header(), v.report()))
                .with_context(|| "writing gate log")?;
            std::fs::write(root.join(&cli.counts), format!("{}\n", v.counts_line()))
                .with_context(|| "writing counts artifact")?;
        } else if cli.only.is_some() {
            eprintln!("note: --only run — verdict artifacts NOT written (partial scope never speaks for the tree)");
        }

        // INVARIANT(GateVerdict): red exits FAILURE via Termination so destructors
        // run and block-buffered stdout finishes — not process::exit (tip 262).
        Ok(if v.red() {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        })
    }
}
