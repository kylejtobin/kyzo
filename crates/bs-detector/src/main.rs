/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The Bullshit Detector CLI — the one door, and the ONLY writer of the
//! gate log. Verdict contract (frozen; the Stop hook, the watcher, and CI
//! all parse it): line 1 of the log is `GATE: PASS` or
//! `GATE: FAIL <check, check, …>`; the counts artifact is one line,
//! `name:N …  = TOTAL violations`. All detection lives in the library;
//! this binary only parses arguments, runs, prints, writes, and exits.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(about = "the bullshit detector: default deny, one door, zero baseline")]
struct Cli {
    /// Repo root (defaults to the working directory).
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Run only this check (a ban name or pass name).
    #[arg(long)]
    only: Option<String>,
    /// Gate log path (line 1 is the verdict header).
    #[arg(long, default_value = "crates/xtask/gate.log")]
    log: PathBuf,
    /// Counts artifact path (the [GATE] banner's source).
    #[arg(long, default_value = "crates/xtask/gate-counts.txt")]
    counts: PathBuf,
    /// Print findings without writing the log/counts artifacts.
    #[arg(long)]
    dry_run: bool,
    /// Print the identity hash of one item: <file>#<ident>. Grant
    /// tooling: a waiver's site_hash/citation_hash come from here; a wrong
    /// hash is self-defeating (the entry never consumes and stales), so
    /// this door needs no trust.
    #[arg(long)]
    hash: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = cli
        .root
        .canonicalize()
        .with_context(|| format!("resolving root {}", cli.root.display()))?;

    if let Some(spec) = &cli.hash {
        let Some((file, ident)) = spec.split_once('#') else {
            anyhow::bail!("--hash requires <file>#<ident>");
        };
        let text = std::fs::read_to_string(root.join(file))
            .with_context(|| format!("reading {file}"))?;
        let ast = syn::parse_file(&text).with_context(|| format!("parsing {file}"))?;
        match bs_detector::identity::named_item_hash(&ast, ident) {
            Some(h) => {
                println!("{h}");
                return Ok(());
            }
            None => anyhow::bail!("item `{ident}` absent or ambiguous in {file}"),
        }
    }

    let v = bs_detector::run::run(&root, cli.only.as_deref())?;

    println!("{}", v.header);
    print!("{}", v.report);
    println!("[GATE] {}", v.counts_line);

    // A partial (--only) run NEVER writes the verdict artifacts: a
    // one-check log wearing the full-tree header is a scope lie the hooks
    // would believe.
    if !cli.dry_run && cli.only.is_none() {
        std::fs::write(root.join(&cli.log), format!("{}\n{}", v.header, v.report))
            .with_context(|| "writing gate log")?;
        std::fs::write(root.join(&cli.counts), format!("{}\n", v.counts_line))
            .with_context(|| "writing counts artifact")?;
    } else if cli.only.is_some() {
        eprintln!("note: --only run — verdict artifacts NOT written (partial scope never speaks for the tree)");
    }

    if v.red {
        std::process::exit(1); // INVARIANT(GateVerdict): the gate's red exit IS the verdict for hooks/CI — a named, audited circuit breaker, not an error swallow.
    }
    Ok(())
}
