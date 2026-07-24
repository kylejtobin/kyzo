/*
 * Copyright 2022, The Cozo Project Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */
/*
 * Copyright 2026, The KyzoDB Authors. Modified from the CozoDB original
 * (MPL-2.0). HTTP/REST `server` product protocol deleted (zone-bin.md +
 * decisions.md seats 15/18/92): the host is REPL + marshal-only adapters;
 * network carriage is the Kyzo envelope over NATS, not a second meaning door.
 * `exit(-1)` became `exit(1)` / ExitCode; errors print via `{e:?}` for miette.
 */

// Zero `unsafe` is a compiler guarantee here too, matching kyzo-core
// (`lib.rs`'s `#![forbid(unsafe_code)]`); `cargo xtask unsafe` checks
// for this attribute at both crate roots.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::repl::{ReplArgs, repl_main};

mod bulk;
mod engine;
mod repl;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct AppArgs {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the interactive REPL.
    Repl(ReplArgs),
}

// Returning ExitCode instead of calling process::exit keeps every
// destructor on the unwind-free path alive — the runtime and storage
// handles drop before the process code is surrendered.
fn main() -> ExitCode {
    match AppArgs::parse().command {
        Commands::Repl(args) => {
            if let Err(e) = repl_main(args) {
                eprintln!("{e:?}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}
