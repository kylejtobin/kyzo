/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! One gate run: walk the boundary, run the grammar's banned-shape
//! predicates, the default-deny classifier, the relational and meta
//! passes, filter waivers where the grammar permits them, report. The
//! [`Verdict`] returned here is the ONLY source of the gate log and
//! counts artifact; hooks/CI parse those artifacts and never re-derive
//! them.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::boundary::{Boundary, SourceFile};
use crate::classify;
use crate::engines::{Hit, graph, meta, shape};
use crate::grammar::{Grammar, Laws};
use crate::waiver::WaiverFile;

pub struct Verdict {
    /// `GATE: PASS` or `GATE: FAIL <check, …>` — frozen contract.
    pub header: String,
    /// One `FAIL file:line — construct — law` line per violation, plus
    /// `SCOPE`/stale lines.
    pub report: String,
    /// `name:N … = TOTAL violations` — frozen contract for the banner.
    pub counts_line: String,
    pub red: bool,
}

/// Whether a waiver may cover hits of this check. Absolute bans and the
/// gate's self-checks are never waivable; everything else is, one entry
/// per hit, written only by the kyzo-waiver agent.
fn waivable(grammar: &Grammar, check: &str) -> bool {
    if grammar.bans_absolute.iter().any(|b| b == check) {
        return false;
    }
    !matches!(check, "agreement_registry" | "coverage" | "unparsed" | "stale_waivers")
}

pub fn run(root: &Path, only: Option<&str>) -> Result<Verdict> {
    let bite_src = std::fs::read_to_string(root.join("crates/bs-detector/tests/bite_proofs.rs"))
        .with_context(|| "reading bite_proofs.rs — a gate without bite proofs may not run")?;
    let grammar = Grammar::load(&root.join("crates/bs-detector/grammar.toml"), &bite_src)?;
    let laws = Laws::load(&root.join("crates/bs-detector/laws.toml"))?;
    let waivers = WaiverFile::load(&root.join("crates/bs-detector/waivers.toml"))?;
    let b = Boundary::walk(root)?;

    let mut report = String::new();
    let mut failed: Vec<String> = vec![];
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut raw_by_check: Vec<(String, Vec<Hit>)> = vec![];

    // The fixed pass list. Order is report order; every entry must hold a
    // law in laws.toml or the run refuses before any verdict exists.
    let ban_names: Vec<&str> = grammar
        .bans_absolute
        .iter()
        .chain(grammar.bans.iter())
        .map(|s| s.as_str())
        .collect();

    let mut passes: Vec<(&str, Vec<Hit>)> = vec![];
    for name in &ban_names {
        if let Some(o) = only {
            if o != *name {
                continue;
            }
        }
        let m = match shape::matcher_by_name(name) {
            Some(m) => m,
            None => anyhow::bail!("ban `{name}` vanished post-load"),
        };
        let scope = waivers.scope_for(name);
        let in_scope = |file: &str| -> bool {
            match scope {
                None => true,
                Some(s) => s.scope.iter().any(|p| file.starts_with(p.as_str())),
            }
        };
        let scoped: Vec<&SourceFile> =
            b.files.iter().filter(|f| in_scope(&f.rel_path)).collect();
        let hits: Vec<Hit> = scoped.iter().flat_map(|f| shape::run_matcher(m, f)).collect();
        passes.push((name, hits));
    }
    let run_pass = |name: &str| only.is_none() || only == Some(name);
    if run_pass("unclassified") {
        let hits: Vec<Hit> = b
            .files
            .iter()
            .flat_map(|f| classify::unclassified(&grammar, f))
            .collect();
        passes.push(("unclassified", hits));
    }
    let all: Vec<&SourceFile> = b.files.iter().collect();
    if run_pass("derive_bypass") {
        passes.push(("derive_bypass", graph::derive_bypass(&all)));
    }
    if run_pass("copy_detector") {
        passes.push(("copy_detector", graph::copy_detector(&all)));
    }
    if run_pass("agreement_registry") {
        let reg_path = root.join("crates/xtask/agreements.toml");
        let text = std::fs::read_to_string(&reg_path)
            .with_context(|| "reading agreements.toml — a missing registry is drift, not a pass")?;
        passes.push(("agreement_registry", graph::agreement_registry(&all, &text)));
    }
    if run_pass("coverage") {
        passes.push(("coverage", meta::coverage(&b)));
    }
    if run_pass("unparsed") {
        passes.push(("unparsed", meta::unparsed(&b)));
    }
    if run_pass("forbid_roots") {
        passes.push(("forbid_roots", meta::forbid_roots(&b)));
    }

    for (check, raw) in passes {
        let law = laws.require(check)?;
        raw_by_check.push((check.to_string(), raw.clone()));

        let violations: Vec<&Hit> = if waivable(&grammar, check) {
            // One waiver covers exactly ONE hit. Two violations of the
            // same construct sharing a line coordinate cannot ride one
            // entry — the duplicate-site refusal in WaiverFile::load
            // means the second occurrence stays red until FIXED.
            let entries = waivers.for_check(check);
            let mut consumed = vec![false; entries.len()];
            raw.iter()
                .filter(|h| {
                    let found = entries.iter().enumerate().find(|(i, w)| {
                        !consumed[*i]
                            && w.file == h.file
                            && w.line == h.line
                            && w.construct == h.construct
                    });
                    match found {
                        Some((i, _)) => {
                            consumed[i] = true;
                            false
                        }
                        None => true,
                    }
                })
                .collect()
        } else {
            raw.iter().collect()
        };

        if !violations.is_empty() {
            failed.push(check.to_string());
        }
        counts.insert(check.to_string(), violations.len());
        for h in &violations {
            report.push_str(&format!("FAIL {}:{} — {} — {}\n", h.file, h.line, h.construct, law));
        }
    }

    if only.is_none() {
        let stale = meta::stale_waivers(&waivers, &raw_by_check);
        laws.require("stale_waivers")?;
        if !stale.is_empty() {
            failed.push("stale_waivers".to_string());
            counts.insert("stale_waivers".to_string(), stale.len());
            for h in &stale {
                report.push_str(&format!("FAIL {}:{} — {}\n", h.file, h.line, h.construct));
            }
        }
    }
    for s in &waivers.scope_waiver {
        report.push_str(&format!(
            "SCOPE {} limited to {:?} — justification: {}\n",
            s.check, s.scope, s.why_full_scope_breaks
        ));
    }

    let total: usize = counts.values().sum();
    let red = !failed.is_empty();
    let header = if red {
        format!("GATE: FAIL {}", failed.join(", "))
    } else {
        "GATE: PASS".to_string()
    };
    let counts_line = {
        let mut parts: Vec<(&String, &usize)> = counts.iter().filter(|(_, n)| **n > 0).collect();
        parts.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let body: Vec<String> = parts.iter().map(|(k, v)| format!("{k}:{v}")).collect();
        format!("{} = {total} violations", body.join(" "))
    };

    Ok(Verdict {
        header,
        report,
        counts_line,
        red,
    })
}
