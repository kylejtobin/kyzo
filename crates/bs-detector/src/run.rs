/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! One gate run: walk the boundary, build the alias table, run the
//! grammar's banned-shape matchers and the default-deny classifier, the
//! relational and meta passes, filter waivers where the grammar permits
//! them, report. The [`Verdict`] returned here is the ONLY source of the
//! gate log and counts artifact; hooks/CI parse those artifacts and never
//! re-derive them.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::boundary::{Boundary, SourceFile};
use crate::classify::{self, AliasTable};
use crate::engines::{Hit, graph, meta, shape};
use crate::grammar::{Grammar, Laws};
use crate::identity;
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

/// Whether a waiver may cover hits of this check. Absolute bans, the
/// gate's self-checks, and seat drift are never waivable; everything else
/// is, one entry per hit, written only by the kyzo-waiver agent.
fn waivable(grammar: &Grammar, check: &str) -> bool {
    if grammar.is_absolute(check) {
        return false;
    }
    !matches!(
        check,
        "agreement_registry" | "coverage" | "unparsed" | "stale_waivers" | "seat_drift"
    )
}

/// The classifier-emitted check names, in report order. Every one must
/// hold a law in laws.toml; they appear in the pass list even at zero
/// hits so the law requirement is enforced on every run.
const CLASSIFY_CHECKS: [&str; 9] = [
    "unclassified",
    "condemned",
    "static_mut",
    "path_attr",
    "assign_expr",
    "nested_place_assign",
    "async_outside_io",
    "main_flow",
    "seat_drift",
];

pub fn run(root: &Path, only: Option<&str>) -> Result<Verdict> {
    let crate_dir = root.join("crates/bs-detector");
    let bite_src = std::fs::read_to_string(crate_dir.join("tests/bite_proofs.rs"))
        .with_context(|| "reading bite_proofs.rs — a gate without bite proofs may not run")?;
    let grammar = Grammar::load(
        &crate_dir.join("grammar.toml"),
        &bite_src,
        &crate_dir.join("fixtures"),
    )?;
    let laws = Laws::load(&crate_dir.join("laws.toml"))?;
    let waivers = WaiverFile::load(&crate_dir.join("waivers.toml"))?;
    let b = Boundary::walk(root)?;
    let aliases = AliasTable::build(&b.files)?;

    let mut report = String::new();
    let mut failed: Vec<String> = vec![];
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut raw_by_check: Vec<(String, Vec<(Hit, Option<String>)>)> = vec![];

    // The content-identity index: every item's span and hash, per file.
    // Rulings bind to these hashes; lines are display-only.
    let index_by_file: BTreeMap<&str, Vec<identity::ItemSpan>> = b
        .files
        .iter()
        .map(|f| (f.rel_path.as_str(), identity::item_index(&f.ast)))
        .collect();
    let hash_of = |h: &Hit| -> Option<String> {
        index_by_file
            .get(h.file.as_str())
            .and_then(|idx| identity::enclosing_hash(idx, h.line))
            .map(str::to_string)
    };

    let run_pass = |name: &str| only.is_none() || only == Some(name);

    // Shape-backed bans (expression + attribute jurisdictions). Names
    // registered in classify.rs are emitted by the classifier pass below.
    let mut passes: Vec<(String, Vec<Hit>)> = vec![];
    for name in grammar
        .bans_expression
        .iter()
        .chain(grammar.bans_attribute.iter())
    {
        if !run_pass(name) {
            continue;
        }
        let Some(m) = shape::matcher_by_name(name) else {
            continue; // classify-side rule; emitted below
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
        passes.push((name.clone(), hits));
    }

    // The default-deny classifier: one walk emits every classify check.
    if CLASSIFY_CHECKS.iter().any(|c| run_pass(c)) {
        let mut by_check: BTreeMap<&str, Vec<Hit>> = BTreeMap::new();
        for c in CLASSIFY_CHECKS {
            by_check.insert(c, vec![]);
        }
        for f in &b.files {
            for (check, hit) in classify::classify_file(&grammar, &aliases, f) {
                match by_check.get_mut(check.as_str()) {
                    Some(slot) => slot.push(hit),
                    None => anyhow::bail!(
                        "classifier emitted unknown check `{check}` — not in CLASSIFY_CHECKS"
                    ),
                }
            }
        }
        for c in CLASSIFY_CHECKS {
            if run_pass(c) {
                passes.push((c.to_string(), by_check.remove(c).unwrap_or_default()));
            }
        }
    }

    let all: Vec<&SourceFile> = b.files.iter().collect();
    if run_pass("derive_bypass") {
        passes.push(("derive_bypass".into(), graph::derive_bypass(&all)));
    }
    if run_pass("copy_detector") {
        passes.push(("copy_detector".into(), graph::copy_detector(&all)));
    }
    if run_pass("agreement_registry") {
        let reg_path = root.join("crates/xtask/agreements.toml");
        let text = std::fs::read_to_string(&reg_path)
            .with_context(|| "reading agreements.toml — a missing registry is drift, not a pass")?;
        passes.push(("agreement_registry".into(), graph::agreement_registry(&all, &text)));
    }
    if run_pass("coverage") {
        passes.push(("coverage".into(), meta::coverage(&b)));
    }
    if run_pass("unparsed") {
        passes.push(("unparsed".into(), meta::unparsed(&b)));
    }
    if run_pass("forbid_roots") {
        passes.push(("forbid_roots".into(), meta::forbid_roots(&b)));
    }

    if run_pass("dead_citation") {
        passes.push(("dead_citation".into(), meta::dead_citation(root, &waivers, &b, &laws)));
    }

    for (check, raw) in passes {
        let law = laws.require(&check)?;
        let annotated: Vec<(Hit, Option<String>)> =
            raw.iter().map(|h| (h.clone(), hash_of(h))).collect();
        raw_by_check.push((check.clone(), annotated.clone()));

        let violations: Vec<&Hit> = if waivable(&grammar, &check) {
            // One waiver covers exactly ONE hit, matched by CONTENT:
            // file + construct + the enclosing item's identity hash. The
            // duplicate-site refusal in WaiverFile::load means a second
            // occurrence in the same item stays red until FIXED.
            let entries = waivers.for_check(&check);
            let mut consumed = vec![false; entries.len()];
            annotated
                .iter()
                .filter(|(h, hash)| {
                    let found = entries.iter().enumerate().find(|(i, w)| {
                        !consumed[*i]
                            && w.file == h.file
                            && w.construct == h.construct
                            && hash.as_deref() == Some(w.site_hash.as_str())
                    });
                    match found {
                        Some((i, _)) => {
                            consumed[i] = true;
                            false
                        }
                        None => true,
                    }
                })
                .map(|(h, _)| h)
                .collect()
        } else {
            raw.iter().collect()
        };

        if !violations.is_empty() {
            failed.push(check.clone());
        }
        counts.insert(check.clone(), violations.len());
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
