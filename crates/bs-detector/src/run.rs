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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};

use crate::alias::AliasTable;
use crate::boundary::{Boundary, SourceFile};
use crate::citation;
use crate::classify;
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

/// Whether a waiver may cover hits of this check. Absolute bans and the
/// gate's self-checks are never waivable; everything else is, one entry
/// per hit, written only by the kyzo-waiver agent.
fn waivable(grammar: &Grammar, check: &str) -> bool {
    if grammar.bans_absolute().iter().any(|b| b == check) {
        return false;
    }
    // TRUTH item 1: condemned kinds are "red on sight" — the same absolute
    // standing as bans_absolute, expressed through the kind table instead
    // of the shape-ban list.
    if grammar
        .condemned()
        .iter()
        .any(|k| k.condemned_law_name() == Some(check))
    {
        return false;
    }
    !matches!(
        check,
        "agreement_registry"
            | "coverage"
            | "unparsed"
            | "stale_waivers"
            | "dead_citation"
            | "unclassified"
    )
}

pub fn run(root: &Path, only: Option<&str>) -> Result<Verdict> {
    let bite_src = std::fs::read_to_string(root.join("crates/bs-detector/tests/bite_proofs.rs"))
        .with_context(|| "reading bite_proofs.rs — a gate without bite proofs may not run")?;
    let grammar = Grammar::load(
        &root.join("crates/bs-detector/grammar.toml"),
        &bite_src,
        &root.join("crates/bs-detector/fixtures"),
    )?;
    let laws = Laws::load(&root.join("crates/bs-detector/laws.toml"))?;
    let waivers = WaiverFile::load(&root.join("crates/bs-detector/waivers.toml"))?;
    let b = Boundary::walk(root)?;

    let mut report = String::new();
    let mut failed: Vec<String> = vec![];
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut raw_by_check: Vec<(String, Vec<Hit>)> = vec![];

    // Expression + attribute jurisdictions (item 5 a/b). Construct-scoped
    // bans run after classify so span containment can see construct shapes.
    let ban_names: Vec<&str> = grammar
        .bans_absolute()
        .iter()
        .chain(grammar.bans().iter())
        .chain(grammar.bans_attribute().iter())
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
            // No scope waiver → whole tree. `is_none_or` avoids `None => true`.
            scope.is_none_or(|s| s.scope.iter().any(|p| file.starts_with(p.as_str())))
        };
        let scoped: Vec<&SourceFile> =
            b.files().iter().filter(|f| in_scope(f.rel_path())).collect();
        let hits: Vec<Hit> = scoped.iter().flat_map(|f| shape::run_matcher(m, f)).collect();
        passes.push((name, hits));
    }
    let run_pass = |name: &str| only.is_none() || only == Some(name);
    // Item 1: one walk, then partition. Condemned kinds report under their
    // own laws.toml name (red on sight, never absorbed by `unclassified`).
    // Seated items matching no construct report under `unclassified`.
    let condemned_names: Vec<&str> = grammar
        .condemned()
        .iter()
        .filter_map(|k| k.condemned_law_name())
        .collect();
    let need_classify = run_pass("unclassified")
        || condemned_names.iter().any(|n| run_pass(n));
    let all_files: Vec<&SourceFile> = b.files().iter().collect();
    let aliases = if need_classify
        || grammar.constructs().iter().any(|c| !c.bans.is_empty())
    {
        Some(
            AliasTable::build(&all_files)
                .with_context(|| "building item-4 workspace alias table")?,
        )
    } else {
        None
    };
    if need_classify {
        let aliases = aliases
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("alias table required for classify — refuse"))?;
        let all: Vec<Hit> = b
            .files()
            .iter()
            .flat_map(|f| classify::classify_file(&grammar, f, aliases))
            .collect();
        let mut condemned_hits: BTreeMap<&str, Vec<Hit>> =
            condemned_names.iter().map(|n| (*n, Vec::new())).collect();
        let mut unclassified_hits: Vec<Hit> = Vec::new();
        for h in all {
            if let Some(bucket) = condemned_hits.get_mut(h.construct()) {
                bucket.push(h);
            } else {
                unclassified_hits.push(h);
            }
        }
        if run_pass("unclassified") {
            passes.push(("unclassified", unclassified_hits));
        }
        for name in &condemned_names {
            if run_pass(name) {
                let hits = condemned_hits.remove(name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "condemned hit bucket for `{name}` vanished post-partition — refuse"
                    )
                })?;
                passes.push((name, hits));
            }
        }
    }
    // Item 5 (c): construct-scoped bans — matcher hits kept only when the
    // site line sits inside a shape-matched construct that lists the ban.
    {
        let mut scoped_ban_names: BTreeSet<&str> = BTreeSet::new();
        for c in grammar.constructs() {
            for ban in &c.bans {
                scoped_ban_names.insert(ban.as_str());
            }
        }
        if let Some(aliases) = aliases.as_ref() {
            for name in scoped_ban_names {
                if !run_pass(name) {
                    continue;
                }
                let m = match shape::matcher_by_name(name) {
                    Some(m) => m,
                    None => anyhow::bail!("construct-scoped ban `{name}` vanished post-load"),
                };
                let scope = waivers.scope_for(name);
                let in_scope = |file: &str| -> bool {
                    scope.is_none_or(|s| s.scope.iter().any(|p| file.starts_with(p.as_str())))
                };
                let mut hits = Vec::new();
                for f in b.files().iter().filter(|f| in_scope(f.rel_path())) {
                    let spans = classify::scoped_construct_spans(&grammar, f, aliases);
                    let raw = shape::run_matcher(m, f);
                    for h in raw {
                        let inside = spans.iter().any(|s| {
                            s.bans.iter().any(|b| b == name)
                                && h.line() >= s.start_line
                                && h.line() <= s.end_line
                        });
                        if inside {
                            hits.push(h);
                        }
                    }
                }
                passes.push((name, hits));
            }
        }
    }
    let all: Vec<&SourceFile> = b.files().iter().collect();
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
    if run_pass("total_refusal") {
        passes.push(("total_refusal", graph::total_refusal(&all)));
    }
    if run_pass("sealed_public_door") {
        passes.push((
            "sealed_public_door",
            graph::sealed_public_door(&all, grammar.hosts()),
        ));
    }
    if run_pass("config_once") {
        passes.push((
            "config_once",
            graph::config_once(&all, grammar.config_once()),
        ));
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
            // One waiver covers exactly ONE hit. Binding is by content
            // (site_hash of the enclosing item) — TRUTH item 6. The
            // waiver's `line` is display-only and must not gate matching,
            // or a `//` insert above the item would falsely stale it.
            let entries = waivers.for_check(check);
            let mut consumed = vec![false; entries.len()];
            raw.iter()
                .filter(|h| {
                    let found = entries.iter().enumerate().find(|(i, w)| {
                        !consumed[*i]
                            && identity::waiver_matches_hit(w, h, b.files())
                            // TRUTH item 7: a dead citation stops the waiver
                            // from applying (in addition to reporting it).
                            && citation::citation_live(root, &laws, w)
                    });
                    if let Some((i, _)) = found {
                        consumed[i] = true;
                        false
                    } else {
                        true
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
            report.push_str(&format!(
                "FAIL {}:{} — {} — {}\n",
                h.file(),
                h.line(),
                h.construct(),
                law
            ));
        }
    }

    if only.is_none() {
        let stale = meta::stale_waivers(&waivers, &raw_by_check, b.files());
        laws.require("stale_waivers")?;
        if !stale.is_empty() {
            failed.push("stale_waivers".to_string());
            counts.insert("stale_waivers".to_string(), stale.len());
            for h in &stale {
                report.push_str(&format!(
                    "FAIL {}:{} — {}\n",
                    h.file(),
                    h.line(),
                    h.construct()
                ));
            }
        }
        let dead = citation::dead_citations(root, &laws, &waivers);
        laws.require("dead_citation")?;
        if !dead.is_empty() {
            failed.push("dead_citation".to_string());
            counts.insert("dead_citation".to_string(), dead.len());
            for h in &dead {
                report.push_str(&format!(
                    "FAIL {}:{} — {}\n",
                    h.file(),
                    h.line(),
                    h.construct()
                ));
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
