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
use crate::boundary::{Boundary, Label, SourceFile};
use crate::citation;
use crate::classify;
use crate::engines::{Hit, behavior, graph, meta, shape};
use crate::grammar::{Grammar, Laws};
use crate::identity;
use crate::waiver::WaiverFile;

/// Whether the gate run is green or red — stored as a sum, never a bool field
/// (TRUTH item 9 / rust-values: a domain decision is not a bit).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateColor {
    Pass,
    Fail,
}

/// Gate outcome — frozen contract for the log and counts artifact.
///
/// Fields are private (TRUTH item 9). [`Verdict::admit`] is the sole
/// constructor. Text fields are [`Label`]; pass/fail is [`GateColor`].
pub struct Verdict {
    /// `GATE: PASS` or `GATE: FAIL <check, …>` — frozen contract.
    header: Label,
    /// One `FAIL file:line — construct — law` line per violation, plus
    /// `SCOPE`/stale lines.
    report: Label,
    /// `name:N … = TOTAL violations` — frozen contract for the banner.
    counts_line: Label,
    color: GateColor,
}

impl Verdict {
    /// Sole admission constructor.
    pub fn admit(
        header: impl Into<Label>,
        report: impl Into<Label>,
        counts_line: impl Into<Label>,
        color: GateColor,
    ) -> Self {
        Self {
            header: header.into(),
            report: report.into(),
            counts_line: counts_line.into(),
            color,
        }
    }

    pub fn header(&self) -> &str {
        self.header.as_str()
    }

    pub fn report(&self) -> &str {
        self.report.as_str()
    }

    pub fn counts_line(&self) -> &str {
        self.counts_line.as_str()
    }

    pub fn color(&self) -> GateColor {
        self.color
    }

    /// Process-exit helper: true when the gate is red.
    pub fn red(&self) -> bool {
        matches!(self.color, GateColor::Fail)
    }
}

/// Run-gate authority — tip 806/914: no free helpers.
pub struct RunLaw;

/// The one production door for the detector run.
pub const RUN: RunLaw = RunLaw;

impl RunLaw {
    /// Whether a waiver may cover hits of this check. Absolute bans and the
    /// gate's self-checks are never waivable; everything else is, one entry
    /// per hit, written only by the kyzo-waiver agent.
    fn waivable(&self, grammar: &Grammar, check: &str) -> bool {
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
        // Tip 650: every unseated kind is a first-class hard check
        // (`unclassified-fn`, `unclassified-struct`, …) — never waivable.
        if check.starts_with("unclassified-") {
            return false;
        }
        !matches!(
            check,
            "agreement_registry"
                | "coverage"
                | "unparsed"
                | "stale_waivers"
                | "dead_citation"
                | "pure_rust"
                | "unsafe_check"
                | "campaign_artifact"
        )
    }

    /// Hard check name for a non-condemned classify hit.
    ///
    /// Construct form is `unclassified-<kind>:<label>` (classify.rs). The
    /// check name is the exact prefix before `:`. Anything else is refused —
    /// no soft umbrella may absorb an unexpected construct shape.
    pub(crate) fn hard_unclassified_check(&self, construct: &str) -> Result<String> {
        let Some((prefix, _label)) = construct.split_once(':') else {
            anyhow::bail!(
                "classify hit `{construct}` has no kind prefix — refuse soft umbrella"
            );
        };
        if !prefix.starts_with("unclassified-") {
            anyhow::bail!(
                "classify hit `{construct}` is not unclassified-* and not condemned — refuse"
            );
        }
        Ok(prefix.to_string())
    }

    /// Tip 686 / 689: one check name → one meter. A second insert would
    /// overwrite and make TOTAL lower than the FAIL lines (double-count
    /// fraud / silent undercount). Refuse — never soft-merge.
    pub(crate) fn record_check_count(
        &self,
        counts: &mut BTreeMap<String, usize>,
        check: String,
        n: usize,
    ) -> Result<()> {
        if counts.contains_key(&check) {
            anyhow::bail!(
                "check `{check}` emitted twice in one run — refuse double-count / counts overwrite"
            );
        }
        counts.insert(check, n);
        Ok(())
    }

    pub fn run(&self, root: &Path, only: Option<&str>) -> Result<Verdict> {
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

        let mut passes: Vec<(String, Vec<Hit>)> = vec![];
        for name in &ban_names {
            if let Some(o) = only {
                if o != *name {
                    continue;
                }
            }
            let m = match shape::MATCHER_LOOKUP.by_name(name) {
                Some(m) => m,
                None => anyhow::bail!("ban `{name}` vanished post-load"),
            };
            let scope = waivers.scope_for(name);
            let in_scope = |file: &str| -> bool {
                // No scope waiver → whole tree. `is_none_or` avoids `None => true`.
                scope.is_none_or(|s| s.scope().iter().any(|p| file.starts_with(p.as_str())))
            };
            let scoped: Vec<&SourceFile> =
                b.files().iter().filter(|f| in_scope(f.rel_path())).collect();
            let hits: Vec<Hit> = scoped.iter().flat_map(|f| m.run(f)).collect();
            passes.push(((*name).to_string(), hits));
        }
        let run_pass = |name: &str| only.is_none() || only == Some(name);
        // Item 1 + tip 650: one walk, then partition. Condemned kinds report
        // under their own laws.toml name (red on sight). Unseated items report
        // under a HARD check named by construct prefix (`unclassified-fn`,
        // `unclassified-struct`, …) — the soft umbrella `unclassified` is gone.
        let condemned_names: Vec<&str> = grammar
            .condemned()
            .iter()
            .filter_map(|k| k.condemned_law_name())
            .collect();
        let need_classify = only.is_none()
            || only.is_some_and(|o| o.starts_with("unclassified-"))
            || condemned_names.iter().any(|n| run_pass(n));
        let all_files: Vec<&SourceFile> = b.files().iter().collect();
        let aliases = if need_classify
            || grammar.constructs().iter().any(|c| !c.bans().is_empty())
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
                .flat_map(|f| classify::CLASSIFY.classify_file(&grammar, f, aliases))
                .collect();
            let mut condemned_hits: BTreeMap<&str, Vec<Hit>> =
                condemned_names.iter().map(|n| (*n, Vec::new())).collect();
            let mut by_unclassified_kind: BTreeMap<String, Vec<Hit>> = BTreeMap::new();
            for h in all {
                if let Some(bucket) = condemned_hits.get_mut(h.construct()) {
                    bucket.push(h);
                } else {
                    let check = self.hard_unclassified_check(h.construct())?;
                    by_unclassified_kind.entry(check).or_default().push(h);
                }
            }
            for (name, hits) in by_unclassified_kind {
                if run_pass(&name) {
                    passes.push((name, hits));
                }
            }
            for name in &condemned_names {
                if run_pass(name) {
                    let hits = condemned_hits.remove(name).ok_or_else(|| {
                        anyhow::anyhow!(
                            "condemned hit bucket for `{name}` vanished post-partition — refuse"
                        )
                    })?;
                    passes.push(((*name).to_string(), hits));
                }
            }
        }
        // Item 5 (c): construct-scoped bans — matcher hits kept only when the
        // site line sits inside a shape-matched construct that lists the ban.
        {
            let mut scoped_ban_names: BTreeSet<&str> = BTreeSet::new();
            for c in grammar.constructs() {
                for ban in c.bans() {
                    scoped_ban_names.insert(ban.as_str());
                }
            }
            if let Some(aliases) = aliases.as_ref() {
                for name in scoped_ban_names {
                    if !run_pass(name) {
                        continue;
                    }
                    let m = match shape::MATCHER_LOOKUP.by_name(name) {
                        Some(m) => m,
                        None => anyhow::bail!("construct-scoped ban `{name}` vanished post-load"),
                    };
                    let scope = waivers.scope_for(name);
                    let in_scope = |file: &str| -> bool {
                        scope.is_none_or(|s| s.scope().iter().any(|p| file.starts_with(p.as_str())))
                    };
                    let mut hits = Vec::new();
                    for f in b.files().iter().filter(|f| in_scope(f.rel_path())) {
                        let spans = classify::CLASSIFY.scoped_construct_spans(&grammar, f, aliases);
                        let raw = m.run(f);
                        for h in raw {
                            let inside = spans.iter().any(|s| {
                                s.bans().iter().any(|b| b == name)
                                    && h.line() >= s.start_line()
                                    && h.line() <= s.end_line()
                            });
                            if inside {
                                hits.push(h);
                            }
                        }
                    }
                    passes.push((name.to_string(), hits));
                }
            }
        }
        let all: Vec<&SourceFile> = b.files().iter().collect();
        if run_pass("derive_bypass") {
            passes.push(("derive_bypass".to_string(), graph::GRAPH.derive_bypass(&all)));
        }
        if run_pass("copy_detector") {
            passes.push(("copy_detector".to_string(), graph::GRAPH.copy_detector(&all)));
        }
        if run_pass("agreement_registry") {
            let reg_path = root.join("crates/xtask/agreements.toml");
            let text = std::fs::read_to_string(&reg_path)
                .with_context(|| "reading agreements.toml — a missing registry is drift, not a pass")?;
            passes.push((
                "agreement_registry".to_string(),
                graph::GRAPH.agreement_registry(&all, &text),
            ));
        }
        if run_pass("total_refusal") {
            passes.push(("total_refusal".to_string(), graph::GRAPH.total_refusal(&all)));
        }
        if run_pass("sealed_public_door") {
            passes.push((
                "sealed_public_door".to_string(),
                graph::GRAPH.sealed_public_door(&all, grammar.hosts()),
            ));
        }
        if run_pass("config_once") {
            passes.push((
                "config_once".to_string(),
                graph::GRAPH.config_once(&all, grammar.config_once()),
            ));
        }
        if run_pass("coverage") {
            passes.push(("coverage".to_string(), meta::META.coverage(&b)));
        }
        if run_pass("unparsed") {
            passes.push(("unparsed".to_string(), meta::META.unparsed(&b)));
        }
        if run_pass("forbid_roots") {
            passes.push(("forbid_roots".to_string(), meta::META.forbid_roots(&b)));
        }
        // TRUTH item 10: live execution checks (ported from xtask/src/checks).
        if run_pass("pure_rust") {
            passes.push((
                "pure_rust".to_string(),
                behavior::BEHAVIOR.pure_rust_hits(root),
            ));
        }
        if run_pass("unsafe_check") {
            passes.push((
                "unsafe_check".to_string(),
                behavior::BEHAVIOR.unsafe_check_hits(root),
            ));
        }
        // Campaign artifact meta (build_script_sandbox seated as campaign).
        if run_pass("campaign_artifact") {
            passes.push((
                "campaign_artifact".to_string(),
                behavior::campaign::CAMPAIGN.verify_campaigns(root, laws.campaigns()),
            ));
        }

        for (check, raw) in passes {
            let law = laws.require(&check)?;
            raw_by_check.push((check.clone(), raw.clone()));

            let violations: Vec<&Hit> = if self.waivable(&grammar, &check) {
                // One waiver covers exactly ONE hit. Binding is by content
                // (site_hash of the enclosing item) — TRUTH item 6. The
                // waiver's `line` is display-only and must not gate matching,
                // or a `//` insert above the item would falsely stale it.
                let entries = waivers.for_check(&check);
                let mut consumed: BTreeSet<usize> = BTreeSet::new();
                raw.iter()
                    .filter(|h| {
                        let found = entries.iter().enumerate().find(|(i, w)| {
                            !consumed.contains(i)
                                && identity::IDENTITY.waiver_matches_hit(w, h, b.files())
                                // TRUTH item 7: a dead citation stops the waiver
                                // from applying (in addition to reporting it).
                                && citation::CITATION.citation_live(root, &laws, w)
                        });
                        if let Some((i, _)) = found {
                            consumed.insert(i);
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
                failed.push(check.clone());
            }
            self.record_check_count(&mut counts, check.clone(), violations.len())?;
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
            let stale = meta::META.stale_waivers(&waivers, &raw_by_check, b.files());
            laws.require("stale_waivers")?;
            if !stale.is_empty() {
                failed.push("stale_waivers".to_string());
                self.record_check_count(&mut counts, "stale_waivers".to_string(), stale.len())?;
                for h in &stale {
                    report.push_str(&format!(
                        "FAIL {}:{} — {}\n",
                        h.file(),
                        h.line(),
                        h.construct()
                    ));
                }
            }
            let dead = citation::CITATION.dead_citations(root, &laws, &waivers);
            laws.require("dead_citation")?;
            if !dead.is_empty() {
                failed.push("dead_citation".to_string());
                self.record_check_count(&mut counts, "dead_citation".to_string(), dead.len())?;
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
        for s in waivers.scope_waivers() {
            report.push_str(&format!(
                "SCOPE {} limited to {:?} — justification: {}\n",
                s.check(),
                s.scope(),
                s.why_full_scope_breaks()
            ));
        }

        let total: usize = counts.values().sum();
        let color = if failed.is_empty() {
            GateColor::Pass
        } else {
            GateColor::Fail
        };
        let header = match color {
            GateColor::Fail => format!("GATE: FAIL {}", failed.join(", ")),
            GateColor::Pass => "GATE: PASS".to_string(),
        };
        let counts_line = {
            let mut parts: Vec<(&String, &usize)> = counts.iter().filter(|(_, n)| **n > 0).collect();
            parts.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let body: Vec<String> = parts.iter().map(|(k, v)| format!("{k}:{v}")).collect();
            format!("{} = {total} violations", body.join(" "))
        };

        Ok(Verdict::admit(header, report, counts_line, color))
    }
}


/// Typed test refusal — file-level for `total_refusal` workspace-enum index (tip 777).
#[cfg(test)]
#[derive(Debug)]
enum RunProofRefuse {
    Tempdir,
    Mkdir,
    Copy,
    FixturesDir,
    Entry,
    Write,
    Run,
    Banner,
    ZeroCount,
    ProbeHit,
    Prefix,
    FirstCount,
    SecondSilent,
    Overwrite,
}

#[cfg(test)]
impl RunProofRefuse {
    fn require(self, cond: bool) -> Result<(), RunProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RunProofRefuse, RUN};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    type TestResult = Result<(), RunProofRefuse>;

    /// Receiver for run test helpers (tip 806/896).
    struct RunProofs;

    impl RunProofs {
        fn stage_root_with_free_fn(
            &self,
            probe_src: &str,
        ) -> Result<tempfile::TempDir, RunProofRefuse> {
            let dir = tempfile::tempdir().map_err(|_| RunProofRefuse::Tempdir)?;
            let root = dir.path();
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let det = root.join("crates/bs-detector");
            fs::create_dir_all(det.join("tests")).map_err(|_| RunProofRefuse::Mkdir)?;
            fs::create_dir_all(det.join("fixtures")).map_err(|_| RunProofRefuse::Mkdir)?;
            fs::create_dir_all(root.join("crates/probe/src")).map_err(|_| RunProofRefuse::Mkdir)?;
            for name in ["grammar.toml", "laws.toml", "waivers.toml"] {
                fs::copy(src.join(name), det.join(name)).map_err(|_| RunProofRefuse::Copy)?;
            }
            fs::copy(
                src.join("tests/bite_proofs.rs"),
                det.join("tests/bite_proofs.rs"),
            )
            .map_err(|_| RunProofRefuse::Copy)?;
            for entry in fs::read_dir(src.join("fixtures")).map_err(|_| RunProofRefuse::FixturesDir)?
            {
                let entry = entry.map_err(|_| RunProofRefuse::Entry)?;
                let name = entry.file_name();
                let to = det.join("fixtures").join(&name);
                fs::write(&to, "struct FixtureUnit;\n").map_err(|_| RunProofRefuse::Write)?;
            }
            fs::write(root.join("crates/probe/src/lib.rs"), probe_src)
                .map_err(|_| RunProofRefuse::Write)?;
            Ok(dir)
        }
    }

    const R: RunProofs = RunProofs;

    /// Tip 650 anti-fraud: free unseated fn meters as hard `unclassified-fn:N`
    /// on the counts banner — exact token equality, not soft contains/any.
    #[test]
    fn anti_fraud_counts_line_meters_unclassified_fn_exactly() -> TestResult {
        let dir = R.stage_root_with_free_fn("fn free_unseated() {}\n")?;
        let v = RUN.run(dir.path(), Some("unclassified-fn")).map_err(|_| RunProofRefuse::Run)?;
        let n = v
            .report()
            .lines()
            .filter(|line| {
                let Some((_, rest)) = line.split_once(" — ") else {
                    return false;
                };
                let Some((construct, _)) = rest.split_once(" — ") else {
                    return false;
                };
                construct.starts_with("unclassified-fn:")
            })
            .count();
        RunProofRefuse::Banner.require(
            v.counts_line() == format!("unclassified-fn:{n} = {n} violations"),
        )?;
        RunProofRefuse::ZeroCount.require(n != 0)?;
        let probe_hits = v
            .report()
            .lines()
            .filter(|line| {
                line.starts_with(
                    "FAIL crates/probe/src/lib.rs:1 — unclassified-fn:free_unseated — ",
                )
            })
            .count();
        RunProofRefuse::ProbeHit.require(probe_hits == 1)
    }

    #[test]
    fn hard_unclassified_check_extracts_prefix() -> TestResult {
        RunProofRefuse::Prefix.require(
            RUN.hard_unclassified_check("unclassified-fn:foo").ok().as_deref()
                == Some("unclassified-fn"),
        )?;
        RunProofRefuse::Prefix.require(
            RUN.hard_unclassified_check("unclassified-impl-fn:m")
                .ok()
                .as_deref()
                == Some("unclassified-impl-fn"),
        )?;
        RunProofRefuse::Prefix.require(RUN.hard_unclassified_check("extern_crate").is_err())?;
        RunProofRefuse::Prefix.require(RUN.hard_unclassified_check("unknown-syn-item-kind").is_err())
    }

    /// Tip 686: overwrite of counts[check] hid FAIL lines (TOTAL < truth).
    #[test]
    fn anti_fraud_duplicate_check_count_refuses() -> TestResult {
        let mut counts = BTreeMap::new();
        RUN.record_check_count(&mut counts, "await".into(), 3)
            .map_err(|_| RunProofRefuse::FirstCount)?;
        let err = match RUN.record_check_count(&mut counts, "await".into(), 1) {
            Err(e) => e,
            Ok(()) => return Err(RunProofRefuse::SecondSilent),
        };
        RunProofRefuse::SecondSilent.require(
            format!("{err}")
                == "check `await` emitted twice in one run — refuse double-count / counts overwrite",
        )?;
        RunProofRefuse::Overwrite.require(counts.get("await").copied() == Some(3))
    }
}
