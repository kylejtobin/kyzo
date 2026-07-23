/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Engine 4 — Meta: the detector policing itself. Always-on:
//! - coverage: a run must prove it saw every file in the boundary.
//! - unparsed: a file syn can't read is invisible to every syn check, so
//!   it is reported, never skipped.
//! - stale waivers: a waiver whose content hash no longer encloses a live
//!   hit is itself a violation — rulings die with their content.
//! - dead citations: every waiver's anchor must exist and be unchanged.
//! - forbid roots: every crate root carries `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;

use crate::boundary::Boundary;
use crate::engines::Hit;
use crate::grammar::Laws;
use crate::identity;
use crate::waiver::{Citation, WaiverFile};

pub fn coverage(b: &Boundary) -> Vec<Hit> {
    b.coverage_proof()
        .missing
        .into_iter()
        .map(|f| Hit {
            file: f,
            line: 0,
            construct: "coverage_hole".to_string(),
        })
        .collect()
}

pub fn unparsed(b: &Boundary) -> Vec<Hit> {
    b.unparsed
        .iter()
        .map(|u| Hit {
            file: u.rel_path.clone(),
            line: 0,
            construct: format!("unparseable: {}", u.error),
        })
        .collect()
}

/// Waivers whose site no longer matches any raw hit of their check —
/// matched by CONTENT: file + construct + the identity hash of the item
/// enclosing the hit. The caller supplies every check's raw (pre-waiver)
/// hits annotated with their enclosing-item hash; lines never decide.
pub fn stale_waivers(
    waivers: &WaiverFile,
    raw_hits: &[(String, Vec<(Hit, Option<String>)>)],
) -> Vec<Hit> {
    let mut stale = vec![];
    for w in &waivers.waiver {
        let live = raw_hits.iter().any(|(check, hits)| {
            *check == w.check
                && hits.iter().any(|(h, hash)| {
                    h.file == w.file
                        && h.construct == w.construct
                        && hash.as_deref() == Some(w.site_hash.as_str())
                })
        });
        if !live {
            stale.push(Hit {
                file: w.file.clone(),
                line: w.line,
                construct: format!("stale_waiver:{}:{}", w.check, w.construct),
            });
        }
    }
    stale
}

/// Every waiver's citation, resolved against the tree on every run: a
/// missing target or a changed anchor is a violation. The attestation
/// forced truth at grant time; this keeps the factual anchor from rotting
/// out from under the prose afterward.
pub fn dead_citation(
    root: &std::path::Path,
    waivers: &WaiverFile,
    b: &Boundary,
    laws: &Laws,
) -> Vec<Hit> {
    let by_path: BTreeMap<&str, &crate::boundary::SourceFile> =
        b.files.iter().map(|f| (f.rel_path.as_str(), f)).collect();
    let mut hits = vec![];
    let mut dead = |w: &crate::waiver::Waiver, why: &str| {
        hits.push(Hit {
            file: w.file.clone(),
            line: w.line,
            construct: format!("dead_citation:{}:{}", w.citation, why),
        });
    };
    for w in &waivers.waiver {
        let citation = match Citation::parse(&w.citation) {
            Ok(c) => c,
            // Unreachable after load validation; reported, never skipped.
            Err(_) => {
                dead(w, "unparseable");
                continue;
            }
        };
        match citation {
            Citation::Law { name } => {
                if laws.require(&name).is_err() {
                    dead(w, "law-entry-missing");
                }
            }
            Citation::Item { file, ident } | Citation::Test { file, ident } => {
                let current = by_path
                    .get(file.as_str())
                    .and_then(|f| identity::named_item_hash(&f.ast, &ident));
                match (current, &w.citation_hash) {
                    (None, _) => dead(w, "target-missing-or-ambiguous"),
                    (Some(h), Some(rec)) if &h != rec => dead(w, "anchor-changed"),
                    _ => {}
                }
            }
            Citation::Doc { file, line } => {
                let text = std::fs::read_to_string(root.join(file.as_str())).unwrap_or_default();
                let found = text.lines().any(|l| l == line);
                let hash_ok = w
                    .citation_hash
                    .as_deref()
                    .is_some_and(|rec| blake3::hash(line.as_bytes()).to_hex().to_string() == rec);
                if !found || !hash_ok {
                    dead(w, "doc-line-missing-or-changed");
                }
            }
        }
    }
    hits
}

/// Every compilation root under `crates/` must forbid unsafe at the root:
/// lib/main roots, every extra binary root under src/bin/, and build
/// scripts — each is its own crate root where the forbid must live.
pub fn forbid_roots(b: &Boundary) -> Vec<Hit> {
    let mut hits = vec![];
    for f in &b.files {
        let is_root = f.rel_path.ends_with("/src/lib.rs")
            || f.rel_path.ends_with("/src/main.rs")
            || f.rel_path.contains("/src/bin/")
            || f.rel_path.ends_with("/build.rs");
        if is_root && !f.text.contains("#![forbid(unsafe_code)]") {
            hits.push(Hit {
                file: f.rel_path.clone(),
                line: 1,
                construct: "root_without_forbid_unsafe".to_string(),
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::SourceFile;

    #[test]
    fn stale_waiver_is_reported_when_its_content_dies() {
        let attestation = "FALSE. I read every line of this site. I know what max purity demands here and this is it. I searched for a purer form: I tried a typed length proof and it fails because the wire fixes the width; I tried a clamp and it fails because a clamp fabricates data. There is no purer form I am aware of. Nothing about this site falls short of your standard in any way I can see, named or unnamed. Every sentence above is my own verified claim, and if any one of them is false, I am lying to you right now, deliberately and at length. || GRANTER: FALSE. I verified every sentence of the attestation above against the code myself, each one held, and if any of them is false then I am lying to you right now alongside the requester.";
        let toml = format!(
            r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "crates/x/src/a.rs"
line = 3
construct = "expect"
site_hash = "{h}"
citation = "law:expect"
why_not_sabotage = '''{attestation}'''
"#,
            h = "a".repeat(64)
        );
        let mut tf = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut tf, toml.as_bytes()).expect("write");
        let wf = match WaiverFile::load(tf.path()) {
            Ok(w) => w,
            Err(e) => panic!("loads: {e:#}"),
        };

        let hit = Hit {
            file: "crates/x/src/a.rs".to_string(),
            line: 3,
            construct: "expect".to_string(),
        };
        let live = vec![(
            "expect".to_string(),
            vec![(hit.clone(), Some("a".repeat(64)))],
        )];
        assert!(stale_waivers(&wf, &live).is_empty(), "matching content = not stale");
        // Same site, same line — but the enclosing item's content changed.
        let drifted = vec![("expect".to_string(), vec![(hit, Some("b".repeat(64)))])];
        assert_eq!(stale_waivers(&wf, &drifted).len(), 1, "changed content = stale");
    }

    #[test]
    fn root_without_forbid_detonates() {
        let b = Boundary {
            files: vec![SourceFile {
                rel_path: "crates/x/src/lib.rs".to_string(),
                text: "pub fn f() {}\n".to_string(),
                ast: syn::parse_file("pub fn f() {}\n").expect("parses"),
            }],
            unparsed: vec![],
            existing: vec!["crates/x/src/lib.rs".to_string()],
        };
        assert_eq!(forbid_roots(&b).len(), 1);
    }
}
