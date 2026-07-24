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
//! - stale waivers: a waiver entry whose content (`site_hash`) no longer
//!   matches any live hit is itself a violation (BANNED #22 / TRUTH item 6).
//! - forbid roots: every crate root carries `#![forbid(unsafe_code)]`.

use crate::boundary::{Boundary, SourceFile};
use crate::engines::Hit;
use crate::identity;
use crate::waiver::WaiverFile;

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

/// Waivers whose content binding no longer matches any raw hit of their
/// check. Matching is by check/file/construct/`site_hash` (TRUTH item 6);
/// the waiver's `line` is display-only and never decides staleness.
pub fn stale_waivers(
    waivers: &WaiverFile,
    raw_hits: &[(String, Vec<Hit>)],
    files: &[SourceFile],
) -> Vec<Hit> {
    let mut stale = vec![];
    for w in &waivers.waiver {
        let live = raw_hits.iter().any(|(check, hits)| {
            *check == w.check && hits.iter().any(|h| identity::waiver_matches_hit(w, h, files))
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
    use crate::identity;
    use syn::spanned::Spanned;

    const HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn stale_waiver_is_reported_when_its_site_dies() {
        let toml = format!(
            r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "crates/x/src/a.rs"
line = 3
construct = "expect"
site_hash = "{HASH}"
why_not_sabotage = "a genuinely long justification for the fixture"
"#
        );
        let mut tf = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut tf, toml.as_bytes()).expect("write");
        let wf = WaiverFile::load(tf.path()).expect("loads");

        let src = "fn f() { let x = 1; x }";
        let ast = syn::parse_file(src).expect("parses");
        let real_hash = identity::site_hash(ast.items.first().expect("item"));
        let files = vec![SourceFile {
            rel_path: "crates/x/src/a.rs".to_string(),
            text: src.to_string(),
            ast,
        }];
        // Live hit whose enclosing item hash matches the waiver.
        let mut live_w = wf.waiver[0].clone();
        live_w.site_hash = real_hash.clone();
        let live_wf = WaiverFile {
            waiver: vec![live_w],
            scope_waiver: vec![],
        };
        let live = vec![(
            "expect".to_string(),
            vec![Hit {
                file: "crates/x/src/a.rs".to_string(),
                line: 1,
                construct: "expect".to_string(),
            }],
        )];
        assert!(
            stale_waivers(&live_wf, &live, &files).is_empty(),
            "matching content site = not stale"
        );
        let drifted: Vec<(String, Vec<Hit>)> = vec![("expect".to_string(), vec![])];
        assert_eq!(
            stale_waivers(&live_wf, &drifted, &files).len(),
            1,
            "dead site = reported"
        );
        // Content rename: same line/construct, different identity → stale.
        let renamed = syn::parse_file("fn f() { let y = 1; y }").expect("parses");
        let renamed_files = vec![SourceFile {
            rel_path: "crates/x/src/a.rs".to_string(),
            text: "fn f() { let y = 1; y }".to_string(),
            ast: renamed,
        }];
        assert_eq!(
            stale_waivers(&live_wf, &live, &renamed_files).len(),
            1,
            "rename a local must stale the waiver (site_hash mismatch)"
        );
    }

    #[test]
    fn item_6_proof_line_comment_above_does_not_stale_waiver() {
        let bare = "fn f() { let x = 1; x }";
        let bare_ast = syn::parse_file(bare).expect("parses");
        let hash = identity::site_hash(bare_ast.items.first().expect("item"));
        let noisy = "// inserted comment\nfn f() { let x = 1; x }";
        let noisy_ast = syn::parse_file(noisy).expect("parses");
        let item_line = noisy_ast.items.first().expect("item").span().start().line;
        let files = vec![SourceFile {
            rel_path: "crates/x/src/a.rs".to_string(),
            text: noisy.to_string(),
            ast: noisy_ast,
        }];
        let wf = WaiverFile {
            waiver: vec![crate::waiver::Waiver {
                check: "expect".to_string(),
                file: "crates/x/src/a.rs".to_string(),
                line: 1, // old display line, pre-insert
                construct: "expect".to_string(),
                site_hash: hash,
                why_not_sabotage: "a genuinely long justification for the fixture".to_string(),
            }],
            scope_waiver: vec![],
        };
        let live = vec![(
            "expect".to_string(),
            vec![Hit {
                file: "crates/x/src/a.rs".to_string(),
                line: item_line,
                construct: "expect".to_string(),
            }],
        )];
        assert!(
            stale_waivers(&wf, &live, &files).is_empty(),
            "insert // above the item must NOT stale — layout only"
        );
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
