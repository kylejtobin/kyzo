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
        .missing()
        .iter()
        .cloned()
        .map(|f| Hit::admit(f, 0, "coverage_hole".to_string()))
        .collect()
}

pub fn unparsed(b: &Boundary) -> Vec<Hit> {
    b.unparsed()
        .iter()
        .map(|u| Hit::admit(u.rel_path().clone(), 0, format!("unparseable: {}", u.error())))
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
    for w in waivers.waivers() {
        let live = raw_hits.iter().any(|(check, hits)| {
            check.as_str() == w.check() && hits.iter().any(|h| identity::waiver_matches_hit(w, h, files))
        });
        if !live {
            stale.push(Hit::admit(w.file(), w.line(), format!("stale_waiver:{}:{}", w.check(), w.construct())));
        }
    }
    stale
}

/// Every compilation root under `crates/` must forbid unsafe at the root:
/// lib/main roots, every extra binary root under src/bin/, and build
/// scripts — each is its own crate root where the forbid must live.
pub fn forbid_roots(b: &Boundary) -> Vec<Hit> {
    let mut hits = vec![];
    for f in b.files() {
        let is_root = f.rel_path().ends_with("/src/lib.rs")
            || f.rel_path().ends_with("/src/main.rs")
            || f.rel_path().contains("/src/bin/")
            || f.rel_path().ends_with("/build.rs");
        if is_root && !f.text().contains("#![forbid(unsafe_code)]") {
            hits.push(Hit::admit(f.rel_path().to_string(), 1, "root_without_forbid_unsafe".to_string()));
        }
    }
    hits
}

/// Typed test refusal — file-level for `total_refusal` workspace-enum index (tip 777).
#[cfg(test)]
#[derive(Debug)]
enum MetaProofRefuse {
    Template,
    Fill,
    Parse,
    MissingItem,
    Tempfile,
    Write,
    Load,
    LiveNotStale,
    DeadNotReported,
    RenameNotStale,
    CommentStaled,
    ForbidMiss,
}

#[cfg(test)]
impl MetaProofRefuse {
    fn require(self, cond: bool) -> Result<(), MetaProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::SourceFile;
    use crate::identity;
    use syn::spanned::Spanned;

    type TestResult = Result<(), MetaProofRefuse>;

    const HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Receiver for meta test helpers (tip 806/896).
    struct MetaProofs;

    impl MetaProofs {
        fn valid_attestation_why(&self) -> Result<String, MetaProofRefuse> {
            use crate::waiver::AttestationTemplate;
            AttestationTemplate::load_canonical()
                .map_err(|_| MetaProofRefuse::Template)?
                .fill(&[
                    ("alt_one", "typed refusal at the site"),
                    ("reason_one", "the protocol admits no domain error channel"),
                    ("alt_two", "sentinel zero"),
                    ("reason_two", "zero is a live column value"),
                ])
                .map_err(|_| MetaProofRefuse::Fill)
        }

        fn toml_basic_escape(&self, s: &str) -> String {
            let mut out = String::from('"');
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }

    }

    const M: MetaProofs = MetaProofs;

    #[test]
    fn stale_waiver_is_reported_when_its_site_dies() -> TestResult {
        let src = "fn f() { let x = 1; x }";
        let ast = syn::parse_file(src).map_err(|_| MetaProofRefuse::Parse)?;
        let real_hash = identity::site_hash(
            ast.items.first().ok_or(MetaProofRefuse::MissingItem)?,
        );
        let files = vec![SourceFile::admit(
            "crates/x/src/a.rs".to_string(),
            src.to_string(),
            ast,
        )];

        // Live hit whose enclosing item hash matches the waiver from the start.
        let why = M.toml_basic_escape(&M.valid_attestation_why()?);
        let toml = format!(
            r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "crates/x/src/a.rs"
line = 3
construct = "expect"
site_hash = "{real_hash}"
citation = "expect"
anchor_hash = "{HASH}"
why_not_sabotage = {why}
"#
        );
        let mut tf = tempfile::NamedTempFile::new().map_err(|_| MetaProofRefuse::Tempfile)?;
        std::io::Write::write_all(&mut tf, toml.as_bytes()).map_err(|_| MetaProofRefuse::Write)?;
        let live_wf = WaiverFile::load(tf.path()).map_err(|_| MetaProofRefuse::Load)?;
        let live = vec![(
            "expect".to_string(),
            vec![Hit::admit("crates/x/src/a.rs".to_string(), 1, "expect".to_string())],
        )];
        MetaProofRefuse::LiveNotStale
            .require(stale_waivers(&live_wf, &live, &files).is_empty())?;
        let drifted: Vec<(String, Vec<Hit>)> = vec![("expect".to_string(), vec![])];
        MetaProofRefuse::DeadNotReported
            .require(stale_waivers(&live_wf, &drifted, &files).len() == 1)?;
        // Content rename: same line/construct, different identity → stale.
        let renamed =
            syn::parse_file("fn f() { let y = 1; y }").map_err(|_| MetaProofRefuse::Parse)?;
        let renamed_files = vec![SourceFile::admit(
            "crates/x/src/a.rs".to_string(),
            "fn f() { let y = 1; y }".to_string(),
            renamed,
        )];
        MetaProofRefuse::RenameNotStale
            .require(stale_waivers(&live_wf, &live, &renamed_files).len() == 1)
    }

    #[test]
    fn item_6_proof_line_comment_above_does_not_stale_waiver() -> TestResult {
        let bare = "fn f() { let x = 1; x }";
        let bare_ast = syn::parse_file(bare).map_err(|_| MetaProofRefuse::Parse)?;
        let hash = identity::site_hash(
            bare_ast.items.first().ok_or(MetaProofRefuse::MissingItem)?,
        );
        let noisy = "// inserted comment\nfn f() { let x = 1; x }";
        let noisy_ast = syn::parse_file(noisy).map_err(|_| MetaProofRefuse::Parse)?;
        let item_line = noisy_ast
            .items
            .first()
            .ok_or(MetaProofRefuse::MissingItem)?
            .span()
            .start()
            .line;
        let files = vec![SourceFile::admit(
            "crates/x/src/a.rs".to_string(),
            noisy.to_string(),
            noisy_ast,
        )];
        let why = M.toml_basic_escape(&M.valid_attestation_why()?);
        let toml = format!(
            r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "crates/x/src/a.rs"
line = 1
construct = "expect"
site_hash = "{hash}"
citation = "expect"
anchor_hash = "{HASH}"
why_not_sabotage = {why}
"#
        );
        let mut tf = tempfile::NamedTempFile::new().map_err(|_| MetaProofRefuse::Tempfile)?;
        std::io::Write::write_all(&mut tf, toml.as_bytes()).map_err(|_| MetaProofRefuse::Write)?;
        let wf = WaiverFile::load(tf.path()).map_err(|_| MetaProofRefuse::Load)?;
        let live = vec![(
            "expect".to_string(),
            vec![Hit::admit(
                "crates/x/src/a.rs".to_string(),
                item_line,
                "expect".to_string(),
            )],
        )];
        MetaProofRefuse::CommentStaled.require(stale_waivers(&wf, &live, &files).is_empty())
    }

    #[test]
    fn root_without_forbid_detonates() -> TestResult {
        let b = Boundary::admit(
            vec![SourceFile::admit(
                "crates/x/src/lib.rs".to_string(),
                "pub fn f() {}\n".to_string(),
                syn::parse_file("pub fn f() {}\n").map_err(|_| MetaProofRefuse::Parse)?,
            )],
            vec![],
            vec![crate::boundary::RelPath::admit("crates/x/src/lib.rs")],
        );
        MetaProofRefuse::ForbidMiss.require(forbid_roots(&b).len() == 1)
    }
}
