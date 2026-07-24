/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Site identity (TRUTH item 6): a ruling binds to CONTENT.
//!
//! `identity_tokens` is the item's token stream stringified — identifiers
//! and literals byte-verbatim. The site hash is blake3 of that string.
//! Doc comments are attributes, therefore tokens, therefore content:
//! editing one changes the identity. Plain `//` comments and
//! whitespace/layout are not tokens and do not.
//!
//! `normalize_tokens` in `engines/graph.rs` collapses identifiers for the
//! copy detector's clone job. It is never used here. A rename that is
//! invisible to the clone shingles is still a content change for identity.

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::boundary::SourceFile;
use crate::engines::Hit;
use crate::waiver::Waiver;

/// The canonical identity string of an item: its token stream, stringified.
/// Layout-independent; identifier- and literal-exact.
pub fn identity_tokens(item: &dyn ToTokens) -> String {
    let ts: TokenStream = item.to_token_stream();
    ts.to_string()
}

/// The site hash a declared-fn seat and a waiver swear to: blake3 of
/// [`identity_tokens`], lowercase hex.
pub fn site_hash(item: &dyn ToTokens) -> String {
    blake3::hash(identity_tokens(item).as_bytes())
        .to_hex()
        .to_string()
}

/// Site hash of the innermost item-like node whose span covers `line`.
/// Used to bind a hit (which carries a display line) to content.
pub fn enclosing_item_site_hash(ast: &syn::File, line: usize) -> Option<String> {
    let mut v = Enclosing {
        line,
        best: None,
    };
    v.visit_file(ast);
    v.best.map(|c| c.hash.to_string())
}

/// Look up the content hash for a detector hit via its file + display line.
pub fn hit_site_hash(files: &[SourceFile], h: &Hit) -> Option<String> {
    let f = files.iter().find(|f| f.rel_path() == h.file())?;
    enclosing_item_site_hash(f.ast(), h.line())
}

/// Content binding for a waiver against a hit. Lines are display-only:
/// matching is check/file/construct/`site_hash`, never `w.line == h.line()`.
pub fn waiver_matches_hit(w: &Waiver, h: &Hit, files: &[SourceFile]) -> bool {
    w.file() == h.file().as_str()
        && w.construct() == h.construct()
        && hit_site_hash(files, h).as_deref() == Some(w.site_hash())
}

struct Candidate {
    start: usize,
    end: usize,
    hash: crate::boundary::Label,
}

struct Enclosing {
    line: usize,
    best: Option<Candidate>,
}

impl Enclosing {
    fn consider(&mut self, node: &dyn ToTokens, span: proc_macro2::Span) {
        let start = span.start().line;
        let end = span.end().line;
        if self.line < start || self.line > end {
            return;
        }
        let tighter = match &self.best {
            None => true,
            Some(c) => (end - start) < (c.end - c.start),
        };
        if tighter {
            self.best = Some(Candidate {
                start,
                end,
                hash: crate::boundary::Label::admit(site_hash(node)),
            });
        }
    }
}

impl<'ast> Visit<'ast> for Enclosing {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        self.consider(node, node.span());
        syn::visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        self.consider(node, node.span());
        syn::visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        self.consider(node, node.span());
        syn::visit::visit_trait_item(self, node);
    }
}

/// Typed test refusal — file-level for `total_refusal` workspace-enum index (tip 777).
#[cfg(test)]
#[derive(Debug)]
enum IdentityProofRefuse {
    Parse,
    MissingItem,
    LayoutBreaksIdentity,
    RenameKeepsIdentity,
    DocKeepsIdentity,
    LocalRenameKeepsIdentity,
    LineCommentBreaksIdentity,
    EnclosingHashMismatch,
    IdentityNormalizesIdents,
    IdentsNotVerbatim,
    WaiverMissesOnSiteHash,
    DriftedWaiverStillMatches,
}
#[cfg(test)]
impl IdentityProofRefuse {
    fn require(self, cond: bool) -> Result<(), IdentityProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
struct IdentityProofs;

#[cfg(test)]
impl IdentityProofs {
    fn item(&self, src: &str) -> Result<syn::Item, IdentityProofRefuse> {
        syn::parse_str(src).map_err(|_| IdentityProofRefuse::Parse)
    }

    fn file(&self, src: &str) -> Result<syn::File, IdentityProofRefuse> {
        syn::parse_file(src).map_err(|_| IdentityProofRefuse::Parse)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), IdentityProofRefuse>;

    const PROOFS: IdentityProofs = IdentityProofs;

    #[test]
    fn layout_change_keeps_identity_and_content_change_breaks_it() -> TestResult {
        let a = site_hash(&PROOFS.item("fn f(x: u64) -> u64 { x }")?);
        let b = site_hash(&PROOFS.item("fn f(x: u64)  ->\n    u64 { x }")?);
        IdentityProofRefuse::LayoutBreaksIdentity.require(a == b)?;

        let c = site_hash(&PROOFS.item("fn f(y: u64) -> u64 { y }")?);
        IdentityProofRefuse::RenameKeepsIdentity.require(a != c)?;

        let d = site_hash(&PROOFS.item("/// documented\nfn f(x: u64) -> u64 { x }")?);
        IdentityProofRefuse::DocKeepsIdentity.require(a != d)
    }

    #[test]
    fn item_6_proof_rename_local_changes_site_hash() -> TestResult {
        let before = site_hash(&PROOFS.item("fn f() { let x = 1; x }")?);
        let after = site_hash(&PROOFS.item("fn f() { let y = 1; y }")?);
        IdentityProofRefuse::LocalRenameKeepsIdentity.require(before != after)
    }

    #[test]
    fn item_6_proof_line_comment_above_item_keeps_site_hash() -> TestResult {
        let bare = PROOFS.file("fn f() { let x = 1; x }")?;
        let with_noise = PROOFS.file("// noise above the item\nfn f() { let x = 1; x }")?;
        let bare_item = bare.items.first().ok_or(IdentityProofRefuse::MissingItem)?;
        let noise_item = with_noise
            .items
            .first()
            .ok_or(IdentityProofRefuse::MissingItem)?;
        let h_bare = site_hash(bare_item);
        let h_noise = site_hash(noise_item);
        IdentityProofRefuse::LineCommentBreaksIdentity.require(h_bare == h_noise)?;
        // Enclosing lookup at the shifted line still yields the same hash.
        let line = noise_item.span().start().line;
        IdentityProofRefuse::EnclosingHashMismatch.require(enclosing_item_site_hash(&with_noise, line).as_deref() == Some(h_bare.as_str()))
    }

    #[test]
    fn item_6_identity_keeps_identifiers_verbatim_unlike_clone_normalize() -> TestResult {
        // graph::normalize_tokens collapses idents to "id" for clone shingles.
        // Identity must NOT: two rename-apart bodies must differ here.
        let a = identity_tokens(&PROOFS.item("fn f() { let alpha = 1; alpha }")?);
        let b = identity_tokens(&PROOFS.item("fn f() { let beta = 1; beta }")?);
        IdentityProofRefuse::IdentityNormalizesIdents.require(a != b)?;
        IdentityProofRefuse::IdentsNotVerbatim.require(a.contains("alpha") && b.contains("beta"))
    }

    #[test]
    fn item_6_waiver_matches_by_site_hash_not_line() -> TestResult {
        let src = "// shift\nfn f() { let x = 1; x }";
        let ast = PROOFS.file(src)?;
        let (item_line, hash) = {
            let first = ast.items.first().ok_or(IdentityProofRefuse::MissingItem)?;
            (first.span().start().line, site_hash(first))
        };
        let files = vec![SourceFile::admit(
            "crates/x/src/a.rs".to_string(),
            src.to_string(),
            ast,
        )];
        let w = Waiver::admit(
            "expect",
            "crates/x/src/a.rs",
            1, // deliberately wrong display line
            "expect",
            hash.clone(),
            "expect",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "a genuinely long justification for the fixture",
        );
        let h = Hit::admit("crates/x/src/a.rs".to_string(), item_line, "expect".to_string());
        IdentityProofRefuse::WaiverMissesOnSiteHash.require(waiver_matches_hit(&w, &h, &files))?;
        let drifted = Waiver::admit(
            "expect",
            "crates/x/src/a.rs",
            1,
            "expect",
            "0".repeat(64),
            "expect",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "a genuinely long justification for the fixture",
        );
        IdentityProofRefuse::DriftedWaiverStillMatches.require(!waiver_matches_hit(&drifted, &h, &files))
    }
}
