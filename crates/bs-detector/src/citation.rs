/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Citation anchors (TRUTH item 7): every waiver cites a checkable anchor
//! that must exist and be unchanged.
//!
//! Grammar (exactly one form per citation string):
//! - laws.toml law name — no `#`, no `::`
//! - `file#item-path` — repo-relative file, `#`, then `fn` or `Type::method`
//! - test fn path — `file.rs::fn_name` (contains `::`, no `#`)
//! - `decisions.md#N` — seat number N in docs/decisions.md
//!
//! Grant records `anchor_hash` = blake3 of the anchor's identity. Missing
//! target or hash mismatch is a `dead_citation` violation; the waiver
//! stops applying.

use std::path::Path;

use quote::ToTokens;
use syn::visit::Visit;

use crate::engines::Hit;
use crate::grammar::Laws;
use crate::identity;
use crate::waiver::{Waiver, WaiverFile};

/// Parsed citation form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Citation {
    LawName(String),
    FileItem { file: String, item_path: String },
    TestFn { file: String, fn_name: String },
    DecisionsSeat(u32),
}

impl Citation {
    /// Parse the citation grammar. Empty / ambiguous forms refuse.
    pub fn parse(raw: &str) -> Result<Citation, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("citation is empty".into());
        }
        if let Some(rest) = s.strip_prefix("decisions.md#") {
            let n: u32 = rest
                .parse()
                .map_err(|_| format!("decisions.md seat id must be a number, got `{rest}`"))?;
            if n == 0 {
                return Err("decisions.md seat id must be >= 1".into());
            }
            return Ok(Citation::DecisionsSeat(n));
        }
        if s.contains('#') {
            let (file, item) = s.split_once('#').expect("contains #");
            if file.is_empty() || item.is_empty() {
                return Err(format!("file#item-path malformed: `{s}`"));
            }
            return Ok(Citation::FileItem {
                file: file.to_string(),
                item_path: item.to_string(),
            });
        }
        if s.contains("::") {
            let (file, name) = s
                .rsplit_once("::")
                .ok_or_else(|| format!("test fn path malformed: `{s}`"))?;
            if !file.ends_with(".rs") || name.is_empty() || name.contains(':') {
                return Err(format!(
                    "test fn path must be `path/to/file.rs::fn_name`, got `{s}`"
                ));
            }
            return Ok(Citation::TestFn {
                file: file.to_string(),
                fn_name: name.to_string(),
            });
        }
        // laws.toml law name: identifier matching [[law]].name (snake / R-*).
        if s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Ok(Citation::LawName(s.to_string()));
        }
        Err(format!(
            "citation `{s}` matches none of: laws.toml law name, file#item-path, file.rs::fn, decisions.md#N"
        ))
    }
}

/// Blake3 hex of arbitrary anchor bytes (law text, seat block, …).
pub fn anchor_bytes_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Resolve a citation to its live identity hash, or None if the target is
/// missing.
pub fn resolve_hash(root: &Path, laws: &Laws, citation: &Citation) -> Option<String> {
    match citation {
        Citation::LawName(name) => laws.get(name).map(|text| anchor_bytes_hash(text.as_bytes())),
        Citation::FileItem { file, item_path } => {
            let ast = parse_rs(root, file)?;
            let item = find_item(&ast, item_path)?;
            Some(identity::site_hash(&item))
        }
        Citation::TestFn { file, fn_name } => {
            let ast = parse_rs(root, file)?;
            let item = find_fn(&ast, fn_name)?;
            Some(identity::site_hash(&item))
        }
        Citation::DecisionsSeat(n) => {
            let text = std::fs::read_to_string(root.join("docs/decisions.md")).ok()?;
            let block = seat_block(&text, *n)?;
            Some(anchor_bytes_hash(block.as_bytes()))
        }
    }
}

/// Whether a waiver's citation still resolves to the recorded hash.
pub fn citation_live(root: &Path, laws: &Laws, w: &Waiver) -> bool {
    let Ok(c) = Citation::parse(&w.citation) else {
        return false;
    };
    match resolve_hash(root, laws, &c) {
        Some(h) => h == w.anchor_hash,
        None => false,
    }
}

/// Every waiver whose citation is missing or whose anchor hash drifted.
pub fn dead_citations(root: &Path, laws: &Laws, waivers: &WaiverFile) -> Vec<Hit> {
    let mut hits = vec![];
    for w in &waivers.waiver {
        if citation_live(root, laws, w) {
            continue;
        }
        hits.push(Hit {
            file: w.file.clone(),
            line: w.line,
            construct: format!("dead_citation:{}", w.citation),
        });
    }
    hits
}

fn parse_rs(root: &Path, rel: &str) -> Option<syn::File> {
    let text = std::fs::read_to_string(root.join(rel)).ok()?;
    syn::parse_file(&text).ok()
}

/// Owned token-stream carrier so `site_hash` can borrow it.
struct FoundItem(proc_macro2::TokenStream);

impl ToTokens for FoundItem {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(self.0.clone());
    }
}

fn find_item(ast: &syn::File, item_path: &str) -> Option<FoundItem> {
    if let Some((ty, method)) = item_path.split_once("::") {
        return find_impl_method(ast, ty, method);
    }
    find_named_item(ast, item_path)
}

fn find_fn(ast: &syn::File, name: &str) -> Option<FoundItem> {
    find_named_item(ast, name)
}

fn find_named_item(ast: &syn::File, name: &str) -> Option<FoundItem> {
    struct V<'a> {
        name: &'a str,
        found: Option<FoundItem>,
    }
    impl<'ast> Visit<'ast> for V<'_> {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            if self.found.is_none() && node.sig.ident == self.name {
                self.found = Some(FoundItem(node.to_token_stream()));
            }
            syn::visit::visit_item_fn(self, node);
        }
        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            if self.found.is_none() && node.sig.ident == self.name {
                self.found = Some(FoundItem(node.to_token_stream()));
            }
            syn::visit::visit_impl_item_fn(self, node);
        }
        fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
            if self.found.is_none() && node.ident == self.name {
                self.found = Some(FoundItem(node.to_token_stream()));
            }
            syn::visit::visit_item_struct(self, node);
        }
        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            if self.found.is_none() && node.ident == self.name {
                self.found = Some(FoundItem(node.to_token_stream()));
            }
            syn::visit::visit_item_enum(self, node);
        }
    }
    let mut v = V { name, found: None };
    v.visit_file(ast);
    v.found
}

fn find_impl_method(ast: &syn::File, ty: &str, method: &str) -> Option<FoundItem> {
    struct V<'a> {
        ty: &'a str,
        method: &'a str,
        in_match: bool,
        found: Option<FoundItem>,
    }
    impl<'ast> Visit<'ast> for V<'_> {
        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            let self_ty = type_path_tail(&node.self_ty);
            let prev = self.in_match;
            self.in_match = self_ty.as_deref() == Some(self.ty);
            syn::visit::visit_item_impl(self, node);
            self.in_match = prev;
        }
        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            if self.in_match && self.found.is_none() && node.sig.ident == self.method {
                self.found = Some(FoundItem(node.to_token_stream()));
            }
            syn::visit::visit_impl_item_fn(self, node);
        }
    }
    let mut v = V {
        ty,
        method,
        in_match: false,
        found: None,
    };
    v.visit_file(ast);
    v.found
}

fn type_path_tail(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// Extract the prose block for seat `n` from decisions.md (from the
/// `n. **` heading through the line before the next seat or EOF).
fn seat_block(text: &str, n: u32) -> Option<String> {
    let start_pat = format!("{n}. **");
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|l| l.starts_with(&start_pat))?;
    let mut end = lines.len();
    for (i, l) in lines.iter().enumerate().skip(start + 1) {
        // Next numbered seat: `^\d+\. \*\*`
        let trimmed = l.trim_start();
        if let Some(dot) = trimmed.find(". **") {
            let num = &trimmed[..dot];
            if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                end = i;
                break;
            }
        }
    }
    Some(lines[start..end].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_temp_rs(dir: &Path, rel: &str, src: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&path, src).expect("write");
    }

    #[test]
    fn citation_grammar_parses_four_forms() {
        assert_eq!(
            Citation::parse("unwrap").unwrap(),
            Citation::LawName("unwrap".into())
        );
        assert_eq!(
            Citation::parse("crates/x/src/a.rs#foo").unwrap(),
            Citation::FileItem {
                file: "crates/x/src/a.rs".into(),
                item_path: "foo".into(),
            }
        );
        assert_eq!(
            Citation::parse("crates/x/src/a.rs::bite_foo").unwrap(),
            Citation::TestFn {
                file: "crates/x/src/a.rs".into(),
                fn_name: "bite_foo".into(),
            }
        );
        assert_eq!(
            Citation::parse("decisions.md#2").unwrap(),
            Citation::DecisionsSeat(2)
        );
        assert_eq!(
            Citation::parse("R-citation-prose").unwrap(),
            Citation::LawName("R-citation-prose".into())
        );
        assert!(Citation::parse("crates/x/src/a.rs#").is_err());
        assert!(Citation::parse("not a form !!!").is_err());
        assert!(Citation::parse("").is_err());
    }

    #[test]
    fn item_7_proof_edit_cited_test_fn_is_dead_citation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let laws_path = root.join("laws.toml");
        std::fs::write(
            &laws_path,
            r#"
[[law]]
name = "expect"
law = "fixture law text"
caught_by = "fixture"
"#,
        )
        .expect("laws");
        let laws = Laws::load(&laws_path).expect("laws load");

        let file = "crates/probe/src/lib.rs";
        let before = "#[cfg(test)]\nmod tests {\n    fn cited() { let x = 1; x }\n}\n";
        write_temp_rs(root, file, before);
        let c = Citation::parse(&format!("{file}::cited")).expect("parse");
        let hash = resolve_hash(root, &laws, &c).expect("resolves before edit");

        let w = Waiver {
            check: "expect".into(),
            file: file.into(),
            line: 3,
            construct: "expect".into(),
            site_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            citation: format!("{file}::cited"),
            anchor_hash: hash,
            why_not_sabotage: "a genuinely long justification for the fixture".into(),
        };
        let wf = WaiverFile {
            waiver: vec![w.clone()],
            scope_waiver: vec![],
        };
        assert!(
            dead_citations(root, &laws, &wf).is_empty(),
            "live citation must not be dead"
        );

        let after = "#[cfg(test)]\nmod tests {\n    fn cited() { let y = 1; y }\n}\n";
        write_temp_rs(root, file, after);
        let dead = dead_citations(root, &laws, &wf);
        assert_eq!(
            dead.len(),
            1,
            "edit the body of a cited test fn must dead the citation: {dead:?}"
        );
        assert!(
            !citation_live(root, &laws, &w),
            "dead citation must stop the waiver from applying"
        );
    }

    #[test]
    fn law_name_and_decisions_seat_resolve() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates")
            .parent()
            .expect("repo")
            .to_path_buf();
        let laws = Laws::load(&root.join("crates/bs-detector/laws.toml")).expect("laws");
        let c = Citation::parse("stale_waivers").expect("parse");
        let h = resolve_hash(&root, &laws, &c).expect("law resolves");
        assert_eq!(h.len(), 64);
        let seat = Citation::parse("decisions.md#1").expect("seat");
        let sh = resolve_hash(&root, &laws, &seat).expect("seat resolves");
        assert_eq!(sh.len(), 64);
        assert!(resolve_hash(&root, &laws, &Citation::DecisionsSeat(99999)).is_none());
    }

    #[test]
    fn file_item_path_hashes_with_identity_tokens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let laws_path = root.join("laws.toml");
        std::fs::write(
            &laws_path,
            r#"[[law]]
name = "x"
law = "x"
caught_by = "x"
"#,
        )
        .expect("laws");
        let laws = Laws::load(&laws_path).expect("load");
        let file = "crates/x/src/lib.rs";
        write_temp_rs(root, file, "fn target() { let a = 1; a }\n");
        let c = Citation::parse(&format!("{file}#target")).expect("parse");
        let h1 = resolve_hash(root, &laws, &c).expect("h1");
        write_temp_rs(root, file, "fn target() { let b = 1; b }\n");
        let h2 = resolve_hash(root, &laws, &c).expect("h2");
        assert_ne!(h1, h2, "item-path citation must use identity_tokens");
    }
}
