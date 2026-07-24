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

use crate::boundary::Label;
use crate::engines::Hit;
use crate::grammar::Laws;
use crate::identity;
use crate::waiver::{Waiver, WaiverFile};

/// Parsed citation form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Citation {
    LawName(Label),
    FileItem { file: Label, item_path: Label },
    TestFn { file: Label, fn_name: Label },
    DecisionsSeat(u32),
}

/// Refuse reasons for [`Citation::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CitationRefuse {
    Empty,
    DecisionsSeatNotNumber { rest: Label },
    DecisionsSeatZero,
    FileItemMalformed { raw: Label },
    TestFnMalformed { raw: Label },
    UnknownForm { raw: Label },
}

impl std::fmt::Display for CitationRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CitationRefuse::Empty => f.write_str("citation is empty"),
            CitationRefuse::DecisionsSeatNotNumber { rest } => write!(
                f,
                "decisions.md seat id must be a number, got `{}`",
                rest.as_str()
            ),
            CitationRefuse::DecisionsSeatZero => {
                f.write_str("decisions.md seat id must be >= 1")
            }
            CitationRefuse::FileItemMalformed { raw } => {
                write!(f, "file#item-path malformed: `{}`", raw.as_str())
            }
            CitationRefuse::TestFnMalformed { raw } => write!(
                f,
                "test fn path must be `path/to/file.rs::fn_name`, got `{}`",
                raw.as_str()
            ),
            CitationRefuse::UnknownForm { raw } => write!(
                f,
                "citation `{}` matches none of: laws.toml law name, file#item-path, file.rs::fn, decisions.md#N",
                raw.as_str()
            ),
        }
    }
}

impl Citation {
    /// Parse the citation grammar. Empty / ambiguous forms refuse.
    pub fn parse(raw: &str) -> Result<Citation, CitationRefuse> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(CitationRefuse::Empty);
        }
        if let Some(rest) = s.strip_prefix("decisions.md#") {
            let n: u32 = rest.parse().map_err(|_| CitationRefuse::DecisionsSeatNotNumber {
                rest: Label::admit(rest),
            })?;
            if n == 0 {
                return Err(CitationRefuse::DecisionsSeatZero);
            }
            return Ok(Citation::DecisionsSeat(n));
        }
        if s.contains('#') {
            let Some((file, item)) = s.split_once('#') else {
                return Err(CitationRefuse::FileItemMalformed {
                    raw: Label::admit(s),
                });
            };
            if file.is_empty() || item.is_empty() {
                return Err(CitationRefuse::FileItemMalformed {
                    raw: Label::admit(s),
                });
            }
            return Ok(Citation::FileItem {
                file: Label::admit(file),
                item_path: Label::admit(item),
            });
        }
        if s.contains("::") {
            let Some((file, name)) = s.rsplit_once("::") else {
                return Err(CitationRefuse::TestFnMalformed {
                    raw: Label::admit(s),
                });
            };
            if !file.ends_with(".rs") || name.is_empty() || name.contains(':') {
                return Err(CitationRefuse::TestFnMalformed {
                    raw: Label::admit(s),
                });
            }
            return Ok(Citation::TestFn {
                file: Label::admit(file),
                fn_name: Label::admit(name),
            });
        }
        // laws.toml law name: identifier matching [[law]].name (snake / R-*).
        if s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Ok(Citation::LawName(Label::admit(s)));
        }
        Err(CitationRefuse::UnknownForm {
            raw: Label::admit(s),
        })
    }
}

/// Owned token-stream carrier so `site_hash` can borrow it.
struct FoundItem(proc_macro2::TokenStream);

impl ToTokens for FoundItem {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(self.0.clone());
    }
}

/// AST walk that binds a citation name to the first matching item.
struct NamedItemFinder {
    name: Label,
    found: Option<FoundItem>,
}

impl<'ast> Visit<'ast> for NamedItemFinder {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if self.found.is_none() && node.sig.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_fn(self, node);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if self.found.is_none() && node.sig.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_impl_item_fn(self, node);
    }
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if self.found.is_none() && node.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_struct(self, node);
    }
    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if self.found.is_none() && node.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_enum(self, node);
    }
    // Tip 686: citing const/type/static/trait was blind (resolve None →
    // dead or, worse, a wrong earlier match). Exact name, first hit.
    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if self.found.is_none() && node.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_const(self, node);
    }
    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if self.found.is_none() && node.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_static(self, node);
    }
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if self.found.is_none() && node.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_type(self, node);
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if self.found.is_none() && node.ident == self.name.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_item_trait(self, node);
    }
}

/// AST walk that binds `Type::method` citations.
struct ImplMethodFinder {
    ty: Label,
    method: Label,
    in_match: bool,
    found: Option<FoundItem>,
}

impl<'ast> Visit<'ast> for ImplMethodFinder {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let self_ty = CITATION.type_path_tail(&node.self_ty);
        let prev = self.in_match;
        self.in_match = self_ty.as_deref() == Some(self.ty.as_str());
        syn::visit::visit_item_impl(self, node);
        self.in_match = prev;
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if self.in_match && self.found.is_none() && node.sig.ident == self.method.as_str() {
            self.found = Some(FoundItem(node.to_token_stream()));
        }
        syn::visit::visit_impl_item_fn(self, node);
    }
}

/// Citation-anchor resolution authority — tip 806/914: no free helpers.
pub struct CitationLaw;

/// The one production door for citation anchor resolution.
pub const CITATION: CitationLaw = CitationLaw;

impl CitationLaw {
    /// Blake3 hex of arbitrary anchor bytes (law text, seat block, …).
    pub fn anchor_bytes_hash(&self, bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    /// Resolve a citation to its live identity hash, or None if the target is
    /// missing.
    pub fn resolve_hash(&self, root: &Path, laws: &Laws, citation: &Citation) -> Option<String> {
        match citation {
            Citation::LawName(name) => laws
                .get(name.as_str())
                .map(|text| self.anchor_bytes_hash(text.as_bytes())),
            Citation::FileItem { file, item_path } => {
                let ast = self.parse_rs(root, file.as_str())?;
                let item = self.find_item(&ast, item_path.as_str())?;
                Some(identity::IDENTITY.site_hash(&item))
            }
            Citation::TestFn { file, fn_name } => {
                let ast = self.parse_rs(root, file.as_str())?;
                let item = self.find_fn(&ast, fn_name.as_str())?;
                Some(identity::IDENTITY.site_hash(&item))
            }
            Citation::DecisionsSeat(n) => {
                let text = std::fs::read_to_string(root.join("docs/decisions.md")).ok()?;
                let block = self.seat_block(&text, *n)?;
                Some(self.anchor_bytes_hash(block.as_bytes()))
            }
        }
    }

    /// Whether a waiver's citation still resolves to the recorded hash.
    pub fn citation_live(&self, root: &Path, laws: &Laws, w: &Waiver) -> bool {
        let Ok(c) = Citation::parse(w.citation()) else {
            return false;
        };
        match self.resolve_hash(root, laws, &c) {
            Some(h) => h == w.anchor_hash(),
            None => false,
        }
    }

    /// Every waiver whose citation is missing or whose anchor hash drifted.
    pub fn dead_citations(&self, root: &Path, laws: &Laws, waivers: &WaiverFile) -> Vec<Hit> {
        let mut hits = vec![];
        for w in waivers.waivers() {
            if self.citation_live(root, laws, w) {
                continue;
            }
            hits.push(Hit::admit(
                w.file(),
                w.line(),
                format!("dead_citation:{}", w.citation()),
            ));
        }
        hits
    }

    fn parse_rs(&self, root: &Path, rel: &str) -> Option<syn::File> {
        let text = std::fs::read_to_string(root.join(rel)).ok()?;
        syn::parse_file(&text).ok()
    }

    fn find_item(&self, ast: &syn::File, item_path: &str) -> Option<FoundItem> {
        if let Some((ty, method)) = item_path.split_once("::") {
            return self.find_impl_method(ast, ty, method);
        }
        self.find_named_item(ast, item_path)
    }

    fn find_fn(&self, ast: &syn::File, name: &str) -> Option<FoundItem> {
        self.find_named_item(ast, name)
    }

    fn find_named_item(&self, ast: &syn::File, name: &str) -> Option<FoundItem> {
        let mut v = NamedItemFinder {
            name: name.into(),
            found: None,
        };
        v.visit_file(ast);
        v.found
    }

    fn find_impl_method(&self, ast: &syn::File, ty: &str, method: &str) -> Option<FoundItem> {
        let mut v = ImplMethodFinder {
            ty: ty.into(),
            method: method.into(),
            in_match: false,
            found: None,
        };
        v.visit_file(ast);
        v.found
    }

    fn type_path_tail(&self, ty: &syn::Type) -> Option<String> {
        // if-let chain — syn::Type is non_exhaustive, so a match `_ =>` would be
        // catchall_arm (tip 794). Unhandled shapes are citation-blind by design.
        if let syn::Type::Path(p) = ty {
            return p.path.segments.last().map(|s| s.ident.to_string());
        }
        // Tip 686: `impl &Foo` / `impl (Foo)` were citation-blind for Type::method.
        if let syn::Type::Reference(r) = ty {
            return self.type_path_tail(&r.elem);
        }
        if let syn::Type::Paren(p) = ty {
            return self.type_path_tail(&p.elem);
        }
        if let syn::Type::Group(g) = ty {
            return self.type_path_tail(&g.elem);
        }
        None
    }

    /// Extract the prose block for seat `n` from decisions.md (from the
    /// `n. **` heading through the line before the next seat or EOF).
    fn seat_block(&self, text: &str, n: u32) -> Option<String> {
        let start_pat = format!("{n}. **");
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.iter().position(|l| l.starts_with(&start_pat))?;
        let end = lines
            .iter()
            .enumerate()
            .skip(start + 1)
            .find_map(|(i, l)| {
                // Next numbered seat: `^\d+\. \*\*`
                let trimmed = l.trim_start();
                let dot = trimmed.find(". **")?;
                let num = &trimmed[..dot];
                if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                    Some(i)
                } else {
                    None
                }
            })
            .unwrap_or(lines.len());
        Some(lines[start..end].join("\n"))
    }
}

/// Typed test refusal — file-level for `total_refusal` workspace-enum index (tip 777).
#[cfg(test)]
#[derive(Debug)]
enum CitationProofRefuse {
    Mkdir,
    Write,
    TempDir,
    LawsWrite,
    LawsLoad,
    Parse,
    Resolve,
    LawNameForm,
    FileItemForm,
    TestFnForm,
    DecisionsSeatForm,
    RLawNameForm,
    MalformedMustErr,
    GarbageMustErr,
    EmptyMustErr,
    LiveMustNotBeDead,
    EditMustDead,
    DeadMustStopWaiver,
    Template,
    Load,
    CratesParent,
    RepoRoot,
    HashLen,
    MissingSeatMustNone,
    HashMustChange,
    ConstResolveBlind,
    ConstHashMustChange,
    ImplRefResolveBlind,
}
#[cfg(test)]
impl CitationProofRefuse {
    fn require(self, cond: bool) -> Result<(), CitationProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::{Citation, CitationProofRefuse, Laws, Path, WaiverFile, CITATION};
    use std::path::PathBuf;

    type TestResult = Result<(), CitationProofRefuse>;

    /// Receiver for citation test helpers (tip 806/896).
    struct CitationProofs;

    impl CitationProofs {
        fn write_temp_rs(&self, dir: &Path, rel: &str, src: &str) -> TestResult {
            let path = dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|_| CitationProofRefuse::Mkdir)?;
            }
            std::fs::write(&path, src).map_err(|_| CitationProofRefuse::Write)?;
            Ok(())
        }

        fn fixture_laws(&self, root: &Path, body: &str) -> Result<Laws, CitationProofRefuse> {
            let laws_path = root.join("laws.toml");
            std::fs::write(&laws_path, body).map_err(|_| CitationProofRefuse::LawsWrite)?;
            Laws::load(&laws_path).map_err(|_| CitationProofRefuse::LawsLoad)
        }

        fn temp_root(&self) -> Result<tempfile::TempDir, CitationProofRefuse> {
            tempfile::tempdir().map_err(|_| CitationProofRefuse::TempDir)
        }
    }

    const C: CitationProofs = CitationProofs;

    #[test]
    fn citation_grammar_parses_four_forms() -> TestResult {
        CitationProofRefuse::LawNameForm.require(Citation::parse("unwrap") == Ok(Citation::LawName("unwrap".into())))?;
        CitationProofRefuse::FileItemForm.require(Citation::parse("crates/x/src/a.rs#foo")
                == Ok(Citation::FileItem {
                    file: "crates/x/src/a.rs".into(),
                    item_path: "foo".into(),
                }))?;
        CitationProofRefuse::TestFnForm.require(Citation::parse("crates/x/src/a.rs::bite_foo")
                == Ok(Citation::TestFn {
                    file: "crates/x/src/a.rs".into(),
                    fn_name: "bite_foo".into(),
                }))?;
        CitationProofRefuse::DecisionsSeatForm.require(Citation::parse("decisions.md#2") == Ok(Citation::DecisionsSeat(2)))?;
        CitationProofRefuse::RLawNameForm.require(Citation::parse("R-citation-prose")
                == Ok(Citation::LawName("R-citation-prose".into())))?;
        CitationProofRefuse::MalformedMustErr.require(Citation::parse("crates/x/src/a.rs#").is_err())?;
        CitationProofRefuse::GarbageMustErr.require(Citation::parse("not a form !!!").is_err())?;
        CitationProofRefuse::EmptyMustErr.require(Citation::parse("").is_err())
    }

    #[test]
    fn item_7_proof_edit_cited_test_fn_is_dead_citation() -> TestResult {
        let dir = C.temp_root()?;
        let root = dir.path();
        let laws = C.fixture_laws(
            root,
            r#"
[[law]]
name = "expect"
law = "fixture law text"
caught_by = "fixture"
"#,
        )?;

        let file = "crates/probe/src/lib.rs";
        let before = "#[cfg(test)]\nmod tests {\n    fn cited() { let x = 1; x }\n}\n";
        C.write_temp_rs(root, file, before)?;
        let c = Citation::parse(&format!("{file}::cited")).map_err(|_| CitationProofRefuse::Parse)?;
        let hash =
            CITATION.resolve_hash(root, &laws, &c).ok_or(CitationProofRefuse::Resolve)?;

        let template = crate::waiver::AttestationTemplate::load_canonical()
            .map_err(|_| CitationProofRefuse::Template)?;
        let why = template
            .fill(&[
                ("alt_one", "a typed Result refusal at this call site"),
                ("reason_one", "fixture reason one"),
                ("alt_two", "returning a sentinel"),
                ("reason_two", "fixture reason two"),
            ])
            .map_err(|_| CitationProofRefuse::Template)?;
        let waivers_toml = format!(
            "scope_waiver = []\n\n[[waiver]]\ncheck = \"expect\"\nfile = {file:?}\nline = 3\nconstruct = \"expect\"\nsite_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\ncitation = \"{file}::cited\"\nanchor_hash = \"{hash}\"\nwhy_not_sabotage = {why:?}\n"
        );
        let waivers_path = root.join("waivers.toml");
        std::fs::write(&waivers_path, &waivers_toml).map_err(|_| CitationProofRefuse::Write)?;
        let wf = WaiverFile::load(&waivers_path).map_err(|_| CitationProofRefuse::Load)?;
        let w = wf.waivers()[0].clone();

        CitationProofRefuse::LiveMustNotBeDead.require(CITATION.dead_citations(root, &laws, &wf).is_empty())?;

        let after = "#[cfg(test)]\nmod tests {\n    fn cited() { let y = 1; y }\n}\n";
        C.write_temp_rs(root, file, after)?;
        let dead = CITATION.dead_citations(root, &laws, &wf);
        CitationProofRefuse::EditMustDead.require(dead.len() == 1)?;
        CitationProofRefuse::DeadMustStopWaiver.require(!CITATION.citation_live(root, &laws, &w))
    }

    #[test]
    fn law_name_and_decisions_seat_resolve() -> TestResult {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or(CitationProofRefuse::CratesParent)?
            .parent()
            .ok_or(CitationProofRefuse::RepoRoot)?
            .to_path_buf();
        let laws = Laws::load(&root.join("crates/bs-detector/laws.toml"))
            .map_err(|_| CitationProofRefuse::LawsLoad)?;
        let c = Citation::parse("stale_waivers").map_err(|_| CitationProofRefuse::Parse)?;
        let h = CITATION.resolve_hash(&root, &laws, &c).ok_or(CitationProofRefuse::Resolve)?;
        CitationProofRefuse::HashLen.require(h.len() == 64)?;
        let seat = Citation::parse("decisions.md#1").map_err(|_| CitationProofRefuse::Parse)?;
        let sh = CITATION.resolve_hash(&root, &laws, &seat).ok_or(CitationProofRefuse::Resolve)?;
        CitationProofRefuse::HashLen.require(sh.len() == 64)?;
        CitationProofRefuse::MissingSeatMustNone.require(CITATION.resolve_hash(&root, &laws, &Citation::DecisionsSeat(99999)).is_none())
    }

    #[test]
    fn file_item_path_hashes_with_identity_tokens() -> TestResult {
        let dir = C.temp_root()?;
        let root = dir.path();
        let laws = C.fixture_laws(
            root,
            r#"[[law]]
name = "x"
law = "x"
caught_by = "x"
"#,
        )?;
        let file = "crates/x/src/lib.rs";
        C.write_temp_rs(root, file, "fn target() { let a = 1; a }\n")?;
        let c = Citation::parse(&format!("{file}#target")).map_err(|_| CitationProofRefuse::Parse)?;
        let h1 = CITATION.resolve_hash(root, &laws, &c).ok_or(CitationProofRefuse::Resolve)?;
        C.write_temp_rs(root, file, "fn target() { let b = 1; b }\n")?;
        let h2 = CITATION.resolve_hash(root, &laws, &c).ok_or(CitationProofRefuse::Resolve)?;
        CitationProofRefuse::HashMustChange.require(h1 != h2)
    }

    /// Tip 686: const citations were resolve-None blind.
    #[test]
    fn anti_fraud_file_item_const_citation_resolves() -> TestResult {
        let dir = C.temp_root()?;
        let root = dir.path();
        let laws = C.fixture_laws(
            root,
            r#"[[law]]
name = "x"
law = "x"
caught_by = "x"
"#,
        )?;
        let file = "crates/x/src/lib.rs";
        C.write_temp_rs(root, file, "const TARGET: u8 = 1;\n")?;
        let c = Citation::parse(&format!("{file}#TARGET")).map_err(|_| CitationProofRefuse::Parse)?;
        let h = CITATION.resolve_hash(root, &laws, &c).ok_or(CitationProofRefuse::ConstResolveBlind)?;
        CitationProofRefuse::HashLen.require(h.len() == 64)?;
        C.write_temp_rs(root, file, "const TARGET: u8 = 2;\n")?;
        let h2 = CITATION.resolve_hash(root, &laws, &c).ok_or(CitationProofRefuse::Resolve)?;
        CitationProofRefuse::ConstHashMustChange.require(h != h2)
    }

    /// Tip 686: `impl &Type { fn m }` was type_path_tail-blind.
    #[test]
    fn anti_fraud_impl_ref_self_ty_method_citation_resolves() -> TestResult {
        let dir = C.temp_root()?;
        let root = dir.path();
        let laws = C.fixture_laws(
            root,
            r#"[[law]]
name = "x"
law = "x"
caught_by = "x"
"#,
        )?;
        let file = "crates/x/src/lib.rs";
        C.write_temp_rs(
            root,
            file,
            "struct Foo;\nimpl &Foo { fn method(&self) { let a = 1; let _ = a; } }\n",
        )?;
        let c = Citation::parse(&format!("{file}#Foo::method"))
            .map_err(|_| CitationProofRefuse::Parse)?;
        let h = CITATION.resolve_hash(root, &laws, &c).ok_or(CitationProofRefuse::ImplRefResolveBlind)?;
        CitationProofRefuse::HashLen.require(h.len() == 64)
    }
}
