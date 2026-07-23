/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The default-deny classifier: every item in the boundary — every kind,
//! every impl/trait interior — is an instance of a grammar construct, a
//! condemned kind, or a violation. The classifier only accepts — it never
//! argues. Code conforms to the grammar; the grammar never chases code.
//!
//! String-carrying is decided by type STRUCTURE (a syn::Type walk joined
//! to a workspace alias table), never by spelling — `Restrict` is clean,
//! `type Name = String` is red at the alias and at every use.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use syn::visit::Visit;

use crate::boundary::{SourceFile, span_line};
use crate::engines::Hit;
use crate::grammar::{ConstructKind, Grammar, StructuralRule};
use crate::identity;

// ---------------------------------------------------------------------------
// classify-side rule registry (bans implemented here, not in engines/shape)
// ---------------------------------------------------------------------------

/// The classify-side matcher names. Grammar::load accepts a ban name iff it
/// is registered here or in `engines::shape`.
pub const SCOPED_RULES: [&str; 7] = [
    "static_mut",
    "path_attr",
    "assign_expr",
    "nested_place_assign",
    "async_outside_io",
    "main_flow",
    "empty_test",
];

pub fn scoped_rule_registered(name: &str) -> bool {
    SCOPED_RULES.contains(&name)
}

// ---------------------------------------------------------------------------
// the alias table: type Name = ... and use path as Name, workspace-wide
// ---------------------------------------------------------------------------

/// The alias table. `type Name = T` aliases are workspace-global (a
/// collision — one ident aliased to different targets — resolves
/// CONSERVATIVELY: if any target is string-carrying, the ident is; the
/// safe direction for a deny gate is the loud one). `use path as Name`
/// renames are FILE-scoped: imports bind per module, and keying them
/// globally manufactures false cycles between unrelated modules (the
/// recorded IncLiteral↔Literal swap between kyzo-core and kyzo-trials).
pub struct AliasTable {
    types: BTreeMap<String, Vec<syn::Type>>,
    renames_by_file: BTreeMap<String, BTreeMap<String, Vec<syn::Type>>>,
}

impl AliasTable {
    /// Build from every `type Name = T` and every `use path as Name` in the
    /// boundary, then prove every chain resolves: a cycle refuses at load.
    pub fn build(files: &[SourceFile]) -> anyhow::Result<AliasTable> {
        struct V {
            types: BTreeMap<String, Vec<syn::Type>>,
            renames: BTreeMap<String, Vec<syn::Type>>,
        }
        impl<'ast> Visit<'ast> for V {
            fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
                self.types
                    .entry(node.ident.to_string())
                    .or_default()
                    .push((*node.ty).clone());
                syn::visit::visit_item_type(self, node);
            }
            fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
                collect_renames(&node.tree, &mut Vec::new(), &mut self.renames);
                syn::visit::visit_item_use(self, node);
            }
        }
        fn collect_renames(
            tree: &syn::UseTree,
            prefix: &mut Vec<String>,
            out: &mut BTreeMap<String, Vec<syn::Type>>,
        ) {
            match tree {
                syn::UseTree::Path(p) => {
                    prefix.push(p.ident.to_string());
                    collect_renames(&p.tree, prefix, out);
                    prefix.pop();
                }
                syn::UseTree::Rename(r) => {
                    let mut segs = prefix.clone();
                    segs.push(r.ident.to_string());
                    let path = segs.join("::");
                    if let Ok(ty) = syn::parse_str::<syn::Type>(&path) {
                        out.entry(r.rename.to_string()).or_default().push(ty);
                    }
                }
                syn::UseTree::Group(g) => {
                    for t in &g.items {
                        collect_renames(t, prefix, out);
                    }
                }
                syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
            }
        }

        let mut types = BTreeMap::new();
        let mut renames_by_file = BTreeMap::new();
        for f in files {
            let mut v = V {
                types: std::mem::take(&mut types),
                renames: BTreeMap::new(),
            };
            v.visit_file(&f.ast);
            types = v.types;
            if !v.renames.is_empty() {
                renames_by_file.insert(f.rel_path.clone(), v.renames);
            }
        }
        let table = AliasTable {
            types,
            renames_by_file,
        };
        // Prove resolution: every chain terminates in every file context.
        // Re-entry = cycle = load Err.
        let no_renames = BTreeMap::new();
        for ident in table.types.keys() {
            let mut visiting = BTreeSet::new();
            table.resolve_ident(ident, &no_renames, &mut visiting)?;
        }
        for renames in table.renames_by_file.values() {
            for ident in renames.keys() {
                let mut visiting = BTreeSet::new();
                table.resolve_ident(ident, renames, &mut visiting)?;
            }
        }
        Ok(table)
    }

    fn resolve_ident(
        &self,
        ident: &str,
        renames: &BTreeMap<String, Vec<syn::Type>>,
        visiting: &mut BTreeSet<String>,
    ) -> anyhow::Result<bool> {
        if !visiting.insert(ident.to_string()) {
            anyhow::bail!("alias cycle through `{ident}` — resolution cannot terminate");
        }
        let mut any = false;
        for tys in [self.types.get(ident), renames.get(ident)].into_iter().flatten() {
            for ty in tys {
                if self.string_carrying_inner(ty, renames, visiting)? {
                    any = true;
                }
            }
        }
        visiting.remove(ident);
        Ok(any)
    }

    /// The string rule: structure, never spelling. `rel_path` selects the
    /// file's rename scope.
    pub fn string_carrying(&self, rel_path: &str, ty: &syn::Type) -> bool {
        let empty = BTreeMap::new();
        let renames = self.renames_by_file.get(rel_path).unwrap_or(&empty);
        // Cycles were refused at build; re-entry cannot occur here.
        let mut visiting = BTreeSet::new();
        self.string_carrying_inner(ty, renames, &mut visiting)
            .unwrap_or(true)
    }

    fn string_carrying_inner(
        &self,
        ty: &syn::Type,
        renames: &BTreeMap<String, Vec<syn::Type>>,
        visiting: &mut BTreeSet<String>,
    ) -> anyhow::Result<bool> {
        Ok(match ty {
            syn::Type::Reference(r) => self.string_carrying_inner(&r.elem, renames, visiting)?,
            syn::Type::Paren(p) => self.string_carrying_inner(&p.elem, renames, visiting)?,
            syn::Type::Group(g) => self.string_carrying_inner(&g.elem, renames, visiting)?,
            syn::Type::Slice(s) => self.string_carrying_inner(&s.elem, renames, visiting)?,
            syn::Type::Array(a) => self.string_carrying_inner(&a.elem, renames, visiting)?,
            syn::Type::Tuple(t) => {
                let mut any = false;
                for e in &t.elems {
                    if self.string_carrying_inner(e, renames, visiting)? {
                        any = true;
                    }
                }
                any
            }
            syn::Type::Path(p) => {
                let Some(last) = p.path.segments.last() else {
                    return Ok(false);
                };
                let ident = last.ident.to_string();
                let terminal = matches!(ident.as_str(), "String" | "str")
                    && is_string_namespace(&p.path);
                // Only a bare ident can be a table alias: a qualified path
                // names its own module's item — external ones are the R1
                // residual, and recursing on their last segment manufactures
                // false cycles (the recorded pest::iterators::Pair
                // self-alias).
                let aliased = if terminal || p.path.segments.len() != 1 {
                    false
                } else {
                    self.resolve_ident(&ident, renames, visiting)?
                };
                let mut generic = false;
                for seg in &p.path.segments {
                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        for a in &args.args {
                            if let syn::GenericArgument::Type(t) = a {
                                if self.string_carrying_inner(t, renames, visiting)? {
                                    generic = true;
                                }
                            }
                        }
                    }
                }
                terminal || aliased || generic
            }
            _ => false,
        })
    }
}

/// True when a String/str terminal actually names the std string types:
/// bare `String`/`str`, or a path through `std::string`/`alloc::string`/
/// `core`/`std` primitives. A user type named `String` in a module path
/// that is visibly not std still matches bare use — conservative, loud.
fn is_string_namespace(path: &syn::Path) -> bool {
    if path.segments.len() == 1 {
        return true;
    }
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    matches!(
        segs.iter().map(String::as_str).collect::<Vec<_>>().as_slice(),
        ["std", "string", "String"]
            | ["alloc", "string", "String"]
            | ["std", "str"]
            | ["core", "str"]
    )
}

// ---------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------

/// Where a fn sits: the position half of the skeleton discriminator.
#[derive(Clone, Copy, PartialEq)]
enum FnPosition {
    ModuleLevel,
    InImpl,
    InTrait,
}

/// Every enum ident in the boundary: the resolution set for the
/// total-refusal law (a workspace `Result` error position must land on
/// one of these).
pub fn enum_idents(files: &[SourceFile]) -> BTreeSet<String> {
    struct V {
        out: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for V {
        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            self.out.insert(node.ident.to_string());
            syn::visit::visit_item_enum(self, node);
        }
    }
    let mut v = V { out: BTreeSet::new() };
    for f in files {
        v.visit_file(&f.ast);
    }
    v.out
}

/// One classification pass over one file. Returns (check, hit) pairs;
/// check names group hits for laws.toml and waiver jurisdiction.
pub fn classify_file(
    grammar: &Grammar,
    aliases: &AliasTable,
    enums: &BTreeSet<String>,
    file: &SourceFile,
) -> Vec<(String, Hit)> {
    let crate_name = file
        .rel_path
        .strip_prefix("crates/")
        .and_then(|r| r.split('/').next())
        .unwrap_or("")
        .to_string();
    let mut w = Walker {
        rel: &file.rel_path,
        grammar,
        aliases,
        enums,
        crate_name,
        is_bin: file.rel_path.contains("src/main.rs") || file.rel_path.contains("/src/bin/"),
        in_test_scope: file.rel_path.contains("/tests/") || file.rel_path.contains("/benches/"),
        out: vec![],
    };
    for item in &file.ast.items {
        w.item(item);
    }
    w.out
}

struct Walker<'a> {
    rel: &'a str,
    grammar: &'a Grammar,
    aliases: &'a AliasTable,
    enums: &'a BTreeSet<String>,
    crate_name: String,
    is_bin: bool,
    /// Inside a tests/ or benches/ file, or a #[cfg(test)] module: the two
    /// test cells (test-proof, test-support) exist only here.
    in_test_scope: bool,
    out: Vec<(String, Hit)>,
}

impl<'a> Walker<'a> {
    fn hit(&mut self, check: &str, line: usize, construct: String) {
        self.out.push((
            check.to_string(),
            Hit {
                file: self.rel.to_string(),
                line,
                construct,
            },
        ));
    }

    fn condemned(&mut self, kind: &str, line: usize) {
        self.hit("condemned", line, format!("condemned-{kind}"));
    }

    fn item(&mut self, item: &syn::Item) {
        match item {
            syn::Item::Struct(n) => self.classify_struct(n),
            syn::Item::Enum(n) => self.classify_enum(n),
            syn::Item::Fn(n) => self.classify_module_fn(n),
            syn::Item::Impl(n) => self.classify_impl(n),
            syn::Item::Trait(n) => self.classify_trait(n),
            syn::Item::Mod(n) => {
                if n.attrs.iter().any(|a| a.path().is_ident("path")) {
                    self.hit("path_attr", span_line(&n.ident.span()), "path_attr".into());
                    self.hit(
                        "unclassified",
                        span_line(&n.ident.span()),
                        format!("unclassified-mod:{}", n.ident),
                    );
                }
                if let Some((_, items)) = &n.content {
                    let was = self.in_test_scope;
                    if is_cfg_test(&n.attrs) {
                        self.in_test_scope = true;
                    }
                    for i in items {
                        self.item(i);
                    }
                    self.in_test_scope = was;
                }
            }
            syn::Item::Use(n) => {
                let rendered = n.tree.to_token_stream().to_string().replace(' ', "");
                if use_tree_has_glob(&n.tree) {
                    self.hit(
                        "unclassified",
                        span_line(&n.use_token.span),
                        format!("unclassified-use:{rendered}"),
                    );
                }
                // The door law: a host crate importing an engine path
                // outside its allowed prefix list. Engine and tool crates
                // pass by role — a role the grammar states, never silence.
                if let Some(allowed) = self.grammar.door.hosts.get(&self.crate_name) {
                    let first = rendered.split("::").next().unwrap_or("");
                    let is_engine = self
                        .grammar
                        .door
                        .engine
                        .iter()
                        .any(|e| e.replace('-', "_") == first);
                    if is_engine && !allowed.iter().any(|p| rendered.starts_with(p.as_str())) {
                        self.hit(
                            "sealed_public_door",
                            span_line(&n.use_token.span),
                            format!("sealed_public_door:{rendered}"),
                        );
                    }
                }
            }
            syn::Item::Const(n) => {
                if self.aliases.string_carrying(self.rel, &n.ty) {
                    self.hit(
                        "unclassified",
                        span_line(&n.ident.span()),
                        format!("unclassified-const:{}", n.ident),
                    );
                }
            }
            syn::Item::Static(n) => {
                if matches!(n.mutability, syn::StaticMutability::Mut(_)) {
                    self.hit("static_mut", span_line(&n.ident.span()), "static_mut".into());
                    self.hit(
                        "unclassified",
                        span_line(&n.ident.span()),
                        format!("unclassified-static:{}", n.ident),
                    );
                } else if self.aliases.string_carrying(self.rel, &n.ty) {
                    self.hit(
                        "unclassified",
                        span_line(&n.ident.span()),
                        format!("unclassified-static:{}", n.ident),
                    );
                }
            }
            syn::Item::Type(n) => {
                if self.aliases.string_carrying(self.rel, &n.ty) {
                    self.hit(
                        "unclassified",
                        span_line(&n.ident.span()),
                        format!("unclassified-type:{}", n.ident),
                    );
                }
            }
            syn::Item::ExternCrate(n) => self.condemned("extern-crate", span_line(&n.ident.span())),
            syn::Item::ForeignMod(n) => {
                self.condemned("foreign-mod", span_line(&n.abi.extern_token.span))
            }
            syn::Item::Union(n) => self.condemned("union", span_line(&n.ident.span())),
            syn::Item::TraitAlias(n) => self.condemned("trait-alias", span_line(&n.ident.span())),
            syn::Item::Macro(n) => {
                let line = n
                    .ident
                    .as_ref()
                    .map(|i| span_line(&i.span()))
                    .unwrap_or_else(|| span_line(&n.mac.path.segments[0].ident.span()));
                self.condemned("macro", line)
            }
            syn::Item::Verbatim(ts) => {
                let line = ts
                    .clone()
                    .into_iter()
                    .next()
                    .map(|t| span_line(&t.span()))
                    .unwrap_or(1);
                self.condemned("verbatim", line)
            }
            _ => {}
        }
    }

    /// The total-refusal law: every `Result` return position resolves its
    /// error type to a workspace enum or an in-scope type parameter. An
    /// elided error (`anyhow::Result<T>`), `String`, `Box<dyn Error>`, or
    /// any non-enum terminal is red.
    fn check_total_refusal(&mut self, sig: &syn::Signature, line: usize) {
        let syn::ReturnType::Type(_, ty) = &sig.output else { return };
        let syn::Type::Path(p) = ty.as_ref() else { return };
        let Some(last) = p.path.segments.last() else { return };
        if last.ident != "Result" {
            return;
        }
        let generics: BTreeSet<String> = sig
            .generics
            .type_params()
            .map(|t| t.ident.to_string())
            .collect();
        let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
            self.hit("total_refusal", line, "total_refusal:elided-error".into());
            return;
        };
        let types: Vec<&syn::Type> = args
            .args
            .iter()
            .filter_map(|a| match a {
                syn::GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect();
        let Some(err) = types.get(1) else {
            self.hit("total_refusal", line, "total_refusal:elided-error".into());
            return;
        };
        let ok = match err {
            syn::Type::Path(ep) => ep.path.segments.last().is_some_and(|s| {
                let ident = s.ident.to_string();
                self.enums.contains(&ident) || generics.contains(&ident)
            }),
            _ => false,
        };
        if !ok {
            let rendered = err.to_token_stream().to_string().replace(' ', "");
            self.hit(
                "total_refusal",
                line,
                format!("total_refusal:{rendered}"),
            );
        }
    }

    fn classify_struct(&mut self, n: &syn::ItemStruct) {
        // Doctrine seat law: a serde-derived struct is a wire envelope and
        // must be declared as one — mechanical candidate detection.
        if has_serde_derive(&n.attrs)
            && !self.grammar.seats.declared.iter().any(|s| {
                s.construct == "wire-envelope" && s.name == n.ident.to_string()
            })
        {
            self.hit(
                "undeclared_wire",
                span_line(&n.ident.span()),
                format!("undeclared_wire:{}", n.ident),
            );
        }
        self.classify_struct_rules(n)
    }

    fn classify_struct_rules(&mut self, n: &syn::ItemStruct) {
        let matches: Vec<&str> = self
            .grammar
            .constructs
            .iter()
            .filter(|c| c.kind == ConstructKind::Struct)
            .filter(|c| struct_rule_matches(c.rule, n))
            .map(|c| c.name.as_str())
            .collect();
        let string_field = n
            .fields
            .iter()
            .any(|f| self.aliases.string_carrying(self.rel, &f.ty));
        if matches.len() != 1 || string_field {
            self.hit(
                "unclassified",
                span_line(&n.ident.span()),
                format!("unclassified-struct:{}", n.ident),
            );
        }
    }

    fn classify_enum(&mut self, n: &syn::ItemEnum) {
        let clean = n.variants.iter().all(|v| {
            v.fields
                .iter()
                .all(|f| !self.aliases.string_carrying(self.rel, &f.ty))
        });
        if !clean {
            self.hit(
                "unclassified",
                span_line(&n.ident.span()),
                format!("unclassified-enum:{}", n.ident),
            );
        }
    }

    fn classify_module_fn(&mut self, n: &syn::ItemFn) {
        let line = span_line(&n.sig.ident.span());
        if has_test_attr(&n.attrs) {
            // test-proof: the #[test] attribute is the discriminator; the
            // in-cell refusal is empty_test — a test with no body is
            // theater wearing a green checkmark.
            if n.block.stmts.is_empty() {
                self.hit("empty_test", line, "empty_test".into());
            }
            self.fn_body_rules("test-proof", &n.sig, Some(&n.block), line, false);
            return;
        }
        if self.is_bin && n.sig.ident == "main" {
            self.fn_body_rules("composition-root", &n.sig, Some(&n.block), line, false);
            return;
        }
        if self.in_test_scope {
            // test-support: receiverless, test scope, module-internal. A
            // pub helper is exported test scaffolding — refused.
            if matches!(n.vis, syn::Visibility::Inherited) {
                self.fn_body_rules("test-support", &n.sig, Some(&n.block), line, false);
            } else {
                self.hit(
                    "unclassified",
                    line,
                    format!("unclassified-fn:{}", n.sig.ident),
                );
            }
            return;
        }
        match self.grammar.seat_for(self.rel, &n.sig.ident.to_string()) {
            Some(seat) => {
                let current = identity::site_hash(n);
                if current != seat.hash {
                    self.hit(
                        "seat_drift",
                        line,
                        format!("seat-drift:{}", n.sig.ident),
                    );
                } else {
                    self.fn_body_rules("declared-fn", &n.sig, Some(&n.block), line, seat.io);
                }
            }
            None => {
                self.hit(
                    "unclassified",
                    line,
                    format!("unclassified-fn:{}", n.sig.ident),
                );
            }
        }
    }

    fn classify_impl(&mut self, n: &syn::ItemImpl) {
        let self_ident = impl_self_ident(n);
        // Doctrine seat law: a Drop impl marks a drop-bound resource and
        // its type must be declared as one.
        let is_drop = n
            .trait_
            .as_ref()
            .is_some_and(|(_, p, _)| p.segments.last().is_some_and(|s| s.ident == "Drop"));
        if is_drop {
            let declared = self_ident.as_deref().is_some_and(|name| {
                self.grammar
                    .seats
                    .declared
                    .iter()
                    .any(|s| s.construct == "drop-bound-resource" && s.name == name)
            });
            if !declared {
                self.hit(
                    "undeclared_resource",
                    span_line(&n.impl_token.span),
                    format!(
                        "undeclared_resource:{}",
                        self_ident.as_deref().unwrap_or("?")
                    ),
                );
            }
        }
        for it in &n.items {
            match it {
                syn::ImplItem::Fn(f) => {
                    self.classify_method(&f.sig, Some(&f.block), self_ident.as_deref(), FnPosition::InImpl)
                }
                syn::ImplItem::Const(c) => {
                    if self.aliases.string_carrying(self.rel, &c.ty) {
                        self.hit(
                            "unclassified",
                            span_line(&c.ident.span()),
                            format!("unclassified-const:{}", c.ident),
                        );
                    }
                }
                syn::ImplItem::Type(t) => {
                    if self.aliases.string_carrying(self.rel, &t.ty) {
                        self.hit(
                            "unclassified",
                            span_line(&t.ident.span()),
                            format!("unclassified-type:{}", t.ident),
                        );
                    }
                }
                syn::ImplItem::Macro(m) => self.condemned(
                    "impl-item-macro",
                    span_line(&m.mac.path.segments[0].ident.span()),
                ),
                _ => {}
            }
        }
    }

    fn classify_trait(&mut self, n: &syn::ItemTrait) {
        for it in &n.items {
            match it {
                syn::TraitItem::Fn(f) => {
                    self.classify_method(&f.sig, f.default.as_ref(), None, FnPosition::InTrait)
                }
                syn::TraitItem::Const(c) => {
                    if self.aliases.string_carrying(self.rel, &c.ty) {
                        self.hit(
                            "unclassified",
                            span_line(&c.ident.span()),
                            format!("unclassified-const:{}", c.ident),
                        );
                    }
                }
                syn::TraitItem::Type(t) => {
                    if let Some((_, ty)) = &t.default {
                        if self.aliases.string_carrying(self.rel, ty) {
                            self.hit(
                                "unclassified",
                                span_line(&t.ident.span()),
                                format!("unclassified-type:{}", t.ident),
                            );
                        }
                    }
                }
                syn::TraitItem::Macro(m) => self.condemned(
                    "trait-item-macro",
                    span_line(&m.mac.path.segments[0].ident.span()),
                ),
                _ => {}
            }
        }
    }

    /// The receiver-skeleton partition for impl and trait fns.
    fn classify_method(
        &mut self,
        sig: &syn::Signature,
        body: Option<&syn::Block>,
        self_ident: Option<&str>,
        pos: FnPosition,
    ) {
        let line = span_line(&sig.ident.span());
        match receiver_form(sig) {
            ReceiverForm::SharedRef => self.fn_body_rules("derivation", sig, body, line, false),
            ReceiverForm::UniqueRef => self.fn_body_rules("transition", sig, body, line, false),
            ReceiverForm::Owned => {
                if returns_self(sig, self_ident) {
                    // A self-consuming fn returning Self is a builder chain:
                    // multi-step construction the values doctrine forbids.
                    self.hit(
                        "unclassified",
                        line,
                        format!("unclassified-fn:{}", sig.ident),
                    );
                } else {
                    self.fn_body_rules("consuming-verb", sig, body, line, false);
                }
            }
            ReceiverForm::Exotic => {
                self.hit(
                    "unclassified",
                    line,
                    format!("unclassified-fn:{}", sig.ident),
                );
            }
            ReceiverForm::None => {
                if pos == FnPosition::InImpl && returns_self(sig, self_ident) {
                    self.fn_body_rules("admission-door", sig, body, line, false);
                } else {
                    self.hit(
                        "unclassified",
                        line,
                        format!("unclassified-fn:{}", sig.ident),
                    );
                }
            }
        }
    }

    /// The construct-scoped body rules, driven by the grammar's `bans` list
    /// for the classified construct, plus the async law (uniform: await and
    /// async are red everywhere except an io=true declared seat).
    fn fn_body_rules(
        &mut self,
        construct: &str,
        sig: &syn::Signature,
        body: Option<&syn::Block>,
        line: usize,
        io_seat: bool,
    ) {
        if !io_seat && sig.asyncness.is_some() {
            self.hit("async_outside_io", line, "async_outside_io".into());
        }
        self.check_total_refusal(sig, line);
        // The config-once law: only a declared config constructor reads
        // the environment.
        let is_config_seat = self
            .grammar
            .seats
            .config_fns
            .iter()
            .any(|c| c.file == self.rel && c.path == sig.ident.to_string());
        let Some(body) = body else { return };
        let scoped: Vec<&str> = self
            .grammar
            .constructs
            .iter()
            .find(|c| c.name == construct)
            .map(|c| c.bans.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let mut v = BodyRules {
            rel: self.rel,
            scoped: &scoped,
            io_seat,
            is_config_seat,
            out: &mut self.out,
        };
        v.visit_block(body);
    }
}

struct BodyRules<'a, 'o> {
    rel: &'a str,
    scoped: &'a [&'a str],
    io_seat: bool,
    is_config_seat: bool,
    out: &'o mut Vec<(String, Hit)>,
}

impl<'a, 'o> BodyRules<'a, 'o> {
    fn hit(&mut self, check: &str, line: usize) {
        self.out.push((
            check.to_string(),
            Hit {
                file: self.rel.to_string(),
                line,
                construct: check.to_string(),
            },
        ));
    }
}

impl<'a, 'o, 'ast> Visit<'ast> for BodyRules<'a, 'o> {
    fn visit_expr(&mut self, e: &'ast syn::Expr) {
        match e {
            syn::Expr::Await(a) => {
                if !self.io_seat {
                    self.hit("async_outside_io", span_line(&a.await_token.span));
                }
            }
            syn::Expr::Path(p) if !self.is_config_seat => {
                // env::var / env::args and kin, matched on adjacent path
                // segments — structure, not spelling of the whole path.
                let segs: Vec<String> =
                    p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                let env_read = segs.windows(2).any(|w| {
                    w[0] == "env"
                        && matches!(w[1].as_str(), "var" | "vars" | "var_os" | "args" | "args_os")
                });
                if env_read {
                    self.hit("config_once", span_line(&p.path.segments[0].ident.span()));
                }
            }
            syn::Expr::Assign(a) => {
                if self.scoped.contains(&"assign_expr") {
                    self.hit("assign_expr", span_line(&a.eq_token.span));
                }
                if self.scoped.contains(&"nested_place_assign")
                    && self_place_depth(&a.left) > 1
                {
                    self.hit("nested_place_assign", span_line(&a.eq_token.span));
                }
            }
            syn::Expr::If(n) => {
                if self.scoped.contains(&"main_flow") {
                    self.hit("main_flow", span_line(&n.if_token.span));
                }
            }
            syn::Expr::Match(n) => {
                if self.scoped.contains(&"main_flow") {
                    self.hit("main_flow", span_line(&n.match_token.span));
                }
            }
            syn::Expr::Loop(n) => {
                if self.scoped.contains(&"main_flow") {
                    self.hit("main_flow", span_line(&n.loop_token.span));
                }
            }
            syn::Expr::While(n) => {
                if self.scoped.contains(&"main_flow") {
                    self.hit("main_flow", span_line(&n.while_token.span));
                }
            }
            syn::Expr::ForLoop(n) => {
                if self.scoped.contains(&"main_flow") {
                    self.hit("main_flow", span_line(&n.for_token.span));
                }
            }
            _ => {}
        }
        syn::visit::visit_expr(self, e);
    }
}

// ---------------------------------------------------------------------------
// parse-fact helpers (the discriminators)
// ---------------------------------------------------------------------------

enum ReceiverForm {
    SharedRef,
    UniqueRef,
    Owned,
    Exotic,
    None,
}

fn receiver_form(sig: &syn::Signature) -> ReceiverForm {
    match sig.inputs.first() {
        Some(syn::FnArg::Receiver(r)) => {
            if r.colon_token.is_some() {
                ReceiverForm::Exotic // self: Box<Self> and kin
            } else if r.reference.is_some() {
                if r.mutability.is_some() {
                    ReceiverForm::UniqueRef
                } else {
                    ReceiverForm::SharedRef
                }
            } else {
                ReceiverForm::Owned
            }
        }
        _ => ReceiverForm::None,
    }
}

/// Structural Self-return: `Self`, the impl type's own ident, or either as
/// the success type of `Result`/`Option` — path comparison, not token
/// search.
fn returns_self(sig: &syn::Signature, self_ident: Option<&str>) -> bool {
    let syn::ReturnType::Type(_, ty) = &sig.output else {
        return false;
    };
    type_is_self(ty, self_ident)
}

fn type_is_self(ty: &syn::Type, self_ident: Option<&str>) -> bool {
    match ty {
        syn::Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return false;
            };
            let ident = last.ident.to_string();
            if ident == "Self" || Some(ident.as_str()) == self_ident {
                return true;
            }
            if matches!(ident.as_str(), "Result" | "Option") {
                if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                    if let Some(syn::GenericArgument::Type(t)) = args.args.first() {
                        return type_is_self(t, self_ident);
                    }
                }
            }
            false
        }
        syn::Type::Paren(p) => type_is_self(&p.elem, self_ident),
        _ => false,
    }
}

fn impl_self_ident(n: &syn::ItemImpl) -> Option<String> {
    match n.self_ty.as_ref() {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

fn struct_rule_matches(rule: StructuralRule, n: &syn::ItemStruct) -> bool {
    let all_private = n
        .fields
        .iter()
        .all(|f| matches!(f.vis, syn::Visibility::Inherited));
    match rule {
        StructuralRule::TupleSinglePrivateField => {
            matches!(&n.fields, syn::Fields::Unnamed(u) if u.unnamed.len() == 1) && all_private
        }
        StructuralRule::NamedFieldsAllPrivate => {
            matches!(&n.fields, syn::Fields::Named(_)) && all_private
        }
        StructuralRule::UnitStruct => matches!(&n.fields, syn::Fields::Unit),
        _ => false,
    }
}

/// A serde derive: `#[derive(...)]` naming Serialize or Deserialize —
/// matched on the derive list's path idents, structurally.
fn has_serde_derive(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = a.parse_nested_meta(|meta| {
            if meta
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Serialize" || s.ident == "Deserialize")
            {
                found = true;
            }
            Ok(())
        });
        found
    })
}

/// The #[test] attribute family: any attribute whose path ends in `test`
/// (`#[test]`, `#[tokio::test]`) — a parse fact, not a spelling guess on
/// the whole path.
fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "test")
    })
}

/// `#[cfg(test)]` on a module, matched structurally on the cfg argument.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("cfg") {
            return false;
        }
        let mut is_test = false;
        let _ = a.parse_nested_meta(|meta| {
            if meta.path.is_ident("test") {
                is_test = true;
            }
            Ok(())
        });
        is_test
    })
}

fn use_tree_has_glob(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Glob(_) => true,
        syn::UseTree::Path(p) => use_tree_has_glob(&p.tree),
        syn::UseTree::Group(g) => g.items.iter().any(use_tree_has_glob),
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) => false,
    }
}

/// Depth of a self-rooted place chain: `self.a` = 1, `self.a.b` = 2,
/// `self.a[i]` = 2. Non-self-rooted places are 0 — locals are not state.
fn self_place_depth(e: &syn::Expr) -> usize {
    fn walk(e: &syn::Expr) -> Option<usize> {
        match e {
            syn::Expr::Path(p) if p.path.is_ident("self") => Some(0),
            syn::Expr::Field(f) => walk(&f.base).map(|d| d + 1),
            syn::Expr::Index(i) => walk(&i.expr).map(|d| d + 1),
            _ => None,
        }
    }
    walk(e).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::ConstructDef;

    fn test_grammar() -> Grammar {
        Grammar {
            bans_expression: vec!["unwrap".into()],
            bans_attribute: vec![],
            absolute: std::collections::BTreeSet::new(),
            constructs: vec![
                ConstructDef {
                    name: "newtype-scalar".into(),
                    kind: ConstructKind::Struct,
                    rule: StructuralRule::TupleSinglePrivateField,
                    bans: vec![],
                },
                ConstructDef {
                    name: "sealed-struct".into(),
                    kind: ConstructKind::Struct,
                    rule: StructuralRule::NamedFieldsAllPrivate,
                    bans: vec![],
                },
                ConstructDef {
                    name: "unit-marker".into(),
                    kind: ConstructKind::Struct,
                    rule: StructuralRule::UnitStruct,
                    bans: vec![],
                },
                ConstructDef {
                    name: "derivation".into(),
                    kind: ConstructKind::Fn,
                    rule: StructuralRule::ReceiverSharedRef,
                    bans: vec!["assign_expr".into()],
                },
                ConstructDef {
                    name: "transition".into(),
                    kind: ConstructKind::Fn,
                    rule: StructuralRule::ReceiverUniqueRef,
                    bans: vec!["nested_place_assign".into()],
                },
            ],
            seats: crate::grammar::Seats::default(),
            door: crate::grammar::Door::default(),
        }
    }

    fn classify(src: &str) -> Vec<(String, Hit)> {
        let file = SourceFile {
            rel_path: "crates/x/src/a.rs".to_string(),
            text: src.to_string(),
            ast: syn::parse_file(src).expect("fixture parses"),
        };
        let aliases = AliasTable::build(std::slice::from_ref(&file)).expect("aliases");
        let enums = enum_idents(std::slice::from_ref(&file));
        classify_file(&test_grammar(), &aliases, &enums, &file)
    }

    fn checks(hits: &[(String, Hit)]) -> Vec<&str> {
        hits.iter().map(|(c, _)| c.as_str()).collect()
    }

    #[test]
    fn bite_alias_and_rename_are_red_and_restrict_is_clean() {
        let hits = classify(
            "type Name = String;\nstruct S { n: Name }\nuse std::string::String as Text;\nstruct T { t: Text }\nstruct R { r: Restrict }",
        );
        let c = checks(&hits);
        assert_eq!(
            c.iter().filter(|x| **x == "unclassified").count(),
            3,
            "alias itself, S, T red; R clean: {hits:?}"
        );
    }

    #[test]
    fn bite_alias_cycle_refuses_at_build() {
        let file = SourceFile {
            rel_path: "crates/x/src/a.rs".into(),
            text: String::new(),
            ast: syn::parse_file("type A = B;\ntype B = A;").expect("parses"),
        };
        assert!(AliasTable::build(std::slice::from_ref(&file)).is_err());
    }

    #[test]
    fn bite_glob_import_and_exotic_receiver_and_builder_are_red() {
        let hits = classify(
            "use std::collections::*;\nstruct T { a: u64 }\nimpl T { fn with_a(mut self) -> Self { self } fn boxed(self: Box<Self>) {} }",
        );
        let c = checks(&hits);
        assert_eq!(c.iter().filter(|x| **x == "unclassified").count(), 3, "{hits:?}");
    }

    #[test]
    fn bite_static_mut_is_red_and_condemned_kinds_report() {
        let hits = classify("static mut G: u64 = 0;\nmacro_rules! m { () => {} }");
        let c = checks(&hits);
        assert!(c.contains(&"static_mut"), "{hits:?}");
        assert!(c.contains(&"condemned"), "{hits:?}");
    }

    #[test]
    fn bite_scoped_bans_fire_only_in_their_construct() {
        let hits = classify(
            "struct T { a: u64, b: Vec<u64> }\nimpl T { fn read(&self) -> u64 { let mut x = 0; x = 1; x }\n fn step(&mut self) { self.b[0] = 1; } }",
        );
        let c = checks(&hits);
        assert!(c.contains(&"assign_expr"), "derivation assignment: {hits:?}");
        assert!(c.contains(&"nested_place_assign"), "nested place: {hits:?}");
    }

    #[test]
    fn bite_await_outside_io_seat_is_red() {
        let hits = classify(
            "struct T { a: u64 }\nimpl T { async fn go(&self) { other().await; } }\nasync fn other() {}",
        );
        let c = checks(&hits);
        assert!(
            c.iter().filter(|x| **x == "async_outside_io").count() >= 2,
            "async fn + await both red: {hits:?}"
        );
    }

    #[test]
    fn bite_admission_door_result_self_classifies() {
        let hits = classify(
            "struct T { a: u64 }\nimpl T { fn new() -> Result<Self, u8> { Ok(T { a: 0 }) } }",
        );
        assert!(
            checks(&hits).iter().all(|x| *x != "unclassified"),
            "Result<Self, E> door must classify: {hits:?}"
        );
    }
}
