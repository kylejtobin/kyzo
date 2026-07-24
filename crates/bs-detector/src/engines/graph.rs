/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Engine 2 — Graph: lies that are relational, invisible at any one site.
//! - `derive_bypass`: a type with a fallible constructor (`new`/`try_new*`
//!   returning `Result`/`Option`) must not also derive `Deserialize`,
//!   `From`, or `Default` — each builds by field assignment, a second door
//!   around the admission proof.
//! - `copy_detector`: near-identical fn/method bodies across files by
//!   normalized token-shingle similarity — second authority by copy.
//! - `agreement_registry`: every test named in `crates/xtask/agreements.toml`
//!   must still exist as a `fn` in the tree.
//! - `total_refusal` (item 2): every workspace `Result` error position
//!   resolves to a workspace enum; `String` / `anyhow` / `Box<dyn Error>` red.
//! - `sealed_public_door` (item 2): per-host-crate allowed-import list;
//!   an import outside it is red.
//! - `config_once` (item 2): env/args call sites per binary — exactly one,
//!   inside the declared config constructor.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::boundary::{Label, RelPath, SourceFile, span_line};
use crate::engines::Hit;
use crate::grammar::{ConfigOnceSeat, HostDoor};

// ---------------------------------------------------------------------------
// derive_bypass
// ---------------------------------------------------------------------------

pub fn derive_bypass(files: &[&SourceFile]) -> Vec<Hit> {
    struct TypeFacts {
        file: RelPath,
        line: usize,
        fallible_ctor: bool,
        bad_derives: Vec<Label>,
    }
    let mut types: BTreeMap<Label, TypeFacts> = BTreeMap::new();

    for f in files {
        struct V<'a> {
            rel: &'a RelPath,
            types: &'a mut BTreeMap<Label, TypeFacts>,
        }
        fn record_derives(
            v: &mut V<'_>,
            ident: &syn::Ident,
            attrs: &[syn::Attribute],
        ) {
            let bad: Vec<Label> = derive_names(attrs)
                .into_iter()
                .filter(|d| d == "Deserialize" || d == "Default" || d == "From")
                .map(Label::admit)
                .collect();
            let rel = v.rel.clone();
            v.types
                .entry(Label::admit(ident.to_string()))
                .or_insert(TypeFacts {
                    file: rel,
                    line: span_line(&ident.span()),
                    fallible_ctor: false,
                    bad_derives: vec![],
                })
                .bad_derives
                .extend(bad);
        }
        // A fallible admission door is ANY constructor-shaped name that can
        // refuse — not just `new`: parse/decode/from_*/admit/build/of_*
        // returning Result/Option all claim "this type is proven at entry".
        fn is_admission_name(name: &str) -> bool {
            name == "new"
                || name.starts_with("try_")
                || name.starts_with("parse")
                || name.starts_with("decode")
                || name.starts_with("from_")
                || name.starts_with("of_")
                || name.starts_with("admit")
                || name.starts_with("build")
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
                record_derives(self, &node.ident, &node.attrs);
                visit::visit_item_struct(self, node);
            }
            fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
                record_derives(self, &node.ident, &node.attrs);
                visit::visit_item_enum(self, node);
            }
            fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
                if let syn::Type::Path(tp) = &*node.self_ty {
                    if let Some(seg) = tp.path.segments.last() {
                        let ty = seg.ident.to_string();
                        for item in &node.items {
                            if let syn::ImplItem::Fn(m) = item {
                                let name = m.sig.ident.to_string();
                                let ret = m.sig.output.to_token_stream().to_string();
                                if is_admission_name(&name)
                                    && (ret.contains("Result <") || ret.contains("Option <"))
                                {
                                    self.types
                                        .entry(Label::admit(ty.clone()))
                                        .or_insert(TypeFacts {
                                            file: self.rel.clone(),
                                            line: span_line(&m.sig.ident.span()),
                                            fallible_ctor: false,
                                            bad_derives: vec![],
                                        })
                                        .fallible_ctor = true;
                                }
                            }
                        }
                    }
                }
                visit::visit_item_impl(self, node);
            }
        }
        let mut v = V {
            rel: f.rel_path_ref(),
            types: &mut types,
        };
        v.visit_file(f.ast());
    }

    types
        .into_iter()
        .filter(|(_, t)| t.fallible_ctor && !t.bad_derives.is_empty())
        .map(|(name, t)| {
            let derives: Vec<&str> = t.bad_derives.iter().map(Label::as_str).collect();
            Hit::admit(t.file, t.line, format!("{name}+derive({})", derives.join("+")))
        })
        .collect()
}

fn derive_names(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = vec![];
    for a in attrs {
        if a.path().is_ident("derive") {
            let text = a.to_token_stream().to_string();
            for cand in ["Deserialize", "Default", "From"] {
                if text.contains(cand) {
                    out.push(cand.to_string());
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// copy_detector
// ---------------------------------------------------------------------------

const SHINGLE: usize = 8;
const MIN_TOKENS: usize = 60;
/// Jaccard similarity floor, in percent. Integer arithmetic end to end:
/// `inter * 100 >= union * SIMILARITY_PERCENT` — no float, no cast.
const SIMILARITY_PERCENT: usize = 60;

struct Unit {
    label: Label,
    file: RelPath,
    line: usize,
    /// Line of the body's closing brace — used to refuse parent~nested-fn
    /// "pairs": a fn textually contained in another is the same text
    /// counted twice, one authority, not a copy.
    line_end: usize,
    shingles: BTreeSet<u64>,
}

pub fn copy_detector(files: &[&SourceFile]) -> Vec<Hit> {
    let mut units: Vec<Unit> = vec![];
    for f in files {
        struct V<'a> {
            rel: &'a RelPath,
            units: &'a mut Vec<Unit>,
        }
        fn push_unit(units: &mut Vec<Unit>, rel: &RelPath, name: &str, line: usize, body: &syn::Block) {
            let toks = normalize_tokens(body);
            if toks.len() < MIN_TOKENS {
                return;
            }
            let mut shingles = BTreeSet::new();
            for w in toks.windows(SHINGLE) {
                shingles.insert(fnv(w));
            }
            units.push(Unit {
                label: Label::admit(format!("{rel}::{name}")),
                file: rel.clone(),
                line,
                line_end: body.brace_token.span.close().end().line,
                shingles,
            });
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
                push_unit(
                    self.units,
                    self.rel,
                    &node.sig.ident.to_string(),
                    span_line(&node.sig.ident.span()),
                    &node.block,
                );
                visit::visit_item_fn(self, node);
            }
            fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
                push_unit(
                    self.units,
                    self.rel,
                    &node.sig.ident.to_string(),
                    span_line(&node.sig.ident.span()),
                    &node.block,
                );
                visit::visit_impl_item_fn(self, node);
            }
        }
        let mut v = V {
            rel: f.rel_path_ref(),
            units: &mut units,
        };
        v.visit_file(f.ast());
    }

    // Exact Jaccard via an inverted shingle index: a pair's co-occurrence
    // count across postings IS its intersection size (shingle sets are
    // deduped), so union = |A| + |B| - inter with no second pass. The
    // size-ratio skip is a proven bound, not a heuristic: inter ≤ min and
    // union ≥ max, so score ≤ min/max — below threshold means the pair
    // can never qualify.
    let mut postings: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, u) in units.iter().enumerate() {
        for s in &u.shingles {
            postings.entry(*s).or_default().push(i);
        }
    }
    let mut inter: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for list in postings.values() {
        for (ai, a) in list.iter().enumerate() {
            for b in &list[ai + 1..] {
                let (sa, sb) = (units[*a].shingles.len(), units[*b].shingles.len());
                let (mn, mx) = if sa < sb { (sa, sb) } else { (sb, sa) };
                if mn * 100 < mx * SIMILARITY_PERCENT {
                    continue;
                }
                *inter.entry((*a, *b)).or_insert(0) += 1;
            }
        }
    }
    let mut hits = vec![];
    for ((a, b), n) in &inter {
        let (a, b) = (&units[*a], &units[*b]);
        let union = a.shingles.len() + b.shingles.len() - n;
        if union == 0 || n * 100 < union * SIMILARITY_PERCENT {
            continue;
        }
        let contained = a.file == b.file
            && ((a.line <= b.line && b.line_end <= a.line_end)
                || (b.line <= a.line && a.line_end <= b.line_end));
        if contained {
            continue;
        }
        // The construct is the bare pair — stable across edits, so a
        // approved waiver binds to the twins, not to a drifting score.
        hits.push(Hit::admit(a.file.clone(), a.line, format!("{} ~ {}", a.label, b.label)));
    }
    hits.sort_by(|x, y| {
        (x.file(), x.line(), x.construct())
            .cmp(&(y.file(), y.line(), y.construct()))
    });
    hits
}

fn normalize_tokens(block: &syn::Block) -> Vec<String> {
    block
        .to_token_stream()
        .into_iter()
        .flat_map(flatten)
        .collect()
}

fn flatten(t: proc_macro2::TokenTree) -> Vec<String> {
    if let proc_macro2::TokenTree::Group(g) = t {
        let mut v = vec![format!("open{:?}", g.delimiter())];
        v.extend(g.stream().into_iter().flat_map(flatten));
        v.push("close".to_string());
        return v;
    }
    if let proc_macro2::TokenTree::Ident(i) = &t {
        // Identifiers normalize to a class token so renames can't hide a
        // copy; keywords keep their spelling (they carry structure).
        let s = i.to_string();
        let kw = [
            "if", "else", "match", "for", "while", "loop", "let", "fn", "return", "mut", "ref",
            "move", "break", "continue",
        ];
        if kw.contains(&s.as_str()) {
            return vec![s];
        }
        return vec!["id".to_string()];
    }
    vec![t.to_string()]
}

fn fnv(words: &[String]) -> u64 {
    // FNV-1a published mix is wrapping mul — expressed via Wrapping so the
    // wrap is the type's contract, not a naked wrapping_* method call.
    use std::num::Wrapping;
    let mut h = Wrapping(0xcbf2_9ce4_8422_2325_u64);
    for w in words {
        for b in w.as_bytes() {
            h ^= Wrapping(u64::from(*b));
            h *= Wrapping(0x100_0000_01b3_u64);
        }
        h ^= Wrapping(0x1f_u64);
        h *= Wrapping(0x100_0000_01b3_u64);
    }
    h.0
}

// ---------------------------------------------------------------------------
// agreement_registry
// ---------------------------------------------------------------------------

pub fn agreement_registry(files: &[&SourceFile], registry_text: &str) -> Vec<Hit> {
    // Parsed, never line-scanned: a declaration reformatted onto one line
    // or into an inline table is the same declaration.
    let parsed: toml::Value = match toml::from_str(registry_text) {
        Ok(v) => v,
        Err(e) => {
            return vec![Hit::admit("crates/xtask/agreements.toml".to_string(), 0, format!("unparseable-registry: {e}"))];
        }
    };
    let mut declared: Vec<(String, usize)> = vec![];
    if let Some(entries) = parsed.get("agreement").and_then(|v| v.as_array()) {
        for entry in entries {
            if let Some(name) = entry.get("test_fn").and_then(|v| v.as_str()) {
                // Line 0 is the explicit "declared but not textually
                // locatable" convention (same as meta's file-level hits) —
                // a name split across lines still counts, never invents a
                // position. if-let avoids a `None => 0` costume arm.
                let line = if let Some(idx) = registry_text.lines().position(|l| l.contains(name))
                {
                    idx + 1
                } else {
                    0
                };
                declared.push((name.to_string(), line));
            }
        }
    }
    let mut defined: BTreeSet<Label> = BTreeSet::new();
    for f in files {
        struct V<'a> {
            defined: &'a mut BTreeSet<Label>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
                self.defined.insert(Label::admit(node.sig.ident.to_string()));
                visit::visit_item_fn(self, node);
            }
        }
        let mut v = V {
            defined: &mut defined,
        };
        v.visit_file(f.ast());
    }
    declared
        .into_iter()
        .filter(|(name, _)| !defined.contains(&Label::admit(name.as_str())))
        .map(|(name, line)| {
            Hit::admit(
                "crates/xtask/agreements.toml".to_string(),
                line,
                format!("declared-but-missing:{name}"),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// total_refusal (item 2 relational)
// ---------------------------------------------------------------------------

fn path_last_ident(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

fn type_is_explicitly_banned_error(ty: &syn::Type) -> Option<&'static str> {
    match ty {
        syn::Type::Path(tp) => {
            let segs: Vec<String> = tp
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segs.last().is_some_and(|s| s == "String") {
                return Some("String");
            }
            if segs.iter().any(|s| s == "anyhow") {
                return Some("anyhow");
            }
            None
        }
        syn::Type::TraitObject(_) => Some("dyn-error"),
        syn::Type::Paren(p) => type_is_explicitly_banned_error(&p.elem),
        syn::Type::Group(g) => type_is_explicitly_banned_error(&g.elem),
        syn::Type::Reference(r) => type_is_explicitly_banned_error(&r.elem),
        _not_a_named_banned_shape => None,
    }
}

fn result_error_type(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(tp) = ty else {
        return None;
    };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let types: Vec<&syn::Type> = args
        .args
        .iter()
        .filter_map(|a| match a {
            syn::GenericArgument::Type(t) => Some(t),
            syn::GenericArgument::Lifetime(_)
            | syn::GenericArgument::AssocType(_)
            | syn::GenericArgument::AssocConst(_)
            | syn::GenericArgument::Constraint(_)
            | syn::GenericArgument::Const(_) => None,
            _unrecognized_generic_arg => None,
        })
        .collect();
    // Result<T, E> — keep E; T is witness-position only.
    match types.as_slice() {
        [_, err] => Some(*err),
        _not_result_arity => None,
    }
}

fn error_ty_is_workspace_enum(ty: &syn::Type, enums: &BTreeSet<Label>) -> bool {
    let syn::Type::Path(tp) = ty else {
        return false;
    };
    // Box<dyn Error> / aliased wrappers handled by banned check first.
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if let syn::PathArguments::AngleBracketed(_args) = &seg.arguments {
        // Box<dyn …> — Path with one type arg that is TraitObject.
        if seg.ident == "Box" {
            return false;
        }
    }
    path_last_ident(&tp.path).is_some_and(|name| enums.contains(&Label::admit(name)))
}

/// Every `Result<_, E>` in the workspace: E must be a workspace enum.
/// `String`, `anyhow::*`, and `Box<dyn …>` are red by name.
pub fn total_refusal(files: &[&SourceFile]) -> Vec<Hit> {
    let mut enums: BTreeSet<Label> = BTreeSet::new();
    for f in files {
        for item in &f.ast().items {
            if let syn::Item::Enum(e) = item {
                enums.insert(Label::admit(e.ident.to_string()));
            }
        }
    }
    let mut hits = vec![];
    for f in files {
        struct V<'a> {
            rel: &'a RelPath,
            enums: &'a BTreeSet<Label>,
            hits: &'a mut Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_type(&mut self, node: &'ast syn::Type) {
                if let Some(err) = result_error_type(node) {
                    let reason = if let Some(tag) = type_is_explicitly_banned_error(err) {
                        Some(tag.to_string())
                    } else if looks_like_box_dyn(err) {
                        Some("Box<dyn Error>".to_string())
                    } else if !error_ty_is_workspace_enum(err, self.enums) {
                        Some(format!(
                            "not-workspace-enum:{}",
                            err.to_token_stream()
                        ))
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        self.hits.push(Hit::admit(
                            self.rel.clone(),
                            span_line(&node.span()),
                            format!("result-error:{reason}"),
                        ));
                    }
                }
                visit::visit_type(self, node);
            }
        }
        let mut v = V {
            rel: f.rel_path_ref(),
            enums: &enums,
            hits: &mut hits,
        };
        v.visit_file(f.ast());
    }
    hits
}

fn looks_like_box_dyn(ty: &syn::Type) -> bool {
    let syn::Type::Path(tp) = ty else {
        return false;
    };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident != "Box" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    args.args.iter().any(|a| matches!(a, syn::GenericArgument::Type(syn::Type::TraitObject(_))))
}

// ---------------------------------------------------------------------------
// sealed_public_door (item 2 relational)
// ---------------------------------------------------------------------------

fn use_tree_roots(tree: &syn::UseTree, out: &mut Vec<(String, proc_macro2::Span)>) {
    match tree {
        syn::UseTree::Path(p) => {
            out.push((p.ident.to_string(), p.ident.span()));
        }
        syn::UseTree::Name(n) => {
            out.push((n.ident.to_string(), n.ident.span()));
        }
        syn::UseTree::Rename(r) => {
            out.push((r.ident.to_string(), r.ident.span()));
        }
        syn::UseTree::Glob(g) => {
            // Glob without a path prefix is illegal rust at item level for
            // `use *`; nested globs are reached via Path. Record as `*`.
            out.push(("*".to_string(), g.star_token.spans[0]));
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                use_tree_roots(item, out);
            }
        }
    }
}

/// Per-host allowed-import list: a `use` whose first segment is outside
/// `{crate, super, self} ∪ allowed_imports` is red.
pub fn sealed_public_door(files: &[&SourceFile], hosts: &[HostDoor]) -> Vec<Hit> {
    let mut hits = vec![];
    for f in files {
        let Some(host) = hosts.iter().find(|h| f.rel_path().starts_with(h.path())) else {
            continue;
        };
        let allowed: BTreeSet<&str> = host.allowed_imports().iter().map(|s| s.as_str()).collect();
        for item in &f.ast().items {
            let syn::Item::Use(u) = item else {
                continue;
            };
            let mut roots = vec![];
            use_tree_roots(&u.tree, &mut roots);
            for (root, span) in roots {
                if root == "crate" || root == "super" || root == "self" {
                    continue;
                }
                if allowed.contains(root.as_str()) {
                    continue;
                }
                hits.push(Hit::admit(f.rel_path().to_string(), span_line(&span), format!("import-outside-door:{root}")));
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// config_once (item 2 relational)
// ---------------------------------------------------------------------------

fn is_env_or_args_path(path: &syn::Path) -> bool {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    let Some(last) = segs.last() else {
        return false;
    };
    let is_env_fn = matches!(
        last.as_str(),
        "var" | "var_os" | "vars" | "vars_os" | "args" | "args_os"
    );
    if !is_env_fn {
        return false;
    }
    // …::env::var / env::var / std::env::args
    segs.iter().any(|s| s == "env")
}

struct EnvSite {
    line: usize,
    /// Module path of the enclosing fn, e.g. `host_env::read` or `main`.
    fn_path: Label,
}

fn collect_env_sites(file: &SourceFile) -> Vec<EnvSite> {
    // File-path module prefix: `crates/xtask/src/host_env.rs` → `host_env`,
    // `crates/xtask/src/a/b.rs` → `a::b`, `.../main.rs`/`lib.rs`/`mod.rs` → ∅.
    let file_mod_prefix: Vec<Label> = {
        let marker = "/src/";
        if let Some(idx) = file.rel_path().find(marker) {
            let rest = &file.rel_path()[idx + marker.len()..];
            if let Some(stem) = rest.strip_suffix(".rs") {
                if matches!(stem, "main" | "lib" | "mod") {
                    vec![]
                } else {
                    stem.split('/')
                        .filter(|s| *s != "mod")
                        .map(Label::admit)
                        .collect()
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    };
    struct V<'a> {
        mod_stack: Vec<Label>,
        fn_stack: Vec<Label>,
        sites: &'a mut Vec<EnvSite>,
    }
    impl V<'_> {
        fn current_fn_path(&self) -> Label {
            let mut parts: Vec<&str> = self.mod_stack.iter().map(Label::as_str).collect();
            if let Some(f) = self.fn_stack.last() {
                parts.push(f.as_str());
            }
            Label::admit(parts.join("::"))
        }
    }
    impl<'ast> Visit<'ast> for V<'_> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            self.mod_stack.push(Label::admit(node.ident.to_string()));
            visit::visit_item_mod(self, node);
            self.mod_stack.pop();
        }
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            self.fn_stack.push(Label::admit(node.sig.ident.to_string()));
            visit::visit_item_fn(self, node);
            self.fn_stack.pop();
        }
        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            self.fn_stack.push(Label::admit(node.sig.ident.to_string()));
            visit::visit_impl_item_fn(self, node);
            self.fn_stack.pop();
        }
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            // Bare path expressions are not call sites; calls are handled
            // in visit_expr_call. Still walk children.
            visit::visit_expr_path(self, node);
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = &*node.func {
                if is_env_or_args_path(&p.path) && !self.fn_stack.is_empty() {
                    self.sites.push(EnvSite {
                        line: span_line(&p.path.span()),
                        fn_path: self.current_fn_path(),
                    });
                }
            }
            visit::visit_expr_call(self, node);
        }
    }
    let mut sites = vec![];
    let mut v = V {
        mod_stack: file_mod_prefix,
        fn_stack: vec![],
        sites: &mut sites,
    };
    v.visit_file(file.ast());
    sites
}

/// Env/args call sites under each declared binary path: exactly one, and
/// it must sit inside the declared `fn_path` constructor.
pub fn config_once(files: &[&SourceFile], seats: &[ConfigOnceSeat]) -> Vec<Hit> {
    let mut hits = vec![];
    for seat in seats {
        let scoped: Vec<&&SourceFile> = files
            .iter()
            .filter(|f| f.rel_path().starts_with(seat.path()))
            .collect();
        // Skip test/bite fixtures under the host when they are not the
        // binary's production tree? No — law is absolute over the path.
        let mut sites: Vec<(&str, EnvSite)> = vec![];
        for f in &scoped {
            for s in collect_env_sites(f) {
                sites.push((f.rel_path(), s));
            }
        }
        if sites.len() != 1 {
            hits.push(Hit::admit(
                seat.path().trim_end_matches('/').to_string(),
                0,
                format!(
                    "config-once-count:{} (want 1 in `{}`)",
                    sites.len(),
                    seat.fn_path()
                ),
            ));
            for (file, s) in &sites {
                if s.fn_path != seat.fn_path() {
                    hits.push(Hit::admit(
                        (*file).to_string(),
                        s.line,
                        format!(
                            "config-once-outside-ctor:{} (want `{}`)",
                            s.fn_path,
                            seat.fn_path()
                        ),
                    ));
                }
            }
            continue;
        }
        let (file, s) = &sites[0];
        if s.fn_path != seat.fn_path() {
            hits.push(Hit::admit(
                (*file).to_string(),
                s.line,
                format!(
                    "config-once-outside-ctor:{} (want `{}`)",
                    s.fn_path,
                    seat.fn_path()
                ),
            ));
        }
    }
    hits
}

/// Typed test refusal — file-level so `total_refusal` indexes it as a workspace
/// enum (tip 777). Nested inside `mod tests` was `not-workspace-enum`.
#[cfg(test)]
#[derive(Debug)]
enum GraphProofRefuse {
    Parse,
    DeriveBypassHitCount,
    CopyDetectorHitCount,
    CopyDetectorConstruct,
    AgreementHitCount,
    AgreementConstruct,
    TotalRefusalString,
    TotalRefusalAnyhow,
    TotalRefusalBox,
    TotalRefusalNotWorkspaceEnum,
    TotalRefusalExactCount,
    SealedDoorStdOutside,
    SealedDoorAllowedPass,
    SealedDoorCrateInternal,
    ConfigOnceDeclaredPass,
    ConfigOnceTwoSitesRed,
}
#[cfg(test)]
impl GraphProofRefuse {
    fn require(self, cond: bool) -> Result<(), GraphProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }

    fn require_eq<T: PartialEq>(self, got: T, want: T) -> Result<(), GraphProofRefuse> {
        self.require(got == want)
    }
}

#[cfg(test)]
struct GraphProofs;

#[cfg(test)]
impl GraphProofs {
    fn parse(&self, rel: &str, src: &str) -> Result<SourceFile, GraphProofRefuse> {
        let ast = syn::parse_file(src).map_err(|_| GraphProofRefuse::Parse)?;
        Ok(SourceFile::admit(rel.to_string(), src.to_string(), ast))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), GraphProofRefuse>;

    const PROOFS: GraphProofs = GraphProofs;

    #[test]
    fn derive_bypass_detonates_on_the_historical_shape() -> TestResult {
        let f = PROOFS.parse(
            "crates/x/src/a.rs",
            "#[derive(Default)] struct Interval(u8);\n impl Interval { fn new(x: u8) -> Result<Interval, ()> { if x > 0 { Ok(Interval(x)) } else { Err(()) } } }",
        )?;
        let hits = derive_bypass(&[&f]);
        GraphProofRefuse::DeriveBypassHitCount.require_eq(hits.len(), 1)
    }

    #[test]
    fn copy_detector_detonates_on_a_renamed_copy() -> TestResult {
        let body = "{ let mut acc = 0; for i in 0..100 { if i % 2 == 0 { acc += i * 3 + 7; } else { acc -= i / 2 + 11; } while acc > 500 { acc /= 2; } match acc { 0 => acc = 1, 1 => acc = 2, other => acc = other - 1, } } acc }";
        let a = PROOFS.parse("crates/x/src/a.rs", &format!("fn alpha() -> i64 {body}"))?;
        let b = PROOFS.parse("crates/y/src/b.rs", &format!("fn beta() -> i64 {body}"))?;
        let hits = copy_detector(&[&a, &b]);
        GraphProofRefuse::CopyDetectorHitCount.require_eq(hits.len(), 1)?;
        GraphProofRefuse::CopyDetectorConstruct.require_eq(hits[0].construct(), "crates/x/src/a.rs::alpha ~ crates/y/src/b.rs::beta")
    }

    #[test]
    fn agreement_registry_detonates_on_drift() -> TestResult {
        let f = PROOFS.parse("crates/x/src/a.rs", "fn law_alive() {}")?;
        let reg = "[[agreement]]\ntest_fn = \"law_alive\"\n[[agreement]]\ntest_fn = \"law_deleted\"\n";
        let hits = agreement_registry(&[&f], reg);
        GraphProofRefuse::AgreementHitCount.require_eq(hits.len(), 1)?;
        GraphProofRefuse::AgreementConstruct.require(hits[0].construct().contains("law_deleted"))
    }

    #[test]
    fn total_refusal_reds_string_anyhow_and_box_dyn() -> TestResult {
        let enums = PROOFS.parse("crates/x/src/e.rs", "enum E { A }")?;
        let bad = PROOFS.parse(
            "crates/x/src/a.rs",
            "fn a() -> Result<(), String> { Ok(()) }\n\
             fn b() -> Result<(), anyhow::Error> { Ok(()) }\n\
             fn c() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             fn d() -> Result<(), u8> { Ok(()) }\n\
             fn e() -> Result<(), E> { Ok(()) }",
        )?;
        let hits = total_refusal(&[&enums, &bad]);
        GraphProofRefuse::TotalRefusalString.require(hits.iter().any(|h| h.construct().contains("String")))?;
        GraphProofRefuse::TotalRefusalAnyhow.require(hits.iter().any(|h| h.construct().contains("anyhow")))?;
        GraphProofRefuse::TotalRefusalBox.require(hits.iter().any(|h| h.construct().contains("Box")))?;
        GraphProofRefuse::TotalRefusalNotWorkspaceEnum.require(hits.iter().any(|h| h.construct().contains("not-workspace-enum")))?;
        GraphProofRefuse::TotalRefusalExactCount.require_eq(hits.len(), 4)
    }

    #[test]
    fn sealed_public_door_reds_import_outside_allowlist() -> TestResult {
        let f = PROOFS.parse(
            "crates/kyzo-bin/src/main.rs",
            "use std::process::ExitCode;\nuse crate::engine::Engine;\nuse kyzo_core::Db;\n",
        )?;
        let hosts = vec![HostDoor::admit(
            "crates/kyzo-bin/",
            vec![crate::boundary::Label::admit("kyzo_core")],
        )];
        let hits = sealed_public_door(&[&f], &hosts);
        GraphProofRefuse::SealedDoorStdOutside.require(hits.iter().any(|h| h.construct().contains("import-outside-door:std")))?;
        GraphProofRefuse::SealedDoorAllowedPass.require(!hits.iter().any(|h| h.construct().contains("kyzo_core")))?;
        GraphProofRefuse::SealedDoorCrateInternal.require(!hits.iter().any(|h| h.construct().contains("crate")))
    }

    #[test]
    fn config_once_demands_exactly_one_site_in_declared_ctor() -> TestResult {
        let good = PROOFS.parse(
            "crates/xtask/src/host_env.rs",
            "fn read(name: &str) -> Option<String> { std::env::var(name).ok() }",
        )?;
        let seats = vec![ConfigOnceSeat::admit("crates/xtask/", "host_env::read")];
        let hits = config_once(&[&good], &seats);
        GraphProofRefuse::ConfigOnceDeclaredPass.require(hits.is_empty())?;

        let two = PROOFS.parse(
            "crates/xtask/src/host_env.rs",
            "fn read(name: &str) -> Option<String> { std::env::var(name).ok() }\n\
             fn other() { let _ = std::env::var(\"X\"); }",
        )?;
        let hits = config_once(&[&two], &seats);
        GraphProofRefuse::ConfigOnceTwoSitesRed.require(hits.iter().any(|h| h.construct().contains("config-once-count:2")))
    }
}
