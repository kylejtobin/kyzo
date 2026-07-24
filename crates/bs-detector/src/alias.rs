/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! TRUTH item 4 — workspace alias table + string-carrying type walk.
//!
//! Every `ItemType` and every `use … as` rename across the boundary is an
//! edge keyed by `(file, name)` — workspace-wide collection, file-scoped
//! resolution. [`AliasTable::build`] refuses cycles; the resulting table
//! is acyclic by construction and [`AliasTable::type_carries_string`] is
//! infallible (precomputed string-carrying names, no Result at classify).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use quote::ToTokens;
use syn::visit::{self, Visit};

use crate::boundary::{Label, RelPath, SourceFile};

/// `(file, simple name)` key for alias edges — no `String` terminals.
type AliasKey = (RelPath, Label);

fn alias_key(file: &str, name: impl Into<Label>) -> AliasKey {
    (RelPath::admit(file), name.into())
}

/// Validated alias table: constructible only via [`AliasTable::build`]
/// (or [`AliasTable::empty`]), which has already refused every cycle.
#[derive(Debug)]
pub struct AliasTable {
    /// `(rel_path, simple name)` known to resolve to a string-carrying type.
    string_names: BTreeSet<AliasKey>,
}

impl AliasTable {
    pub fn empty() -> Self {
        Self {
            string_names: BTreeSet::new(),
        }
    }

    /// Collect every `type Name = …` and `use … as Rename` across `files`,
    /// refuse cycles, and seal the string-carrying name set.
    pub fn build(files: &[&SourceFile]) -> Result<Self> {
        let mut edges: BTreeMap<AliasKey, syn::Type> = BTreeMap::new();
        for f in files {
            collect_file(f, &mut edges)?;
        }
        let raw = RawEdges { edges };
        let mut string_names = BTreeSet::new();
        let keys: Vec<AliasKey> = raw.edges.keys().cloned().collect();
        for (file, name) in keys {
            let mut stack = BTreeSet::new();
            if raw.resolve_name_is_string(file.as_str(), name.as_str(), &mut stack)? {
                string_names.insert((file, name));
            }
        }
        Ok(Self { string_names })
    }

    /// Whether `ty` carries a string terminal under aliases visible in `file`.
    /// Infallible: acyclicity was proven at [`AliasTable::build`].
    pub fn type_carries_string(&self, file: &str, ty: &syn::Type) -> bool {
        match ty {
            syn::Type::Reference(r) => self.type_carries_string(file, &r.elem),
            syn::Type::Paren(p) => self.type_carries_string(file, &p.elem),
            syn::Type::Group(g) => self.type_carries_string(file, &g.elem),
            syn::Type::Array(a) => self.type_carries_string(file, &a.elem),
            syn::Type::Slice(s) => self.type_carries_string(file, &s.elem),
            syn::Type::Ptr(p) => self.type_carries_string(file, &p.elem),
            syn::Type::Tuple(t) => t.elems.iter().any(|e| self.type_carries_string(file, e)),
            syn::Type::BareFn(f) => bare_fn_carries(f, |inner| self.type_carries_string(file, inner)),
            syn::Type::TraitObject(t) => {
                trait_bounds_carry(&t.bounds, |inner| self.type_carries_string(file, inner))
            }
            syn::Type::ImplTrait(t) => {
                trait_bounds_carry(&t.bounds, |inner| self.type_carries_string(file, inner))
            }
            syn::Type::Path(tp) => {
                if path_is_string_terminal(&tp.path) {
                    return true;
                }
                if path_generic_args_carry(&tp.path, |inner| self.type_carries_string(file, inner))
                {
                    return true;
                }
                // Only bare idents resolve through the alias table.
                if tp.path.segments.len() == 1 {
                    if let Some(seg) = tp.path.segments.last() {
                        let name = seg.ident.to_string();
                        return self.string_names.contains(&alias_key(file, name));
                    }
                }
                false
            }
            _not_walked_further => false,
        }
    }
}

/// Unvalidated edge bag — exists only inside [`AliasTable::build`].
struct RawEdges {
    edges: BTreeMap<AliasKey, syn::Type>,
}

impl RawEdges {
    fn resolve_name_is_string(
        &self,
        file: &str,
        name: &str,
        stack: &mut BTreeSet<String>,
    ) -> Result<bool> {
        let Some(rhs) = self.edges.get(&alias_key(file, name)) else {
            return Ok(false);
        };
        let cycle_key = format!("{file}::{name}");
        if !stack.insert(cycle_key.clone()) {
            bail!(
                "alias cycle involving `{name}` in `{file}` — item 4 fixpoint refuses a cyclic alias table"
            );
        }
        let out = self.type_carries_string_rec(file, rhs, stack)?;
        stack.remove(&cycle_key);
        Ok(out)
    }

    fn type_carries_string_rec(
        &self,
        file: &str,
        ty: &syn::Type,
        stack: &mut BTreeSet<String>,
    ) -> Result<bool> {
        match ty {
            syn::Type::Reference(r) => self.type_carries_string_rec(file, &r.elem, stack),
            syn::Type::Paren(p) => self.type_carries_string_rec(file, &p.elem, stack),
            syn::Type::Group(g) => self.type_carries_string_rec(file, &g.elem, stack),
            syn::Type::Array(a) => self.type_carries_string_rec(file, &a.elem, stack),
            syn::Type::Slice(s) => self.type_carries_string_rec(file, &s.elem, stack),
            syn::Type::Ptr(p) => self.type_carries_string_rec(file, &p.elem, stack),
            syn::Type::Tuple(t) => {
                for e in &t.elems {
                    if self.type_carries_string_rec(file, e, stack)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            syn::Type::BareFn(f) => {
                for inp in &f.inputs {
                    if self.type_carries_string_rec(file, &inp.ty, stack)? {
                        return Ok(true);
                    }
                }
                match &f.output {
                    syn::ReturnType::Type(_, ty) => self.type_carries_string_rec(file, ty, stack),
                    syn::ReturnType::Default => Ok(false),
                }
            }
            syn::Type::TraitObject(t) => self.bounds_carry_rec(file, &t.bounds, stack),
            syn::Type::ImplTrait(t) => self.bounds_carry_rec(file, &t.bounds, stack),
            syn::Type::Path(tp) => {
                if path_is_string_terminal(&tp.path) {
                    return Ok(true);
                }
                if self.path_args_carry_rec(file, &tp.path, stack)? {
                    return Ok(true);
                }
                if tp.path.segments.len() == 1 {
                    if let Some(seg) = tp.path.segments.last() {
                        let name = seg.ident.to_string();
                        return self.resolve_name_is_string(file, &name, stack);
                    }
                }
                Ok(false)
            }
            _not_walked_further => Ok(false),
        }
    }

    fn path_args_carry_rec(
        &self,
        file: &str,
        path: &syn::Path,
        stack: &mut BTreeSet<String>,
    ) -> Result<bool> {
        for seg in &path.segments {
            match &seg.arguments {
                syn::PathArguments::None => {}
                syn::PathArguments::AngleBracketed(args) => {
                    for a in &args.args {
                        match a {
                            syn::GenericArgument::Type(inner)
                            | syn::GenericArgument::AssocType(syn::AssocType {
                                ty: inner, ..
                            }) => {
                                if self.type_carries_string_rec(file, inner, stack)? {
                                    return Ok(true);
                                }
                            }
                            syn::GenericArgument::Lifetime(_)
                            | syn::GenericArgument::Const(_)
                            | syn::GenericArgument::AssocConst(_)
                            | syn::GenericArgument::Constraint(_)
                            | _ => {}
                        }
                    }
                }
                syn::PathArguments::Parenthesized(p) => {
                    for t in &p.inputs {
                        if self.type_carries_string_rec(file, t, stack)? {
                            return Ok(true);
                        }
                    }
                    if let syn::ReturnType::Type(_, ty) = &p.output {
                        if self.type_carries_string_rec(file, ty, stack)? {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn bounds_carry_rec(
        &self,
        file: &str,
        bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::token::Plus>,
        stack: &mut BTreeSet<String>,
    ) -> Result<bool> {
        for b in bounds {
            if let syn::TypeParamBound::Trait(tb) = b {
                if self.path_args_carry_rec(file, &tb.path, stack)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn bare_fn_carries(f: &syn::TypeBareFn, mut carry: impl FnMut(&syn::Type) -> bool) -> bool {
    f.inputs.iter().any(|inp| carry(&inp.ty))
        || match &f.output {
            syn::ReturnType::Type(_, ty) => carry(ty),
            syn::ReturnType::Default => false,
        }
}

fn trait_bounds_carry(
    bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::token::Plus>,
    mut carry: impl FnMut(&syn::Type) -> bool,
) -> bool {
    for b in bounds {
        if let syn::TypeParamBound::Trait(tb) = b {
            if path_generic_args_carry(&tb.path, &mut carry) {
                return true;
            }
        }
    }
    false
}

fn path_generic_args_carry(path: &syn::Path, mut carry: impl FnMut(&syn::Type) -> bool) -> bool {
    for seg in &path.segments {
        match &seg.arguments {
            syn::PathArguments::None => {}
            syn::PathArguments::AngleBracketed(args) => {
                for a in &args.args {
                    match a {
                        syn::GenericArgument::Type(inner)
                        | syn::GenericArgument::AssocType(syn::AssocType { ty: inner, .. }) => {
                            if carry(inner) {
                                return true;
                            }
                        }
                        syn::GenericArgument::Lifetime(_)
                        | syn::GenericArgument::Const(_)
                        | syn::GenericArgument::AssocConst(_)
                        | syn::GenericArgument::Constraint(_)
                        | _ => {}
                    }
                }
            }
            // Tip 686: `Fn() -> String` / `FnOnce(String)` parenthesized args
            // were AngleBracketed-only blind — dyn Fn silent-greened.
            syn::PathArguments::Parenthesized(p) => {
                if p.inputs.iter().any(|t| carry(t)) {
                    return true;
                }
                if let syn::ReturnType::Type(_, ty) = &p.output {
                    if carry(ty) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Banned string terminals per item 4: `String`, `str`,
/// `std::string::String`, `alloc::string::String`.
fn path_is_string_terminal(path: &syn::Path) -> bool {
    let segs: Vec<String> = path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let s: Vec<&str> = segs.iter().map(|x| x.as_str()).collect();
    matches!(
        s.as_slice(),
        ["String"]
            | ["str"]
            | ["std", "string", "String"]
            | ["alloc", "string", "String"]
    )
}

fn insert_edge(
    edges: &mut BTreeMap<AliasKey, syn::Type>,
    ambiguous: &mut BTreeSet<AliasKey>,
    file: &str,
    name: String,
    rhs: syn::Type,
) {
    let key = alias_key(file, name);
    if ambiguous.contains(&key) {
        return;
    }
    if let Some(prev) = edges.get(&key) {
        let prev_toks = prev.to_token_stream().to_string();
        let new_toks = rhs.to_token_stream().to_string();
        if prev_toks != new_toks {
            // Same-file dual binding (almost always cfg-forked imports).
            edges.remove(&key);
            ambiguous.insert(key);
            return;
        }
        return;
    }
    edges.insert(key, rhs);
}

fn collect_use_renames(
    tree: &syn::UseTree,
    prefix: &[String],
    file: &str,
    edges: &mut BTreeMap<AliasKey, syn::Type>,
    ambiguous: &mut BTreeSet<AliasKey>,
) {
    match tree {
        syn::UseTree::Path(p) => {
            let mut next = prefix.to_vec();
            next.push(p.ident.to_string());
            collect_use_renames(&p.tree, &next, file, edges, ambiguous);
        }
        syn::UseTree::Rename(r) => {
            let rename = r.rename.to_string();
            if rename == "_" {
                return;
            }
            let mut segs = prefix.to_vec();
            segs.push(r.ident.to_string());
            let mut path = syn::Path {
                leading_colon: None,
                segments: syn::punctuated::Punctuated::new(),
            };
            for s in segs {
                path.segments.push(syn::PathSegment {
                    ident: syn::Ident::new(&s, proc_macro2::Span::call_site()),
                    arguments: syn::PathArguments::None,
                });
            }
            insert_edge(
                edges,
                ambiguous,
                file,
                rename,
                syn::Type::Path(syn::TypePath { qself: None, path }),
            );
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                collect_use_renames(item, prefix, file, edges, ambiguous);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
    }
}

fn collect_file(
    file: &SourceFile,
    edges: &mut BTreeMap<AliasKey, syn::Type>,
) -> Result<()> {
    struct V<'a> {
        file: &'a str,
        edges: &'a mut BTreeMap<AliasKey, syn::Type>,
        ambiguous: BTreeSet<AliasKey>,
    }
    impl<'ast> Visit<'ast> for V<'_> {
        fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
            insert_edge(
                self.edges,
                &mut self.ambiguous,
                self.file,
                node.ident.to_string(),
                (*node.ty).clone(),
            );
            visit::visit_item_type(self, node);
        }
        fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
            collect_use_renames(
                &node.tree,
                &[],
                self.file,
                self.edges,
                &mut self.ambiguous,
            );
            visit::visit_item_use(self, node);
        }
    }
    let mut v = V {
        file: file.rel_path(),
        edges,
        ambiguous: BTreeSet::new(),
    };
    v.visit_file(file.ast());
    Ok(())
}

/// Typed test refusal — file-level so `total_refusal` indexes it as a workspace
/// enum (tip 777). Nested inside `mod tests` was `not-workspace-enum`.
#[cfg(test)]
#[derive(Debug)]
enum AliasProofRefuse {
    Parse,
    Build,
    Type,
    MustCarry,
    MustNotCarry,
    CycleSilent,
    CycleUnnamed,
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), AliasProofRefuse>;

    fn require(cond: bool, refuse: AliasProofRefuse) -> TestResult {
        if cond {
            Ok(())
        } else {
            Err(refuse)
        }
    }

    fn file(src: &str) -> Result<SourceFile, AliasProofRefuse> {
        let ast = syn::parse_file(src).map_err(|_| AliasProofRefuse::Parse)?;
        Ok(SourceFile::admit("crates/probe/src/lib.rs", src, ast))
    }

    #[test]
    fn item_4_proof_type_alias_to_string_carries() -> TestResult {
        let f = file("type Name = String;")?;
        let t = AliasTable::build(&[&f]).map_err(|_| AliasProofRefuse::Build)?;
        let ty: syn::Type = syn::parse_str("Name").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string(f.rel_path(), &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    #[test]
    fn item_4_proof_use_as_string_carries() -> TestResult {
        let f = file("use std::string::String as Text;")?;
        let t = AliasTable::build(&[&f]).map_err(|_| AliasProofRefuse::Build)?;
        let ty: syn::Type = syn::parse_str("Text").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string(f.rel_path(), &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    #[test]
    fn item_4_proof_restrict_does_not_carry() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type = syn::parse_str("Restrict").map_err(|_| AliasProofRefuse::Type)?;
        require(
            !t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustNotCarry,
        )
    }

    #[test]
    fn item_4_proof_alias_cycle_is_a_load_error() -> TestResult {
        let f = file("type A = B; type B = A;")?;
        let e = AliasTable::build(&[&f]);
        require(e.is_err(), AliasProofRefuse::CycleSilent)?;
        let msg = format!("{:?}", e.err());
        require(msg.contains("cycle"), AliasProofRefuse::CycleUnnamed)
    }

    /// Soft drain: Ptr/`fn`/dyn/impl wrappers around String were `_ => false`
    /// — sealed-struct false-green. Exact terminal through the wrapper.
    #[test]
    fn anti_fraud_ptr_to_string_carries() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("*const String").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    #[test]
    fn anti_fraud_bare_fn_returning_string_carries() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("fn() -> String").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    #[test]
    fn anti_fraud_dyn_asref_str_carries() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("dyn AsRef<str>").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    #[test]
    fn anti_fraud_impl_asref_str_carries() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("impl AsRef<str>").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    /// Tip 686: Parenthesized `Fn() -> String` was AngleBracketed-only blind.
    #[test]
    fn anti_fraud_dyn_fn_returning_string_carries() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("dyn Fn() -> String").map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    /// Tip 686: AssocType generic arg `Item = String` was Type-only blind.
    #[test]
    fn anti_fraud_assoc_type_item_string_carries() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type = syn::parse_str("dyn IntoIterator<Item = String>")
            .map_err(|_| AliasProofRefuse::Type)?;
        require(
            t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustCarry,
        )
    }

    #[test]
    fn anti_fraud_clean_dyn_fn_u8_does_not_carry() -> TestResult {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("dyn Fn() -> u8").map_err(|_| AliasProofRefuse::Type)?;
        require(
            !t.type_carries_string("crates/probe/src/lib.rs", &ty),
            AliasProofRefuse::MustNotCarry,
        )
    }
}
