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

/// One authority for banned string-terminal paths (item 4) — tip 1002 copy_detector burn.
struct StringTerminalLaw;

const STRING_TERMINAL: StringTerminalLaw = StringTerminalLaw;

impl StringTerminalLaw {
    /// Banned string terminals: `String`, `str`, `std::string::String`, `alloc::string::String`.
    fn path_is(&self, path: &syn::Path) -> bool {
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
        let mut raw = RawEdges {
            edges: BTreeMap::new(),
            ambiguous: BTreeSet::new(),
        };
        for f in files {
            raw.collect_file(f)?;
        }
        Ok(Self {
            string_names: raw.seal_string_names()?,
        })
    }

    fn edge_key(&self, file: &str, name: impl Into<Label>) -> AliasKey {
        (RelPath::admit(file), name.into())
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
            syn::Type::BareFn(f) => {
                self.bare_fn_carries(f, |inner| self.type_carries_string(file, inner))
            }
            syn::Type::TraitObject(t) => {
                self.trait_bounds_carry(&t.bounds, |inner| self.type_carries_string(file, inner))
            }
            syn::Type::ImplTrait(t) => {
                self.trait_bounds_carry(&t.bounds, |inner| self.type_carries_string(file, inner))
            }
            syn::Type::Path(tp) => {
                if STRING_TERMINAL.path_is(&tp.path) {
                    return true;
                }
                if self.path_generic_args_carry(&tp.path, |inner| self.type_carries_string(file, inner))
                {
                    return true;
                }
                // Only bare idents resolve through the alias table.
                if tp.path.segments.len() == 1 {
                    if let Some(seg) = tp.path.segments.last() {
                        let name = seg.ident.to_string();
                        return self.string_names.contains(&self.edge_key(file, name));
                    }
                }
                false
            }
            _not_walked_further => false,
        }
    }

    fn bare_fn_carries(
        &self,
        f: &syn::TypeBareFn,
        mut carry: impl FnMut(&syn::Type) -> bool,
    ) -> bool {
        f.inputs.iter().any(|inp| carry(&inp.ty))
            || match &f.output {
                syn::ReturnType::Type(_, ty) => carry(ty),
                syn::ReturnType::Default => false,
            }
    }

    fn trait_bounds_carry(
        &self,
        bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::token::Plus>,
        mut carry: impl FnMut(&syn::Type) -> bool,
    ) -> bool {
        for b in bounds {
            if let syn::TypeParamBound::Trait(tb) = b {
                if self.path_generic_args_carry(&tb.path, &mut carry) {
                    return true;
                }
            }
        }
        false
    }

    fn path_generic_args_carry(
        &self,
        path: &syn::Path,
        mut carry: impl FnMut(&syn::Type) -> bool,
    ) -> bool {
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
}

/// Unvalidated edge bag — exists only inside [`AliasTable::build`].
struct RawEdges {
    edges: BTreeMap<AliasKey, syn::Type>,
    ambiguous: BTreeSet<AliasKey>,
}

impl RawEdges {
    fn edge_key(&self, file: &str, name: impl Into<Label>) -> AliasKey {
        (RelPath::admit(file), name.into())
    }

    fn seal_string_names(self) -> Result<BTreeSet<AliasKey>> {
        let mut string_names = BTreeSet::new();
        let keys: Vec<AliasKey> = self.edges.keys().cloned().collect();
        for (file, name) in keys {
            let mut stack = BTreeSet::new();
            if self.resolve_name_is_string(file.as_str(), name.as_str(), &mut stack)? {
                string_names.insert((file, name));
            }
        }
        Ok(string_names)
    }

    fn insert_edge(&mut self, file: &str, name: String, rhs: syn::Type) {
        let key = self.edge_key(file, name);
        if self.ambiguous.contains(&key) {
            return;
        }
        if let Some(prev) = self.edges.get(&key) {
            let prev_toks = prev.to_token_stream().to_string();
            let new_toks = rhs.to_token_stream().to_string();
            if prev_toks != new_toks {
                // Same-file dual binding (almost always cfg-forked imports).
                self.edges.remove(&key);
                self.ambiguous.insert(key);
                return;
            }
            return;
        }
        self.edges.insert(key, rhs);
    }

    fn collect_use_renames(&mut self, tree: &syn::UseTree, prefix: &[String], file: &str) {
        match tree {
            syn::UseTree::Path(p) => {
                let mut next = prefix.to_vec();
                next.push(p.ident.to_string());
                self.collect_use_renames(&p.tree, &next, file);
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
                self.insert_edge(
                    file,
                    rename,
                    syn::Type::Path(syn::TypePath { qself: None, path }),
                );
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.collect_use_renames(item, prefix, file);
                }
            }
            syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
        }
    }

    fn collect_file(&mut self, file: &SourceFile) -> Result<()> {
        struct V<'a> {
            raw: &'a mut RawEdges,
            file: &'a RelPath,
        }
        impl<'ast> Visit<'ast> for V<'_> {
            fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
                self.raw.insert_edge(
                    self.file.as_str(),
                    node.ident.to_string(),
                    (*node.ty).clone(),
                );
                visit::visit_item_type(self, node);
            }
            fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
                self.raw
                    .collect_use_renames(&node.tree, &[], self.file.as_str());
                visit::visit_item_use(self, node);
            }
        }
        let mut v = V {
            raw: self,
            file: file.rel_path_ref(),
        };
        v.visit_file(file.ast());
        Ok(())
    }

    fn resolve_name_is_string(
        &self,
        file: &str,
        name: &str,
        stack: &mut BTreeSet<String>,
    ) -> Result<bool> {
        let Some(rhs) = self.edges.get(&self.edge_key(file, name)) else {
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
                if STRING_TERMINAL.path_is(&tp.path) {
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
impl AliasProofRefuse {
    fn require(self, cond: bool) -> Result<(), AliasProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
struct AliasProofs;

#[cfg(test)]
impl AliasProofs {
    fn file(&self, src: &str) -> Result<SourceFile, AliasProofRefuse> {
        let ast = syn::parse_file(src).map_err(|_| AliasProofRefuse::Parse)?;
        Ok(SourceFile::admit("crates/probe/src/lib.rs", src, ast))
    }

    /// Shared carry proof for item-4 alias edges (tip 1017 copy_detector).
    fn assert_alias_src_carries(&self, src: &str, ty_name: &str) -> Result<(), AliasProofRefuse> {
        let f = self.file(src)?;
        let t = AliasTable::build(&[&f]).map_err(|_| AliasProofRefuse::Build)?;
        let ty: syn::Type = syn::parse_str(ty_name).map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string(f.rel_path(), &ty))
    }

    fn item_4_proof_type_alias_to_string_carries(&self) -> Result<(), AliasProofRefuse> {
        self.assert_alias_src_carries("type Name = String;", "Name")
    }

    fn item_4_proof_use_as_string_carries(&self) -> Result<(), AliasProofRefuse> {
        self.assert_alias_src_carries("use std::string::String as Text;", "Text")
    }

    fn item_4_proof_restrict_does_not_carry(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type = syn::parse_str("Restrict").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustNotCarry.require(!t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    fn item_4_proof_alias_cycle_is_a_load_error(&self) -> Result<(), AliasProofRefuse> {
        let f = self.file("type A = B; type B = A;")?;
        let e = AliasTable::build(&[&f]);
        AliasProofRefuse::CycleSilent.require(e.is_err())?;
        let msg = format!("{:?}", e.err());
        AliasProofRefuse::CycleUnnamed.require(msg.contains("cycle"))
    }

    /// Soft drain: Ptr/`fn`/dyn/impl wrappers around String were `_ => false`
    /// — sealed-struct false-green. Exact terminal through the wrapper.
    fn anti_fraud_ptr_to_string_carries(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("*const String").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    fn anti_fraud_bare_fn_returning_string_carries(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("fn() -> String").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    fn anti_fraud_dyn_asref_str_carries(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("dyn AsRef<str>").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    fn anti_fraud_impl_asref_str_carries(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("impl AsRef<str>").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    /// Tip 686: Parenthesized `Fn() -> String` was AngleBracketed-only blind.
    fn anti_fraud_dyn_fn_returning_string_carries(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("dyn Fn() -> String").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    /// Tip 686: AssocType generic arg `Item = String` was Type-only blind.
    fn anti_fraud_assoc_type_item_string_carries(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type = syn::parse_str("dyn IntoIterator<Item = String>")
            .map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustCarry.require(t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }

    fn anti_fraud_clean_dyn_fn_u8_does_not_carry(&self) -> Result<(), AliasProofRefuse> {
        let t = AliasTable::empty();
        let ty: syn::Type =
            syn::parse_str("dyn Fn() -> u8").map_err(|_| AliasProofRefuse::Type)?;
        AliasProofRefuse::MustNotCarry.require(!t.type_carries_string("crates/probe/src/lib.rs", &ty))
    }
}

#[cfg(test)]
mod tests {
    use super::{AliasProofRefuse, AliasProofs};

    type TestResult = Result<(), AliasProofRefuse>;

    const PROOFS: AliasProofs = AliasProofs;

    #[test]
    fn item_4_proof_type_alias_to_string_carries() -> TestResult {
        PROOFS.item_4_proof_type_alias_to_string_carries()
    }

    #[test]
    fn item_4_proof_use_as_string_carries() -> TestResult {
        PROOFS.item_4_proof_use_as_string_carries()
    }

    #[test]
    fn item_4_proof_restrict_does_not_carry() -> TestResult {
        PROOFS.item_4_proof_restrict_does_not_carry()
    }

    #[test]
    fn item_4_proof_alias_cycle_is_a_load_error() -> TestResult {
        PROOFS.item_4_proof_alias_cycle_is_a_load_error()
    }

    #[test]
    fn anti_fraud_ptr_to_string_carries() -> TestResult {
        PROOFS.anti_fraud_ptr_to_string_carries()
    }

    #[test]
    fn anti_fraud_bare_fn_returning_string_carries() -> TestResult {
        PROOFS.anti_fraud_bare_fn_returning_string_carries()
    }

    #[test]
    fn anti_fraud_dyn_asref_str_carries() -> TestResult {
        PROOFS.anti_fraud_dyn_asref_str_carries()
    }

    #[test]
    fn anti_fraud_impl_asref_str_carries() -> TestResult {
        PROOFS.anti_fraud_impl_asref_str_carries()
    }

    #[test]
    fn anti_fraud_dyn_fn_returning_string_carries() -> TestResult {
        PROOFS.anti_fraud_dyn_fn_returning_string_carries()
    }

    #[test]
    fn anti_fraud_assoc_type_item_string_carries() -> TestResult {
        PROOFS.anti_fraud_assoc_type_item_string_carries()
    }

    #[test]
    fn anti_fraud_clean_dyn_fn_u8_does_not_carry() -> TestResult {
        PROOFS.anti_fraud_clean_dyn_fn_u8_does_not_carry()
    }
}
