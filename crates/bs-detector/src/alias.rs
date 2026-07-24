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

use crate::boundary::SourceFile;

/// Validated alias table: constructible only via [`AliasTable::build`]
/// (or [`AliasTable::empty`]), which has already refused every cycle.
#[derive(Debug, Default)]
pub struct AliasTable {
    /// `(rel_path, simple name)` known to resolve to a string-carrying type.
    string_names: BTreeSet<(String, String)>,
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
        let mut edges: BTreeMap<(String, String), syn::Type> = BTreeMap::new();
        for f in files {
            collect_file(f, &mut edges)?;
        }
        let raw = RawEdges { edges };
        let mut string_names = BTreeSet::new();
        let keys: Vec<(String, String)> = raw.edges.keys().cloned().collect();
        for (file, name) in keys {
            let mut stack = BTreeSet::new();
            if raw.resolve_name_is_string(&file, &name, &mut stack)? {
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
            syn::Type::Tuple(t) => t.elems.iter().any(|e| self.type_carries_string(file, e)),
            syn::Type::Path(tp) => {
                if path_is_string_terminal(&tp.path) {
                    return true;
                }
                if let Some(seg) = tp.path.segments.last() {
                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        for a in &args.args {
                            if let syn::GenericArgument::Type(inner) = a {
                                if self.type_carries_string(file, inner) {
                                    return true;
                                }
                            }
                        }
                    }
                    // Only bare idents resolve through the alias table.
                    if tp.path.segments.len() == 1 {
                        let name = seg.ident.to_string();
                        return self
                            .string_names
                            .contains(&(file.to_string(), name));
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
    edges: BTreeMap<(String, String), syn::Type>,
}

impl RawEdges {
    fn resolve_name_is_string(
        &self,
        file: &str,
        name: &str,
        stack: &mut BTreeSet<String>,
    ) -> Result<bool> {
        let Some(rhs) = self.edges.get(&(file.to_string(), name.to_string())) else {
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
            syn::Type::Tuple(t) => {
                for e in &t.elems {
                    if self.type_carries_string_rec(file, e, stack)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            syn::Type::Path(tp) => {
                if path_is_string_terminal(&tp.path) {
                    return Ok(true);
                }
                if let Some(seg) = tp.path.segments.last() {
                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        for a in &args.args {
                            if let syn::GenericArgument::Type(inner) = a {
                                if self.type_carries_string_rec(file, inner, stack)? {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                    if tp.path.segments.len() == 1 {
                        let name = seg.ident.to_string();
                        return self.resolve_name_is_string(file, &name, stack);
                    }
                }
                Ok(false)
            }
            _not_walked_further => Ok(false),
        }
    }
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
    edges: &mut BTreeMap<(String, String), syn::Type>,
    ambiguous: &mut BTreeSet<(String, String)>,
    file: &str,
    name: String,
    rhs: syn::Type,
) {
    let key = (file.to_string(), name);
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
    edges: &mut BTreeMap<(String, String), syn::Type>,
    ambiguous: &mut BTreeSet<(String, String)>,
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
    edges: &mut BTreeMap<(String, String), syn::Type>,
) -> Result<()> {
    struct V<'a> {
        file: &'a str,
        edges: &'a mut BTreeMap<(String, String), syn::Type>,
        ambiguous: BTreeSet<(String, String)>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn file(src: &str) -> SourceFile {
        SourceFile::admit("crates/probe/src/lib.rs".to_string(), src.to_string(), syn::parse_file(src).expect("parses"))
    }

    #[test]
    fn item_4_proof_type_alias_to_string_carries() {
        let f = file("type Name = String;");
        let t = AliasTable::build(&[&f]).expect("builds");
        let ty: syn::Type = syn::parse_str("Name").expect("type");
        assert!(t.type_carries_string(f.rel_path(), &ty));
    }

    #[test]
    fn item_4_proof_use_as_string_carries() {
        let f = file("use std::string::String as Text;");
        let t = AliasTable::build(&[&f]).expect("builds");
        let ty: syn::Type = syn::parse_str("Text").expect("type");
        assert!(t.type_carries_string(f.rel_path(), &ty));
    }

    #[test]
    fn item_4_proof_restrict_does_not_carry() {
        let t = AliasTable::empty();
        let ty: syn::Type = syn::parse_str("Restrict").expect("type");
        assert!(!t.type_carries_string("crates/probe/src/lib.rs", &ty));
    }

    #[test]
    fn item_4_proof_alias_cycle_is_a_load_error() {
        let f = file("type A = B; type B = A;");
        let e = AliasTable::build(&[&f]);
        assert!(e.is_err(), "cycle must refuse");
        let msg = format!("{:?}", e.err());
        assert!(msg.contains("cycle"), "refusal names the cycle: {msg}");
    }
}
