/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Site identity: a ruling binds to content, never to a line number.
//!
//! `identity_string` renders an item's token stream with identifiers and
//! literals byte-verbatim; spans, whitespace, and layout vanish, doc
//! comments remain (they are attributes, therefore content). It is a
//! second, separately named rendering from `normalize_tokens` in
//! `engines/graph.rs`, which collapses identifiers for clone detection and
//! must never be used for identity: an identifier-blind hash lets a
//! renamed body ride an old ruling.

use quote::ToTokens;

/// The identity-preserving rendering: token stream stringified. Identifiers
/// and literals are byte-verbatim; comments are gone (doc comments survive
/// as attributes); whitespace is token-separator only.
pub fn identity_string<T: ToTokens>(item: &T) -> String {
    item.to_token_stream().to_string()
}

/// The site hash a ruling binds to: blake3 of the identity rendering,
/// lowercase hex.
pub fn site_hash<T: ToTokens>(item: &T) -> String {
    blake3::hash(identity_string(item).as_bytes())
        .to_hex()
        .to_string()
}

/// One item's line range and identity hash: the lookup that binds a hit
/// (a line) to the content a ruling swore over.
pub struct ItemSpan {
    pub start: usize,
    pub end: usize,
    pub hash: String,
}

/// Every item's span+hash in one file: top-level items, plus impl and
/// trait members as finer entries so a hit inside a method binds to the
/// method, not the whole impl. `enclosing` picks the SMALLEST range.
pub fn item_index(ast: &syn::File) -> Vec<ItemSpan> {
    use syn::spanned::Spanned;
    fn push<T: ToTokens + Spanned>(out: &mut Vec<ItemSpan>, node: &T) {
        let span = node.span();
        out.push(ItemSpan {
            start: span.start().line,
            end: span.end().line,
            hash: site_hash(node),
        });
    }
    let mut out = Vec::new();
    for item in &ast.items {
        push(&mut out, item);
        match item {
            syn::Item::Impl(i) => {
                for m in &i.items {
                    push(&mut out, m);
                }
            }
            syn::Item::Trait(t) => {
                for m in &t.items {
                    push(&mut out, m);
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    for inner in items {
                        push(&mut out, inner);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The hash of the smallest item enclosing `line`, if any.
pub fn enclosing_hash(index: &[ItemSpan], line: usize) -> Option<&str> {
    index
        .iter()
        .filter(|s| s.start <= line && line <= s.end)
        .min_by_key(|s| s.end - s.start)
        .map(|s| s.hash.as_str())
}

/// The identity hash of the item named `ident` in a file, if exactly one
/// exists — the resolver for content-anchored citations. Searches
/// top-level items and impl/trait members.
pub fn named_item_hash(ast: &syn::File, ident: &str) -> Option<String> {
    fn ident_of(item: &syn::Item) -> Option<String> {
        match item {
            syn::Item::Fn(f) => Some(f.sig.ident.to_string()),
            syn::Item::Struct(s) => Some(s.ident.to_string()),
            syn::Item::Enum(e) => Some(e.ident.to_string()),
            syn::Item::Type(t) => Some(t.ident.to_string()),
            syn::Item::Const(c) => Some(c.ident.to_string()),
            syn::Item::Static(s) => Some(s.ident.to_string()),
            syn::Item::Trait(t) => Some(t.ident.to_string()),
            syn::Item::Mod(m) => Some(m.ident.to_string()),
            _ => None,
        }
    }
    let mut found: Vec<String> = Vec::new();
    fn walk(items: &[syn::Item], ident: &str, found: &mut Vec<String>) {
        for item in items {
            if ident_of(item).as_deref() == Some(ident) {
                found.push(site_hash(item));
            }
            match item {
                syn::Item::Impl(i) => {
                    for m in &i.items {
                        if let syn::ImplItem::Fn(f) = m {
                            if f.sig.ident == ident {
                                found.push(site_hash(f));
                            }
                        }
                    }
                }
                syn::Item::Trait(t) => {
                    for m in &t.items {
                        if let syn::TraitItem::Fn(f) = m {
                            if f.sig.ident == ident {
                                found.push(site_hash(f));
                            }
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        walk(inner, ident, found);
                    }
                }
                _ => {}
            }
        }
        // ident_of on Item::Impl returns None, so impl members are only
        // reached through the explicit arm above.
    }
    walk(&ast.items, ident, &mut found);
    match found.as_slice() {
        [one] => Some(one.clone()),
        _ => None, // absent or ambiguous — both unresolvable, both loud
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(src: &str) -> syn::ItemFn {
        syn::parse_str(src).expect("fixture parses")
    }

    #[test]
    fn renaming_a_local_flips_the_hash() {
        let a = item("fn f() { let alpha = 1; }");
        let b = item("fn f() { let beta = 1; }");
        assert_ne!(site_hash(&a), site_hash(&b), "identifiers are identity");
    }

    #[test]
    fn layout_does_not_flip_the_hash() {
        let a = item("fn f() { let alpha = 1; }");
        let b = item("fn f() {\n    let alpha = 1;\n}");
        assert_eq!(site_hash(&a), site_hash(&b), "layout is not identity");
    }

    #[test]
    fn doc_comment_edit_flips_the_hash() {
        let a = item("#[doc = \"one\"] fn f() {}");
        let b = item("#[doc = \"two\"] fn f() {}");
        assert_ne!(site_hash(&a), site_hash(&b), "doc comments are content");
    }
}
