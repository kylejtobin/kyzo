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
