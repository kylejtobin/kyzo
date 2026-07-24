/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Site identity (TRUTH item 6's `identity_tokens`, built here because
//! item 1's declared-fn seat binds to it): a ruling binds to CONTENT.
//!
//! The identity of an item is its token stream stringified — identifiers
//! and literals byte-verbatim. Doc comments are attributes, therefore
//! tokens, therefore content: editing one changes the identity. Plain
//! `//` comments and whitespace/layout are not tokens and do not.

use proc_macro2::TokenStream;
use quote::ToTokens;

/// The canonical identity string of an item: its token stream, stringified.
/// Layout-independent; identifier- and literal-exact.
pub fn identity_tokens(item: &dyn ToTokens) -> String {
    let ts: TokenStream = item.to_token_stream();
    ts.to_string()
}

/// The site hash a declared-fn seat (and, at item 6, a waiver) swears to:
/// blake3 of [`identity_tokens`], lowercase hex.
pub fn site_hash(item: &dyn ToTokens) -> String {
    blake3::hash(identity_tokens(item).as_bytes())
        .to_hex()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(src: &str) -> syn::Item {
        syn::parse_str(src).expect("fixture parses")
    }

    #[test]
    fn layout_change_keeps_identity_and_content_change_breaks_it() {
        let a = site_hash(&item("fn f(x: u64) -> u64 { x }"));
        let b = site_hash(&item("fn f(x: u64)  ->\n    u64 { x }"));
        assert_eq!(a, b, "layout is not content");

        let c = site_hash(&item("fn f(y: u64) -> u64 { y }"));
        assert_ne!(a, c, "an identifier rename IS content");

        let d = site_hash(&item("/// documented\nfn f(x: u64) -> u64 { x }"));
        assert_ne!(a, d, "a doc comment is an attribute, therefore content");
    }
}
