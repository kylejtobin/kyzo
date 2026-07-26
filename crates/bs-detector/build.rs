/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * Use of this software is governed by the Business Source License 1.1
 * included in the repository as LICENSE-BSL. See LICENSING.md.
 *
 * Change Date:    2030-07-11
 * Change License: Mozilla Public License, version 2.0
 */

//! Drift guard: count `syn::Item`'s variants in the pinned source and hand the
//! number to the crate as an environment constant.
//!
//! `ItemKind` is a hand-written mirror of a foreign `#[non_exhaustive]` enum,
//! so the compiler cannot check it. This does: `const _: () = assert!(..)` in
//! `construct.rs` compares the mirror's size against the number counted here,
//! and a `syn` upgrade that adds a variant fails the build until someone
//! teaches `ItemKind` the new kind.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    let count = syn_item_variant_count().unwrap_or(0);
    println!("cargo:rustc-env=SYN_ITEM_VARIANTS={count}");
}

/// Find the pinned `syn` source in the cargo registry and count the variants
/// of `pub enum Item`.
fn syn_item_variant_count() -> Option<usize> {
    let version = pinned_syn_version()?;
    let home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| std::env::var("HOME").ok().map(|h| Path::new(&h).join(".cargo")))?;
    let registry = home.join("registry").join("src");
    let wanted = format!("syn-{version}");
    for index in std::fs::read_dir(&registry).ok()? {
        let dir = index.ok()?.path().join(&wanted).join("src").join("item.rs");
        if let Ok(text) = std::fs::read_to_string(&dir) {
            return Some(count_variants(&text));
        }
    }
    None
}

/// The exact version between `"=` and `"` on the `syn = ` line of our manifest.
fn pinned_syn_version() -> Option<String> {
    let text = std::fs::read_to_string("Cargo.toml").ok()?;
    let line = text.lines().find(|l| l.trim_start().starts_with("syn = "))?;
    let start = line.find("\"=")? + 2;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Variants of the `pub enum Item` block: every line at one indent level that
/// begins with an uppercase identifier.
fn count_variants(text: &str) -> usize {
    let Some(start) = text.find("pub enum Item {") else {
        return 0;
    };
    let body = &text[start..];
    let Some(end) = body.find("\n}") else {
        return 0;
    };
    body[..end]
        .lines()
        .skip(1)
        .filter(|l| {
            let t = l.trim();
            t.chars().next().is_some_and(char::is_uppercase) && t.contains('(')
        })
        .count()
}
