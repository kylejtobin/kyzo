/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The fixture law, executed: every construct in the loaded grammar proves
//! itself with a pass fixture that produces ZERO hits and a deny fixture
//! that produces at least one. Proof is execution, not presence — a
//! fixture file that proves nothing fails here, not in a reviewer's
//! attention. Uniqueness of classification is proven separately at load
//! (the disjointness table), so zero-hits-on-pass means "classified as
//! exactly this construct". Helpers return `Option`; the only panics live
//! inside `#[test]` scope.

use bs_detector::boundary::SourceFile;
use bs_detector::classify::{self, AliasTable};
use bs_detector::grammar::Grammar;

fn load_grammar() -> Option<Grammar> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // The fixture executor may not weaken the load path: same bite source,
    // same fixtures dir as the real gate.
    let bite = std::fs::read_to_string(root.join("tests/bite_proofs.rs")).ok()?;
    Grammar::load(&root.join("grammar.toml"), &bite, &root.join("fixtures")).ok()
}

fn fixture_file(construct: &str, which: &str) -> Option<SourceFile> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join(format!("fixtures/{construct}.{which}.rs"));
    let text = std::fs::read_to_string(&path).ok()?;
    let ast = syn::parse_file(&text).ok()?;
    // composition-root discriminates on bin position, the test cells on
    // test scope; everything else is judged as library code.
    let rel = match construct {
        "composition-root" => "crates/fx/src/main.rs",
        "test-proof" | "test-support" => "crates/fx/tests/t.rs",
        _ => "crates/fx/src/lib.rs",
    };
    Some(SourceFile {
        rel_path: rel.to_string(),
        text,
        ast,
    })
}

fn hits_for(grammar: &Grammar, file: &SourceFile) -> Option<Vec<(String, String)>> {
    let aliases = AliasTable::build(std::slice::from_ref(file)).ok()?;
    let enums = classify::enum_idents(std::slice::from_ref(file));
    Some(
        classify::classify_file(grammar, &aliases, &enums, file)
            .into_iter()
            .map(|(c, h)| (c, h.construct))
            .collect(),
    )
}

fn first_fn(file: &SourceFile) -> Option<syn::ItemFn> {
    file.ast.items.iter().find_map(|i| match i {
        syn::Item::Fn(f) => Some(f.clone()),
        _ => None,
    })
}

#[test]
fn fixtures_prove_every_construct() {
    let mut grammar = match load_grammar() {
        Some(g) => g,
        None => panic!("grammar + fixtures load"),
    };
    for c in grammar.constructs.clone() {
        // declared-fn's pass fixture is green only through a seat; bind the
        // seat to the fixture's real content hash, per the law.
        if c.name == "declared-fn" {
            let f = match fixture_file(&c.name, "pass") {
                Some(f) => f,
                None => panic!("declared-fn pass fixture reads"),
            };
            let item = match first_fn(&f) {
                Some(i) => i,
                None => panic!("declared-fn pass fixture holds a fn"),
            };
            grammar.seats.fns.push(bs_detector::grammar::SeatFn {
                file: "crates/fx/src/lib.rs".to_string(),
                path: item.sig.ident.to_string(),
                hash: bs_detector::identity::site_hash(&item),
                io: false,
            });
        }

        let pass = match fixture_file(&c.name, "pass") {
            Some(f) => f,
            None => panic!("construct `{}` pass fixture reads", c.name),
        };
        let pass_hits = match hits_for(&grammar, &pass) {
            Some(h) => h,
            None => panic!("construct `{}` pass fixture classifies", c.name),
        };
        assert!(
            pass_hits.is_empty(),
            "construct `{}` pass fixture must classify clean, got {pass_hits:?}",
            c.name
        );

        let deny = match fixture_file(&c.name, "deny") {
            Some(f) => f,
            None => panic!("construct `{}` deny fixture reads", c.name),
        };
        let deny_hits = match hits_for(&grammar, &deny) {
            Some(h) => h,
            None => panic!("construct `{}` deny fixture classifies", c.name),
        };
        assert!(
            !deny_hits.is_empty(),
            "construct `{}` deny fixture must be refused — an unrefusable construct is vacuous",
            c.name
        );
    }
}

#[test]
fn seat_drift_reds_a_declared_fn_whose_body_changed() {
    let mut grammar = match load_grammar() {
        Some(g) => g,
        None => panic!("grammar + fixtures load"),
    };
    let f = match fixture_file("declared-fn", "pass") {
        Some(f) => f,
        None => panic!("declared-fn pass fixture reads"),
    };
    let item = match first_fn(&f) {
        Some(i) => i,
        None => panic!("declared-fn pass fixture holds a fn"),
    };
    grammar.seats.fns.push(bs_detector::grammar::SeatFn {
        file: "crates/fx/src/lib.rs".to_string(),
        path: item.sig.ident.to_string(),
        // A stale hash: the operator approved a different body.
        hash: "0".repeat(64),
        io: false,
    });
    let hits = match hits_for(&grammar, &f) {
        Some(h) => h,
        None => panic!("classifies"),
    };
    assert!(
        hits.iter().any(|(c, _)| c == "seat_drift"),
        "drifted seat must red, got {hits:?}"
    );
}
