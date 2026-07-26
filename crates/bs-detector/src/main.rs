/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * Use of this software is governed by the Business Source License 1.1
 * included in the repository as LICENSE-BSL. See LICENSING.md.
 *
 * Change Date:    2030-07-11
 * Change License: Mozilla Public License, version 2.0
 */

//! AUTHORITY: The one conduct gate — every item under crates/ is an approved pattern or a violation
//! SEAT: bs-detector/main
//! FILE_KIND: composition_root
//!
//! This file holds no law. It walks `crates/`, asks [`Scope`] to approve each
//! item and each method, and reports one number. Every approval decision lives
//! in the pattern file; to let a kind of item through, someone adds a
//! construct there, in the open, and signs the diff.
//!
//! No item reaches the end of the walk unjudged. Every container is approved
//! on its own terms *and* descended into: inline modules, impl and trait
//! bodies, items declared inside function bodies, items a macro invocation
//! declares, foreign-block members, and `const`/`static` initialisers. An
//! unreadable or unparseable file becomes a violation and still counts against
//! coverage.
//!
//! Approval never touches `syn::Item` here. [`Seat::of`] is the one reading of
//! the foreign type; this file matches `syn::Item` only to *descend*, never to
//! decide. Three wildcards remain: `item_name`'s display fallback, and two
//! descent arms that decline to guess at the interior of a variant already
//! refused as `Unknown`. `judge_nested`'s `filter_map` selects `Stmt::Item`.
//! None of them can approve anything.
//!
//! Boundary is all of `crates/`; `target/` is the only exclusion. Files found
//! versus files parsed is a proof and any gap is a violation. No waiver, no
//! baseline, no partial run.

mod construct;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use construct::{Construct, Imports, Scope, Seat};
use syn::spanned::Spanned;
use walkdir::WalkDir;

// --- zone-file:types ---

/// One place in the tree that no approved pattern covers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Violation {
    file: PathBuf,
    line: usize,
    what: String,
}

impl Violation {
    fn render(&self) -> String {
        format!(
            "{}:{} violation {}",
            self.file.display(),
            self.line,
            self.what
        )
    }
}

// --- zone-file:construction ---

/// The boundary: all of `crates/` under `root`, minus `target/`.
struct Boundary {
    root: PathBuf,
}

impl Boundary {
    /// The only door. No constructor accepts a narrower path.
    fn all_of_crates(root: &Path) -> Self {
        Self {
            root: root.join("crates"),
        }
    }

    /// Every `.rs` file inside the boundary, in a stable order.
    fn files(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .filter(|p| !p.components().any(|c| c.as_os_str() == "target"))
            .collect();
        out.sort();
        out
    }
}

// --- zone-file:wiring ---

fn item_name(item: &syn::Item) -> String {
    match item {
        syn::Item::Const(i) => i.ident.to_string(),
        syn::Item::Enum(i) => i.ident.to_string(),
        syn::Item::Fn(i) => i.sig.ident.to_string(),
        syn::Item::Mod(i) => i.ident.to_string(),
        syn::Item::Static(i) => i.ident.to_string(),
        syn::Item::Struct(i) => i.ident.to_string(),
        syn::Item::Trait(i) => i.ident.to_string(),
        syn::Item::TraitAlias(i) => i.ident.to_string(),
        syn::Item::Type(i) => i.ident.to_string(),
        syn::Item::Union(i) => i.ident.to_string(),
        _ => "<anonymous>".to_string(),
    }
}

/// Judge every item, then descend. A container earns its own approval and
/// still has to answer for what is inside it.
fn judge_items(file: &Path, scope: &Scope, imports: &Imports, items: &[syn::Item], out: &mut Vec<Violation>) {
    for item in items {
        let owned = Seat::of(item);
        let seat = scope.seat_item(&owned);
        if seat.is_none() {
            // `ItemKind::Unknown` renders as `unknown-item-kind`: a syn variant
            // this crate has never been taught surfaces as its own category in
            // the log, not folded into a neighbour's name.
            out.push(Violation {
                file: file.to_path_buf(),
                line: item.span().start().line,
                what: format!("{} {}", Seat::of(item).kind().law_name(), item_name(item)),
            });
        }
        // Descent. Every `syn::Item` variant is named: the ones that can hold
        // another item are descended into, the ones that cannot are named as
        // childless. No item kind is silently passed over.
        match item {
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    judge_items(file, scope, imports, inner, out);
                }
            }
            syn::Item::Impl(i) => judge_impl(file, scope, imports, i, out),
            syn::Item::Trait(t) => judge_trait(file, scope, imports, t, out),
            syn::Item::Fn(f) => {
                // The composition-root law as its inverse: effects are lawful
                // in the root and nowhere else, so every effect site outside
                // it is a violation where it happens. The test is whether the
                // function actually *seated* as the root — a `fn main` that
                // failed its conditions is not the root and does not shelter
                // the effects inside it.
                if seat != Some(Construct::CompositionRoot) {
                    push_ambient(file, scope, imports, &f.block, out);
                }
                judge_nested(file, scope, imports, &f.block.stmts, out);
            }
            // A macro body can declare anything. If its tokens parse as items
            // they are judged like any other; if they do not, the macro is
            // already a violation and its interior is unreachable to anyone,
            // including whoever wrote it.
            syn::Item::Macro(m) => judge_tokens(file, scope, imports, m.mac.tokens.clone(), out),
            // Foreign items are surface the discipline cannot cross. Each one
            // is named where it sits.
            syn::Item::ForeignMod(fm) => {
                for foreign in &fm.items {
                    out.push(Violation {
                        file: file.to_path_buf(),
                        line: foreign.span().start().line,
                        what: "foreign-item".to_string(),
                    });
                }
            }
            // A const or static initialiser is an expression: it may open a
            // block that declares items, and it may perform effects. Neither
                // is the composition root.
            syn::Item::Const(c) => {
                push_ambient_expr(file, scope, imports, &c.expr, out);
                judge_expr(file, scope, imports, &c.expr, out);
            }
            syn::Item::Static(s) => {
                push_ambient_expr(file, scope, imports, &s.expr, out);
                judge_expr(file, scope, imports, &s.expr, out);
            }
            // Childless: nothing inside them can declare a seat.
            syn::Item::Struct(_)
            | syn::Item::Enum(_)
            | syn::Item::Union(_)
            | syn::Item::Type(_)
            | syn::Item::Use(_)
            | syn::Item::ExternCrate(_)
            | syn::Item::TraitAlias(_)
            | syn::Item::Verbatim(_) => {}
            // Required by `#[non_exhaustive]` on `syn::Item`. A variant that
            // lands here was already refused by `seat_item`; this arm only
            // declines to guess at its interior.
            _ => {}
        }
    }
}

/// Judge whatever items a token stream turns out to declare.
fn judge_tokens(
    file: &Path,
    scope: &Scope,
    imports: &Imports,
    tokens: proc_macro2::TokenStream,
    out: &mut Vec<Violation>,
) {
    if let Ok(parsed) = syn::parse2::<syn::File>(tokens) {
        judge_items(file, scope, imports, &parsed.items, out);
    }
}

/// Walk an expression for the items a nested block may declare.
fn judge_expr(file: &Path, scope: &Scope, imports: &Imports, expr: &syn::Expr, out: &mut Vec<Violation>) {
    struct Collect {
        items: Vec<syn::Item>,
    }
    impl<'ast> syn::visit::Visit<'ast> for Collect {
        fn visit_item(&mut self, i: &'ast syn::Item) {
            self.items.push(i.clone());
            syn::visit::visit_item(self, i);
        }
    }
    let mut collect = Collect { items: Vec::new() };
    syn::visit::Visit::visit_expr(&mut collect, expr);
    judge_items(file, scope, imports, &collect.items, out);
}

/// One violation per ambient-authority site, at the line that performs it.
fn push_ambient(file: &Path, scope: &Scope, imports: &Imports, block: &syn::Block, out: &mut Vec<Violation>) {
    for (line, what) in scope.ambient_sites(imports, block) {
        out.push(Violation {
            file: file.to_path_buf(),
            line,
            what,
        });
    }
}

/// The same law over a bare expression, for initialisers that have no block.
fn push_ambient_expr(file: &Path, scope: &Scope, imports: &Imports, expr: &syn::Expr, out: &mut Vec<Violation>) {
    let wrapped = syn::Block {
        brace_token: syn::token::Brace::default(),
        stmts: vec![syn::Stmt::Expr(expr.clone(), None)],
    };
    push_ambient(file, scope, imports, &wrapped, out);
}

/// Items declared inside a function body are still items.
fn judge_nested(file: &Path, scope: &Scope, imports: &Imports, stmts: &[syn::Stmt], out: &mut Vec<Violation>) {
    let inner: Vec<syn::Item> = stmts
        .iter()
        .filter_map(|s| match s {
            syn::Stmt::Item(i) => Some(i.clone()),
            _ => None,
        })
        .collect();
    judge_items(file, scope, imports, &inner, out);
}

fn judge_impl(file: &Path, scope: &Scope, imports: &Imports, block: &syn::ItemImpl, out: &mut Vec<Violation>) {
    let self_ty = construct::type_name(&block.self_ty);
    for member in &block.items {
        match member {
            syn::ImplItem::Fn(f) => {
                if scope.seat_method(&f.sig, Some(&f.block), &self_ty).is_none() {
                    out.push(Violation {
                        file: file.to_path_buf(),
                        line: f.span().start().line,
                        what: format!("fn {}", f.sig.ident),
                    });
                }
                // No method is the composition root, so every effect site in
                // one is a violation.
                push_ambient(file, scope, imports, &f.block, out);
                judge_nested(file, scope, imports, &f.block.stmts, out);
            }
            other => out.push(Violation {
                file: file.to_path_buf(),
                line: other.span().start().line,
                what: "impl-member".to_string(),
            }),
        }
    }
}

fn judge_trait(file: &Path, scope: &Scope, imports: &Imports, block: &syn::ItemTrait, out: &mut Vec<Violation>) {
    let self_ty = block.ident.to_string();
    for member in &block.items {
        match member {
            syn::TraitItem::Fn(f) => {
                if scope.seat_method(&f.sig, f.default.as_ref(), &self_ty).is_none() {
                    out.push(Violation {
                        file: file.to_path_buf(),
                        line: f.span().start().line,
                        what: format!("trait-fn {}", f.sig.ident),
                    });
                }
                // A default body is a body. No trait method is the root.
                if let Some(body) = &f.default {
                    push_ambient(file, scope, imports, body, out);
                    judge_nested(file, scope, imports, &body.stmts, out);
                }
            }
            other => out.push(Violation {
                file: file.to_path_buf(),
                line: other.span().start().line,
                what: "trait-member".to_string(),
            }),
        }
    }
}

/// Every construct a source text seats, in order. Used by the fixture law to
/// prove a pass fixture seats as the construct it is named for, rather than
/// merely drawing no violation.
#[cfg(test)]
fn seats_of(text: &str) -> Vec<Construct> {
    let Ok(ast) = syn::parse_file(text) else {
        return Vec::new();
    };
    let scope = Scope::of(&ast.items);
    let mut found = Vec::new();
    collect_seats(&scope, &ast.items, &mut found);
    found
}

#[cfg(test)]
fn collect_seats(scope: &Scope, items: &[syn::Item], out: &mut Vec<Construct>) {
    for item in items {
        out.extend(scope.seat_item(&Seat::of(item)));
        match item {
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_seats(scope, inner, out);
                }
            }
            syn::Item::Impl(i) => {
                for member in &i.items {
                    if let syn::ImplItem::Fn(f) = member {
                        out.extend(scope.seat_method(&f.sig, Some(&f.block), &construct::type_name(&i.self_ty)));
                    }
                }
            }
            syn::Item::Trait(t) => {
                for member in &t.items {
                    if let syn::TraitItem::Fn(f) = member {
                        out.extend(scope.seat_method(&f.sig, f.default.as_ref(), &t.ident.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Judge one source text as if it were a file at `label`. The fixture law's
/// door; the tree run parses once and judges against one tree-wide scope.
#[cfg(test)]
fn judge_source(label: &Path, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    match syn::parse_file(text) {
        Ok(ast) => {
            let scope = Scope::of(&ast.items);
            let imports = Imports::of(&ast.items);
            judge_items(label, &scope, &imports, &ast.items, &mut out);
        }
        Err(e) => out.push(Violation {
            file: label.to_path_buf(),
            line: 0,
            what: format!("unparsed {e}"),
        }),
    }
    out
}

/// The full run. Boundary is fixed; there is no narrower scope to pass.
///
/// Two passes. The first parses every file and builds one [`Scope`] over the
/// whole tree, so a call that crosses a module boundary is judged on the
/// callee's actual body instead of being refused for ignorance. The second
/// judges each file against that scope.
fn run(root: &Path) -> (Vec<Violation>, usize, usize) {
    let files = Boundary::all_of_crates(root).files();
    let mut violations: Vec<Violation> = Vec::new();
    let mut parsed = 0usize;
    let mut asts: Vec<(PathBuf, syn::File)> = Vec::new();

    for path in &files {
        match std::fs::read_to_string(path) {
            Ok(text) => match syn::parse_file(&text) {
                Ok(ast) => {
                    parsed += 1;
                    asts.push((path.clone(), ast));
                }
                Err(e) => violations.push(Violation {
                    file: path.clone(),
                    line: 0,
                    what: format!("unparsed {e}"),
                }),
            },
            Err(e) => violations.push(Violation {
                file: path.clone(),
                line: 0,
                what: format!("unreadable {e}"),
            }),
        }
    }

    let trees: Vec<Vec<syn::Item>> = asts.iter().map(|(_, a)| a.items.clone()).collect();
    let scope = Scope::of_tree(&trees);
    for (path, ast) in &asts {
        let imports = Imports::of(&ast.items);
        judge_items(path, &scope, &imports, &ast.items, &mut violations);
    }

    if parsed != files.len() {
        violations.push(Violation {
            file: PathBuf::from("<boundary>"),
            line: 0,
            what: format!("coverage-gap found={} parsed={parsed}", files.len()),
        });
    }
    (violations, files.len(), parsed)
}

/// The verdict artifacts the pester hook reads.
fn write_verdict(root: &Path, violations: &[Violation]) {
    let dir = root.join("crates").join("xtask");
    let header = match violations.is_empty() {
        true => "GATE: CLEAR",
        false => "GATE: ALARM",
    };
    let mut log = String::from(header);
    log.push('\n');
    for v in violations {
        log.push_str(&v.render());
        log.push('\n');
    }
    let _ = std::fs::write(dir.join("gate.log"), log);
    let _ = std::fs::write(
        dir.join("gate-counts.txt"),
        format!("violation:{n} = {n} violations\n", n = violations.len()),
    );
}

fn main() -> ExitCode {
    // `--root <path>` names the tree; every other argument is ignored. There
    // is no flag that narrows scope, selects a category, or sets a baseline.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root: PathBuf = match args.iter().position(|a| a == "--root") {
        Some(i) => args.get(i + 1).map(PathBuf::from),
        None => args
            .first()
            .filter(|a| !a.starts_with("--"))
            .map(PathBuf::from),
    }
    .unwrap_or_else(|| PathBuf::from("."));

    let (violations, found, parsed) = run(&root);

    for v in &violations {
        println!("{}", v.render());
    }
    eprintln!(
        "files {found} parsed {parsed} violations {}",
        violations.len()
    );

    write_verdict(&root, &violations);

    match violations.is_empty() {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}

// --- zone-file:tests ---

/// The fixture law: every approved pattern proves both directions.
#[cfg(test)]
mod fixture_law {
    use super::{judge_source, seats_of, Construct};
    use std::path::{Path, PathBuf};

    fn dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    fn fixture(stem: &str, side: &str) -> Option<(PathBuf, String)> {
        let path = dir().join(format!("{stem}.{side}.fixture"));
        std::fs::read_to_string(&path).ok().map(|t| (path, t))
    }

    /// Every deny fixture for a stem: `<stem>.deny.fixture` and any
    /// `<stem>.deny-<condition>.fixture` beside it. One per condition, so a
    /// seat cannot pass the law on the strength of its cheapest forbid.
    fn deny_fixtures(stem: &str) -> Vec<(PathBuf, String)> {
        let prefix = format!("{stem}.deny");
        let Ok(entries) = std::fs::read_dir(dir()) else {
            return Vec::new();
        };
        let mut found: Vec<(PathBuf, String)> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".fixture"))
            })
            .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
            .collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }

    #[test]
    fn every_construct_has_a_pass_fixture_that_seats() {
        for c in Construct::ALL {
            let stem = c.law_name();
            let Some((path, text)) = fixture(stem, "pass") else {
                panic!("{stem}: no pass fixture — the pattern proves nothing");
            };
            let found = judge_source(&path, &text);
            assert!(
                found.is_empty(),
                "{stem}: pass fixture drew {} violation(s): {:?}",
                found.len(),
                found.iter().map(|v| v.render()).collect::<Vec<_>>()
            );
            let seats = seats_of(&text);
            assert!(
                seats.contains(&c),
                "{stem}: pass fixture seats {seats:?}, never {c:?} — it proves \
                 some other construct's conditions, not this one's"
            );
        }
    }

    /// Every condition a construct states must have a fixture beside it.
    ///
    /// A condition written into `Construct::conditions` with no
    /// `<stem>.deny-<condition>.fixture` is a claim with no proof, and it
    /// fails here rather than shipping as prose.
    #[test]
    fn every_stated_condition_has_a_fixture() {
        for c in Construct::ALL {
            let stem = c.law_name();
            for condition in c.conditions() {
                let name = format!("{stem}.deny-{condition}.fixture");
                assert!(
                    dir().join(&name).is_file(),
                    "{stem}: condition `{condition}` is stated with no proof — \
                     write fixtures/{name}"
                );
            }
        }
    }

    /// Every deny fixture must fail *this* seat, not merely draw a red
    /// somewhere in the file. A fixture that still seats as the construct is
    /// proving some neighbour's condition and leaving this one untested.
    #[test]
    fn every_deny_fixture_detonates_its_own_seat() {
        for c in Construct::ALL {
            let stem = c.law_name();
            let found = deny_fixtures(stem);
            assert!(
                !found.is_empty(),
                "{stem}: no deny fixture — the conditions refuse nothing"
            );
            for (path, text) in found {
                let name = path.display();
                assert!(
                    !judge_source(&path, &text).is_empty(),
                    "{name}: drew nothing — the condition is vacuous"
                );
                assert!(
                    !seats_of(&text).contains(&c),
                    "{name}: still seats as {c:?} — it draws blood somewhere \
                     else while this construct's condition lets it pass"
                );
            }
        }
    }

    /// `syn::Item` is foreign and `#[non_exhaustive]`, so `ItemKind` mirrors it
    /// by hand. An exact pin is what keeps the mirror honest: a caret range
    /// could pull in a new variant with no diff to review.
    #[test]
    fn syn_pin_is_exact() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            panic!("cannot read {}", manifest.display());
        };
        let pinned = text
            .lines()
            .find(|l| l.trim_start().starts_with("syn = "))
            .is_some_and(|l| l.contains("\"=2."));
        assert!(
            pinned,
            "syn must be pinned exactly (`=x.y.z`): ItemKind mirrors its \
             variant set and a range hides a new variant behind an update"
        );
    }
}
