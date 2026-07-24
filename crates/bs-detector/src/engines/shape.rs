/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Engine 1 — Shape: a banned construct at one site in source text.
//!
//! Every matcher is a named entry in [`MATCHERS`]; checks.toml references
//! them by name and the registry refuses a name this table doesn't export.
//! Matchers are registered with a [`ScanClass`] label (historical family:
//! swallow-shapes vs surface/panic-shapes). Tip 650/659: there is **no
//! blanket `cfg(test)` strip**. Test code is code — every matcher scans
//! it. Test-legitimate shapes are admitted only by **named** laws in
//! `laws.toml` (exact shape + why lawful), never by a silent line filter.
//!
//! This file applies its own law to itself: no `unwrap`/`expect`, no `as`
//! casts, and no `_ =>` arms — foreign non-exhaustive enums are handled
//! with `if let`/`matches!` so there is no catch-all left unnamed.

use quote::ToTokens;
use syn::visit::{self, Visit};

use crate::boundary::{Label, RelPath, SourceFile, BOUNDARY};
use crate::engines::Hit;

/// Matcher family label. Does **not** gate scanning (tip 650/659: no strip).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanClass {
    Everything,
    ProductionOnly,
}

/// Named shape matcher — sealed-struct (TRUTH item 9).
///
/// Fields private; sole admission is [`Matcher::admit`]. Name is [`Label`],
/// never a `str`/`String` field terminal. [`ScanClass`] is retained as
/// historical family metadata and does **not** gate the scan (tip 650/659).
pub struct Matcher {
    name: Label,
    class: ScanClass,
    detect: fn(&SourceFile) -> Vec<Hit>,
}

impl Matcher {
    /// Sole admission for registry rows. Name bytes enter as [`Label`].
    pub const fn admit(
        name: &'static [u8],
        class: ScanClass,
        detect: fn(&SourceFile) -> Vec<Hit>,
    ) -> Self {
        Self {
            name: Label::admit_static(name),
            class,
            detect,
        }
    }

    /// UTF-8 view of the matcher name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Historical scan-class label (does not gate — tip 650/659).
    pub fn class(&self) -> ScanClass {
        self.class
    }

    /// Run this matcher over one file. Tip 650/659: no scan-class strip —
    /// test code is scanned the same as production code. `ScanClass` is
    /// read and discarded so it cannot silently gate a strip (the tip-659
    /// lock).
    pub fn run(&self, file: &SourceFile) -> Vec<Hit> {
        // Tip 659 lock — class must be observed so a strip cannot return silently.
        // Match (not `let _ =`) so let_underscore stays red elsewhere; anti_fraud_tip_659
        // still locks the seat for sabotage_audit.
        match self.class() {
            ScanClass::Everything | ScanClass::ProductionOnly => {}
        }
        (self.detect)(file)
    }
}

/// Sealed-struct lookup door onto [`MATCHERS`] (TRUTH item 9): a receiver
/// method, not a free `matcher_by_name`. checks.toml refers to matchers by
/// name through this one door.
pub struct MatcherLookup;

impl MatcherLookup {
    /// Look a matcher up by its checks.toml name.
    pub fn by_name(&self, name: &str) -> Option<&'static Matcher> {
        MATCHERS.iter().find(|m| m.name() == name)
    }
}

/// The one lookup instance — a ZST, so this costs nothing over the free
/// fn it replaces.
pub const MATCHER_LOOKUP: MatcherLookup = MatcherLookup;

// ---------------------------------------------------------------------------
// shared visitors
// ---------------------------------------------------------------------------

/// The one name-scan walker: every site scanner that matches a name list
/// against one AST node kind lives HERE, so there is a single push shape and
/// a single authority. Wrappers below select a node kind by filling one
/// list; the others stay empty.
struct NameSites<'a> {
    methods: Vec<Label>,
    macros: Vec<Label>,
    paths: Vec<Label>,
    construct: Label,
    rel: &'a RelPath,
    hits: Vec<Hit>,
}

/// Which name-list a site checks — one hit authority (tip 862: the three
/// Visit arms must not be twin bodies after Label conversion).
#[derive(Clone, Copy)]
enum NameListKind {
    Methods,
    Macros,
    Paths,
}

impl<'ast, 'a> Visit<'ast> for NameSites<'a> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.hit_listed(
            NameListKind::Methods,
            &node.method.to_string(),
            &node.method.span(),
        );
        visit::visit_expr_method_call(self, node);
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(seg) = node.path.segments.last() {
            self.hit_listed(
                NameListKind::Macros,
                &seg.ident.to_string(),
                &seg.ident.span(),
            );
        }
        visit::visit_macro(self, node);
    }
    fn visit_path(&mut self, node: &'ast syn::Path) {
        for seg in &node.segments {
            self.hit_listed(
                NameListKind::Paths,
                &seg.ident.to_string(),
                &seg.ident.span(),
            );
        }
        visit::visit_path(self, node);
    }
}

impl NameSites<'_> {
    fn hit_listed(&mut self, kind: NameListKind, name: &str, span: &proc_macro2::Span) {
        let list = match kind {
            NameListKind::Methods => &self.methods,
            NameListKind::Macros => &self.macros,
            NameListKind::Paths => &self.paths,
        };
        if list.iter().any(|l| l.as_str() == name) {
            HIT_PUSH.push(
                &mut self.hits,
                self.rel,
                BOUNDARY.span_line(span),
                self.construct.as_str(),
            );
        }
    }
}

/// The one hit-recording door (TRUTH item 9): every walker below records
/// through this ZST receiver, never a free `push`.
struct HitPush;

impl HitPush {
    fn push(&self, hits: &mut Vec<Hit>, rel: &RelPath, line: usize, construct: &str) {
        hits.push(Hit::admit(rel.clone(), line, construct.to_string()));
    }
}

const HIT_PUSH: HitPush = HitPush;

/// Which shape a shared file walk is collecting. One `Visit` impl — not three
/// cloned visitor bodies, and not a `macro_rules!` (condemned `macro_item`).
#[derive(Clone, Copy)]
enum FileHitKind {
    AsCast,
    DefaultImpl,
    UnsafeToken,
}

struct FileHitVisitor<'a> {
    rel: &'a RelPath,
    kind: FileHitKind,
    hits: Vec<Hit>,
}

impl FileHitVisitor<'_> {
    fn hit(&mut self, line: usize, construct: &str) {
        HIT_PUSH.push(&mut self.hits, self.rel, line, construct);
    }
}

impl<'ast> Visit<'ast> for FileHitVisitor<'_> {
    fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
        if matches!(self.kind, FileHitKind::AsCast) {
            self.hit(BOUNDARY.span_line(&node.as_token.span), "as_cast");
        }
        visit::visit_expr_cast(self, node);
    }
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        if matches!(self.kind, FileHitKind::UnsafeToken) {
            self.hit(BOUNDARY.span_line(&node.unsafe_token.span), "unsafe_token");
        }
        visit::visit_expr_unsafe(self, node);
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if matches!(self.kind, FileHitKind::UnsafeToken) {
            if let Some(u) = &node.sig.unsafety {
                self.hit(BOUNDARY.span_line(&u.span), "unsafe_token");
            }
        }
        visit::visit_item_fn(self, node);
    }
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        match self.kind {
            FileHitKind::DefaultImpl => {
                if let Some((_, path, _)) = &node.trait_ {
                    if path.segments.last().is_some_and(|s| s.ident == "Default") {
                        self.hit(BOUNDARY.span_line(&node.impl_token.span), "default_impl");
                    }
                }
            }
            FileHitKind::UnsafeToken => {
                if let Some(u) = &node.unsafety {
                    self.hit(BOUNDARY.span_line(&u.span), "unsafe_token");
                }
            }
            FileHitKind::AsCast => {}
        }
        visit::visit_item_impl(self, node);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if matches!(self.kind, FileHitKind::UnsafeToken) {
            if let Some(u) = &node.sig.unsafety {
                self.hit(BOUNDARY.span_line(&u.span), "unsafe_token");
            }
        }
        visit::visit_impl_item_fn(self, node);
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if matches!(self.kind, FileHitKind::UnsafeToken) {
            if let Some(u) = &node.unsafety {
                self.hit(BOUNDARY.span_line(&u.span), "unsafe_token");
            }
        }
        visit::visit_item_trait(self, node);
    }
}

/// Shared walker doors onto one file (TRUTH item 9): every matcher below
/// scans through one of these receiver methods, never a free `fn(&SourceFile, …)`.
impl SourceFile {
    fn file_hits(&self, kind: FileHitKind) -> Vec<Hit> {
        let mut v = FileHitVisitor {
            rel: self.rel_path_ref(),
            kind,
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    fn name_sites(
        &self,
        methods: &[&str],
        macros: &[&str],
        paths: &[&str],
        construct: &str,
    ) -> Vec<Hit> {
        let mut v = NameSites {
            methods: methods.iter().map(|s| Label::admit(*s)).collect(),
            macros: macros.iter().map(|s| Label::admit(*s)).collect(),
            paths: paths.iter().map(|s| Label::admit(*s)).collect(),
            construct: Label::admit(construct),
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Hits on every method call whose name is in `names`.
    fn method_calls(&self, names: &[&str], construct: &str) -> Vec<Hit> {
        self.name_sites(names, &[], &[], construct)
    }

    /// Hits on every path whose segments include one of `idents` (matches
    /// `std::time::Instant::now` on the `Instant` segment).
    fn path_idents(&self, idents: &[&str], construct: &str) -> Vec<Hit> {
        self.name_sites(&[], &[], idents, construct)
    }

    /// Hits on every macro invocation with one of `names`.
    fn macro_calls(&self, names: &[&str], construct: &str) -> Vec<Hit> {
        self.name_sites(&[], names, &[], construct)
    }

    /// Hits on `#[allow(lint)]` / `#![allow(lint)]` attributes whose argument
    /// mentions one of `needles`.
    fn allow_attrs(&self, needles: &[&str], construct: &str) -> Vec<Hit> {
        let mut hits = vec![];
        for (idx, raw) in self.text().lines().enumerate() {
            let t = raw.trim_start();
            let is_attr = t.starts_with("#[allow(") || t.starts_with("#![allow(");
            if is_attr && needles.iter().any(|n| t.contains(n)) {
                hits.push(Hit::admit(self.rel_path().to_string(), idx + 1, construct.to_string()));
            }
        }
        hits
    }
}

// ---------------------------------------------------------------------------
// matchers
// ---------------------------------------------------------------------------

impl SourceFile {
    fn detect_unwrap(&self) -> Vec<Hit> {
        self.method_calls(&["unwrap"], "unwrap")
    }
    fn detect_expect(&self) -> Vec<Hit> {
        self.method_calls(&["expect"], "expect")
    }
    fn detect_unwrap_or(&self) -> Vec<Hit> {
        self.method_calls(&["unwrap_or"], "unwrap_or")
    }
    fn detect_unwrap_or_else(&self) -> Vec<Hit> {
        self.method_calls(&["unwrap_or_else"], "unwrap_or_else")
    }
    fn detect_unwrap_or_default(&self) -> Vec<Hit> {
        self.method_calls(&["unwrap_or_default"], "unwrap_or_default")
    }
    fn detect_unchecked_unwrap(&self) -> Vec<Hit> {
        self.method_calls(&["unwrap_unchecked"], "unwrap_unchecked")
    }

    fn detect_panic_bang(&self) -> Vec<Hit> {
        self.macro_calls(&["panic"], "panic_bang")
    }
    fn detect_unreachable_bang(&self) -> Vec<Hit> {
        self.macro_calls(&["unreachable"], "unreachable_bang")
    }
    fn detect_todo_bang(&self) -> Vec<Hit> {
        self.macro_calls(&["todo", "unimplemented"], "todo_bang")
    }
    fn detect_debug_assert(&self) -> Vec<Hit> {
        let mut hits = self.macro_calls(
            &["debug_assert", "debug_assert_eq", "debug_assert_ne"],
            "debug_assert",
        );
        // #[cfg(debug_assertions)] is the same law compiled out of release.
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
                if node.path().is_ident("cfg")
                    && node.to_token_stream().to_string().contains("debug_assertions")
                {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.pound_token.spans[0]), "debug_assert");
                }
                visit::visit_attribute(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        hits.append(&mut v.hits);
        hits
    }

    /// `let _ = fallible(...)` — discarding a value that had something to say.
    fn detect_let_underscore(&self) -> Vec<Hit> {
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_local(&mut self, node: &'ast syn::Local) {
                // `let _guard = …` discards by convention — an RAII hold
                // that is real swears a waiver saying what it holds.
                let discards = matches!(&node.pat, syn::Pat::Wild(_))
                    || matches!(&node.pat, syn::Pat::Ident(pi) if pi.ident.to_string().starts_with('_'));
                if discards && node.init.is_some() {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.let_token.span), "let_underscore");
                }
                visit::visit_local(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// `.ok()`/`.err()` in statement position, and every one-arg `drop(...)`
    /// call — a value told to shut up. Tip 686: match-arm / tail-position
    /// `mem::drop(value)` was silent-green when only semicolon stmts were scanned.
    fn detect_ok_drop(&self) -> Vec<Hit> {
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl V<'_> {
            fn is_drop_call(&self, c: &syn::ExprCall) -> bool {
                c.args.len() == 1
                    && c.func
                        .to_token_stream()
                        .to_string()
                        .ends_with("drop")
            }
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
                // `.ok();` / `.err();` — only with a semicolon: a bare tail
                // `.ok()` may be returning the Option, not discarding it.
                if let syn::Stmt::Expr(syn::Expr::MethodCall(mc), Some(_)) = node {
                    if (mc.method == "ok" || mc.method == "err") && mc.args.is_empty() {
                        HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&mc.method.span()), "ok_drop");
                    }
                }
                visit::visit_stmt(self, node);
            }
            fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
                // Every one-arg `drop(...)` / `mem::drop(...)` — arm body,
                // tail expr, or stmt. The call's only job is discarding.
                if self.is_drop_call(node) {
                    HIT_PUSH.push(
                        &mut self.hits,
                        self.rel,
                        BOUNDARY.span_line(&node.paren_token.span.open()),
                        "ok_drop",
                    );
                }
                visit::visit_expr_call(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Numeric `as` casts — truncation costumes. (Discriminant extractions like
    /// a repr(u8) enum's `self as u8` are detected too; the two lawful ones
    /// carry approved waivers, which is the point: visible, not structural.)
    fn detect_as_cast(&self) -> Vec<Hit> {
        // Every `as` cast, no numeric shortlist: `type W = u8; x as W` dodges
        // any list of names. Lossless and pointer-shaped casts buy waivers.
        self.file_hits(FileHitKind::AsCast)
    }

    /// wrapping_*/saturating_*/overflowing_*/unchecked_* arithmetic — every
    /// site, unconditionally. A comment is not a waiver entry: a site whose wrap
    /// IS the published contract swears a [[waiver]] the operator can audit,
    /// never a magic string the author grants themself.
    fn detect_unchecked_arith(&self) -> Vec<Hit> {
        const OPS: &[&str] = &[
            "wrapping_add",
            "wrapping_sub",
            "wrapping_mul",
            "wrapping_neg",
            "wrapping_shl",
            "wrapping_shr",
            "saturating_add",
            "saturating_sub",
            "saturating_mul",
            "overflowing_add",
            "overflowing_sub",
            "overflowing_mul",
            "unchecked_add",
            "unchecked_sub",
            "unchecked_mul",
        ];
        self.method_calls(OPS, "unchecked_arith")
    }
}

impl SourceFile {
    /// `with_capacity`/`reserve` whose argument carries a `.min(...)` cap —
    /// inline OR hoisted through a let binding — a reservation bound decided
    /// at the wrong door. The hoisted net is file-wide by ident name: wider
    /// than scope truth on purpose; a false neighbor costs a wrong report.
    fn detect_capacity_min_cap(&self) -> Vec<Hit> {
        struct Clamped {
            idents: std::collections::BTreeSet<Label>,
        }
        impl<'ast> Visit<'ast> for Clamped {
            fn visit_local(&mut self, node: &'ast syn::Local) {
                if let Some(init) = &node.init {
                    let toks = init.expr.to_token_stream().to_string();
                    if toks.contains(". min (") || toks.contains(".min(") {
                        if let syn::Pat::Ident(pi) = &node.pat {
                            self.idents.insert(Label::admit(pi.ident.to_string()));
                        }
                    }
                }
                visit::visit_local(self, node);
            }
        }
        let mut clamped = Clamped {
            idents: std::collections::BTreeSet::new(),
        };
        clamped.visit_file(self.ast());

        struct V<'a> {
            clamped: &'a std::collections::BTreeSet<Label>,
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl V<'_> {
            fn args_capped(
                &self,
                args: &syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
            ) -> bool {
                args.iter().any(|a| {
                    let toks = a.to_token_stream().to_string();
                    if toks.contains(". min (") || toks.contains(".min(") {
                        return true;
                    }
                    toks.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                        .any(|w| self.clamped.contains(&Label::admit(w)))
                })
            }
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                if (node.method == "with_capacity" || node.method == "reserve")
                    && self.args_capped(&node.args)
                {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.method.span()), "capacity_min_cap");
                }
                visit::visit_expr_method_call(self, node);
            }
            fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
                let is_with_capacity = node
                    .func
                    .to_token_stream()
                    .to_string()
                    .ends_with("with_capacity");
                if is_with_capacity && self.args_capped(&node.args) {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&syn::spanned::Spanned::span(&node.func)), "capacity_min_cap");
                }
                visit::visit_expr_call(self, node);
            }
        }
        let mut v = V {
            clamped: &clamped.idents,
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Silenced lints hiding defects (BANNED #11), split per lint family so
    /// counts stay legible.
    fn detect_allow_dead_code(&self) -> Vec<Hit> {
        self.allow_attrs(&["dead_code"], "allow_dead_code")
    }
    fn detect_allow_unused(&self) -> Vec<Hit> {
        self.allow_attrs(&["unused"], "allow_unused")
    }
    fn detect_allow_clippy(&self) -> Vec<Hit> {
        self.allow_attrs(&["clippy::"], "allow_clippy")
    }
    fn detect_allow_missing_docs(&self) -> Vec<Hit> {
        self.allow_attrs(&["missing_docs"], "allow_missing_docs")
    }
    fn detect_allow_private(&self) -> Vec<Hit> {
        self.allow_attrs(
            &["private_interfaces", "private_bounds"],
            "allow_private",
        )
    }
    fn detect_allow_unsafe(&self) -> Vec<Hit> {
        self.allow_attrs(&["unsafe_code"], "allow_unsafe")
    }
}

/// Which match-arm shape a matcher hunts — one enum, one walker.
enum ArmSiteKind {
    Catchall,
    TestErrEarlyReturn,
    ErrCostume,
}

impl ArmSiteKind {
    fn site(&self, arm: &syn::Arm) -> Option<(usize, &'static str)> {
        match self {
            ArmSiteKind::Catchall => {
                if let syn::Pat::Wild(w) = &arm.pat {
                    Some((BOUNDARY.span_line(&w.underscore_token.span), "catchall_arm"))
                } else {
                    None
                }
            }
            ArmSiteKind::TestErrEarlyReturn => {
                if !arm.pat.to_token_stream().to_string().starts_with("Err") {
                    return None;
                }
                let line = BOUNDARY.span_line(&arm.fat_arrow_token.spans[0]);
                if let syn::Expr::Return(r) = &*arm.body {
                    if r.expr.is_none() {
                        return Some((line, "test_err_early_return"));
                    }
                }
                // `Err(_) => {}` — the error evaporates and the test proceeds
                // as if proof happened.
                if let syn::Expr::Block(b) = &*arm.body {
                    if b.block.stmts.is_empty() {
                        return Some((line, "test_err_early_return"));
                    }
                }
                None
            }
            ArmSiteKind::ErrCostume => {
                let pat = arm.pat.to_token_stream().to_string();
                if !(pat.starts_with("Err") || pat == "None") {
                    return None;
                }
                let line = BOUNDARY.span_line(&arm.fat_arrow_token.spans[0]);
                let body = &arm.body;
                let s = body.to_token_stream().to_string();
                let t = s.trim();
                let name = if t.ends_with(":: Null") || t == "Null" {
                    Some("err_to_null_costume")
                } else if t == "0" || t == "0.0" || t.ends_with("from (0)") {
                    Some("err_to_zero_costume")
                } else if t.ends_with(":: MAX") {
                    Some("err_to_max_costume")
                } else if t == "& []" || t == "&[]" {
                    Some("empty_slice_costume")
                } else if matches!(&**body, syn::Expr::Lit(_)) {
                    Some("err_to_literal_costume")
                } else if let syn::Expr::Unary(u) = &**body {
                    if matches!(&*u.expr, syn::Expr::Lit(_)) {
                        Some("err_to_literal_costume")
                    } else {
                        None
                    }
                } else if let syn::Expr::Call(c) = &**body {
                    if c.args.is_empty() {
                        Some("err_to_constructor_costume")
                    } else {
                        None
                    }
                } else if t == "vec ! []" || t.starts_with("Default :: default") {
                    Some("err_to_constructor_costume")
                } else if matches!(&**body, syn::Expr::Continue(_)) {
                    Some("err_flow_swallow")
                } else {
                    None
                };
                name.map(|construct| (line, construct))
            }
        }
    }
}

/// A construction-door predicate as a ZST value receiver (TRUTH item 9):
/// `ConstructionDoorPick.pick(sig)` — a real method, never a bare fn
/// pointer masquerading as an associated fn.
struct ConstructionDoorPick;

impl ConstructionDoorPick {
    fn pick(&self, sig: &syn::Signature) -> Option<usize> {
        let name = sig.ident.to_string();
        // Bite harnesses are named `bite_<ban>`; the ban spelling may itself
        // end in `_unchecked`. They prove the matcher, they are not doors.
        if name.starts_with("bite_") {
            return None;
        }
        // Every raw-door name, unconditionally — a Result-returning
        // from_bytes that never actually refuses would dodge any
        // "fallible = validated" carve; a genuinely validating door swears
        // one waiver naming its proof.
        if name == "from_raw" || name.ends_with("_unchecked") || name == "from_bytes" {
            return Some(BOUNDARY.span_line(&sig.ident.span()));
        }
        None
    }
}

impl SourceFile {
    /// `_ =>` / `_ if` match arms swallowing unenumerated variants.
    fn detect_catchall_arm(&self) -> Vec<Hit> {
        self.arm_sites(ArmSiteKind::Catchall)
    }

    /// The one match-arm walker: every matcher that judges a `match` arm rides
    /// this shell, so arm traversal has a single authority.
    fn arm_sites(&self, kind: ArmSiteKind) -> Vec<Hit> {
        struct V<'a> {
            kind: ArmSiteKind,
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_arm(&mut self, node: &'ast syn::Arm) {
                if let Some((line, construct)) = self.kind.site(node) {
                    HIT_PUSH.push(&mut self.hits, self.rel, line, construct);
                }
                visit::visit_arm(self, node);
            }
        }
        let mut v = V {
            kind,
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    fn detect_default_derive(&self) -> Vec<Hit> {
        // AST attribute walk — not line_starts_scan. A split
        // `#[derive(\n  Default,\n)]` is the same second door; reading only the
        // `#[derive(` line was the tip-686 soft drain.
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
                let toks = node.to_token_stream().to_string();
                let direct = node.path().is_ident("derive") && toks.contains("Default");
                let smuggled = node.path().is_ident("cfg_attr")
                    && toks.contains("derive")
                    && toks.contains("Default");
                if direct || smuggled {
                    HIT_PUSH.push(
                        &mut self.hits,
                        self.rel,
                        BOUNDARY.span_line(&node.pound_token.spans[0]),
                        "default_derive",
                    );
                }
                visit::visit_attribute(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    fn detect_default_impl(&self) -> Vec<Hit> {
        self.file_hits(FileHitKind::DefaultImpl)
    }

    /// Unchecked construction doors: `from_raw` / `*_unchecked` /
    /// unvalidated `from_bytes` production definitions.
    fn detect_construction_door(&self) -> Vec<Hit> {
        self.sig_sites(&|sig| ConstructionDoorPick.pick(sig), "construction_door")
    }

    /// The one fn-signature walker: matchers that judge a fn by its signature
    /// (free fns and impl methods alike) share this shell, so the two syn node
    /// kinds are handled by a single authority.
    fn sig_sites(
        &self,
        pick: &dyn Fn(&syn::Signature) -> Option<usize>,
        construct: &str,
    ) -> Vec<Hit> {
        struct V<'a> {
            pick: &'a dyn Fn(&syn::Signature) -> Option<usize>,
            construct: Label,
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
                if let Some(line) = (self.pick)(&node.sig) {
                    HIT_PUSH.push(&mut self.hits, self.rel, line, self.construct.as_str());
                }
                visit::visit_impl_item_fn(self, node);
            }
            fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
                if let Some(line) = (self.pick)(&node.sig) {
                    HIT_PUSH.push(&mut self.hits, self.rel, line, self.construct.as_str());
                }
                visit::visit_item_fn(self, node);
            }
        }
        let mut v = V {
            pick,
            construct: Label::admit(construct),
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }
}

impl SourceFile {
    /// A test that can pass without asserting: `Err(_) => return` inside test
    /// scope, `#[should_panic]`, `#[ignore]`.
    fn detect_test_err_early_return(&self) -> Vec<Hit> {
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl V<'_> {
            fn block_is_bare_return_or_empty(&self, b: &syn::Block) -> bool {
                if b.stmts.is_empty() {
                    return true;
                }
                if let [syn::Stmt::Expr(syn::Expr::Return(r), _)] = b.stmts.as_slice() {
                    return r.expr.is_none();
                }
                false
            }
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            // `if x.is_err() { return; }` — same evaporation, if-shaped.
            fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
                let cond = node.cond.to_token_stream().to_string();
                if cond.contains(". is_err ()") && self.block_is_bare_return_or_empty(&node.then_branch) {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.if_token.span), "test_err_early_return");
                }
                visit::visit_expr_if(self, node);
            }
            // `let Ok(x) = r else { return };` — refusal diverted to a shrug.
            fn visit_local(&mut self, node: &'ast syn::Local) {
                if node.pat.to_token_stream().to_string().starts_with("Ok") {
                    if let Some(init) = &node.init {
                        if let Some((_, diverge)) = &init.diverge {
                            if let syn::Expr::Block(b) = &**diverge {
                                if self.block_is_bare_return_or_empty(&b.block) {
                                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.let_token.span), "test_err_early_return");
                                }
                            }
                        }
                    }
                }
                visit::visit_local(self, node);
            }
        }
        let mut hits = self.arm_sites(ArmSiteKind::TestErrEarlyReturn);
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        hits.append(&mut v.hits);
        hits
    }

    fn detect_ignore_test(&self) -> Vec<Hit> {
        self.attr_sites("ignore", "ignore_test")
    }

    fn detect_should_panic(&self) -> Vec<Hit> {
        self.attr_sites("should_panic", "should_panic")
    }

    /// `#[path = "…"]` / `#![path = "…"]` — file-identity spoof at any
    /// attribute position (item 5 attribute jurisdiction).
    fn detect_path(&self) -> Vec<Hit> {
        self.attr_sites("path", "path")
    }
}

/// Nested place assign: `self.a.b = …` (depth > 1) or a non-self place.
struct BinOpRef<'a>(&'a syn::BinOp);

impl BinOpRef<'_> {
    fn is_compound_assign(&self) -> bool {
        matches!(
            self.0,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
                | syn::BinOp::RemAssign(_)
                | syn::BinOp::BitXorAssign(_)
                | syn::BinOp::BitAndAssign(_)
                | syn::BinOp::BitOrAssign(_)
                | syn::BinOp::ShlAssign(_)
                | syn::BinOp::ShrAssign(_)
        )
    }
}

/// Self-place nesting depth as a ZST value receiver: `self.a.b = …` is
/// depth 2, `self.a = …` is depth 1. Recursion rides `self.depth(...)`
/// method calls, never a free recursive fn.
struct SelfPlaceAssign;

impl SelfPlaceAssign {
    fn depth(&self, expr: &syn::Expr) -> Option<usize> {
        match expr {
            syn::Expr::Path(p) if p.path.is_ident("self") => Some(0),
            syn::Expr::Field(fld) => self.depth(&fld.base).map(|d| d + 1),
            _not_a_self_place => None,
        }
    }

    fn is_nested(&self, lhs: &syn::Expr) -> bool {
        self.depth(lhs).is_none_or(|depth| depth > 1)
    }
}

/// Which assignment sites a matcher hunts — one walk authority (tip 851:
/// `detect_nested_place_assign` / `detect_assignment` must not be twin bodies).
#[derive(Clone, Copy)]
enum AssignSiteKind {
    /// Every `=` / compound-assign (construct-scoped on derivation).
    Any,
    /// Only nested `self.…` places (construct-scoped ban).
    NestedPlace,
}

impl AssignSiteKind {
    fn construct(self) -> &'static str {
        match self {
            Self::Any => "assignment",
            Self::NestedPlace => "nested_place_assign",
        }
    }

    fn wants(self, left: &syn::Expr) -> bool {
        match self {
            Self::Any => true,
            Self::NestedPlace => SelfPlaceAssign.is_nested(left),
        }
    }
}

impl SourceFile {
    /// One assign/compound-assign walker — both matchers share this body.
    fn assign_sites(&self, kind: AssignSiteKind) -> Vec<Hit> {
        use syn::spanned::Spanned;
        struct V<'a> {
            kind: AssignSiteKind,
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
                if self.kind.wants(&node.left) {
                    HIT_PUSH.push(
                        &mut self.hits,
                        self.rel,
                        BOUNDARY.span_line(&node.eq_token.span),
                        self.kind.construct(),
                    );
                }
                visit::visit_expr_assign(self, node);
            }
            fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
                if BinOpRef(&node.op).is_compound_assign() && self.kind.wants(&node.left) {
                    HIT_PUSH.push(
                        &mut self.hits,
                        self.rel,
                        BOUNDARY.span_line(&node.op.span()),
                        self.kind.construct(),
                    );
                }
                visit::visit_expr_binary(self, node);
            }
        }
        let mut v = V {
            kind,
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Construct-scoped (item 5); run.rs keeps hits only inside constructs
    /// that list this ban.
    fn detect_nested_place_assign(&self) -> Vec<Hit> {
        self.assign_sites(AssignSiteKind::NestedPlace)
    }

    /// Any assignment / compound-assign (construct-scoped on derivation).
    fn detect_assignment(&self) -> Vec<Hit> {
        self.assign_sites(AssignSiteKind::Any)
    }

    /// `.await` expression sites (construct-scoped on fn skeletons).
    fn detect_await(&self) -> Vec<Hit> {
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
                HIT_PUSH.push(
                    &mut self.hits,
                    self.rel,
                    BOUNDARY.span_line(&node.await_token.span),
                    "await",
                );
                visit::visit_expr_await(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// AST attribute scan: a bare `#[name]`/`#[name = …]` or a
    /// `#[cfg_attr(…, name…)]` smuggle both count — placement and line
    /// formatting cannot hide an attribute from a parsed walk.
    fn attr_sites(&self, name: &str, construct: &str) -> Vec<Hit> {
        struct V<'a> {
            name: Label,
            construct: Label,
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
                let direct = node.path().is_ident(self.name.as_str());
                let smuggled = node.path().is_ident("cfg_attr")
                    && node.to_token_stream().to_string().contains(self.name.as_str());
                if direct || smuggled {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.pound_token.spans[0]), self.construct.as_str());
                }
                visit::visit_attribute(self, node);
            }
        }
        let mut v = V {
            name: Label::admit(name),
            construct: Label::admit(construct),
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Error laundered into a normal-looking value: an `Err(..)`/`None` match
    /// arm whose body is a costume value (`Json::Null`, `0`, `0.0`, `T::MAX`,
    /// `&[]`, `String::new()`).
    fn detect_err_costume(&self) -> Vec<Hit> {
        self.arm_sites(ArmSiteKind::ErrCostume)
    }

    /// Every `exit`/`abort` path ident. Wide on purpose: an imported
    /// `use std::process::exit; exit(1)` carries no `process::` on its line —
    /// a state machine's own `exit` verb survives only through an approved waiver.
    fn detect_process_exit(&self) -> Vec<Hit> {
        self.path_idents(&["exit", "abort"], "process_exit")
    }
}

/// A naked-array-sig predicate as a ZST value receiver (TRUTH item 9).
struct NakedArraySigPick;

impl NakedArraySigPick {
    fn pick(&self, sig: &syn::Signature) -> Option<usize> {
        // Every fn signature trafficking a naked [u8; 32/12/64], no name
        // exemptions: a newtype's genuine wrap door is one approved waiver, not a
        // prefix anybody can borrow.
        let text = sig.to_token_stream().to_string();
        let naked = text.contains("[u8 ; 32]")
            || text.contains("[u8 ; 12]")
            || text.contains("[u8 ; 64]");
        if naked {
            return Some(BOUNDARY.span_line(&sig.ident.span()));
        }
        None
    }
}

impl SourceFile {
    /// Sleep-based synchronization (BANNED #18): every `sleep` path ident.
    /// Wide on purpose: `use std::thread::sleep; sleep(d)` carries no
    /// `thread::` on its line. A lawful sleep swears a waiver.
    fn detect_sleep_sync(&self) -> Vec<Hit> {
        self.path_idents(&["sleep"], "sleep_sync")
    }

    /// `#[serde(default)]` / `#[serde(skip)]` (BANNED #25): a wire format
    /// field that can silently vanish or self-invent.
    fn detect_serde_default_skip(&self) -> Vec<Hit> {
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            // AST attribute walk, not a text scan: an attribute mid-line or
            // split across lines is the same lie and must cost the same.
            fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
                if node.path().is_ident("serde") {
                    let args = node.to_token_stream().to_string();
                    if args.contains("default")
                        || args.contains("skip")
                        || args.contains("other")
                        || args.contains("untagged")
                    {
                        HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.pound_token.spans[0]), "serde_default_skip");
                    }
                }
                visit::visit_attribute(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Wall-clock / unseeded randomness (seats 25/45/83/84).
    ///
    /// `Local` and `env` are NOT bare path-ident matches: bare `Local` collides
    /// with `syn::Local` / `Stmt::Local`, and bare `env` collides with the
    /// compile-time `env!` macro. Those two are judged with path structure.
    fn detect_nondeterminism(&self) -> Vec<Hit> {
        let mut hits = self.path_idents(
            &[
                "Instant",
                "SystemTime",
                "UNIX_EPOCH",
                "thread_rng",
                "OsRng",
                "getrandom",
                "random",
                "from_entropy",
                "fastrand",
                "Utc",
                "RandomState",
                "DefaultHasher",
            ],
            "nondeterminism",
        );
        struct V<'a> {
            rel: &'a RelPath,
            hits: &'a mut Vec<Hit>,
        }
        impl V<'_> {
            fn segs(&self, path: &syn::Path) -> Vec<String> {
                path.segments.iter().map(|s| s.ident.to_string()).collect()
            }
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_path(&mut self, node: &'ast syn::Path) {
                let s = self.segs(node);
                // chrono::Local (or Local under a chrono crate path) — never syn::Local.
                if s.last().is_some_and(|x| x == "Local") && s.iter().any(|x| x == "chrono") {
                    if let Some(seg) = node.segments.last() {
                        HIT_PUSH.push(
                            self.hits,
                            self.rel,
                            BOUNDARY.span_line(&seg.ident.span()),
                            "nondeterminism",
                        );
                    }
                }
                visit::visit_path(self, node);
            }
            fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
                let s = self.segs(&node.path);
                // Runtime std::env / ::env / env::var — not the env! macro (macros
                // are visited via visit_macro, which we do not flag here).
                if s.iter().any(|x| x == "env") {
                    if let Some(seg) = node.path.segments.iter().find(|sg| sg.ident == "env") {
                        HIT_PUSH.push(
                            self.hits,
                            self.rel,
                            BOUNDARY.span_line(&seg.ident.span()),
                            "nondeterminism",
                        );
                    }
                }
                visit::visit_expr_path(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: &mut hits,
        };
        v.visit_file(self.ast());
        hits
    }

    /// Raw peer/transport sockets (seats 18/92): NATS is the only nervous
    /// system.
    fn detect_peer_dial(&self) -> Vec<Hit> {
        self.path_idents(
            &["TcpStream", "TcpListener", "UdpSocket", "UnixStream", "UnixListener"],
            "peer_dial",
        )
    }

    /// A crypto/auth door taking or returning a naked `[u8; 32/12/64]` (T17)
    /// instead of a typed Dek/Kek/Digest/Mac/Nonce/Signature. The structural
    /// exemption is a newtype's OWN wrap door: `admit`, `as_bytes`,
    /// `as_bytes_mut`, `from_*`, `of_*`.
    fn detect_naked_array_sig(&self) -> Vec<Hit> {
        self.sig_sites(&|sig| NakedArraySigPick.pick(sig), "naked_array_sig")
    }

    /// `unsafe` blocks/fns/impls/traits anywhere (the four crate roots without
    /// `#![forbid(unsafe_code)]` are the meta engine's business; the token
    /// itself is this matcher's).
    fn detect_unsafe_token(&self) -> Vec<Hit> {
        self.file_hits(FileHitKind::UnsafeToken)
    }

    /// `assert!`/`assert_eq!`/`assert_ne!` on a caller-reachable path — a
    /// panic wearing an invariant costume (the historical RelationId decode
    /// bug: hostile stored bytes bound-checked by an assert, panicking the
    /// process instead of refusing typed). In `#[test]` scope asserts ARE the
    /// mechanism; in production they are panics.
    fn detect_assert_bang(&self) -> Vec<Hit> {
        self.macro_calls(&["assert", "assert_eq", "assert_ne"], "assert_bang")
    }
}

/// Story #299 condemned-boundary predicates as ZST value receivers.
struct CondemnedBoundaryPick;

impl CondemnedBoundaryPick {
    fn is_string_collection(&self, ty: &syn::Type) -> bool {
        let syn::Type::Path(tp) = ty else {
            return false;
        };
        let Some(seg) = tp.path.segments.last() else {
            return false;
        };
        if seg.ident != "Vec" {
            return false;
        }
        let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
            return false;
        };
        args.args.iter().any(|arg| {
            let syn::GenericArgument::Type(syn::Type::Path(inner)) = arg else {
                return false;
            };
            inner
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "String" || s.ident == "SmartString")
        })
    }

    fn is_to_string_call(&self, expr: &syn::Expr) -> bool {
        matches!(expr, syn::Expr::MethodCall(m) if m.method == "to_string")
    }

    fn format_is_if_splice(&self, mac: &syn::ExprMacro) -> bool {
        let Ok(args) = mac.mac.parse_body_with(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
        ) else {
            return false;
        };
        let Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(lit),
            ..
        })) = args.first()
        else {
            return false;
        };
        let value = lit.value();
        value.contains("if(") && value.matches('{').count() >= 2
    }
}

impl SourceFile {
    /// Story #299's condemned boundary shapes may never return: triggers
    /// stored as raw source-string collections, and extractor expressions
    /// captured as Display text / textually spliced back together.
    fn detect_condemned_boundary(&self) -> Vec<Hit> {
        const TRIGGER_FIELDS: &[&str] = &["put_triggers", "rm_triggers", "replace_triggers"];
        const EXTRACTOR_NAMES: &[&str] = &["extractor", "extract_filter"];
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_field(&mut self, node: &'ast syn::Field) {
                if let Some(ident) = &node.ident {
                    let name = ident.to_string();
                    if TRIGGER_FIELDS.contains(&name.as_str()) && CondemnedBoundaryPick.is_string_collection(&node.ty) {
                        HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&ident.span()), "stored_source_trigger_field");
                    }
                }
                visit::visit_field(self, node);
            }
            fn visit_expr(&mut self, node: &'ast syn::Expr) {
                if let syn::Expr::Macro(mac) = node {
                    let is_format = mac
                        .mac
                        .path
                        .segments
                        .last()
                        .is_some_and(|seg| seg.ident == "format");
                    if is_format && CondemnedBoundaryPick.format_is_if_splice(mac) {
                        if let Some(seg) = mac.mac.path.segments.last() {
                            HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&seg.ident.span()), "extractor_display_splice");
                        }
                    }
                }
                if let syn::Expr::Assign(a) = node {
                    if let syn::Expr::Path(pth) = a.left.as_ref() {
                        if let Some(seg) = pth.path.segments.last() {
                            if EXTRACTOR_NAMES.contains(&seg.ident.to_string().as_str())
                                && CondemnedBoundaryPick.is_to_string_call(&a.right)
                            {
                                HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&seg.ident.span()), "extractor_to_string_capture");
                            }
                        }
                    }
                }
                if let syn::Expr::Struct(st) = node {
                    for field in &st.fields {
                        if let syn::Member::Named(ident) = &field.member {
                            if EXTRACTOR_NAMES.contains(&ident.to_string().as_str())
                                && CondemnedBoundaryPick.is_to_string_call(&field.expr)
                            {
                                HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&ident.span()), "extractor_to_string_capture");
                            }
                        }
                    }
                }
                visit::visit_expr(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Seat 59: a `hasher.update(b"...")` byte-literal domain tag is the
    /// opening move of a hand-rolled sealed-artifact layout. There is ONE
    /// canonical constructor — `kyzo-core/src/store/transcript.rs` — and its
    /// own sites ARE the authority, exempt structurally by name; every other
    /// site is a second serializer until approved otherwise (KDFs and internal
    /// identity digests are real and are entered individually — no ratchet, no
    /// baseline).
    fn detect_hand_layout(&self) -> Vec<Hit> {
        struct V<'a> {
            rel: &'a RelPath,
            hits: Vec<Hit>,
        }
        impl<'ast, 'a> Visit<'ast> for V<'a> {
            fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                let is_byte_tag = node.method == "update"
                    && matches!(
                        node.args.first(),
                        Some(syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::ByteStr(_),
                            ..
                        }))
                    );
                if is_byte_tag {
                    HIT_PUSH.push(&mut self.hits, self.rel, BOUNDARY.span_line(&node.method.span()), "hand_layout");
                }
                visit::visit_expr_method_call(self, node);
            }
        }
        let mut v = V {
            rel: self.rel_path_ref(),
            hits: vec![],
        };
        v.visit_file(self.ast());
        v.hits
    }

    /// Poisoned-lock silent continue (BANNED #13): `.into_inner()` on a
    /// PoisonError — recovering the guard and carrying on.
    fn detect_poison_continue(&self) -> Vec<Hit> {
        // Every `.into_inner()`, unconditionally. The poisoned-lock recovery
        // this bans does not announce itself in the variable name; the many
        // lawful into_inner calls (BufWriter, Cell, io wrappers…) swear
        // site-bound waivers instead of hiding behind a rename.
        self.method_calls(&["into_inner"], "poison_continue")
    }
}

/// The registry. checks.toml refers to these by name; the meta engine
/// reports any table entry no check references (dead detection is a lie
/// about coverage too).
pub const MATCHERS: &[Matcher] = &[
    Matcher::admit(b"unwrap", ScanClass::ProductionOnly, SourceFile::detect_unwrap),
    Matcher::admit(b"expect", ScanClass::ProductionOnly, SourceFile::detect_expect),
    Matcher::admit(b"unwrap_or", ScanClass::Everything, SourceFile::detect_unwrap_or),
    Matcher::admit(b"unwrap_or_else", ScanClass::Everything, SourceFile::detect_unwrap_or_else),
    Matcher::admit(b"unwrap_or_default", ScanClass::Everything, SourceFile::detect_unwrap_or_default),
    Matcher::admit(b"unwrap_unchecked", ScanClass::Everything, SourceFile::detect_unchecked_unwrap),
    Matcher::admit(b"panic_bang", ScanClass::ProductionOnly, SourceFile::detect_panic_bang),
    Matcher::admit(b"unreachable_bang", ScanClass::ProductionOnly, SourceFile::detect_unreachable_bang),
    Matcher::admit(b"todo_bang", ScanClass::Everything, SourceFile::detect_todo_bang),
    Matcher::admit(b"debug_assert", ScanClass::Everything, SourceFile::detect_debug_assert),
    Matcher::admit(b"let_underscore", ScanClass::Everything, SourceFile::detect_let_underscore),
    Matcher::admit(b"ok_drop", ScanClass::Everything, SourceFile::detect_ok_drop),
    Matcher::admit(b"as_cast", ScanClass::Everything, SourceFile::detect_as_cast),
    Matcher::admit(b"unchecked_arith", ScanClass::Everything, SourceFile::detect_unchecked_arith),
    Matcher::admit(b"capacity_min_cap", ScanClass::Everything, SourceFile::detect_capacity_min_cap),
    Matcher::admit(b"allow_dead_code", ScanClass::Everything, SourceFile::detect_allow_dead_code),
    Matcher::admit(b"allow_unused", ScanClass::Everything, SourceFile::detect_allow_unused),
    Matcher::admit(b"allow_clippy", ScanClass::Everything, SourceFile::detect_allow_clippy),
    Matcher::admit(b"allow_missing_docs", ScanClass::Everything, SourceFile::detect_allow_missing_docs),
    Matcher::admit(b"allow_private", ScanClass::Everything, SourceFile::detect_allow_private),
    Matcher::admit(b"allow_unsafe", ScanClass::Everything, SourceFile::detect_allow_unsafe),
    Matcher::admit(b"catchall_arm", ScanClass::Everything, SourceFile::detect_catchall_arm),
    Matcher::admit(b"default_derive", ScanClass::Everything, SourceFile::detect_default_derive),
    Matcher::admit(b"default_impl", ScanClass::Everything, SourceFile::detect_default_impl),
    Matcher::admit(b"construction_door", ScanClass::Everything, SourceFile::detect_construction_door),
    Matcher::admit(b"test_err_early_return", ScanClass::Everything, SourceFile::detect_test_err_early_return),
    Matcher::admit(b"ignore_test", ScanClass::Everything, SourceFile::detect_ignore_test),
    Matcher::admit(b"should_panic", ScanClass::Everything, SourceFile::detect_should_panic),
    Matcher::admit(b"path", ScanClass::Everything, SourceFile::detect_path),
    Matcher::admit(b"nested_place_assign", ScanClass::Everything, SourceFile::detect_nested_place_assign),
    Matcher::admit(b"assignment", ScanClass::Everything, SourceFile::detect_assignment),
    Matcher::admit(b"await", ScanClass::Everything, SourceFile::detect_await),
    Matcher::admit(b"err_costume", ScanClass::Everything, SourceFile::detect_err_costume),
    Matcher::admit(b"process_exit", ScanClass::Everything, SourceFile::detect_process_exit),
    Matcher::admit(b"sleep_sync", ScanClass::Everything, SourceFile::detect_sleep_sync),
    Matcher::admit(b"serde_default_skip", ScanClass::Everything, SourceFile::detect_serde_default_skip),
    Matcher::admit(b"poison_continue", ScanClass::Everything, SourceFile::detect_poison_continue),
    Matcher::admit(b"nondeterminism", ScanClass::ProductionOnly, SourceFile::detect_nondeterminism),
    Matcher::admit(b"peer_dial", ScanClass::ProductionOnly, SourceFile::detect_peer_dial),
    Matcher::admit(b"naked_array_sig", ScanClass::ProductionOnly, SourceFile::detect_naked_array_sig),
    Matcher::admit(b"unsafe_token", ScanClass::Everything, SourceFile::detect_unsafe_token),
    Matcher::admit(b"assert_bang", ScanClass::ProductionOnly, SourceFile::detect_assert_bang),
    Matcher::admit(b"condemned_boundary", ScanClass::ProductionOnly, SourceFile::detect_condemned_boundary),
    Matcher::admit(b"hand_layout", ScanClass::ProductionOnly, SourceFile::detect_hand_layout),
];

/// Typed test refusal — file-level so `total_refusal` indexes it as a workspace
/// enum (tip 777). Nested inside `mod tests` was `not-workspace-enum`.
#[cfg(test)]
#[derive(Debug)]
enum ShapeProofRefuse {
    Parse,
    MatcherMissing,
    DuplicateName,
    HitCount,
    Construct,
    CommentNotWaiver,
    CfgNotTestStrip,
    CfgTestStrip,
    CfgTestModStrip,
    ModTestsStillScanned,
    NondeterminismCfgModStrip,
    NondeterminismCfgStmtStrip,
    NondeterminismLive,
    PeerDial,
    NakedArrayDoor,
    OwnDoorNaked,
    OkDropMatchArm,
    OkDropTail,
    OkDropCleanMustQuiet,
    MultilineDefaultDerive,
    CfgAttrDefaultDerive,
}
#[cfg(test)]
impl ShapeProofRefuse {
    fn require(self, cond: bool) -> Result<(), ShapeProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }

    fn require_eq<T: PartialEq>(self, got: T, want: T) -> Result<(), ShapeProofRefuse> {
        self.require(got == want)
    }
}

#[cfg(test)]
struct ShapeProofs;

#[cfg(test)]
impl ShapeProofs {
    fn parse(&self, rel: &str, src: &str) -> Result<SourceFile, ShapeProofRefuse> {
        let ast = syn::parse_file(src).map_err(|_| ShapeProofRefuse::Parse)?;
        Ok(SourceFile::admit(rel, src, ast))
    }

    fn run(&self, name: &str, src: &str) -> Result<Vec<Hit>, ShapeProofRefuse> {
        let m = MATCHER_LOOKUP.by_name(name).ok_or(ShapeProofRefuse::MatcherMissing)?;
        Ok(m.run(&self.parse("crates/x/src/probe.rs", src)?))
    }

    fn must_hit(&self, name: &str, src: &str, want: usize, refuse: ShapeProofRefuse) -> Result<(), ShapeProofRefuse> {
        refuse.require_eq(self.run(name, src)?.len(), want)
    }
}

#[cfg(test)]
const SHAPE_PROOFS: ShapeProofs = ShapeProofs;


#[cfg(test)]
mod tests {
    use super::{MATCHERS, SHAPE_PROOFS, ShapeProofRefuse};

    type TestResult = Result<(), ShapeProofRefuse>;

    #[test]
    fn every_matcher_has_a_unique_name() -> TestResult {
        let mut names: Vec<&str> = MATCHERS.iter().map(|m| m.name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        ShapeProofRefuse::DuplicateName.require_eq(before, names.len())
    }

    #[test]
    fn dishonesty_shapes_detonate() -> TestResult {
        SHAPE_PROOFS.must_hit("unwrap", "fn f(x: Option<u8>) { x.unwrap(); }", 1, ShapeProofRefuse::HitCount)?;
        SHAPE_PROOFS.must_hit("expect", "fn f(x: Option<u8>) { x.expect(\"y\"); }", 1, ShapeProofRefuse::HitCount)?;
        SHAPE_PROOFS.must_hit(
            "let_underscore",
            "fn f() { let _ = g(); } fn g() -> u8 { 1 }",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit("ok_drop", "fn f(x: Result<u8, u8>) { x.ok(); }", 1, ShapeProofRefuse::HitCount)?;
        SHAPE_PROOFS.must_hit("as_cast", "fn f(x: u64) -> u8 { x as u8 }", 1, ShapeProofRefuse::HitCount)?;
        SHAPE_PROOFS.must_hit(
            "catchall_arm",
            "fn f(x: u8) -> u8 { match x { 1 => 1, _ => 0 } }",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit("panic_bang", "fn f() { panic!(\"boom\"); }", 1, ShapeProofRefuse::HitCount)?;
        SHAPE_PROOFS.must_hit("todo_bang", "fn f() { todo!(); }", 1, ShapeProofRefuse::HitCount)?;
        SHAPE_PROOFS.must_hit(
            "debug_assert",
            "fn f(x: u8) { debug_assert!(x > 0); }",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit(
            "allow_dead_code",
            "#[allow(dead_code)]\nfn f() {}",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit(
            "err_costume",
            "fn f(r: Result<u8,u8>) -> u8 { match r { Ok(v) => v, Err(_) => 0 } }",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit(
            "sleep_sync",
            "fn f() { std::thread::sleep(std::time::Duration::from_millis(1200)); }",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit(
            "serde_default_skip",
            "struct S { #[serde(default)]\n x: u8 }",
            1,
            ShapeProofRefuse::HitCount,
        )
    }

    #[test]
    fn unchecked_arith_accepts_no_comment_as_waiver() -> TestResult {
        SHAPE_PROOFS.must_hit(
            "unchecked_arith",
            "fn f(a: u64, b: u64) -> u64 { a.wrapping_mul(b) }",
            1,
            ShapeProofRefuse::HitCount,
        )?;
        SHAPE_PROOFS.must_hit(
            "unchecked_arith",
            "fn f(a: u64, b: u64) -> u64 {\n    // INVARIANT(SeedMix): wrap is the published mix contract.\n    a.wrapping_mul(b)\n}",
            1,
            ShapeProofRefuse::CommentNotWaiver,
        )
    }

    /// Tip 650/659: blanket cfg(test) strip is BLINDED — removed. Every
    /// site below must detonate; a silent empty is the soft drain returning.
    /// Named `anti_fraud_tip_659` so sabotage_audit can lock the seat.
    #[test]
    fn anti_fraud_tip_659() -> TestResult {
        anti_fraud_cfg_test_unwrap_must_be_counted()
    }

    #[test]
    fn anti_fraud_cfg_test_unwrap_must_be_counted() -> TestResult {
        SHAPE_PROOFS.must_hit(
            "unwrap",
            "#[cfg(not(test))]\nfn f(x: Option<u8>) -> u8 { x.unwrap() }",
            1,
            ShapeProofRefuse::CfgNotTestStrip,
        )?;
        SHAPE_PROOFS.must_hit(
            "unwrap",
            "#[cfg(all(test, unix))]\nfn f(x: Option<u8>) -> u8 { x.unwrap() }",
            1,
            ShapeProofRefuse::CfgTestStrip,
        )?;
        SHAPE_PROOFS.must_hit(
            "unwrap",
            "#[cfg(test)] mod tests { fn f(x: Option<u8>) -> u8 { x.unwrap() } }",
            1,
            ShapeProofRefuse::CfgTestModStrip,
        )?;
        SHAPE_PROOFS.must_hit(
            "unwrap",
            "mod tests { pub fn f(x: Option<u8>) -> u8 { x.unwrap() } }",
            1,
            ShapeProofRefuse::ModTestsStillScanned,
        )
    }

    #[test]
    fn anti_fraud_cfg_test_nondeterminism_must_be_counted() -> TestResult {
        let hits = SHAPE_PROOFS.run(
            "nondeterminism",
            "#[cfg(test)] mod tests { fn f() { let _t = std::time::Instant::now(); } }",
        )?;
        ShapeProofRefuse::NondeterminismCfgModStrip.require_eq(hits
                .iter()
                .filter(|h| h.construct() == "nondeterminism")
                .count(), 1)?;
        SHAPE_PROOFS.must_hit(
            "nondeterminism",
            "fn live() { #[cfg(test)] let _t0 = std::time::Instant::now(); }",
            1,
            ShapeProofRefuse::NondeterminismCfgStmtStrip,
        )?;
        SHAPE_PROOFS.must_hit(
            "nondeterminism",
            "fn live() { let t = std::time::Instant::now(); let _x = t; }",
            1,
            ShapeProofRefuse::NondeterminismLive,
        )?;
        SHAPE_PROOFS.must_hit(
            "peer_dial",
            "fn f() { let _c = std::net::TcpStream::connect(\"127.0.0.1:1\"); }",
            1,
            ShapeProofRefuse::PeerDial,
        )
    }

    #[test]
    fn naked_array_sig_has_no_name_exemptions() -> TestResult {
        SHAPE_PROOFS.must_hit(
            "naked_array_sig",
            "fn seal_key(k: [u8; 32]) {}",
            1,
            ShapeProofRefuse::NakedArrayDoor,
        )?;
        SHAPE_PROOFS.must_hit(
            "naked_array_sig",
            "struct D([u8; 32]); impl D { fn from_derived(b: [u8; 32]) -> D { D(b) } fn as_bytes(&self) -> &[u8; 32] { &self.0 } }",
            2,
            ShapeProofRefuse::OwnDoorNaked,
        )
    }

    /// Tip 686: match-arm `mem::drop(value)` was a silent-green drain —
    /// stmt-only ok_drop required a trailing semicolon. RED before the widen.
    #[test]
    fn anti_fraud_ok_drop_match_arm_mem_drop_must_be_counted() -> TestResult {
        SHAPE_PROOFS.must_hit(
            "ok_drop",
            "fn f(x: u8) { match x { value => core::mem::drop(value) } }",
            1,
            ShapeProofRefuse::OkDropMatchArm,
        )?;
        SHAPE_PROOFS.must_hit(
            "ok_drop",
            "fn f(x: u8) { drop(x) }",
            1,
            ShapeProofRefuse::OkDropTail,
        )?;
        SHAPE_PROOFS.must_hit(
            "ok_drop",
            "fn f(x: u8) -> u8 { x }",
            0,
            ShapeProofRefuse::OkDropCleanMustQuiet,
        )
    }

    /// Tip 686: `line_starts_scan` only saw `Default` on the `#[derive(` line.
    /// Split / cfg_attr-smuggled derive is the same second door — empty = blind.
    /// Proven RED against pre-fix line scanner (0 hits); AST walk closes it.
    #[test]
    fn anti_fraud_multiline_default_derive_must_be_counted() -> TestResult {
        let hits = SHAPE_PROOFS.run(
            "default_derive",
            "#[derive(\n    Debug,\n    Default,\n)]\nstruct S;",
        )?;
        ShapeProofRefuse::MultilineDefaultDerive.require_eq(hits.len(), 1)?;
        ShapeProofRefuse::Construct.require_eq(hits[0].construct(), "default_derive")?;
        let smuggled = SHAPE_PROOFS.run(
            "default_derive",
            "#[cfg_attr(feature = \"x\", derive(Default))]\nstruct T;",
        )?;
        ShapeProofRefuse::CfgAttrDefaultDerive.require_eq(smuggled.len(), 1)?;
        ShapeProofRefuse::Construct.require_eq(smuggled[0].construct(), "default_derive")
    }
}
