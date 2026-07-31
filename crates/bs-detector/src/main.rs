/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * Use of this software is governed by the Business Source License 1.1
 * included in the repository as LICENSE-BSL. See LICENSING.md.
 *
 * Change Date:    2030-07-11
 * Change License: Mozilla Public License, version 2.0
 */
#![forbid(unsafe_code)]

//! AUTHORITY: The forbidden shapes. A blacklist, and only what a script can
//! decide with certainty.
//!
//! Fifteen rules. Each one is decidable from syntax alone — no type
//! resolution, no call graph.
//!
//! Every rule here is absolute, and every rule has the same scope. The moment a
//! rule needs a clause like "…where a domain fact belongs", or its own list of
//! exempt files, it stops being absolute and does not belong in this file.
//!
//! There is no exemption mechanism. Not a marker, not an attribute, not a list
//! of paths. A rule that can be waived at the site is a rule with a hole, and
//! the hole is used under exactly the pressure the rule exists to resist. The
//! one legitimate reason to write a forbidden shape is to prove a rule fires on
//! it — and that shape is test data, not program text, so it is not a `.rs`
//! file and this walker never sees it.
//!
//! # Two passes, unioned, because neither alone is honest
//!
//! **Tokens, per line.** Catches shapes wherever they are written, including
//! inside macro bodies, which no parser expands. `unsafe`, `panic!`, `todo!`,
//! `env::var` are found here.
//!
//! **The item tree, via `syn`.** Catches shapes the line scanner could not
//! name: a field in a tuple struct, an enum variant payload, a function
//! parameter, a return type, an alias right-hand side. The previous scanner saw
//! only `name: Type` lines and tracked scope with a brace counter, so a shape
//! one column off its expected form was invisible.
//!
//! The two passes are **unioned**, never substituted. Replacing the token pass
//! with the parser would silently drop every shape written inside a macro. A
//! rewrite that lowers the count on unchanged code has narrowed a rule, not
//! fixed a tree.
//!
//! Whether a *stated* order law is *true* stays undecidable here — that is the
//! trials' job. "This type states its law" is decidable, and is what R01 asks.
//!
//! One scope: the whole workspace, or the single path you aim at. No rule
//! carries a private carve-out — not for tests, not for vendored code, not for
//! the crate the rule is inconvenient in.
//!
//! This crate is a workspace member on purpose: the detector scans itself.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// A forbidden shape, with the file and line that holds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    rule: &'static str,
    file: String,
    line: usize,
    detail: String,
}

/// The fifteen rules, as the report prints them.
const RULES: &[(&str, &str)] = &[
    ("R01", "Ord/PartialOrd/Hash on a type that does not state its ORDER_LAW"),
    ("R02", "pub field, or a public constructor that cannot refuse"),
    ("R03", "bare Vec/HashMap/HashSet as a pub field"),
    ("R04", "unwrap/expect/panic!"),
    ("R05", "String-typed error, or a refusal carrying no span"),
    ("R06", "todo!/unimplemented!/unreachable! stub"),
    ("R07", "env::var read outside the composition root"),
    ("R08", "String-typed kind/status/type/name field"),
    ("R09", "bool field carrying a domain decision"),
    ("R10", "bare primitive field outside a newtype"),
    ("R11", "RefCell/Cell/Mutex/RwLock field in a domain type"),
    ("R12", "f32/f64 field in a type that derives an order"),
    ("R13", "unsafe block/fn/impl"),
    ("R14", "allow(unsafe_code) — a lint-lowering on the strongest standard"),
    ("R15", "crate root with no #![forbid(unsafe_code)]"),
];

/// What the parser could not read, reported rather than passed over.
///
/// A parser that cannot see a construct and says nothing is reporting a clean
/// tree it never read. Both numbers print next to the findings.
#[derive(Default)]
struct Coverage {
    /// Files `syn` refused. Their token-pass findings still count; their item
    /// tree is absent.
    unparsed: Vec<String>,
    /// Macro invocations whose body is tokens this walker never expands.
    macro_bodies: usize,
}

/// How the detector was asked.
///
/// `Gate` walks the workspace. `Aim` is one path — a file or a directory —
/// reported to stdout and nothing else. Aiming never writes the verdict,
/// because a verdict about one file is not a verdict about the tree, and a
/// harness that could be satisfied by narrowing its scope is not a harness.
enum Mode {
    Gate { root: PathBuf },
    Aim { target: PathBuf },
}

// Note: neither mode writes crates/xtask/gate.log. The verdict combines this
// report with whether the tree compiles, and only crates/xtask/gate.sh holds
// both facts. A detector that authored the verdict would be claiming a green
// tree it never built.

fn main() {
    let mut root = PathBuf::from(".");
    let mut target: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            // --now-unix is accepted and ignored: this detector never reads a
            // clock, so a replay needs no instant pinned into it.
            "--root" => {
                if let Some(v) = args.next() {
                    root = PathBuf::from(v);
                }
            }
            "--now-unix" => {
                let _ = args.next();
            }
            "--file" | "--path" => {
                if let Some(v) = args.next() {
                    target = Some(PathBuf::from(v));
                }
            }
            other if !other.starts_with("--") => target = Some(PathBuf::from(other)),
            _ => {}
        }
    }
    let mode = match target {
        Some(t) => Mode::Aim { target: t },
        None => Mode::Gate { root: root.clone() },
    };

    let mut files = Vec::new();
    match &mode {
        // The whole workspace, not `crates/` alone. `fuzz/` is first-party and
        // was never scanned; `vendor/` is a first-party fork we publish under
        // our own name. A rule that stops at a directory boundary is a rule
        // with an exemption list, spelled as a walker.
        Mode::Gate { root } => collect(root, &mut files),
        Mode::Aim { target } => {
            if target.is_dir() {
                collect(target, &mut files);
            } else {
                files.push(target.clone());
            }
        }
    }
    files.sort();

    let mut violations = Vec::new();
    let mut coverage = Coverage::default();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let rel = f.strip_prefix(&root).unwrap_or(f).display().to_string();
        scan(&rel, &text, &mut violations, &mut coverage);
    }

    // Runs in both modes. A rule that only fires at the gate is a rule you can
    // walk past while working, which is where the shape gets written.
    check_forbid_unsafe(&files, &mut violations);

    // One shape, one finding. The two passes overlap on purpose — `panic!` is
    // found by both — and deduping on the whole record would keep both copies
    // because their detail strings differ, inflating the count. A padded number
    // is the same defect as a narrowed one, pointing the other way.
    violations.sort();
    violations.dedup_by(|a, b| a.rule == b.rule && a.file == b.file && a.line == b.line);

    match mode {
        Mode::Gate { root } => report_gate(&root, &files, &violations, &coverage),
        Mode::Aim { .. } => report_aim(&files, &violations, &coverage),
    }
}

/// Every crate root must carry `#![forbid(unsafe_code)]`. `forbid`, not `deny`:
/// it cannot be lifted locally by an `allow`, which is what makes zero-unsafe a
/// compiler guarantee rather than a convention. Decided per crate, over the
/// file list, because absence is not a line anyone wrote.
fn check_forbid_unsafe(files: &[PathBuf], out: &mut Vec<Violation>) {
    for f in files {
        let p = f.display().to_string();
        let Some(kind) = crate_root_kind(&p) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        if !text.contains("#![forbid(unsafe_code)]") {
            out.push(Violation {
                rule: "R15",
                file: p,
                line: 1,
                detail: format!("{kind} does not forbid unsafe"),
            });
        }
    }
}

/// Every file rustc compiles as its own crate, not only `src/lib.rs`.
///
/// `#![forbid(unsafe_code)]` is a crate-root attribute, so the one in a lib root
/// says nothing about that crate's `tests/`, `benches/`, `examples/`, or extra
/// binaries — each is a separate crate root, and the only `unsafe` in this tree
/// lives in exactly such a place. Checking two of the five forms is a rule that
/// reports the roots nobody writes unsafe in.
///
/// `tests/common/mod.rs` is a module of a test crate, not a root of its own, so
/// only files directly inside the directory count.
fn crate_root_kind(p: &str) -> Option<&'static str> {
    if p.ends_with("/src/lib.rs") {
        return Some("lib root");
    }
    if p.ends_with("/src/main.rs") {
        return Some("binary root");
    }
    for (dir, kind) in [
        ("/tests/", "integration-test root"),
        ("/benches/", "bench root"),
        ("/examples/", "example root"),
        ("/src/bin/", "binary root"),
    ] {
        if let Some(rest) = p.split(dir).nth(1)
            && !rest.contains('/')
        {
            return Some(kind);
        }
    }
    None
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if n != "target" && n != ".git" {
                collect(&p, out);
            }
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// Both passes over one file. Neither replaces the other.
fn scan(rel: &str, text: &str, out: &mut Vec<Violation>, cov: &mut Coverage) {
    token_pass(rel, text, out);
    match syn::parse_file(text) {
        Ok(file) => {
            // Aliases first: `type Bytes = Vec<u8>` must not hide a `Vec` from
            // R03, nor `type Flag = bool` a bool from R09. Same-crate only —
            // an alias declared in another crate needs resolved types and is
            // tier 2's, but that is no reason to leave the local case blind.
            let mut aliases = Aliases::default();
            aliases.visit_file(&file);
            let mut ast = Ast {
                rel,
                out: Vec::new(),
                macro_bodies: 0,
                aliases: aliases.0,
            };
            ast.visit_file(&file);
            cov.macro_bodies += ast.macro_bodies;
            out.append(&mut ast.out);
        }
        // A file the parser refused keeps its token findings and loses its item
        // findings. Silence here would read as a clean file.
        Err(_) => cov.unparsed.push(rel.to_string()),
    }
}

// ─── Pass one: tokens, per line ──────────────────────────────────────────────

/// The rules that must see inside macro bodies, where no parser reaches.
///
/// This pass is not a fallback for the item tree. It is the only pass that can
/// find `unsafe` written inside `macro_rules!` output or a `quote!` block, and
/// deleting it in favour of `syn` would drop those shapes silently.
fn token_pass(rel: &str, text: &str, out: &mut Vec<Violation>) {
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let t = raw.trim();
        // Literals first, then the comment. Stripping the comment first lets a
        // `//` inside a string truncate the line and hide whatever follows it.
        let blanked = strip_literals(t);
        let code = blanked.split("//").next().unwrap_or(&blanked).trim();

        if code.contains(".unwrap()") || code.contains(".expect(") || code.contains("panic!(") {
            push(out, "R04", rel, line, code);
        }
        if code.contains("todo!(") || code.contains("unimplemented!(") || code.contains("unreachable!(")
        {
            push(out, "R06", rel, line, code);
        }
        if code.contains("env::var") {
            push(out, "R07", rel, line, code);
        }
        if code.contains("Result<") && code.contains(", String>") {
            push(out, "R05", rel, line, code);
        }
        // Not test-exempt, and not scoped to two crates: `forbid(unsafe_code)`
        // in a lib root does not reach that crate's tests/ directory, which is
        // a separate crate root and exactly where unsafe sits unnoticed.
        // The bare keyword, anywhere on the line. Matching only `unsafe` at the
        // start of a line, or only the `fn`/`impl` forms, leaves the strongest
        // rule steppable by writing `let x = unsafe { *p };` — the shape most
        // likely to be reached for. `unsafe_code` is a different token and does
        // not match; R14 owns that one.
        if has_token(code, "unsafe") {
            push(out, "R13", rel, line, code);
        }
        if code.contains("allow(unsafe_code)") {
            push(out, "R14", rel, line, code);
        }
    }
}

/// `needle` present as a whole word: not a prefix, not a suffix, not part of a
/// longer identifier. `unsafe` matches in `unsafe {`, and does not in
/// `unsafe_code` or `not_unsafe`.
fn has_token(code: &str, needle: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(at) = code[from..].find(needle) {
        let at = from + at;
        let before_ok = at == 0 || !code[..at].chars().next_back().is_some_and(word);
        let after_ok = !code[at + needle.len()..].chars().next().is_some_and(word);
        if before_ok && after_ok {
            return true;
        }
        from = at + needle.len();
    }
    false
}

/// Blank the contents of string literals. A token inside a literal is data,
/// not a shape — this detector's own rule text would otherwise report the
/// detector.
fn strip_literals(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut in_str = false;
    let mut escape = false;
    for c in code.chars() {
        if in_str {
            if escape {
                escape = false;
                out.push(' ');
            } else if c == '\\' {
                escape = true;
                out.push(' ');
            } else if c == '"' {
                in_str = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if c == '"' {
            in_str = true;
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out
}

// ─── Pass two: the item tree ─────────────────────────────────────────────────

/// Walks every item, and applies the binding rules at every position a type can
/// appear — not only at a `name: Type` line.
struct Ast<'a> {
    rel: &'a str,
    out: Vec<Violation>,
    macro_bodies: usize,
    /// Same-crate `type X = Y` declarations, so a rule reads what a binding
    /// actually holds rather than the name someone gave it.
    aliases: BTreeMap<String, String>,
}

/// Collects `type X = Y` before the rules run.
///
/// A separate pass because an alias may be declared after its use, and a rule
/// that only resolves backwards is a rule you avoid by moving a line.
#[derive(Default)]
struct Aliases(BTreeMap<String, String>);

impl<'ast> Visit<'ast> for Aliases {
    fn visit_item_type(&mut self, i: &'ast syn::ItemType) {
        self.0.insert(i.ident.to_string(), tystr(&i.ty));
        syn::visit::visit_item_type(self, i);
    }
}

/// Where a type was written. Only `TupleNewtype` changes a verdict: it is the
/// one position where a bare primitive is the point rather than the defect.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Site {
    /// The single unnamed field of a one-field tuple struct — the newtype
    /// itself. R10 asks for a newtype; this is one.
    TupleNewtype,
    /// Every other position: named field, tuple element of a wider struct, enum
    /// variant payload, parameter, return, alias right-hand side, typed let.
    Other,
}

impl Ast<'_> {
    fn hit(&mut self, rule: &'static str, span: proc_macro2::Span, detail: &str) {
        self.out.push(Violation {
            rule,
            file: self.rel.to_string(),
            line: span.start().line,
            detail: detail.chars().take(100).collect(),
        });
    }

    /// Follow same-crate aliases to what the binding actually holds.
    ///
    /// Bounded, because a cycle (`type A = B; type B = A;`) does not compile
    /// but does reach this scanner — a detector that hangs on bad input is a
    /// detector that gets removed from the loop.
    fn resolve(&self, ty: &str) -> String {
        let mut seen = ty.to_string();
        for _ in 0..8 {
            match self.aliases.get(&seen) {
                Some(next) if *next != seen => seen = next.clone(),
                _ => break,
            }
        }
        seen
    }

    /// The rules that read one binding. Applied at every type position, which
    /// is the whole reason this pass exists.
    fn binding(
        &mut self,
        name: Option<&str>,
        ty: &syn::Type,
        is_pub: bool,
        derives_order: bool,
        site: Site,
        span: proc_macro2::Span,
    ) {
        let written = tystr(ty);
        // The rules read what the binding holds, not the name it was given.
        // `type Bytes = Vec<u8>` hid a `Vec` from R03 until this line existed.
        let t = self.resolve(&written);
        let shown = match name {
            Some(n) => format!("{n}: {written}"),
            None => written.clone(),
        };

        if is_pub {
            self.hit("R02", span, &shown);
            if t.starts_with("Vec<") || t.starts_with("HashMap") || t.starts_with("HashSet") {
                self.hit("R03", span, &shown);
            }
        }
        if let Some(n) = name {
            let lower = n.to_ascii_lowercase();
            if (t == "String" || t.starts_with("SmartString"))
                && matches!(lower.as_str(), "kind" | "status" | "type" | "name" | "state")
            {
                self.hit("R08", span, &shown);
            }
        }
        if t == "bool" {
            self.hit("R09", span, &shown);
        }
        // A one-field tuple struct IS the newtype R10 asks for. Every other
        // position holding a bare integer is the shape.
        if site != Site::TupleNewtype && is_bare_primitive(&t) {
            self.hit("R10", span, &shown);
        }
        if t.starts_with("RefCell")
            || t.starts_with("Cell<")
            || t.starts_with("Mutex")
            || t.starts_with("RwLock")
        {
            self.hit("R11", span, &shown);
        }
        if (t == "f32" || t == "f64") && derives_order {
            self.hit("R12", span, &shown);
        }
        // Reaches the nested position the line scanner never read: a `String`
        // error inside `Result<_, String>` written across two lines, or as a
        // parameter, or behind an alias.
        if t.contains("Result<") && t.ends_with(",String>") {
            self.hit("R05", span, &shown);
        }
    }

    fn fields(&mut self, fields: &syn::Fields, derives_order: bool) {
        let newtype = matches!(fields, syn::Fields::Unnamed(u) if u.unnamed.len() == 1);
        for f in fields.iter() {
            let site = if newtype && f.ident.is_none() {
                Site::TupleNewtype
            } else {
                Site::Other
            };
            self.binding(
                f.ident.as_ref().map(|i| i.to_string()).as_deref(),
                &f.ty,
                matches!(f.vis, syn::Visibility::Public(_)),
                derives_order,
                site,
                f.span(),
            );
        }
    }

    fn signature(&mut self, sig: &syn::Signature, is_pub: bool) {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(pt) = input {
                let name = match &*pt.pat {
                    syn::Pat::Ident(i) => Some(i.ident.to_string()),
                    _ => None,
                };
                // A parameter is not a field, so R02's `pub` clause must not
                // reach it: every parameter of a `pub fn` would fire.
                self.binding(name.as_deref(), &pt.ty, false, false, Site::Other, pt.span());
            }
        }
        if let syn::ReturnType::Type(_, ty) = &sig.output {
            let _ = is_pub;
            self.binding(None, ty, false, false, Site::Other, ty.span());
        }
    }
}

impl<'ast> Visit<'ast> for Ast<'_> {
    fn visit_item_struct(&mut self, i: &'ast syn::ItemStruct) {
        let ord = derives_order(&i.attrs);
        if ord && !states_order_law(&i.attrs) {
            self.hit("R01", i.ident.span(), &format!("{} derives an order", i.ident));
        }
        refusal_needs_span(self, &i.ident, i.fields.iter(), i.ident.span());
        self.fields(&i.fields, ord);
        syn::visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast syn::ItemEnum) {
        let ord = derives_order(&i.attrs);
        if ord && !states_order_law(&i.attrs) {
            self.hit("R01", i.ident.span(), &format!("{} derives an order", i.ident));
        }
        refusal_needs_span(
            self,
            &i.ident,
            i.variants.iter().flat_map(|v| v.fields.iter()),
            i.ident.span(),
        );
        for v in &i.variants {
            self.fields(&v.fields, ord);
        }
        syn::visit::visit_item_enum(self, i);
    }

    fn visit_item_union(&mut self, i: &'ast syn::ItemUnion) {
        let ord = derives_order(&i.attrs);
        if ord && !states_order_law(&i.attrs) {
            self.hit("R01", i.ident.span(), &format!("{} derives an order", i.ident));
        }
        for f in &i.fields.named {
            self.binding(
                f.ident.as_ref().map(|x| x.to_string()).as_deref(),
                &f.ty,
                matches!(f.vis, syn::Visibility::Public(_)),
                ord,
                Site::Other,
                f.span(),
            );
        }
        syn::visit::visit_item_union(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let self_ty = tystr(&i.self_ty);
        if let Some((_, path, _)) = &i.trait_ {
            let last = path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if matches!(last.as_str(), "Ord" | "PartialOrd" | "Hash")
                && !states_order_law(&i.attrs)
            {
                self.hit("R01", i.span(), &format!("impl {last} for {self_ty}"));
            }
        }
        // A public constructor that cannot refuse. `-> Self` or `-> TheType`
        // with no `Result`/`Option` wrapper means every caller-supplied value is
        // accepted, which is the second half of R02 and was never implemented.
        if i.trait_.is_none() {
            for item in &i.items {
                let syn::ImplItem::Fn(f) = item else { continue };
                if !matches!(f.vis, syn::Visibility::Public(_)) {
                    continue;
                }
                let syn::ReturnType::Type(_, ty) = &f.sig.output else {
                    continue;
                };
                let r = tystr(ty);
                if r == "Self" || r == self_ty {
                    self.hit(
                        "R02",
                        f.sig.ident.span(),
                        &format!("pub fn {}(..) -> {r}", f.sig.ident),
                    );
                }
            }
        }
        syn::visit::visit_item_impl(self, i);
    }

    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        self.signature(&i.sig, matches!(i.vis, syn::Visibility::Public(_)));
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        self.signature(&i.sig, matches!(i.vis, syn::Visibility::Public(_)));
        syn::visit::visit_impl_item_fn(self, i);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
        self.signature(&i.sig, true);
        syn::visit::visit_trait_item_fn(self, i);
    }

    fn visit_item_type(&mut self, i: &'ast syn::ItemType) {
        self.binding(
            Some(&i.ident.to_string()),
            &i.ty,
            false,
            false,
            Site::Other,
            i.span(),
        );
        syn::visit::visit_item_type(self, i);
    }

    fn visit_local(&mut self, i: &'ast syn::Local) {
        if let syn::Pat::Type(pt) = &i.pat {
            let name = match &*pt.pat {
                syn::Pat::Ident(id) => Some(id.ident.to_string()),
                _ => None,
            };
            self.binding(name.as_deref(), &pt.ty, false, false, Site::Other, i.span());
        }
        syn::visit::visit_local(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        let m = i.method.to_string();
        if m == "unwrap" || m == "expect" {
            self.hit("R04", i.method.span(), &format!(".{m}(..)"));
        }
        syn::visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_path(&mut self, i: &'ast syn::ExprPath) {
        // `env::var` and `std::env::var` resolve to the same call. The token
        // pass matches the written text; this catches the path shape wherever
        // the item tree carries it.
        let p: Vec<String> = i.path.segments.iter().map(|s| s.ident.to_string()).collect();
        if p.len() >= 2 && p[p.len() - 2] == "env" && p[p.len() - 1] == "var" {
            self.hit("R07", i.span(), &p.join("::"));
        }
        syn::visit::visit_expr_path(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let name = i
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        match name.as_str() {
            "panic" => self.hit("R04", i.span(), "panic!"),
            "todo" | "unimplemented" | "unreachable" => self.hit("R06", i.span(), &format!("{name}!")),
            _ => {}
        }
        // Every macro body is tokens this walker does not expand. Counted, and
        // printed with the findings, because a parser that skips a construct in
        // silence is reporting a tree it never read.
        if !i.tokens.is_empty() {
            self.macro_bodies += 1;
        }
        syn::visit::visit_macro(self, i);
    }
}

/// A refusal must carry the position of what it refused. A refusal without a
/// span is an error message; the caller cannot point at anything.
fn refusal_needs_span<'a>(
    ast: &mut Ast<'_>,
    ident: &syn::Ident,
    fields: impl Iterator<Item = &'a syn::Field>,
    span: proc_macro2::Span,
) {
    let n = ident.to_string();
    let is_refusal = n.ends_with("Refusal")
        || n.ends_with("Refuse")
        || n.ends_with("Error")
        || n.ends_with("Denial");
    if !is_refusal {
        return;
    }
    let carries = fields.map(|f| tystr(&f.ty)).any(|t| {
        t.contains("Span") || t.contains("SourceSpan") || t.contains("Offset")
    });
    if !carries {
        ast.hit("R05", span, &format!("{n} carries no span"));
    }
}

/// The type as written, with whitespace removed so `Vec < u8 >` and `Vec<u8>`
/// compare equal.
fn tystr(ty: &syn::Type) -> String {
    ty.to_token_stream()
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

fn is_bare_primitive(t: &str) -> bool {
    matches!(
        t,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn derives_order(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("derive") {
            return false;
        }
        let s = a.to_token_stream().to_string();
        s.contains("Ord") || s.contains("PartialOrd") || s.contains("Hash")
    })
}

/// The law must be on the type, not merely somewhere in the file.
///
/// The previous rule asked `text.contains("ORDER_LAW")`, so one comment
/// anywhere in a three-thousand-line file satisfied every type in it. That is a
/// password, not a check.
fn states_order_law(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .any(|a| a.to_token_stream().to_string().contains("ORDER_LAW"))
}

fn push(out: &mut Vec<Violation>, rule: &'static str, file: &str, line: usize, detail: &str) {
    out.push(Violation {
        rule,
        file: file.to_string(),
        line,
        detail: detail.chars().take(100).collect(),
    });
}

// ─── Reporting ───────────────────────────────────────────────────────────────

fn coverage_lines(cov: &Coverage) {
    println!(
        "unscanned: {} macro bodies, {} file(s) the parser refused",
        cov.macro_bodies,
        cov.unparsed.len()
    );
    for f in cov.unparsed.iter().take(10) {
        println!("  unparsed: {f}");
    }
}

/// One path, reported and nothing more: no verdict is written.
fn report_aim(files: &[PathBuf], violations: &[Violation], cov: &Coverage) {
    for v in violations {
        println!("{}:{}: {} {}", v.file, v.line, v.rule, v.detail);
    }
    println!(
        "{} forbidden shapes in {} file(s)",
        violations.len(),
        files.len()
    );
    coverage_lines(cov);
    if !violations.is_empty() {
        std::process::exit(1);
    }
}

fn report_gate(_root: &Path, files: &[PathBuf], violations: &[Violation], cov: &Coverage) {
    let mut per_rule = BTreeMap::new();
    for v in violations {
        *per_rule.entry(v.rule).or_insert(0usize) += 1;
    }
    let total = violations.len();
    let touched: BTreeSet<&str> = violations.iter().map(|v| v.file.as_str()).collect();

    println!("bs-detector — forbidden shapes, {} files scanned", files.len());
    for (rule, desc) in RULES {
        let n = per_rule.get(rule).copied().unwrap_or(0);
        println!("{rule}  {n:>6}  {desc}");
    }

    // Per-tree subtotals. `vendor/` is large enough to hide movement in the
    // engine if only one number is printed, and a number that cannot show
    // movement is not a signal.
    let mut per_tree: BTreeMap<&str, usize> = BTreeMap::new();
    for v in violations {
        let top = v.file.split('/').next().unwrap_or(".");
        *per_tree.entry(top).or_insert(0) += 1;
    }
    println!("— by tree —");
    for (tree, n) in &per_tree {
        println!("{n:>8}  {tree}");
    }

    for v in violations.iter().take(40) {
        println!("{}:{}: {} {}", v.file, v.line, v.rule, v.detail);
    }
    if total > 40 {
        println!("… {} more", total - 40);
    }
    coverage_lines(cov);
    // The line the gate caller parses. Exactly one line may carry this shape.
    println!("total = {total} violations across {} files", touched.len());

    if total > 0 {
        std::process::exit(1);
    }
}

/// The rules, proven against fixtures that hold the shapes on purpose.
///
/// The fixtures are `.rsfix`, not `.rs`: not compiled, and invisible to the
/// walker. A detector whose own corpus needed an exemption would have proven
/// the exemption, not the rule.
#[cfg(test)]
mod law {
    use super::*;

    fn fire(name: &str, text: &str) -> BTreeSet<(&'static str, usize)> {
        let mut out = Vec::new();
        let mut cov = Coverage::default();
        scan(name, text, &mut out, &mut cov);
        out.iter().map(|v| (v.rule, v.line)).collect()
    }

    /// Every rule, at the line that carries its shape.
    #[test]
    fn every_rule_fires_on_its_shape() {
        let got = fire(
            "forbidden.rsfix",
            include_str!("../fixtures/forbidden.rsfix"),
        );

        let want: &[(&str, usize)] = &[
            ("R01", 18), // derives Ord, no ORDER_LAW on the type
            ("R02", 19), // pub field on a tuple newtype
            ("R02", 21), // pub field in a struct body
            ("R03", 21), // bare Vec as a pub field
            ("R08", 22), // String-typed `kind`
            ("R09", 23), // bool field
            ("R10", 24), // bare usize field
            ("R11", 25), // RefCell field
            ("R09", 27), // bool in a single-line struct body
            ("R10", 27), // bare u64 in a single-line struct body
            ("R02", 28), // pub tuple element of a struct wider than one field
            ("R09", 28), // bool as an unnamed tuple element
            ("R10", 28), // bare u8 as a tuple element — not a newtype, two fields
            ("R10", 29), // bare u64 in an enum variant payload
            ("R09", 30), // bool as a type alias right-hand side
            ("R05", 31), // a refusal carrying no span
            ("R02", 34), // a public constructor that cannot refuse
            ("R05", 37), // Result<_, String>
            ("R09", 38), // bool parameter
            ("R10", 38), // usize parameter and u32 return
            ("R04", 41), // unwrap
            ("R04", 42), // expect
            ("R04", 43), // panic!
            ("R06", 44), // todo!
            ("R06", 45), // unimplemented!
            ("R06", 46), // unreachable!
            ("R07", 47), // env::var
            ("R13", 48), // unsafe block
            ("R13", 51), // unsafe fn
            ("R13", 52), // unsafe impl
            ("R14", 53), // allow(unsafe_code)
        ];
        let missed: Vec<_> = want.iter().filter(|w| !got.contains(*w)).collect();
        assert!(missed.is_empty(), "rules did not fire: {missed:?}");
    }

    /// The fixture must parse, or the item-tree pass is skipped on it and every
    /// rule above that needs the tree is unproven while the suite reads green.
    /// That was the state of this crate before the rewrite.
    #[test]
    fn the_fixture_parses() {
        let mut out = Vec::new();
        let mut cov = Coverage::default();
        scan(
            "forbidden.rsfix",
            include_str!("../fixtures/forbidden.rsfix"),
            &mut out,
            &mut cov,
        );
        assert!(
            cov.unparsed.is_empty(),
            "the fixture does not parse, so the item rules are unproven: {:?}",
            cov.unparsed
        );
    }

    /// R12 fires only where an order is derived, so it needs its own fixture.
    #[test]
    fn float_under_a_derived_order_fires() {
        let got = fire(
            "ordered_float.rsfix",
            include_str!("../fixtures/ordered_float.rsfix"),
        );
        assert!(got.contains(&("R12", 8)), "R12 did not fire: {got:?}");
        assert!(
            !got.iter().any(|(r, _)| *r == "R01"),
            "R01 fired on a type that states its law in its own doc: {got:?}"
        );
    }

    /// The law binds the type, not the file. A doc comment on one type must not
    /// clear a second type that states nothing — the hole the previous rule had.
    #[test]
    fn an_order_law_on_one_type_does_not_clear_another() {
        let text = "\
/// ORDER_LAW: `a <= b <=> encode(a) <=lex encode(b)`.
#[derive(PartialOrd, Ord)]
pub struct Stated(u8);

#[derive(PartialOrd, Ord)]
pub struct Silent(u8);
";
        let got = fire("t.rs", text);
        assert!(
            !got.iter().any(|(r, l)| *r == "R01" && *l == 3),
            "R01 fired on the type that states its law: {got:?}"
        );
        assert!(
            got.contains(&("R01", 6)),
            "a law on one type cleared another: {got:?}"
        );
    }

    /// A module-level comment is not a law. This is the exact shape that
    /// cleared ten types in one file before the rewrite.
    #[test]
    fn a_module_doc_does_not_state_a_types_law() {
        let text = "\
//! ORDER_LAW: identity over canonical bytes.

#[derive(Hash)]
pub struct Borrowed(u8);
";
        let got = fire("t.rs", text);
        assert!(
            got.contains(&("R01", 4)),
            "a module doc satisfied a type's law: {got:?}"
        );
    }

    /// The positions the line scanner could not read. Every one of these is a
    /// shape the tree carried while the old walker reported nothing.
    #[test]
    fn shapes_outside_a_name_colon_type_line_fire() {
        let text = "\
pub struct Wide(pub u8, bool);
pub enum E { V(u64, f32) }
pub fn f(count: usize, flag: bool) -> u32 { 0 }
type Alias = bool;
";
        let got = fire("t.rs", text);
        // tuple element of a struct wider than one field — not a newtype
        assert!(got.contains(&("R10", 1)), "tuple element missed: {got:?}");
        assert!(got.contains(&("R09", 1)), "tuple bool missed: {got:?}");
        // enum variant payload
        assert!(got.contains(&("R10", 2)), "variant payload missed: {got:?}");
        // parameters and return
        assert!(got.contains(&("R10", 3)), "fn param/return missed: {got:?}");
        assert!(got.contains(&("R09", 3)), "bool param missed: {got:?}");
        // alias right-hand side
        assert!(got.contains(&("R09", 4)), "alias RHS missed: {got:?}");
    }

    /// A one-field tuple struct is the newtype R10 asks for. Firing on it would
    /// make the rule demand a newtype around a newtype.
    #[test]
    fn a_newtype_is_not_a_bare_primitive() {
        let got = fire("t.rs", "pub struct Micros(i64);\n");
        assert!(
            !got.iter().any(|(r, _)| *r == "R10"),
            "R10 fired on the newtype itself: {got:?}"
        );
    }

    /// Every form of crate root, not only the two that are easy to match.
    #[test]
    fn every_crate_root_form_is_a_root() {
        for p in [
            "crates/k/src/lib.rs",
            "crates/k/src/main.rs",
            "crates/k/src/bin/tool.rs",
            "crates/k/tests/admit.rs",
            "crates/k/benches/encode.rs",
            "crates/k/examples/demo.rs",
        ] {
            assert!(crate_root_kind(p).is_some(), "{p} was not read as a root");
        }
    }

    /// A file inside a test crate is not a root of its own, and neither is
    /// ordinary source that happens to sit under `src/`.
    #[test]
    fn a_module_is_not_a_crate_root() {
        for p in [
            "crates/k/tests/common/mod.rs",
            "crates/k/src/store/replica.rs",
            "crates/k/src/bin/tool/helper.rs",
        ] {
            assert!(crate_root_kind(p).is_none(), "{p} was read as a root");
        }
    }

    /// A same-crate alias does not hide what a binding holds. Without this,
    /// renaming a type in one line is a working suppression mechanism — the
    /// count drops and nothing was fixed.
    #[test]
    fn an_alias_does_not_hide_the_type_it_names() {
        let text = "\
type Bytes = Vec<u8>;
type Flag = bool;
type Count = usize;
pub struct S { pub b: Bytes, f: Flag, n: Count }
";
        let got = fire("t.rs", text);
        assert!(got.contains(&("R03", 4)), "alias hid a Vec from R03: {got:?}");
        assert!(got.contains(&("R09", 4)), "alias hid a bool from R09: {got:?}");
        assert!(got.contains(&("R10", 4)), "alias hid a usize from R10: {got:?}");
    }

    /// Declaration order must not matter. A rule that only resolves backwards
    /// is a rule you avoid by moving a line.
    #[test]
    fn an_alias_declared_after_its_use_still_resolves() {
        let got = fire("t.rs", "pub struct S { f: Flag }\ntype Flag = bool;\n");
        assert!(got.contains(&("R09", 1)), "forward alias not resolved: {got:?}");
    }

    /// `type A = B; type B = A;` does not compile, but it reaches this scanner.
    /// A detector that hangs on bad input is a detector nobody runs.
    #[test]
    fn an_alias_cycle_terminates() {
        let got = fire("t.rs", "type A = B;\ntype B = A;\npub struct S { f: A }\n");
        let _ = got;
    }

    /// A refusal that cannot point at what it refused.
    #[test]
    fn a_refusal_without_a_span_fires() {
        let text = "\
pub enum ParseRefuse { Empty, TooLong }
pub enum GoodRefuse { Empty(Span) }
";
        let got = fire("t.rs", text);
        assert!(got.contains(&("R05", 1)), "spanless refusal missed: {got:?}");
        assert!(
            !got.iter().any(|(r, l)| *r == "R05" && *l == 2),
            "R05 fired on a refusal that carries a span: {got:?}"
        );
    }

    /// A public constructor that accepts anything.
    #[test]
    fn a_public_constructor_that_cannot_refuse_fires() {
        let text = "\
impl Thing {
    pub fn new(v: Vec<u8>) -> Self { Self(v) }
    pub fn parse(v: Vec<u8>) -> Result<Self, Refuse> { Err(Refuse) }
}
";
        let got = fire("t.rs", text);
        assert!(got.contains(&("R02", 2)), "unchecked ctor missed: {got:?}");
        assert!(
            !got.iter().any(|(r, l)| *r == "R02" && *l == 3),
            "R02 fired on a constructor that can refuse: {got:?}"
        );
    }

    /// A shape inside a string literal is data, and a `//` inside a string
    /// must not truncate the line and hide what follows it.
    #[test]
    fn literals_are_data_and_do_not_truncate() {
        let mut out = Vec::new();
        token_pass("t.rs", "let s = \"unsafe fn f\";\n", &mut out);
        assert!(out.is_empty(), "shape inside a literal reported: {out:?}");

        let mut out = Vec::new();
        token_pass("t.rs", "let u = \"http://x\"; unsafe { }\n", &mut out);
        assert!(
            out.iter().any(|v| v.rule == "R13"),
            "a `//` inside a literal hid the shape after it: {out:?}"
        );
    }

    /// The token pass is not redundant with the parser: `syn` never expands a
    /// macro body, so deleting it would drop every shape written inside one.
    #[test]
    fn a_shape_inside_a_macro_body_still_fires() {
        let text = "macro_rules! m { () => { unsafe { } } }\n";
        let got = fire("t.rs", text);
        assert!(
            got.contains(&("R13", 1)),
            "unsafe inside a macro body was not reported: {got:?}"
        );
    }

    /// There is no exemption. The former marker must not be honoured by any
    /// path — this test is the thing that fails if one is reintroduced.
    #[test]
    fn no_marker_suppresses_a_shape() {
        for marker in [
            "// BS-EXEMPT: R13 — signed for",
            "#[expect(unsafe_code, reason = \"signed for\")]",
            "#[allow(unsafe_code)]",
            "// SAFETY: reviewed",
        ] {
            let text = format!("{marker}\nunsafe fn f() {{}}\n");
            let got = fire("t.rs", &text);
            assert!(
                got.contains(&("R13", 2)),
                "`{marker}` suppressed R13: {got:?}"
            );
        }
    }

    /// A file the parser refuses is recorded, not passed over in silence.
    #[test]
    fn an_unparsable_file_is_reported_as_unscanned() {
        let mut out = Vec::new();
        let mut cov = Coverage::default();
        scan("bad.rs", "pub struct {{{ not rust\n", &mut out, &mut cov);
        assert_eq!(cov.unparsed.len(), 1, "unparsable file not recorded");
    }

    /// Every rule in the table is one the scanner can actually produce. A rule
    /// that only exists as a row is a claim the tree is not being held to.
    #[test]
    fn every_listed_rule_is_reachable() {
        let mut fired: BTreeSet<&str> = BTreeSet::new();
        for (n, t) in [
            ("f.rsfix", include_str!("../fixtures/forbidden.rsfix")),
            ("o.rsfix", include_str!("../fixtures/ordered_float.rsfix")),
        ] {
            fired.extend(fire(n, t).iter().map(|(r, _)| *r));
        }
        // R15 is absence — no line carries it — so it is decided over the file
        // list in `check_forbid_unsafe`, not by `scan`, and no fixture can
        // trigger it here.
        let dead: Vec<&str> = RULES
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| *id != "R15" && !fired.contains(id))
            .collect();
        assert!(dead.is_empty(), "rules no fixture can trigger: {dead:?}");
    }
}
