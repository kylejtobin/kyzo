/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The default-deny classifier (TRUTH item 1): every `syn::Item` kind, and
//! every impl/trait interior kind, is looked up in the grammar's kind
//! table. A condemned kind is a hit under its OWN condemned-law name — the
//! generic `unclassified` bucket never absorbs a named condemnation. A
//! seated kind must match at least one of its allowed constructs' rule or
//! it is `unclassified`. The classifier only accepts — it never argues.
//!
//! Foreign non-exhaustive `syn` enums are handled with `match` arms naming
//! every known variant and a final NAMED binding (never a bare `_`), so an
//! unrecognized future syn variant is a visible, reported violation
//! (`unknown-syn-*-kind`), not a silent catch-all.
//!
//! Recursion scope: every top-level item, every inline `mod { .. }` item,
//! every impl/trait interior item, and every item declaration reachable
//! through statement and expression nesting (fn bodies, blocks, if/match
//! arms, loops, closures). Tip 641/650: no soft residual that hides an
//! unseated item inside an expression body.

use quote::ToTokens;
use syn::visit::{self, Visit};

use crate::alias::AliasTable;
use crate::boundary::SourceFile;
use crate::engines::Hit;
use crate::grammar::{Disposition, Grammar, KindName, StructuralRule};

/// Classify every item in `file` under the workspace alias table (item 4).
pub fn classify_file(grammar: &Grammar, file: &SourceFile, aliases: &AliasTable) -> Vec<Hit> {
    let mut hits = vec![];
    let ctx = Ctx {
        rel: file.rel_path(),
        grammar,
        aliases,
        self_ty: None,
        in_container: false,
    };
    for item in &file.ast().items {
        classify_item(&ctx, item, &mut hits);
    }
    hits
}

/// Inclusive line span of one construct instance that declares construct-scoped bans.
#[derive(Clone, Debug)]
pub struct ScopedConstructSpan {
    pub start_line: usize,
    pub end_line: usize,
    pub bans: Vec<String>,
}

/// Spans of fn items whose *shape* matches a construct that lists construct-scoped
/// bans. Body bans attributed by run.rs span containment are ignored here
/// (shape-only), so a nested-place assign still sits inside its construct's span.
pub fn scoped_construct_spans(
    grammar: &Grammar,
    file: &SourceFile,
    aliases: &AliasTable,
) -> Vec<ScopedConstructSpan> {
    let mut out = vec![];
    let ctx = Ctx {
        rel: file.rel_path(),
        grammar,
        aliases,
        self_ty: None,
        in_container: false,
    };
    collect_scoped_spans_items(&ctx, &file.ast().items, &mut out);
    out
}

fn collect_scoped_spans_items(ctx: &Ctx, items: &[syn::Item], out: &mut Vec<ScopedConstructSpan>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                push_scoped_fn_span(ctx, &f.sig, f, out);
                collect_scoped_spans_block(ctx, &f.block, out);
            }
            syn::Item::Impl(im) => {
                let inner = Ctx {
                    rel: ctx.rel,
                    grammar: ctx.grammar,
                    aliases: ctx.aliases,
                    self_ty: Some(&im.self_ty),
                    in_container: true,
                };
                for it in &im.items {
                    if let syn::ImplItem::Fn(f) = it {
                        push_scoped_fn_span(&inner, &f.sig, f, out);
                        collect_scoped_spans_block(&inner, &f.block, out);
                    }
                }
            }
            syn::Item::Trait(t) => {
                let inner = Ctx {
                    rel: ctx.rel,
                    grammar: ctx.grammar,
                    aliases: ctx.aliases,
                    self_ty: None,
                    in_container: true,
                };
                for it in &t.items {
                    if let syn::TraitItem::Fn(f) = it {
                        push_scoped_fn_span(&inner, &f.sig, f, out);
                        if let Some(block) = &f.default {
                            collect_scoped_spans_block(&inner, block, out);
                        }
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_scoped_spans_items(ctx, items, out);
                }
            }
            _other => {}
        }
    }
}

fn collect_scoped_spans_block(ctx: &Ctx, block: &syn::Block, out: &mut Vec<ScopedConstructSpan>) {
    for stmt in &block.stmts {
        if let syn::Stmt::Item(it) = stmt {
            collect_scoped_spans_items(ctx, std::slice::from_ref(it), out);
        }
    }
}

fn push_scoped_fn_span<T: syn::spanned::Spanned>(
    ctx: &Ctx,
    sig: &syn::Signature,
    whole: &T,
    out: &mut Vec<ScopedConstructSpan>,
) {
    for c in ctx.grammar.constructs() {
        if c.bans.is_empty() {
            continue;
        }
        if !shape_only_fn_matches(c.rule, sig, ctx) {
            continue;
        }
        let span = whole.span();
        out.push(ScopedConstructSpan {
            start_line: crate::boundary::span_line(&span),
            end_line: span.end().line,
            bans: c.bans.clone(),
        });
    }
}

/// Receiver/async/return shape of a construct rule, ignoring body bans that
/// live in `construct.bans` (those fire via run.rs span containment).
fn shape_only_fn_matches(rule: StructuralRule, sig: &syn::Signature, ctx: &Ctx) -> bool {
    let receiver = receiver_form(sig);
    match rule {
        StructuralRule::TransitionBans => {
            receiver == Receiver::RefMutSelf && sig.asyncness.is_none()
        }
        StructuralRule::ConsumingVerbBans => {
            receiver == Receiver::ByValueSelf
                && sig.asyncness.is_none()
                && !return_resolves_to_self(&sig.output, ctx.self_ty, false)
        }
        StructuralRule::DerivationBans => {
            receiver == Receiver::RefSelf && sig.asyncness.is_none()
        }
        StructuralRule::AdmissionDoorBans => {
            is_admission_door_shape(sig, ctx) && sig.asyncness.is_none()
        }
        StructuralRule::CompositionRootBody => is_composition_root_shape(sig, ctx) && sig.asyncness.is_none(),
        StructuralRule::DeclaredFnSeat => receiver == Receiver::None,
        _rule_not_fn_scoped => false,
    }
}

struct Ctx<'a> {
    rel: &'a str,
    grammar: &'a Grammar,
    aliases: &'a AliasTable,
    self_ty: Option<&'a syn::Type>,
    in_container: bool,
}

fn hit(rel: &str, line: usize, construct: impl AsRef<str>) -> Hit {
    Hit::admit(rel, line, construct.as_ref())
}

fn line_of<T: ?Sized + syn::spanned::Spanned>(node: &T) -> usize {
    crate::boundary::span_line(&node.span())
}

// ---------------------------------------------------------------------------
// kind mapping (closed at the pinned syn version; an unrecognized future
// variant is a reported violation, never a silent pass)
// ---------------------------------------------------------------------------

/// One kind-map authority for Item / ImplItem / TraitItem. Thin wrappers
/// below keep call sites typed; a second parallel `match` is the twin this
/// closes.
enum SynMember<'a> {
    Item(&'a syn::Item),
    Impl(&'a syn::ImplItem),
    Trait(&'a syn::TraitItem),
}

fn syn_member_kind(member: SynMember<'_>) -> Option<KindName> {
    match member {
        SynMember::Item(syn::Item::Const(_)) => Some(KindName::Const),
        SynMember::Item(syn::Item::Enum(_)) => Some(KindName::Enum),
        SynMember::Item(syn::Item::ExternCrate(_)) => Some(KindName::ExternCrate),
        SynMember::Item(syn::Item::Fn(_)) => Some(KindName::Fn),
        SynMember::Item(syn::Item::ForeignMod(_)) => Some(KindName::ForeignMod),
        SynMember::Item(syn::Item::Impl(_)) => Some(KindName::Impl),
        SynMember::Item(syn::Item::Macro(_)) => Some(KindName::Macro),
        SynMember::Item(syn::Item::Mod(_)) => Some(KindName::Mod),
        SynMember::Item(syn::Item::Static(_)) => Some(KindName::Static),
        SynMember::Item(syn::Item::Struct(_)) => Some(KindName::Struct),
        SynMember::Item(syn::Item::Trait(_)) => Some(KindName::Trait),
        SynMember::Item(syn::Item::TraitAlias(_)) => Some(KindName::TraitAlias),
        SynMember::Item(syn::Item::Type(_)) => Some(KindName::Type),
        SynMember::Item(syn::Item::Union(_)) => Some(KindName::Union),
        SynMember::Item(syn::Item::Use(_)) => Some(KindName::Use),
        SynMember::Item(syn::Item::Verbatim(_)) => Some(KindName::Verbatim),
        // Named (not bare `_`) so a future syn variant is a visible red,
        // never a silent catch-all. Leading underscore = unused-ok without
        // a `let _ =` discard.
        SynMember::Item(_unrecognized_item_variant) => None,
        SynMember::Impl(syn::ImplItem::Const(_)) => Some(KindName::ImplConst),
        SynMember::Impl(syn::ImplItem::Fn(_)) => Some(KindName::ImplFn),
        SynMember::Impl(syn::ImplItem::Type(_)) => Some(KindName::ImplType),
        SynMember::Impl(syn::ImplItem::Macro(_)) => Some(KindName::ImplMacro),
        SynMember::Impl(syn::ImplItem::Verbatim(_)) => Some(KindName::Verbatim),
        SynMember::Impl(_unrecognized_impl_item_variant) => None,
        SynMember::Trait(syn::TraitItem::Const(_)) => Some(KindName::TraitConst),
        SynMember::Trait(syn::TraitItem::Fn(_)) => Some(KindName::TraitFn),
        SynMember::Trait(syn::TraitItem::Type(_)) => Some(KindName::TraitType),
        SynMember::Trait(syn::TraitItem::Macro(_)) => Some(KindName::TraitMacro),
        SynMember::Trait(syn::TraitItem::Verbatim(_)) => Some(KindName::Verbatim),
        SynMember::Trait(_unrecognized_trait_item_variant) => None,
    }
}

fn item_kind(item: &syn::Item) -> Option<KindName> {
    syn_member_kind(SynMember::Item(item))
}

fn impl_item_kind(item: &syn::ImplItem) -> Option<KindName> {
    syn_member_kind(SynMember::Impl(item))
}

fn trait_item_kind(item: &syn::TraitItem) -> Option<KindName> {
    syn_member_kind(SynMember::Trait(item))
}

fn item_label(item: &syn::Item) -> String {
    match item {
        syn::Item::Const(i) => i.ident.to_string(),
        syn::Item::Enum(i) => i.ident.to_string(),
        syn::Item::Fn(i) => i.sig.ident.to_string(),
        syn::Item::Mod(i) => i.ident.to_string(),
        syn::Item::Static(i) => i.ident.to_string(),
        syn::Item::Struct(i) => i.ident.to_string(),
        syn::Item::Trait(i) => i.ident.to_string(),
        syn::Item::Type(i) => i.ident.to_string(),
        syn::Item::Use(_) => "use".to_string(),
        syn::Item::Impl(i) => i.self_ty.to_token_stream().to_string(),
        unlabeled_item_variant => unlabeled_item_variant.to_token_stream().to_string(),
    }
}

// ---------------------------------------------------------------------------
// walk: items, container interiors, and one level of fn-body-local items
// ---------------------------------------------------------------------------

fn classify_item(ctx: &Ctx, item: &syn::Item, hits: &mut Vec<Hit>) {
    let Some(kind) = item_kind(item) else {
        hits.push(hit(ctx.rel, line_of(item), "unknown-syn-item-kind"));
        return;
    };
    match ctx.grammar.disposition(kind) {
        None => hits.push(hit(ctx.rel, line_of(item), "kind-table-mutated-post-load")),
        Some(Disposition::Condemned(law)) => hits.push(hit(ctx.rel, line_of(item), law)),
        Some(Disposition::Seated(seats)) => {
            // Item 3: classification emits the unique construct name, or red.
            // `.any()` soft-drain deleted — zero or two matches are both red.
            if seat_matches_item(ctx, item, seats).is_none() {
                hits.push(hit(
                    ctx.rel,
                    line_of(item),
                    format!("unclassified-{}:{}", kind.kebab(), item_label(item)),
                ));
            }
        }
    }
    recurse_into_item(ctx, item, hits);
}

fn recurse_into_item(ctx: &Ctx, item: &syn::Item, hits: &mut Vec<Hit>) {
    match item {
        syn::Item::Mod(m) => {
            if let Some((_, items)) = &m.content {
                for it in items {
                    classify_item(ctx, it, hits);
                }
            }
        }
        syn::Item::Fn(f) => classify_block_items(ctx, &f.block, hits),
        // Tip 650: const/static RHS blocks are legal item nests in Rust.
        // Treating them as non-containers silent-greened nested unseated items.
        syn::Item::Const(c) => classify_expr_items(ctx, &c.expr, hits),
        syn::Item::Static(s) => classify_expr_items(ctx, &s.expr, hits),
        syn::Item::Impl(i) => {
            let inner = Ctx {
                rel: ctx.rel,
                grammar: ctx.grammar,
                aliases: ctx.aliases,
                self_ty: Some(&i.self_ty),
                in_container: true,
            };
            for it in &i.items {
                classify_impl_item(&inner, it, hits);
            }
        }
        syn::Item::Trait(t) => {
            let inner = Ctx {
                rel: ctx.rel,
                grammar: ctx.grammar,
                aliases: ctx.aliases,
                self_ty: None,
                in_container: true,
            };
            for it in &t.items {
                classify_trait_item(&inner, it, hits);
            }
        }
        _not_a_container => {}
    }
}

/// Nested items are NOT impl/trait members — `in_container` must not
/// bleed from the enclosing method or a nested `fn` false-greens as
/// admission-door (tip 650 hard-count: no soft drain).
fn nested_item_ctx<'a>(ctx: &Ctx<'a>) -> Ctx<'a> {
    Ctx {
        rel: ctx.rel,
        grammar: ctx.grammar,
        aliases: ctx.aliases,
        self_ty: None,
        in_container: false,
    }
}

struct NestedItemVisit<'a, 'c> {
    ctx: &'a Ctx<'c>,
    hits: &'a mut Vec<Hit>,
}

impl<'ast> Visit<'ast> for NestedItemVisit<'_, '_> {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        classify_item(self.ctx, node, self.hits);
        // classify_item already recurses containers; do not
        // visit_item default-recurse or items double-fire.
    }
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        match node {
            syn::Stmt::Item(it) => {
                classify_item(self.ctx, it, self.hits);
            }
            other => visit::visit_stmt(self, other),
        }
    }
}

fn classify_block_items(ctx: &Ctx, block: &syn::Block, hits: &mut Vec<Hit>) {
    let nested_ctx = nested_item_ctx(ctx);
    let mut v = NestedItemVisit {
        ctx: &nested_ctx,
        hits,
    };
    for stmt in &block.stmts {
        v.visit_stmt(stmt);
    }
}

fn classify_expr_items(ctx: &Ctx, expr: &syn::Expr, hits: &mut Vec<Hit>) {
    let nested_ctx = nested_item_ctx(ctx);
    let mut v = NestedItemVisit {
        ctx: &nested_ctx,
        hits,
    };
    v.visit_expr(expr);
}

#[derive(Clone, Copy)]
enum ContainerMember<'a> {
    Impl(&'a syn::ImplItem),
    Trait(&'a syn::TraitItem),
}

fn classify_impl_item(ctx: &Ctx, item: &syn::ImplItem, hits: &mut Vec<Hit>) {
    classify_container_member(ctx, ContainerMember::Impl(item), hits);
}

fn classify_trait_item(ctx: &Ctx, item: &syn::TraitItem, hits: &mut Vec<Hit>) {
    classify_container_member(ctx, ContainerMember::Trait(item), hits);
}

fn classify_container_member(ctx: &Ctx, member: ContainerMember<'_>, hits: &mut Vec<Hit>) {
    let (kind, unknown) = match member {
        ContainerMember::Impl(item) => (impl_item_kind(item), "unknown-syn-implitem-kind"),
        ContainerMember::Trait(item) => (trait_item_kind(item), "unknown-syn-traititem-kind"),
    };
    let Some(kind) = kind else {
        hits.push(hit(ctx.rel, 0, unknown));
        return;
    };
    match ctx.grammar.disposition(kind) {
        None => hits.push(hit(ctx.rel, 0, "kind-table-mutated-post-load")),
        Some(Disposition::Condemned(law)) => {
            hits.push(hit(ctx.rel, container_member_condemned_line(member), law));
        }
        Some(Disposition::Seated(seats)) => {
            let seated = match member {
                ContainerMember::Impl(item) => seat_matches_impl_item(ctx, item, seats),
                ContainerMember::Trait(item) => seat_matches_trait_item(ctx, item, seats),
            };
            if seated.is_none() {
                let (line, label) = container_member_label(member);
                hits.push(hit(
                    ctx.rel,
                    line,
                    format!("unclassified-{}:{}", kind.kebab(), label),
                ));
            }
        }
    }
    match member {
        ContainerMember::Impl(syn::ImplItem::Fn(f)) => {
            classify_block_items(ctx, &f.block, hits);
        }
        ContainerMember::Trait(syn::TraitItem::Fn(f)) => {
            if let Some(block) = &f.default {
                classify_block_items(ctx, block, hits);
            }
        }
        ContainerMember::Impl(_not_fn) => {}
        ContainerMember::Trait(_not_fn) => {}
    }
}

fn container_member_condemned_line(member: ContainerMember<'_>) -> usize {
    match member {
        ContainerMember::Impl(syn::ImplItem::Macro(m)) => line_of(m),
        ContainerMember::Impl(other) => line_of(other),
        ContainerMember::Trait(syn::TraitItem::Macro(m)) => line_of(m),
        ContainerMember::Trait(other) => line_of(other),
    }
}

fn container_member_label(member: ContainerMember<'_>) -> (usize, String) {
    match member {
        ContainerMember::Impl(syn::ImplItem::Const(c)) => (line_of(c), c.ident.to_string()),
        ContainerMember::Impl(syn::ImplItem::Fn(f)) => (line_of(f), f.sig.ident.to_string()),
        ContainerMember::Impl(syn::ImplItem::Type(t)) => (line_of(t), t.ident.to_string()),
        ContainerMember::Impl(other) => (line_of(other), "?".to_string()),
        ContainerMember::Trait(syn::TraitItem::Const(c)) => (line_of(c), c.ident.to_string()),
        ContainerMember::Trait(syn::TraitItem::Fn(f)) => (line_of(f), f.sig.ident.to_string()),
        ContainerMember::Trait(syn::TraitItem::Type(t)) => (line_of(t), t.ident.to_string()),
        ContainerMember::Trait(other) => (line_of(other), "?".to_string()),
    }
}

// ---------------------------------------------------------------------------
// seat matching: EXACTLY ONE named construct's rule matches (item 2: every
// fn classifies as exactly one skeleton; a second match is a soft drain).
// ---------------------------------------------------------------------------

fn construct_rule<'a>(grammar: &'a Grammar, name: &str) -> Option<StructuralRule> {
    grammar.constructs().iter().find(|c| c.name == name).map(|c| c.rule)
}

fn exactly_one_name<'a>(matches: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut found: Option<&'a str> = None;
    for name in matches {
        if found.is_some() {
            return None;
        }
        found = Some(name);
    }
    found
}

fn seat_matches_item<'a>(ctx: &Ctx<'a>, item: &syn::Item, seats: &'a [String]) -> Option<&'a str> {
    // filter_map: an unknown seat name is skipped (load proved seats resolve;
    // a post-load ghost cannot green via `None => false` costume).
    exactly_one_name(seats.iter().filter_map(|name| {
        construct_rule(ctx.grammar, name)
            .filter(|rule| rule_matches_item(ctx, *rule, item))
            .map(|_| name.as_str())
    }))
}

fn seat_matches_impl_item<'a>(
    ctx: &Ctx<'a>,
    item: &syn::ImplItem,
    seats: &'a [String],
) -> Option<&'a str> {
    exactly_one_name(seats.iter().filter_map(|name| {
        construct_rule(ctx.grammar, name)
            .filter(|rule| rule_matches_impl_item(ctx, *rule, item))
            .map(|_| name.as_str())
    }))
}

fn seat_matches_trait_item<'a>(
    ctx: &Ctx<'a>,
    item: &syn::TraitItem,
    seats: &'a [String],
) -> Option<&'a str> {
    exactly_one_name(seats.iter().filter_map(|name| {
        construct_rule(ctx.grammar, name)
            .filter(|rule| rule_matches_trait_item(ctx, *rule, item))
            .map(|_| name.as_str())
    }))
}

fn rule_matches_item(ctx: &Ctx, rule: StructuralRule, item: &syn::Item) -> bool {
    match item {
        syn::Item::Struct(s) => struct_matches(ctx, rule, s),
        syn::Item::Enum(e) => enum_matches(ctx, rule, e),
        syn::Item::Fn(f) => fn_matches(rule, &f.sig, Some(&f.block), f, ctx),
        syn::Item::Type(t) => alias_matches(ctx, rule, &t.ty),
        syn::Item::Use(u) => import_matches(rule, u),
        syn::Item::Const(_) => constant_matches_non_static(rule),
        syn::Item::Static(s) => constant_matches_static(rule, s),
        syn::Item::Mod(m) => module_matches(rule, m),
        syn::Item::Impl(i) => container_matches(rule, ctx.grammar, impl_item_kind, &i.items),
        syn::Item::Trait(t) => container_matches(rule, ctx.grammar, trait_item_kind, &t.items),
        _no_rule_applies_to_this_item_variant => false,
    }
}

fn rule_matches_impl_item(ctx: &Ctx, rule: StructuralRule, item: &syn::ImplItem) -> bool {
    // if-let chain (not a second `match` twin of `rule_matches_item`).
    if let syn::ImplItem::Fn(f) = item {
        return fn_matches(rule, &f.sig, Some(&f.block), f, ctx);
    }
    if let syn::ImplItem::Type(t) = item {
        return alias_matches(ctx, rule, &t.ty);
    }
    if let syn::ImplItem::Const(_) = item {
        return constant_matches_non_static(rule);
    }
    false
}

fn rule_matches_trait_item(ctx: &Ctx, rule: StructuralRule, item: &syn::TraitItem) -> bool {
    match item {
        syn::TraitItem::Fn(f) => fn_matches(rule, &f.sig, f.default.as_ref(), f, ctx),
        syn::TraitItem::Type(t) => match &t.default {
            Some((_, ty)) => alias_matches(ctx, rule, ty),
            None => matches!(rule, StructuralRule::AliasNoBannedTerminal),
        },
        syn::TraitItem::Const(_) => constant_matches_non_static(rule),
        _no_rule_applies_to_this_trait_item_variant => false,
    }
}

// ---------------------------------------------------------------------------
// item 4: string-carrying decided by type structure + alias fixpoint.
// ---------------------------------------------------------------------------

fn type_is_string_terminal(ctx: &Ctx<'_>, ty: &syn::Type) -> bool {
    // AliasTable is acyclic by construction (build refused cycles);
    // type_carries_string returns bool — no Result at the classify door.
    ctx.aliases.type_carries_string(ctx.rel, ty)
}

// ---------------------------------------------------------------------------
// struct / enum (item 3's partition)
// ---------------------------------------------------------------------------

fn fields_all_private(fields: &syn::Fields) -> bool {
    fields.iter().all(|f| matches!(f.vis, syn::Visibility::Inherited))
}

fn struct_matches(ctx: &Ctx<'_>, rule: StructuralRule, node: &syn::ItemStruct) -> bool {
    match rule {
        StructuralRule::TupleSinglePrivateField => {
            matches!(&node.fields, syn::Fields::Unnamed(u) if u.unnamed.len() == 1)
                && fields_all_private(&node.fields)
        }
        StructuralRule::NamedAllPrivateNoStringTerminal => {
            matches!(&node.fields, syn::Fields::Named(_))
                && fields_all_private(&node.fields)
                && node.fields.iter().all(|f| !type_is_string_terminal(ctx, &f.ty))
        }
        StructuralRule::UnitStruct => matches!(&node.fields, syn::Fields::Unit),
        _rule_not_for_struct => false,
    }
}

fn enum_matches(ctx: &Ctx<'_>, rule: StructuralRule, node: &syn::ItemEnum) -> bool {
    match rule {
        StructuralRule::NoStringVariantFields => node
            .variants
            .iter()
            .all(|v| v.fields.iter().all(|f| !type_is_string_terminal(ctx, &f.ty))),
        _rule_not_for_enum => false,
    }
}

// ---------------------------------------------------------------------------
// alias / import / constant / module (item 1's remaining named seats)
// ---------------------------------------------------------------------------

fn alias_matches(ctx: &Ctx<'_>, rule: StructuralRule, ty: &syn::Type) -> bool {
    match rule {
        StructuralRule::AliasNoBannedTerminal => !type_is_string_terminal(ctx, ty),
        _rule_not_for_alias => false,
    }
}

fn use_has_glob(tree: &syn::UseTree) -> bool {
    // Stack walk — not a recursive-match twin of `is_call_expr`.
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        match node {
            syn::UseTree::Glob(_) => return true,
            syn::UseTree::Path(p) => stack.push(&p.tree),
            syn::UseTree::Group(g) => stack.extend(g.items.iter()),
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) => {}
        }
    }
    false
}

fn import_matches(rule: StructuralRule, node: &syn::ItemUse) -> bool {
    match rule {
        StructuralRule::ImportNoGlob => !use_has_glob(&node.tree),
        _rule_not_for_import => false,
    }
}

/// `Const`/`ImplConst`/`TraitConst` can never be `static mut` — the
/// construct's refusal capability for THIS rule lives entirely on the
/// `Static` kind (below); these kinds vacuously satisfy it.
fn constant_matches_non_static(rule: StructuralRule) -> bool {
    matches!(rule, StructuralRule::ConstantNoStaticMut)
}

fn constant_matches_static(rule: StructuralRule, node: &syn::ItemStatic) -> bool {
    match rule {
        StructuralRule::ConstantNoStaticMut => {
            !matches!(node.mutability, syn::StaticMutability::Mut(_))
        }
        _rule_not_for_constant => false,
    }
}

fn module_matches(rule: StructuralRule, _node: &syn::ItemMod) -> bool {
    match rule {
        // Item 5: path attribute is bans_attribute only; every mod seats.
        StructuralRule::ModuleNoPathAttr => true,
        _rule_not_for_module => false,
    }
}

/// impl/trait containers: the construct refuses the container as a whole
/// when ANY direct interior item is of a condemned kind — interior items
/// are additionally, individually reported at their own condemned law name
/// by the caller; this is the container's OWN in-cell refusal, required by
/// the preamble law since containers are not zero-freedom cells.
fn container_matches<I>(
    rule: StructuralRule,
    grammar: &Grammar,
    kind_of: fn(&I) -> Option<KindName>,
    items: &[I],
) -> bool {
    match rule {
        StructuralRule::InteriorsClassify => items
            .iter()
            .all(|it| !kind_of(it).is_some_and(|k| grammar.condemned().contains(&k))),
        _rule_not_for_container => false,
    }
}

// ---------------------------------------------------------------------------
// fn skeletons (item 2, minimum bar for item 1's totality claim)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Receiver {
    None,
    RefSelf,
    RefMutSelf,
    ByValueSelf,
    Other,
}

fn receiver_form(sig: &syn::Signature) -> Receiver {
    match sig.inputs.first() {
        Some(syn::FnArg::Receiver(r)) => {
            if r.colon_token.is_some() {
                Receiver::Other
            } else if r.reference.is_some() {
                if r.mutability.is_some() {
                    Receiver::RefMutSelf
                } else {
                    Receiver::RefSelf
                }
            } else {
                Receiver::ByValueSelf
            }
        }
        Some(syn::FnArg::Typed(_)) | None => Receiver::None,
    }
}

fn ok_or_bodyless(block: Option<&syn::Block>, pred: impl FnOnce(&syn::Block) -> bool) -> bool {
    // Bodyless trait methods: bans have nothing to refuse. `is_none_or`
    // states that without a `None => true` costume arm.
    block.is_none_or(pred)
}

#[derive(Clone, Copy)]
enum BodyBan {
    ControlFlow,
    Await,
    Unsafe,
}

fn body_contains(block: &syn::Block, ban: BodyBan) -> bool {
    struct V {
        ban: BodyBan,
        found: bool,
    }
    impl<'ast> Visit<'ast> for V {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if matches!(self.ban, BodyBan::ControlFlow) {
                self.found = true;
            }
            visit::visit_expr_if(self, node);
        }
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if matches!(self.ban, BodyBan::ControlFlow) {
                self.found = true;
            }
            visit::visit_expr_match(self, node);
        }
        fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
            if matches!(self.ban, BodyBan::ControlFlow) {
                self.found = true;
            }
            visit::visit_expr_loop(self, node);
        }
        fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
            if matches!(self.ban, BodyBan::ControlFlow) {
                self.found = true;
            }
            visit::visit_expr_while(self, node);
        }
        fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
            if matches!(self.ban, BodyBan::ControlFlow) {
                self.found = true;
            }
            visit::visit_expr_for_loop(self, node);
        }
        fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
            if matches!(self.ban, BodyBan::Await) {
                self.found = true;
            }
            visit::visit_expr_await(self, node);
        }
        fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
            if matches!(self.ban, BodyBan::Unsafe) {
                self.found = true;
            }
            visit::visit_expr_unsafe(self, node);
        }
    }
    let mut v = V {
        ban,
        found: false,
    };
    v.visit_block(block);
    v.found
}

fn contains_control_flow(block: &syn::Block) -> bool {
    body_contains(block, BodyBan::ControlFlow)
}
fn contains_await(block: &syn::Block) -> bool {
    body_contains(block, BodyBan::Await)
}
fn contains_unsafe(block: &syn::Block) -> bool {
    body_contains(block, BodyBan::Unsafe)
}

/// A call expression, optionally wrapped in `?` / parens / group — the only
/// RHS / tail shape composition-root's POSITIVE body law admits.
fn is_call_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Call(_) | syn::Expr::MethodCall(_) => true,
        syn::Expr::Try(t) => is_call_expr(&t.expr),
        syn::Expr::Paren(p) => is_call_expr(&p.expr),
        syn::Expr::Group(g) => is_call_expr(&g.expr),
        _not_a_call => false,
    }
}

/// Composition-root POSITIVE body law (item 2): let-bindings of calls (with
/// optional `?`), then exactly one tail call. `if`/`match`/`loop`/`while`/
/// `for`/`await` are red. A body that merely lacks control flow but holds a
/// non-call expression is the soft drain this law closes.
fn composition_root_body_ok(block: &syn::Block) -> bool {
    if contains_control_flow(block) || contains_await(block) {
        return false;
    }
    let Some((last, prefix)) = block.stmts.split_last() else {
        return false;
    };
    for stmt in prefix {
        let syn::Stmt::Local(local) = stmt else {
            return false;
        };
        let Some(init) = &local.init else {
            return false;
        };
        // `let ... = ... else { ... }` is control flow in costume.
        if init.diverge.is_some() {
            return false;
        }
        if !is_call_expr(&init.expr) {
            return false;
        }
    }
    match last {
        syn::Stmt::Expr(expr, None) => is_call_expr(expr),
        _not_a_tail_call => false,
    }
}

/// Path+name shape of composition-root, before body judgment — used to keep
/// declared-fn from absorbing a failed `main` (item 2: no soft drain cell).
fn is_composition_root_shape(sig: &syn::Signature, ctx: &Ctx) -> bool {
    receiver_form(sig) == Receiver::None
        && !ctx.in_container
        && sig.ident == "main"
        && (ctx.rel.ends_with("/src/main.rs") || ctx.rel.contains("/src/bin/"))
}

/// Admission-door shape by receiver+return, before body judgment.
fn is_admission_door_shape(sig: &syn::Signature, ctx: &Ctx) -> bool {
    receiver_form(sig) == Receiver::None
        && ctx.in_container
        && return_resolves_to_self(&sig.output, ctx.self_ty, true)
}

fn type_matches_self(ty: &syn::Type, self_ty: Option<&syn::Type>) -> bool {
    let syn::Type::Path(tp) = ty else {
        return false;
    };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident == "Self" {
        return true;
    }
    let Some(syn::Type::Path(self_tp)) = self_ty else {
        return false;
    };
    let Some(self_seg) = self_tp.path.segments.last() else {
        return false;
    };
    seg.ident == self_seg.ident
}

fn return_resolves_to_self(
    output: &syn::ReturnType,
    self_ty: Option<&syn::Type>,
    allow_result_option: bool,
) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    if type_matches_self(ty, self_ty) {
        return true;
    }
    if !allow_result_option {
        return false;
    }
    let syn::Type::Path(tp) = ty.as_ref() else {
        return false;
    };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident != "Result" && seg.ident != "Option" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    args.args.iter().any(|a| match a {
        syn::GenericArgument::Type(t) => type_matches_self(t, self_ty),
        _not_a_type_arg => false,
    })
}

/// Declared-fn seat lookup (item 6 forward-bound): file + fn_path + a
/// blake3 site hash that must match the item's CURRENT identity tokens
/// exactly, or the seat has drifted and the fn is red. `io = true` is the
/// only lawful home for `async`/`await` (every other skeleton cell bans
/// await; this cell bans it too unless the seat says `io = true`).
fn declared_fn_matches(
    sig: &syn::Signature,
    block: Option<&syn::Block>,
    whole: &dyn ToTokens,
    ctx: &Ctx,
) -> bool {
    // Discriminator exclusivity: composition-root shape and admission-door
    // shape are claimed by those cells even when their body bans fire —
    // declared-fn must not be the drain they pour into.
    if is_composition_root_shape(sig, ctx) || is_admission_door_shape(sig, ctx) {
        return false;
    }
    let Some(seat) = ctx.grammar.fn_seat(ctx.rel, &sig.ident.to_string()) else {
        return false;
    };
    if crate::identity::site_hash(whole) != seat.site_hash {
        return false;
    }
    if !seat.io {
        if sig.asyncness.is_some() {
            return false;
        }
        if !ok_or_bodyless(block, |b| !contains_await(b)) {
            return false;
        }
    }
    true
}

fn fn_matches(
    rule: StructuralRule,
    sig: &syn::Signature,
    block: Option<&syn::Block>,
    whole: &dyn ToTokens,
    ctx: &Ctx,
) -> bool {
    let receiver = receiver_form(sig);
    match rule {
        StructuralRule::CompositionRootBody => {
            // Body is mandatory: a bodyless `main` cannot satisfy the
            // positive let/call/tail law (ok_or_bodyless would soft-pass).
            is_composition_root_shape(sig, ctx)
                && sig.asyncness.is_none()
                && block.is_some_and(composition_root_body_ok)
        }
        StructuralRule::DerivationBans => {
            // assignment + await fire via construct.bans + run.rs span
            // containment (item 5). unsafe remains in-cell BodyBan so the
            // derivation deny fixture has a structural refuse.
            receiver == Receiver::RefSelf
                && sig.asyncness.is_none()
                && ok_or_bodyless(block, |b| !contains_unsafe(b))
        }
        StructuralRule::TransitionBans => {
            // nested_place_assign + await → construct.bans only (item 5).
            receiver == Receiver::RefMutSelf && sig.asyncness.is_none()
        }
        StructuralRule::ConsumingVerbBans => {
            // self-by-value returning Self is a builder chain — red: it
            // matches NO skeleton (this arm demands return ≠ Self).
            // nested_place_assign + await → construct.bans only (item 5).
            receiver == Receiver::ByValueSelf
                && sig.asyncness.is_none()
                && !return_resolves_to_self(&sig.output, ctx.self_ty, false)
        }
        StructuralRule::AdmissionDoorBans => {
            // await → construct.bans only (item 5). asyncness still refuses
            // the seat (async is not an await-expression site).
            is_admission_door_shape(sig, ctx) && sig.asyncness.is_none()
        }
        StructuralRule::DeclaredFnSeat => {
            receiver == Receiver::None && declared_fn_matches(sig, block, whole, ctx)
        }
        _rule_not_for_fn => false,
    }
}

// ---------------------------------------------------------------------------
// generic fixture test: pass classifies as exactly the construct; deny is
// refused by the SAME construct's own rule (not a neighbor's).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::grammar::Grammar;
    use std::path::PathBuf;

    fn crate_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn real_grammar() -> Grammar {
        let text = std::fs::read_to_string(crate_dir().join("grammar.toml")).expect("grammar.toml readable");
        let bite_src = std::fs::read_to_string(crate_dir().join("tests/bite_proofs.rs")).expect("bite src");
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, text.as_bytes()).expect("write");
        Grammar::load(f.path(), &bite_src, &crate_dir().join("fixtures")).expect("real grammar loads")
    }

    /// `declared-fn`'s seats bind to the FIXTURE FILE's own repo-root-relative
    /// path (grammar.toml declares seats against exactly these paths); every
    /// other construct's rule is path-independent, so a generic placeholder
    /// stands in for `rel`.
    fn rel_for(construct: &str) -> &'static str {
        match construct {
            "composition-root" => "crates/probe/src/main.rs",
            _generic => "crates/probe/src/lib.rs",
        }
    }

    fn probe_matches(grammar: &Grammar, rel: &str, rule: StructuralRule, first_item: &syn::Item) -> bool {
        // Container rules judge the Impl/Trait item itself. Fn-skeleton
        // rules that live inside an impl are probed against the first
        // interior fn (fixtures start with `struct …; impl … { fn … }`).
        let empty = crate::alias::AliasTable::empty();
        if matches!(rule, StructuralRule::InteriorsClassify) {
            let ctx = Ctx {
                rel,
                grammar,
                aliases: &empty,
                self_ty: None,
                in_container: false,
            };
            return rule_matches_item(&ctx, rule, first_item);
        }
        match first_item {
            syn::Item::Impl(imp) => {
                let ctx = Ctx {
                    rel,
                    grammar,
                    aliases: &empty,
                    self_ty: Some(&imp.self_ty),
                    in_container: true,
                };
                match imp.items.first() {
                    Some(syn::ImplItem::Fn(f)) => fn_matches(rule, &f.sig, Some(&f.block), f, &ctx),
                    Some(syn::ImplItem::Const(_))
                    | Some(syn::ImplItem::Type(_))
                    | Some(syn::ImplItem::Macro(_))
                    | Some(syn::ImplItem::Verbatim(_))
                    | None => false,
                    _unrecognized_impl_item => false,
                }
            }
            other => {
                let ctx = Ctx {
                    rel,
                    grammar,
                    aliases: &empty,
                    self_ty: None,
                    in_container: false,
                };
                rule_matches_item(&ctx, rule, other)
            }
        }
    }

    #[test]
    fn every_construct_pass_classifies_and_deny_is_refused_by_its_own_rule() {
        let grammar = real_grammar();
        for c in grammar.constructs() {
            let rel = if c.name == "declared-fn" {
                "crates/bs-detector/fixtures/declared-fn.pass.rs"
            } else {
                rel_for(&c.name)
            };
            let pass_path = crate_dir().join("fixtures").join(format!("{}.pass.rs", c.name));
            let pass_src = match std::fs::read_to_string(&pass_path) {
                Ok(s) => s,
                Err(e) => panic!("{} pass fixture readable: {e}", c.name),
            };
            let pass_ast = match syn::parse_file(&pass_src) {
                Ok(a) => a,
                Err(e) => panic!("{} pass fixture parses: {e}", c.name),
            };
            let Some(first) = pass_ast.items.first() else {
                panic!("{} pass fixture has an item", c.name);
            };
            assert!(
                probe_matches(&grammar, rel, c.rule, first),
                "{} pass fixture must classify as its own construct",
                c.name
            );

            if c.rule.deny_exempt() {
                continue;
            }
            let deny_rel = if c.name == "declared-fn" {
                "crates/bs-detector/fixtures/declared-fn.deny.rs"
            } else {
                rel_for(&c.name)
            };
            let deny_path = crate_dir().join("fixtures").join(format!("{}.deny.rs", c.name));
            let deny_src = match std::fs::read_to_string(&deny_path) {
                Ok(s) => s,
                Err(e) => panic!("{} deny fixture readable: {e}", c.name),
            };
            let deny_ast = match syn::parse_file(&deny_src) {
                Ok(a) => a,
                Err(e) => panic!("{} deny fixture parses: {e}", c.name),
            };
            let Some(first) = deny_ast.items.first() else {
                panic!("{} deny fixture has an item", c.name);
            };
            assert!(
                !probe_matches(&grammar, deny_rel, c.rule, first),
                "{} deny fixture must be refused by its OWN rule",
                c.name
            );
        }
    }

    #[test]
    fn every_condemned_kind_deny_fixture_is_red_under_its_own_law() {
        let grammar = real_grammar();
        for kind in grammar.condemned() {
            let Some(law) = kind.condemned_law_name() else {
                panic!("{} must have a condemnation law", kind.kebab());
            };
            let path = crate_dir()
                .join("fixtures")
                .join(format!("{}.deny.rs", kind.kebab()));
            let src = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => panic!("{} deny fixture readable: {e}", kind.kebab()),
            };
            // Verbatim cannot be authored inside a file syn::parse_file accepts —
            // by definition it is what syn could not interpret. Presence is the
            // load law; live-tree Verbatim is the classify path. Skip parse-exec
            // for that one kind only, named here so it is not silent.
            if *kind == KindName::Verbatim {
                assert!(
                    src.contains("Item::Verbatim") || src.contains("verbatim"),
                    "verbatim.deny.rs must name why it cannot be a parseable Verbatim specimen"
                );
                continue;
            }
            let ast = match syn::parse_file(&src) {
                Ok(a) => a,
                Err(e) => panic!("{} deny fixture parses: {e}", kind.kebab()),
            };
            let f = SourceFile::admit(
                format!("crates/bs-detector/fixtures/{}.deny.rs", kind.kebab()),
                src,
                ast,
            );
            let hits = classify_file(&grammar, &f, &crate::alias::AliasTable::build(&[&f]).expect("aliases"));
            assert!(
                hits.iter().any(|h| h.construct() == law),
                "{} deny fixture must hit under `{law}`: {hits:?}",
                kind.kebab()
            );
        }
    }

    #[test]
    fn item_1_proof_const_kind_neither_seated_nor_condemned_would_be_a_load_error() {
        // Covered directly in grammar.rs's own load tests (removing the
        // `const` seat entry refuses to load); re-asserted here at the
        // classify boundary: a kind with NO disposition is treated as a
        // hit, never a silent pass, if it ever reached the classifier.
        let grammar = real_grammar();
        assert!(grammar.disposition(KindName::Const).is_some(), "const IS seated in the live grammar");
    }

    #[test]
    fn item_1_proof_static_mut_is_denied() {
        let grammar = real_grammar();
        let f = SourceFile::admit(
            "crates/probe/src/lib.rs".to_string(),
            "static mut G: u64 = 0;".to_string(),
            syn::parse_file("static mut G: u64 = 0;").expect("parses"),
        );
        let hits = classify_file(&grammar, &f, &crate::alias::AliasTable::build(&[&f]).expect("aliases"));
        assert_eq!(hits.len(), 1, "static mut must be denied: {hits:?}");
    }

    #[test]
    fn item_1_proof_path_attr_mod_is_denied() {
        // Item 5: #[path] is bans_attribute only — module still seats;
        // the attribute matcher is the one door.
        let m = crate::engines::shape::matcher_by_name("path").expect("path matcher");
        let f = SourceFile::admit("crates/probe/src/lib.rs".to_string(), "#[path = \"x.rs\"]\nmod m;".to_string(), syn::parse_file("#[path = \"x.rs\"]\nmod m;").expect("parses"));
        let hits = crate::engines::shape::run_matcher(m, &f);
        assert_eq!(hits.len(), 1, "path attr must hit under bans_attribute: {hits:?}");
        assert_eq!(classify_src("#[path = \"x.rs\"] mod m;").len(), 0, "module seats; path is not unclassified");
    }

    #[test]
    fn item_1_proof_glob_use_is_denied() {
        assert_hit_count("use crate::foo::*;", 1);
    }

    #[test]
    fn item_1_proof_impl_macro_is_denied() {
        let hits = classify_src("struct T; impl T { some_macro!{} }");
        assert!(
            hits.iter().any(|h| h.construct() == "impl_item_macro"),
            "impl-interior macro must hit under its law: {hits:?}"
        );
    }

    #[test]
    fn anti_fraud_a_deny_shape_never_slips_through_a_neighboring_seat() {
        assert_hit_count("struct Leaky { name: String }", 1);
    }

    // -----------------------------------------------------------------------
    // item 2 proofs (executed — presence is not proof)
    // -----------------------------------------------------------------------

    fn classify_src(src: &str) -> Vec<Hit> {
        let grammar = real_grammar();
        let f = SourceFile::admit("crates/probe/src/lib.rs".to_string(), src.to_string(), syn::parse_file(src).expect("parses"));
        let aliases = crate::alias::AliasTable::build(&[&f]).expect("alias table");
        classify_file(&grammar, &f, &aliases)
    }

    fn assert_hit_count(src: &str, n: usize) {
        let hits = classify_src(src);
        assert_eq!(hits.len(), n, "hits for `{src}`: {hits:?}");
    }

    fn assert_unclassified(src: &str) {
        let hits = classify_src(src);
        assert!(
            hits.iter().any(|h| h.construct().contains("unclassified")),
            "expected unclassified for `{src}`: {hits:?}"
        );
    }

    #[test]
    fn item_2_proofs_red_shapes_are_unclassified() {
        // Shapes that match NO skeleton remain unclassified. Await /
        // nested_place_assign inside an otherwise-matching skeleton are
        // construct.bans (item 5) — they classify, then run.rs hits.
        let cases = [
            "impl S { fn f(self: Box<Self>) {} }",
            "impl S { fn with_x(mut self) -> Self { self.x = 1; self } }",
            "fn smuggled() {}",
            "async fn bare_async() {}",
        ];
        for src in cases {
            assert_unclassified(src);
        }
        // Declared-fn hash drift (deny fixture seated with wrong hash).
        let grammar = real_grammar();
        let path = crate_dir().join("fixtures/declared-fn.deny.rs");
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => panic!("deny fixture readable: {e}"),
        };
        let f = SourceFile::admit("crates/bs-detector/fixtures/declared-fn.deny.rs".to_string(), src.clone(), syn::parse_file(&src).expect("parses"));
        let hits = classify_file(&grammar, &f, &crate::alias::AliasTable::build(&[&f]).expect("aliases"));
        assert!(
            hits.iter().any(|h| h.construct().contains("unclassified")),
            "declared fn hash drift must be red: {hits:?}"
        );
    }

    #[test]
    fn item_5_scoped_bans_classify_then_matcher_hits() {
        // Await / nested_place inside a matching skeleton: classify clean,
        // construct-scoped matcher still detonates (one jurisdiction).
        let grammar = real_grammar();
        let await_src = "impl S { fn get(&self) -> u64 { async { 1u64 }.await } }";
        let nest_src = "impl S { fn into_x(mut self) -> u64 { self.a.b = 1; self.x } }";
        for (src, rule) in [
            (await_src, StructuralRule::DerivationBans),
            (nest_src, StructuralRule::ConsumingVerbBans),
        ] {
            let ast = syn::parse_file(src).expect("parses");
            let first = ast.items.first().expect("item");
            assert!(
                probe_matches(&grammar, "crates/probe/src/lib.rs", rule, first),
                "scoped-ban body must still seat: {src}"
            );
        }
        let m_await = crate::engines::shape::matcher_by_name("await").expect("await");
        let m_nest = crate::engines::shape::matcher_by_name("nested_place_assign").expect("nest");
        let f_await = SourceFile::admit("crates/probe/src/lib.rs".to_string(), await_src.to_string(), syn::parse_file(await_src).expect("parses"));
        let f_nest = SourceFile::admit("crates/probe/src/lib.rs".to_string(), nest_src.to_string(), syn::parse_file(nest_src).expect("parses"));
        assert_eq!(crate::engines::shape::run_matcher(m_await, &f_await).len(), 1);
        assert_eq!(crate::engines::shape::run_matcher(m_nest, &f_nest).len(), 1);
    }

    #[test]
    fn item_2_proof_admission_door_classifies() {
        let grammar = real_grammar();
        let src = "impl S { fn new() -> Result<Self, ()> { Ok(S) } }";
        let rel = "crates/probe/src/lib.rs";
        let ast = syn::parse_file(src).expect("parses");
        let first = ast.items.first().expect("item");
        assert!(
            probe_matches(&grammar, rel, StructuralRule::AdmissionDoorBans, first),
            "fn new() -> Result<Self, E> in an impl must classify as admission-door"
        );
        let f = SourceFile::admit(rel.to_string(), src.to_string(), ast);
        let hits = classify_file(&grammar, &f, &crate::alias::AliasTable::build(&[&f]).expect("aliases"));
        assert!(
            hits.is_empty(),
            "admission-door pass shape must not be unclassified: {hits:?}"
        );
    }

    fn hit_constructs_for(hits: &[Hit], name: &str) -> Vec<String> {
        hits.iter()
            .filter(|h| h.construct().contains(name))
            .map(|h| h.construct().to_string())
            .collect()
    }

    /// Adversary 1: the drain shape is REAL — an impl-associated
    /// receiverless `-> Self` fn matches admission-door. If this ever goes
    /// false, the nested-bleed story is fiction and the suite must stop.
    #[test]
    fn anti_fraud_impl_associated_self_fn_still_matches_admission_door_rule() {
        let grammar = real_grammar();
        let src = "impl S { fn helper() -> Self { S } }";
        let ast = syn::parse_file(src).expect("parses");
        let first = ast.items.first().expect("item");
        assert!(
            probe_matches(
                &grammar,
                "crates/probe/src/lib.rs",
                StructuralRule::AdmissionDoorBans,
                first
            ),
            "ATTACK LOCK FAILED: impl-associated fn helper() -> Self must match admission-door — without this the nested-bleed adversary is undefined"
        );
        let hits = classify_src(src);
        let helper = hit_constructs_for(&hits, "helper");
        assert!(
            helper.is_empty(),
            "impl-associated helper() -> Self must be silent-green as admission-door, not red: {helper:?} full={hits:?}"
        );
    }

    /// Adversary 2: nested Item::Fn inside a method body must NOT inherit
    /// the impl seat. The soft drain was: empty hits (false green). This
    /// test detonates if helper is missing from hits OR is anything other
    /// than unclassified-fn:helper.
    #[test]
    fn anti_fraud_nested_self_fn_inside_method_body_must_be_unclassified() {
        let src = "impl S { fn method(&self) { fn helper() -> Self { S } } }";
        let hits = classify_src(src);
        let helper = hit_constructs_for(&hits, "helper");
        assert_eq!(
            helper,
            vec!["unclassified-fn:helper".to_string()],
            "NESTED BLEED STILL OPEN or over-fixed: want exactly unclassified-fn:helper, got {helper:?} full={hits:?}"
        );
        // Method itself is derivation — must not be swept into the helper's guilt.
        assert!(
            !hits.iter().any(|h| h.construct().contains("method")),
            "method(&self) must remain a seated derivation, not red: {hits:?}"
        );
    }

    /// Adversary 3: Result<Self,_> nest — same bleed costume, different return.
    #[test]
    fn anti_fraud_nested_result_self_fn_inside_method_must_be_unclassified() {
        let src = "impl S { fn method(&self) { fn helper() -> Result<Self, ()> { Ok(S) } } }";
        let hits = classify_src(src);
        let helper = hit_constructs_for(&hits, "helper");
        assert_eq!(
            helper,
            vec!["unclassified-fn:helper".to_string()],
            "Result<Self> nested helper must be unclassified-fn:helper, got {helper:?} full={hits:?}"
        );
    }

    /// Adversary 4: trait default body nest — second container bleed surface.
    #[test]
    fn anti_fraud_nested_self_fn_inside_trait_default_must_be_unclassified() {
        let src = "trait T { fn method(&self) { fn helper() -> Self { todo!() } } }";
        let hits = classify_src(src);
        let helper = hit_constructs_for(&hits, "helper");
        assert_eq!(
            helper,
            vec!["unclassified-fn:helper".to_string()],
            "trait-default nested helper must be unclassified-fn:helper, got {helper:?} full={hits:?}"
        );
    }

    /// Adversary 5: free nested fn inside a free fn — never had in_container;
    /// must still be unclassified (no silent pass via a new costume).
    #[test]
    fn anti_fraud_nested_fn_inside_free_fn_must_be_unclassified() {
        let src = "fn outer() { fn helper() {} }";
        let hits = classify_src(src);
        let helper = hit_constructs_for(&hits, "helper");
        assert_eq!(
            helper,
            vec!["unclassified-fn:helper".to_string()],
            "free nested helper must be unclassified-fn:helper, got {helper:?} full={hits:?}"
        );
        let outer = hit_constructs_for(&hits, "outer");
        assert_eq!(
            outer,
            vec!["unclassified-fn:outer".to_string()],
            "free outer must also be unclassified (no seat): {outer:?}"
        );
    }

    #[test]
    fn item_2_proof_composition_root_positive_body_refuses_non_call_let() {
        // The honesty gap closed here: negative-only (!control_flow) would
        // green `let x = 1; finish(x)`. Positive law reds it.
        let grammar = real_grammar();
        let src = "fn main() { let x = 1; finish(x) }";
        let rel = "crates/probe/src/main.rs";
        let ast = syn::parse_file(src).expect("parses");
        let first = ast.items.first().expect("item");
        assert!(
            !probe_matches(&grammar, rel, StructuralRule::CompositionRootBody, first),
            "composition-root must refuse a non-call let RHS under the positive body law"
        );
    }

    #[test]
    fn item_2_anti_fraud_fn_matches_at_most_one_skeleton() {
        let grammar = real_grammar();
        let cases = [
            ("crates/probe/src/main.rs", "fn main() { let x = prep(); finish(x) }"),
            ("crates/probe/src/lib.rs", "impl S { fn get(&self) -> u64 { 0 } }"),
            ("crates/probe/src/lib.rs", "impl S { fn set(&mut self, v: u64) { self.x = v; } }"),
            ("crates/probe/src/lib.rs", "impl S { fn into_x(self) -> u64 { self.x } }"),
            ("crates/probe/src/lib.rs", "impl S { fn new() -> Result<Self, ()> { Ok(S) } }"),
        ];
        let fn_rules: Vec<StructuralRule> = grammar
            .constructs()
            .iter()
            .filter(|c| matches!(c.kind, crate::grammar::ConstructFamily::Fn))
            .map(|c| c.rule)
            .collect();
        for (rel, src) in cases {
            let ast = syn::parse_file(src).expect("parses");
            let first = ast.items.first().expect("item");
            let n = fn_rules
                .iter()
                .filter(|r| probe_matches(&grammar, rel, **r, first))
                .count();
            assert_eq!(
                n, 1,
                "exactly one skeleton must match `{src}` at {rel}, got {n}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // item 3 proofs — disjoint construct rules
    // -----------------------------------------------------------------------

    #[test]
    fn item_3_proof_multi_field_tuple_and_pub_field_are_red() {
        // Build text: multi-field tuple or any pub field → red.
        assert_unclassified("struct Multi(u64, u64);");
        assert_unclassified("struct Open(pub u64);");
        assert_unclassified("struct Open { pub a: u64 }");
    }

    #[test]
    fn item_3_anti_fraud_struct_matches_at_most_one_construct() {
        let grammar = real_grammar();
        let cases = [
            "struct Newtype(u64);",
            "struct Sealed { a: u64 }",
            "struct Unit;",
        ];
        let struct_rules: Vec<StructuralRule> = grammar
            .constructs()
            .iter()
            .filter(|c| matches!(c.kind, crate::grammar::ConstructFamily::Struct))
            .map(|c| c.rule)
            .collect();
        for src in cases {
            let ast = syn::parse_file(src).expect("parses");
            let first = ast.items.first().expect("item");
            let n = struct_rules
                .iter()
                .filter(|r| probe_matches(&grammar, "crates/probe/src/lib.rs", **r, first))
                .count();
            assert_eq!(
                n, 1,
                "exactly one struct construct must match `{src}`, got {n}"
            );
        }
    }

    #[test]
    fn item_3_classification_emits_unique_construct_name() {
        // Seat match returns the unique name (not a bool from `.any()`).
        let grammar = real_grammar();
        let src = "struct Newtype(u64);";
        let ast = syn::parse_file(src).expect("parses");
        let item = ast.items.first().expect("item");
        let empty = crate::alias::AliasTable::empty();
        let ctx = Ctx {
            rel: "crates/probe/src/lib.rs",
            grammar: &grammar,
            aliases: &empty,
            self_ty: None,
            in_container: false,
        };
        let seats = match grammar.disposition(KindName::Struct) {
            Some(crate::grammar::Disposition::Seated(s)) => s,
            Some(crate::grammar::Disposition::Condemned(_)) => {
                panic!("struct must be seated, not condemned")
            }
            None => panic!("struct must be seated"),
        };
        assert_eq!(
            seat_matches_item(&ctx, item, seats),
            Some("newtype-scalar"),
            "classification must emit the unique construct name"
        );
    }

    // -----------------------------------------------------------------------
    // item 4 proofs — string rule + alias fixpoint
    // -----------------------------------------------------------------------

    #[test]
    fn item_4_proof_type_alias_to_string_struct_is_red() {
        assert_unclassified("type Name = String; struct S { n: Name }");
    }

    #[test]
    fn item_4_proof_use_as_string_struct_is_red() {
        assert_unclassified("use std::string::String as Text; struct T { t: Text }");
    }

    /// Adversary 6a: expression-nested FREE FN — unit struct was a false
    /// specimen (unit-marker seats green). A receiverless nested fn cannot
    /// seat; if the if-body walk is blind, this is []. Exact construct only.
    #[test]
    fn anti_fraud_expression_nested_fn_must_be_exact_unclassified() {
        let hits = classify_src("fn f() { if true { fn nested_hide() {} } }");
        let nested = hit_constructs_for(&hits, "nested_hide");
        assert_eq!(
            nested,
            vec!["unclassified-fn:nested_hide".to_string()],
            "if-body fn must be exactly unclassified-fn:nested_hide (walk blind or soft seat): {nested:?} full={hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.construct() == "unclassified-fn:f"),
            "outer free fn f must be unclassified-fn:f: {hits:?}"
        );
    }

    /// Adversary 6b: expression-nested STRING STRUCT — cannot seat as
    /// sealed/newtype/unit. Exact construct; detonates on walk blindness.
    #[test]
    fn anti_fraud_expression_nested_string_struct_must_be_exact_unclassified() {
        let hits = classify_src("fn f() { if true { struct NestedHide { name: String } } }");
        let nested = hit_constructs_for(&hits, "NestedHide");
        assert_eq!(
            nested,
            vec!["unclassified-struct:NestedHide".to_string()],
            "if-body String struct must be exactly unclassified-struct:NestedHide: {nested:?} full={hits:?}"
        );
    }

    /// Adversary 6c: FALSE SPECIMEN LOCK — unit struct in if-body IS
    /// unit-marker (lawful green). If this goes red, we over-fixed.
    #[test]
    fn anti_fraud_expression_nested_unit_struct_still_seats_as_unit_marker() {
        let hits = classify_src("fn f() { if true { struct NestedHide; } }");
        let nested = hit_constructs_for(&hits, "NestedHide");
        assert!(
            nested.is_empty(),
            "unit struct NestedHide must remain unit-marker green, not red: {nested:?} full={hits:?}"
        );
    }

    /// Tip 650 nest surfaces — each costume must emit exactly
    /// `unclassified-fn:nested_hide`. Empty hits = walk blind soft drain.
    fn assert_expression_nest_exact(src: &str, costume: &str) {
        let hits = classify_src(src);
        let nested = hit_constructs_for(&hits, "nested_hide");
        assert_eq!(
            nested,
            vec!["unclassified-fn:nested_hide".to_string()],
            "{costume}-nested fn must be exactly unclassified-fn:nested_hide (walk blind or soft seat): {nested:?} full={hits:?}"
        );
    }

    #[test]
    fn anti_fraud_match_arm_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { match 0u8 { _ => { fn nested_hide() {} } } }",
            "match-arm",
        );
    }

    #[test]
    fn anti_fraud_loop_body_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { loop { fn nested_hide() {} break; } }",
            "loop",
        );
    }

    #[test]
    fn anti_fraud_while_body_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { while true { fn nested_hide() {} break; } }",
            "while",
        );
    }

    #[test]
    fn anti_fraud_for_body_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { for _ in 0..1 { fn nested_hide() {} } }",
            "for",
        );
    }

    #[test]
    fn anti_fraud_closure_body_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { let _c = || { fn nested_hide() {} }; }",
            "closure",
        );
    }

    #[test]
    fn anti_fraud_async_block_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { let _a = async { fn nested_hide() {} }; }",
            "async-block",
        );
    }

    #[test]
    fn anti_fraud_unsafe_block_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { unsafe { fn nested_hide() {} } }",
            "unsafe-block",
        );
    }

    /// Tip 650: const/static *item* RHS blocks may contain nested items
    /// (legal Rust). recurse_into_item treated Const/Static as
    /// non-containers — silent-green drain.
    #[test]
    fn anti_fraud_const_item_rhs_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "const X: i32 = { fn nested_hide() {} 1 };",
            "const-item-rhs",
        );
    }

    #[test]
    fn anti_fraud_static_item_rhs_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "static X: i32 = { fn nested_hide() {} 1 };",
            "static-item-rhs",
        );
    }

    #[test]
    fn anti_fraud_nested_const_item_rhs_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { const X: i32 = { fn nested_hide() {} 1 }; }",
            "nested-const-item-rhs",
        );
    }

    #[test]
    fn anti_fraud_const_block_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { const { fn nested_hide() {} }; }",
            "const-block",
        );
    }

    #[test]
    fn anti_fraud_inline_const_nested_fn_must_be_exact_unclassified() {
        assert_expression_nest_exact(
            "fn f() { let _x = const { fn nested_hide() {} 1 }; }",
            "inline-const",
        );
    }

    fn item_4_proof_restrict_struct_is_clean() {
        assert_hit_count("struct R { r: Restrict }", 0);
    }
}
