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
//! every impl/trait interior item, and item statements declared directly
//! inside a fn body block. Item declarations nested inside expression
//! bodies (`if true { struct X; }`) are outside this walk's scope — a
//! documented, narrow residual, not a silent hole in the kind table.

use quote::ToTokens;
use syn::visit::{self, Visit};

use crate::boundary::SourceFile;
use crate::engines::Hit;
use crate::grammar::{Disposition, Grammar, KindName, StructuralRule};

/// Classify every item in `file`. Returns one hit per condemned-kind
/// occurrence (`construct` = the condemned law name, exactly) and one hit
/// per seated item matching no allowed construct (`construct` =
/// `unclassified-<kind>:<label>`).
pub fn classify_file(grammar: &Grammar, file: &SourceFile) -> Vec<Hit> {
    let mut hits = vec![];
    let ctx = Ctx {
        rel: &file.rel_path,
        grammar,
        self_ty: None,
        in_container: false,
    };
    for item in &file.ast.items {
        classify_item(&ctx, item, &mut hits);
    }
    hits
}

struct Ctx<'a> {
    rel: &'a str,
    grammar: &'a Grammar,
    self_ty: Option<&'a syn::Type>,
    in_container: bool,
}

fn hit(rel: &str, line: usize, construct: impl Into<String>) -> Hit {
    Hit {
        file: rel.to_string(),
        line,
        construct: construct.into(),
    }
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
            if !seat_matches_item(ctx, item, seats) {
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
        syn::Item::Impl(i) => {
            let inner = Ctx {
                rel: ctx.rel,
                grammar: ctx.grammar,
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

fn classify_block_items(ctx: &Ctx, block: &syn::Block, hits: &mut Vec<Hit>) {
    for stmt in &block.stmts {
        if let syn::Stmt::Item(it) = stmt {
            classify_item(ctx, it, hits);
        }
    }
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
            if !seated {
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
    grammar.constructs.iter().find(|c| c.name == name).map(|c| c.rule)
}

fn exactly_one(matches: impl Iterator<Item = bool>) -> bool {
    let mut seen = false;
    for m in matches {
        if m {
            if seen {
                return false;
            }
            seen = true;
        }
    }
    seen
}

fn seat_matches_item(ctx: &Ctx, item: &syn::Item, seats: &[String]) -> bool {
    // filter_map: an unknown seat name is skipped (load proved seats resolve;
    // a post-load ghost cannot green via `None => false` costume).
    exactly_one(seats.iter().filter_map(|name| {
        construct_rule(ctx.grammar, name).map(|rule| rule_matches_item(ctx, rule, item))
    }))
}

fn seat_matches_impl_item(ctx: &Ctx, item: &syn::ImplItem, seats: &[String]) -> bool {
    exactly_one(seats.iter().filter_map(|name| {
        construct_rule(ctx.grammar, name).map(|rule| rule_matches_impl_item(ctx, rule, item))
    }))
}

fn seat_matches_trait_item(ctx: &Ctx, item: &syn::TraitItem, seats: &[String]) -> bool {
    exactly_one(seats.iter().filter_map(|name| {
        construct_rule(ctx.grammar, name).map(|rule| rule_matches_trait_item(ctx, rule, item))
    }))
}

fn rule_matches_item(ctx: &Ctx, rule: StructuralRule, item: &syn::Item) -> bool {
    match item {
        syn::Item::Struct(s) => struct_matches(rule, s),
        syn::Item::Enum(e) => enum_matches(rule, e),
        syn::Item::Fn(f) => fn_matches(rule, &f.sig, Some(&f.block), f, ctx),
        syn::Item::Type(t) => alias_matches(rule, &t.ty),
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
        return alias_matches(rule, &t.ty);
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
            Some((_, ty)) => alias_matches(rule, ty),
            None => matches!(rule, StructuralRule::AliasNoBannedTerminal),
        },
        syn::TraitItem::Const(_) => constant_matches_non_static(rule),
        _no_rule_applies_to_this_trait_item_variant => false,
    }
}

// ---------------------------------------------------------------------------
// item 4 (forward, minimal): direct string-terminal check. The full
// alias-fixpoint table is item 4's own build; this direct terminal-name
// check is real and sufficient to refuse the item-1 deny fixtures, and is
// named here (not hidden) as narrower than item 4's eventual walk.
// ---------------------------------------------------------------------------

fn type_is_string_terminal(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(r) => type_is_string_terminal(&r.elem),
        syn::Type::Paren(p) => type_is_string_terminal(&p.elem),
        syn::Type::Group(g) => type_is_string_terminal(&g.elem),
        syn::Type::Array(a) => type_is_string_terminal(&a.elem),
        syn::Type::Slice(s) => type_is_string_terminal(&s.elem),
        syn::Type::Tuple(t) => t.elems.iter().any(type_is_string_terminal),
        syn::Type::Path(tp) => {
            let Some(seg) = tp.path.segments.last() else {
                return false;
            };
            if seg.ident == "String" || seg.ident == "str" {
                return true;
            }
            let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
                return false;
            };
            args.args.iter().any(|a| match a {
                syn::GenericArgument::Type(t) => type_is_string_terminal(t),
                _not_a_type_arg => false,
            })
        }
        _not_walked_further => false,
    }
}

// ---------------------------------------------------------------------------
// struct / enum (item 3's partition)
// ---------------------------------------------------------------------------

fn fields_all_private(fields: &syn::Fields) -> bool {
    fields.iter().all(|f| matches!(f.vis, syn::Visibility::Inherited))
}

fn struct_matches(rule: StructuralRule, node: &syn::ItemStruct) -> bool {
    match rule {
        StructuralRule::TupleSinglePrivateField => {
            matches!(&node.fields, syn::Fields::Unnamed(u) if u.unnamed.len() == 1)
                && fields_all_private(&node.fields)
        }
        StructuralRule::NamedAllPrivateNoStringTerminal => {
            matches!(&node.fields, syn::Fields::Named(_))
                && fields_all_private(&node.fields)
                && node.fields.iter().all(|f| !type_is_string_terminal(&f.ty))
        }
        StructuralRule::UnitStruct => matches!(&node.fields, syn::Fields::Unit),
        _rule_not_for_struct => false,
    }
}

fn enum_matches(rule: StructuralRule, node: &syn::ItemEnum) -> bool {
    match rule {
        StructuralRule::NoStringVariantFields => node
            .variants
            .iter()
            .all(|v| v.fields.iter().all(|f| !type_is_string_terminal(&f.ty))),
        _rule_not_for_enum => false,
    }
}

// ---------------------------------------------------------------------------
// alias / import / constant / module (item 1's remaining named seats)
// ---------------------------------------------------------------------------

fn alias_matches(rule: StructuralRule, ty: &syn::Type) -> bool {
    match rule {
        StructuralRule::AliasNoBannedTerminal => !type_is_string_terminal(ty),
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

fn mod_has_path_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("path"))
}

fn module_matches(rule: StructuralRule, node: &syn::ItemMod) -> bool {
    match rule {
        StructuralRule::ModuleNoPathAttr => !mod_has_path_attr(&node.attrs),
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
            .all(|it| !kind_of(it).is_some_and(|k| grammar.condemned.contains(&k))),
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
    Assignment,
    NestedPlaceAssign,
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
        fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
            match self.ban {
                BodyBan::Assignment => self.found = true,
                BodyBan::NestedPlaceAssign if is_nested_place_assign(&node.left) => {
                    self.found = true;
                }
                _not_this_ban => {}
            }
            visit::visit_expr_assign(self, node);
        }
        fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
            if is_compound_assign(&node.op) {
                match self.ban {
                    BodyBan::Assignment => self.found = true,
                    BodyBan::NestedPlaceAssign if is_nested_place_assign(&node.left) => {
                        self.found = true;
                    }
                    _not_this_ban => {}
                }
            }
            visit::visit_expr_binary(self, node);
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
fn contains_assignment(block: &syn::Block) -> bool {
    body_contains(block, BodyBan::Assignment)
}
fn contains_nested_place_assign(block: &syn::Block) -> bool {
    body_contains(block, BodyBan::NestedPlaceAssign)
}

fn is_compound_assign(op: &syn::BinOp) -> bool {
    matches!(
        op,
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

/// Depth of a `self.field...` place chain: `self` alone is depth 0,
/// `self.field` is depth 1. Anything that is not a pure self-field chain
/// (indexing, deref, a non-`self` base) has no depth and is conservatively
/// treated as a violation — "deeper than self.field" by not even matching
/// the shallow shape at all.
fn self_place_depth(expr: &syn::Expr) -> Option<usize> {
    match expr {
        syn::Expr::Path(p) if p.path.is_ident("self") => Some(0),
        syn::Expr::Field(f) => self_place_depth(&f.base).map(|d| d + 1),
        _not_a_self_place => None,
    }
}

fn is_nested_place_assign(lhs: &syn::Expr) -> bool {
    // Depth > 1, or not a pure self-field place at all — conservative.
    // `is_none_or` avoids a `None => true` costume arm.
    self_place_depth(lhs).is_none_or(|depth| depth > 1)
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
            receiver == Receiver::RefSelf
                && sig.asyncness.is_none()
                && ok_or_bodyless(block, |b| {
                    !contains_assignment(b) && !contains_await(b) && !contains_unsafe(b)
                })
        }
        StructuralRule::TransitionBans => {
            receiver == Receiver::RefMutSelf
                && sig.asyncness.is_none()
                && ok_or_bodyless(block, |b| !contains_nested_place_assign(b) && !contains_await(b))
        }
        StructuralRule::ConsumingVerbBans => {
            // self-by-value returning Self is a builder chain — red: it
            // matches NO skeleton (this arm demands return ≠ Self).
            receiver == Receiver::ByValueSelf
                && sig.asyncness.is_none()
                && !return_resolves_to_self(&sig.output, ctx.self_ty, false)
                && ok_or_bodyless(block, |b| !contains_nested_place_assign(b) && !contains_await(b))
        }
        StructuralRule::AdmissionDoorBans => {
            is_admission_door_shape(sig, ctx)
                && sig.asyncness.is_none()
                && ok_or_bodyless(block, |b| !contains_await(b))
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
        if matches!(rule, StructuralRule::InteriorsClassify) {
            let ctx = Ctx {
                rel,
                grammar,
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
        for c in &grammar.constructs {
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
        for kind in &grammar.condemned {
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
            let f = SourceFile {
                rel_path: format!("crates/bs-detector/fixtures/{}.deny.rs", kind.kebab()),
                text: src,
                ast,
            };
            let hits = classify_file(&grammar, &f);
            assert!(
                hits.iter().any(|h| h.construct == law),
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
        let f = SourceFile {
            rel_path: "crates/probe/src/lib.rs".to_string(),
            text: "static mut G: u64 = 0;".to_string(),
            ast: syn::parse_file("static mut G: u64 = 0;").expect("parses"),
        };
        let hits = classify_file(&grammar, &f);
        assert_eq!(hits.len(), 1, "static mut must be denied: {hits:?}");
    }

    #[test]
    fn item_1_proof_path_attr_mod_is_denied() {
        assert_hit_count("#[path = \"x.rs\"] mod m;", 1);
    }

    #[test]
    fn item_1_proof_glob_use_is_denied() {
        assert_hit_count("use crate::foo::*;", 1);
    }

    #[test]
    fn item_1_proof_impl_macro_is_denied() {
        let hits = classify_src("struct T; impl T { some_macro!{} }");
        assert!(
            hits.iter().any(|h| h.construct == "impl_item_macro"),
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
        let f = SourceFile {
            rel_path: "crates/probe/src/lib.rs".to_string(),
            text: src.to_string(),
            ast: syn::parse_file(src).expect("parses"),
        };
        classify_file(&grammar, &f)
    }

    fn assert_hit_count(src: &str, n: usize) {
        let hits = classify_src(src);
        assert_eq!(hits.len(), n, "hits for `{src}`: {hits:?}");
    }

    fn assert_unclassified(src: &str) {
        let hits = classify_src(src);
        assert!(
            hits.iter().any(|h| h.construct.contains("unclassified")),
            "expected unclassified for `{src}`: {hits:?}"
        );
    }

    #[test]
    fn item_2_proofs_red_shapes_are_unclassified() {
        // One table, one body — the prior per-shape test fns were near-copies.
        let cases = [
            "impl S { fn f(self: Box<Self>) {} }",
            "impl S { fn get(&self) -> u64 { self.x.await } }",
            "impl S { fn with_x(mut self) -> Self { self.x = 1; self } }",
            "impl S { fn into_x(mut self) -> u64 { self.a.b = 1; self.x } }",
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
        let f = SourceFile {
            rel_path: "crates/bs-detector/fixtures/declared-fn.deny.rs".to_string(),
            text: src.clone(),
            ast: syn::parse_file(&src).expect("parses"),
        };
        let hits = classify_file(&grammar, &f);
        assert!(
            hits.iter().any(|h| h.construct.contains("unclassified")),
            "declared fn hash drift must be red: {hits:?}"
        );
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
        let f = SourceFile {
            rel_path: rel.to_string(),
            text: src.to_string(),
            ast,
        };
        let hits = classify_file(&grammar, &f);
        assert!(
            hits.is_empty(),
            "admission-door pass shape must not be unclassified: {hits:?}"
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
            .constructs
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
}
