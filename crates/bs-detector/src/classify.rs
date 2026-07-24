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
//! through statement, expression, and type-position nesting (fn bodies,
//! blocks, if/match arms, loops, closures, array lens, const generics,
//! enum discriminants, signatures). Tip 641/650/686: no soft residual that
//! hides an unseated item inside an expression or type body.

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::alias::AliasTable;
use crate::boundary::{RelPath, SourceFile};
use crate::engines::Hit;
use crate::grammar::{Disposition, Grammar, KindName, StructuralRule};

struct Ctx<'a> {
    rel: &'a RelPath,
    grammar: &'a Grammar,
    aliases: &'a AliasTable,
    self_ty: Option<&'a syn::Type>,
    in_container: bool,
}

/// Classify every item in `file` under the workspace alias table (item 4).
pub fn classify_file(grammar: &Grammar, file: &SourceFile, aliases: &AliasTable) -> Vec<Hit> {
    let mut hits = vec![];
    let ctx = Ctx {
        rel: file.rel_path_ref(),
        grammar,
        aliases,
        self_ty: None,
        in_container: false,
    };
    for item in &file.ast().items {
        ctx.classify_item(item, &mut hits);
    }
    hits
}

/// Inclusive line span of one construct instance that declares construct-scoped bans.
///
/// Fields are private (TRUTH item 9). Sole admission is [`ScopedConstructSpan::admit`].
#[derive(Clone, Debug)]
pub struct ScopedConstructSpan {
    start_line: usize,
    end_line: usize,
    bans: Vec<crate::boundary::Label>,
}

impl ScopedConstructSpan {
    pub fn admit(
        start_line: usize,
        end_line: usize,
        bans: Vec<crate::boundary::Label>,
    ) -> Self {
        Self {
            start_line,
            end_line,
            bans,
        }
    }

    pub fn start_line(&self) -> usize {
        self.start_line
    }

    pub fn end_line(&self) -> usize {
        self.end_line
    }

    pub fn bans(&self) -> &[crate::boundary::Label] {
        &self.bans
    }
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
        rel: file.rel_path_ref(),
        grammar,
        aliases,
        self_ty: None,
        in_container: false,
    };
    ctx.collect_scoped_spans_items(&file.ast().items, &mut out);
    out
}

// ---------------------------------------------------------------------------
// kind mapping (closed at the pinned syn version; an unrecognized future
// variant is a reported violation, never a silent pass)
// ---------------------------------------------------------------------------

/// One kind-map authority for Item / ImplItem / TraitItem. The match lives
/// on the sum type as a derivation — free `*_kind` twins are the shape this
/// burns (tip 745 / item-9 unclassified-fn).
enum SynMember<'a> {
    Item(&'a syn::Item),
    Impl(&'a syn::ImplItem),
    Trait(&'a syn::TraitItem),
}

impl SynMember<'_> {
    /// Kind of this syn member, or `None` for an unrecognized future variant
    /// (named binding below — never a bare `_` soft drain).
    fn kind(&self) -> Option<KindName> {
        match self {
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

    fn item_label(&self) -> String {
        let SynMember::Item(item) = self else {
            return "?".to_string();
        };
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
}

impl<'a> Ctx<'a> {
    fn hit(&self, line: usize, construct: impl AsRef<str>) -> Hit {
        Hit::admit(self.rel, line, construct.as_ref())
    }

    fn line_of<T: ?Sized + syn::spanned::Spanned>(&self, node: &T) -> usize {
        crate::boundary::BOUNDARY.span_line(&node.span())
    }

    fn nested(&self) -> Ctx<'a> {
        Ctx {
            rel: self.rel,
            grammar: self.grammar,
            aliases: self.aliases,
            self_ty: None,
            in_container: false,
        }
    }

    fn in_container(&self, self_ty: Option<&'a syn::Type>) -> Ctx<'a> {
        Ctx {
            rel: self.rel,
            grammar: self.grammar,
            aliases: self.aliases,
            self_ty,
            in_container: true,
        }
    }

    fn construct_rule(&self, name: &str) -> Option<StructuralRule> {
        self.grammar
            .constructs()
            .iter()
            .find(|c| c.name() == name)
            .map(|c| c.rule())
    }

    fn exactly_one_seat_name<'b>(&self, matches: impl Iterator<Item = &'b str>) -> Option<&'b str> {
        let mut found: Option<&'b str> = None;
        for name in matches {
            if found.is_some() {
                return None;
            }
            found = Some(name);
        }
        found
    }

    fn collect_scoped_spans_items(&self, items: &[syn::Item], out: &mut Vec<ScopedConstructSpan>) {
        for item in items {
            match item {
                syn::Item::Fn(f) => {
                    self.push_scoped_fn_span(&f.sig, f, out);
                    self.collect_scoped_spans_block(&f.block, out);
                }
                syn::Item::Impl(im) => {
                    let inner = self.in_container(Some(&im.self_ty));
                    for it in &im.items {
                        if let syn::ImplItem::Fn(f) = it {
                            inner.push_scoped_fn_span(&f.sig, f, out);
                            inner.collect_scoped_spans_block(&f.block, out);
                        }
                    }
                }
                syn::Item::Trait(t) => {
                    let inner = self.in_container(None);
                    for it in &t.items {
                        if let syn::TraitItem::Fn(f) = it {
                            inner.push_scoped_fn_span(&f.sig, f, out);
                            if let Some(block) = &f.default {
                                inner.collect_scoped_spans_block(block, out);
                            }
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        self.collect_scoped_spans_items(items, out);
                    }
                }
                _other => {}
            }
        }
    }

    fn collect_scoped_spans_block(&self, block: &syn::Block, out: &mut Vec<ScopedConstructSpan>) {
        for stmt in &block.stmts {
            if let syn::Stmt::Item(it) = stmt {
                self.collect_scoped_spans_items(std::slice::from_ref(it), out);
            }
        }
    }

    fn push_scoped_fn_span<T: syn::spanned::Spanned>(
        &self,
        sig: &syn::Signature,
        whole: &T,
        out: &mut Vec<ScopedConstructSpan>,
    ) {
        for c in self.grammar.constructs() {
            if c.bans().is_empty() {
                continue;
            }
            if !self.shape_only_fn_matches(c.rule(), sig) {
                continue;
            }
            let span = whole.span();
            out.push(ScopedConstructSpan::admit(
                crate::boundary::BOUNDARY.span_line(&span),
                span.end().line,
                c.bans().to_vec(),
            ));
        }
    }

    fn shape_only_fn_matches(&self, rule: StructuralRule, sig: &syn::Signature) -> bool {
        let receiver = SigView(sig).receiver_form();
        match rule {
            StructuralRule::TransitionBans => {
                receiver == Receiver::RefMutSelf && sig.asyncness.is_none()
            }
            StructuralRule::ConsumingVerbBans => {
                receiver == Receiver::ByValueSelf
                    && sig.asyncness.is_none()
                    && !self.return_resolves_to_self(&sig.output, false)
            }
            StructuralRule::DerivationBans => {
                receiver == Receiver::RefSelf && sig.asyncness.is_none()
            }
            StructuralRule::AdmissionDoorBans => {
                self.is_admission_door_shape(sig) && sig.asyncness.is_none()
            }
            StructuralRule::CompositionRootBody => {
                self.is_composition_root_shape(sig) && sig.asyncness.is_none()
            }
            StructuralRule::DeclaredFnSeat => receiver == Receiver::None,
            _rule_not_fn_scoped => false,
        }
    }

    fn classify_item(&self, item: &syn::Item, hits: &mut Vec<Hit>) {
        let Some(kind) = SynMember::Item(item).kind() else {
            hits.push(self.hit(self.line_of(item), "unknown-syn-item-kind"));
            return;
        };
        match self.grammar.disposition(kind) {
            None => hits.push(self.hit(self.line_of(item), "kind-table-mutated-post-load")),
            Some(Disposition::Condemned { law }) => {
                hits.push(self.hit(self.line_of(item), law.as_str()))
            }
            Some(Disposition::Seated(seats)) => {
                if self.seat_matches_item(item, seats).is_none() {
                    hits.push(self.hit(
                        self.line_of(item),
                        format!(
                            "unclassified-{}:{}",
                            kind.kebab(),
                            SynMember::Item(item).item_label()
                        ),
                    ));
                }
            }
        }
        self.recurse_into_item(item, hits);
    }

    fn recurse_into_item(&self, item: &syn::Item, hits: &mut Vec<Hit>) {
        match item {
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    for it in items {
                        self.classify_item(it, hits);
                    }
                }
            }
            syn::Item::Fn(f) => {
                self.classify_signature_items(&f.sig, hits);
                self.classify_block_items(&f.block, hits);
            }
            syn::Item::Const(c) => {
                self.classify_type_items(&c.ty, hits);
                self.classify_expr_items(&c.expr, hits);
            }
            syn::Item::Static(s) => {
                self.classify_type_items(&s.ty, hits);
                self.classify_expr_items(&s.expr, hits);
            }
            syn::Item::Enum(e) => {
                self.classify_generics_items(&e.generics, hits);
                for v in &e.variants {
                    for f in &v.fields {
                        self.classify_type_items(&f.ty, hits);
                    }
                    if let Some((_, expr)) = &v.discriminant {
                        self.classify_expr_items(expr, hits);
                    }
                }
            }
            syn::Item::Struct(s) => {
                self.classify_generics_items(&s.generics, hits);
                for f in &s.fields {
                    self.classify_type_items(&f.ty, hits);
                }
            }
            syn::Item::Union(u) => {
                self.classify_generics_items(&u.generics, hits);
                for f in &u.fields.named {
                    self.classify_type_items(&f.ty, hits);
                }
            }
            syn::Item::Type(t) => {
                self.classify_generics_items(&t.generics, hits);
                self.classify_type_items(&t.ty, hits);
            }
            syn::Item::Impl(i) => {
                self.classify_generics_items(&i.generics, hits);
                if let Some((_, trait_path, _)) = &i.trait_ {
                    self.classify_path_items(trait_path, hits);
                }
                self.classify_type_items(&i.self_ty, hits);
                let inner = self.in_container(Some(&i.self_ty));
                for it in &i.items {
                    inner.classify_impl_item(it, hits);
                }
            }
            syn::Item::Trait(t) => {
                self.classify_generics_items(&t.generics, hits);
                self.classify_bounds_items(&t.supertraits, hits);
                let inner = self.in_container(None);
                for it in &t.items {
                    inner.classify_trait_item(it, hits);
                }
            }
            syn::Item::TraitAlias(t) => {
                self.classify_generics_items(&t.generics, hits);
                self.classify_bounds_items(&t.bounds, hits);
            }
            syn::Item::ForeignMod(m) => {
                for it in &m.items {
                    self.classify_foreign_item(it, hits);
                }
            }
            _not_a_container => {}
        }
    }

    fn classify_block_items(&self, block: &syn::Block, hits: &mut Vec<Hit>) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        for stmt in &block.stmts {
            v.visit_stmt(stmt);
        }
    }

    fn classify_expr_items(&self, expr: &syn::Expr, hits: &mut Vec<Hit>) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        v.visit_expr(expr);
    }

    fn classify_type_items(&self, ty: &syn::Type, hits: &mut Vec<Hit>) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        v.visit_type(ty);
    }

    fn classify_path_items(&self, path: &syn::Path, hits: &mut Vec<Hit>) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        v.visit_path(path);
    }

    fn classify_generics_items(&self, generics: &syn::Generics, hits: &mut Vec<Hit>) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        v.visit_generics(generics);
    }

    fn classify_signature_items(&self, sig: &syn::Signature, hits: &mut Vec<Hit>) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        v.visit_signature(sig);
    }

    fn classify_bounds_items(
        &self,
        bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::token::Plus>,
        hits: &mut Vec<Hit>,
    ) {
        let nested_ctx = self.nested();
        let mut v = NestedItemVisit {
            ctx: &nested_ctx,
            hits,
        };
        for bound in bounds {
            v.visit_type_param_bound(bound);
        }
    }

    fn classify_foreign_item(&self, item: &syn::ForeignItem, hits: &mut Vec<Hit>) {
        match item {
            syn::ForeignItem::Fn(f) => self.classify_signature_items(&f.sig, hits),
            syn::ForeignItem::Static(s) => self.classify_type_items(&s.ty, hits),
            syn::ForeignItem::Type(t) => self.classify_generics_items(&t.generics, hits),
            syn::ForeignItem::Macro(_) => {}
            _unrecognized_foreign_item => {}
        }
    }

    fn classify_impl_item(&self, item: &syn::ImplItem, hits: &mut Vec<Hit>) {
        self.classify_container_member(ContainerMember::Impl(item), hits);
    }

    fn classify_trait_item(&self, item: &syn::TraitItem, hits: &mut Vec<Hit>) {
        self.classify_container_member(ContainerMember::Trait(item), hits);
    }

    fn classify_container_member(&self, member: ContainerMember<'_>, hits: &mut Vec<Hit>) {
        let (kind, unknown) = match member {
            ContainerMember::Impl(item) => (SynMember::Impl(item).kind(), "unknown-syn-implitem-kind"),
            ContainerMember::Trait(item) => (SynMember::Trait(item).kind(), "unknown-syn-traititem-kind"),
        };
        let Some(kind) = kind else {
            hits.push(self.hit(0, unknown));
            return;
        };
        match self.grammar.disposition(kind) {
            None => hits.push(self.hit(0, "kind-table-mutated-post-load")),
            Some(Disposition::Condemned { law }) => {
                hits.push(self.hit(member.condemned_line(), law.as_str()));
            }
            Some(Disposition::Seated(seats)) => {
                let seated = match member {
                    ContainerMember::Impl(item) => self.seat_matches_impl_item(item, seats),
                    ContainerMember::Trait(item) => self.seat_matches_trait_item(item, seats),
                };
                if seated.is_none() {
                    let (line, label) = member.label();
                    hits.push(self.hit(
                        line,
                        format!("unclassified-{}:{}", kind.kebab(), label),
                    ));
                }
            }
        }
        match member {
            ContainerMember::Impl(syn::ImplItem::Fn(f)) => {
                self.classify_signature_items(&f.sig, hits);
                self.classify_block_items(&f.block, hits);
            }
            ContainerMember::Trait(syn::TraitItem::Fn(f)) => {
                self.classify_signature_items(&f.sig, hits);
                if let Some(block) = &f.default {
                    self.classify_block_items(block, hits);
                }
            }
            ContainerMember::Impl(syn::ImplItem::Const(c)) => {
                self.classify_type_items(&c.ty, hits);
                self.classify_expr_items(&c.expr, hits);
            }
            ContainerMember::Trait(syn::TraitItem::Const(c)) => {
                self.classify_type_items(&c.ty, hits);
                if let Some((_, expr)) = &c.default {
                    self.classify_expr_items(expr, hits);
                }
            }
            ContainerMember::Impl(syn::ImplItem::Type(t)) => {
                self.classify_generics_items(&t.generics, hits);
                self.classify_type_items(&t.ty, hits);
            }
            ContainerMember::Trait(syn::TraitItem::Type(t)) => {
                self.classify_generics_items(&t.generics, hits);
                self.classify_bounds_items(&t.bounds, hits);
                if let Some((_, ty)) = &t.default {
                    self.classify_type_items(ty, hits);
                }
            }
            ContainerMember::Impl(_not_fn_const_or_type) => {}
            ContainerMember::Trait(_not_fn_const_or_type) => {}
        }
    }

    fn seat_matches_item<'b>(
        &self,
        item: &syn::Item,
        seats: &'b [crate::boundary::Label],
    ) -> Option<&'b str> {
        self.exactly_one_seat_name(seats.iter().filter_map(|name| {
            self.construct_rule(name.as_str())
                .filter(|rule| self.rule_matches_item(*rule, item))
                .map(|_| name.as_str())
        }))
    }

    fn seat_matches_impl_item<'b>(
        &self,
        item: &syn::ImplItem,
        seats: &'b [crate::boundary::Label],
    ) -> Option<&'b str> {
        self.exactly_one_seat_name(seats.iter().filter_map(|name| {
            self.construct_rule(name.as_str())
                .filter(|rule| self.rule_matches_impl_item(*rule, item))
                .map(|_| name.as_str())
        }))
    }

    fn seat_matches_trait_item<'b>(
        &self,
        item: &syn::TraitItem,
        seats: &'b [crate::boundary::Label],
    ) -> Option<&'b str> {
        self.exactly_one_seat_name(seats.iter().filter_map(|name| {
            self.construct_rule(name.as_str())
                .filter(|rule| self.rule_matches_trait_item(*rule, item))
                .map(|_| name.as_str())
        }))
    }

    fn rule_matches_item(&self, rule: StructuralRule, item: &syn::Item) -> bool {
        match item {
            syn::Item::Struct(s) => self.struct_matches(rule, s),
            syn::Item::Enum(e) => self.enum_matches(rule, e),
            syn::Item::Fn(f) => self.fn_matches(rule, &f.sig, Some(&f.block), f),
            syn::Item::Type(t) => self.alias_matches(rule, &t.ty),
            syn::Item::Use(u) => rule.matches_import(u),
            syn::Item::Const(_) => rule.matches_non_static_const(),
            syn::Item::Static(s) => rule.matches_static(s),
            syn::Item::Mod(m) => rule.matches_module(m),
            syn::Item::Impl(i) => rule.matches_container(self.grammar, |it| SynMember::Impl(it).kind(), &i.items),
            syn::Item::Trait(t) => rule.matches_container(self.grammar, |it| SynMember::Trait(it).kind(), &t.items),
            _no_rule_applies_to_this_item_variant => false,
        }
    }

    fn rule_matches_impl_item(&self, rule: StructuralRule, item: &syn::ImplItem) -> bool {
        if let syn::ImplItem::Fn(f) = item {
            return self.fn_matches(rule, &f.sig, Some(&f.block), f);
        }
        if let syn::ImplItem::Type(t) = item {
            return self.alias_matches(rule, &t.ty);
        }
        if let syn::ImplItem::Const(_) = item {
            return rule.matches_non_static_const();
        }
        false
    }

    fn rule_matches_trait_item(&self, rule: StructuralRule, item: &syn::TraitItem) -> bool {
        match item {
            syn::TraitItem::Fn(f) => self.fn_matches(rule, &f.sig, f.default.as_ref(), f),
            syn::TraitItem::Type(t) => match &t.default {
                Some((_, ty)) => self.alias_matches(rule, ty),
                None => matches!(rule, StructuralRule::AliasNoBannedTerminal),
            },
            syn::TraitItem::Const(_) => rule.matches_non_static_const(),
            _no_rule_applies_to_this_trait_item_variant => false,
        }
    }

    fn type_is_string_terminal(&self, ty: &syn::Type) -> bool {
        self.aliases.type_carries_string(self.rel.as_str(), ty)
    }

    fn struct_matches(&self, rule: StructuralRule, node: &syn::ItemStruct) -> bool {
        match rule {
            StructuralRule::TupleSinglePrivateField => {
                matches!(&node.fields, syn::Fields::Unnamed(u) if u.unnamed.len() == 1)
                    && FieldsView(&node.fields).all_private()
            }
            StructuralRule::NamedAllPrivateNoStringTerminal => {
                matches!(&node.fields, syn::Fields::Named(_))
                    && FieldsView(&node.fields).all_private()
                    && node.fields.iter().all(|f| !self.type_is_string_terminal(&f.ty))
            }
            StructuralRule::UnitStruct => matches!(&node.fields, syn::Fields::Unit),
            _rule_not_for_struct => false,
        }
    }

    fn enum_matches(&self, rule: StructuralRule, node: &syn::ItemEnum) -> bool {
        match rule {
            StructuralRule::NoStringVariantFields => node
                .variants
                .iter()
                .all(|v| v.fields.iter().all(|f| !self.type_is_string_terminal(&f.ty))),
            _rule_not_for_enum => false,
        }
    }

    fn alias_matches(&self, rule: StructuralRule, ty: &syn::Type) -> bool {
        match rule {
            StructuralRule::AliasNoBannedTerminal => !self.type_is_string_terminal(ty),
            _rule_not_for_alias => false,
        }
    }

    fn return_resolves_to_self(&self, output: &syn::ReturnType, allow_result_option: bool) -> bool {
        ReturnTypeView(output).resolves_to_self(self.self_ty, allow_result_option)
    }

    fn is_composition_root_shape(&self, sig: &syn::Signature) -> bool {
        SigView(sig).receiver_form() == Receiver::None
            && !self.in_container
            && sig.ident == "main"
            && (self.rel.ends_with("/src/main.rs") || self.rel.contains("/src/bin/"))
    }

    fn is_admission_door_shape(&self, sig: &syn::Signature) -> bool {
        SigView(sig).receiver_form() == Receiver::None
            && self.in_container
            && self.return_resolves_to_self(&sig.output, true)
    }

    fn declared_fn_matches(
        &self,
        sig: &syn::Signature,
        block: Option<&syn::Block>,
        whole: &dyn ToTokens,
    ) -> bool {
        if self.is_composition_root_shape(sig) || self.is_admission_door_shape(sig) {
            return false;
        }
        let Some(seat) = self.grammar.fn_seat(self.rel.as_str(), &sig.ident.to_string()) else {
            return false;
        };
        if crate::identity::IDENTITY.site_hash(whole) != seat.site_hash() {
            return false;
        }
        if !seat.io() {
            if sig.asyncness.is_some() {
                return false;
            }
            if !Bodyless(block).ok_or(|b| !BlockBody(b).contains(BodyBan::Await)) {
                return false;
            }
        }
        true
    }

    fn fn_matches(
        &self,
        rule: StructuralRule,
        sig: &syn::Signature,
        block: Option<&syn::Block>,
        whole: &dyn ToTokens,
    ) -> bool {
        let receiver = SigView(sig).receiver_form();
        match rule {
            StructuralRule::CompositionRootBody => {
                self.is_composition_root_shape(sig)
                    && sig.asyncness.is_none()
                    && block.is_some_and(|b| BlockBody(b).composition_root_ok())
            }
            StructuralRule::DerivationBans => {
                receiver == Receiver::RefSelf
                    && sig.asyncness.is_none()
                    && Bodyless(block).ok_or(|b| !BlockBody(b).contains(BodyBan::Unsafe))
            }
            StructuralRule::TransitionBans => {
                receiver == Receiver::RefMutSelf && sig.asyncness.is_none()
            }
            StructuralRule::ConsumingVerbBans => {
                receiver == Receiver::ByValueSelf
                    && sig.asyncness.is_none()
                    && !self.return_resolves_to_self(&sig.output, false)
            }
            StructuralRule::AdmissionDoorBans => {
                self.is_admission_door_shape(sig) && sig.asyncness.is_none()
            }
            StructuralRule::DeclaredFnSeat => {
                receiver == Receiver::None && self.declared_fn_matches(sig, block, whole)
            }
            _rule_not_for_fn => false,
        }
    }
}

struct NestedItemVisit<'a, 'c> {
    ctx: &'a Ctx<'c>,
    hits: &'a mut Vec<Hit>,
}

impl<'ast> Visit<'ast> for NestedItemVisit<'_, '_> {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        self.ctx.classify_item(node, self.hits);
    }
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        match node {
            syn::Stmt::Item(it) => {
                self.ctx.classify_item(it, self.hits);
            }
            other => visit::visit_stmt(self, other),
        }
    }
}

#[derive(Clone, Copy)]
enum ContainerMember<'a> {
    Impl(&'a syn::ImplItem),
    Trait(&'a syn::TraitItem),
}

impl ContainerMember<'_> {
    fn condemned_line(self) -> usize {
        match self {
            ContainerMember::Impl(syn::ImplItem::Macro(m)) => crate::boundary::BOUNDARY.span_line(&m.span()),
            ContainerMember::Impl(item) => crate::boundary::BOUNDARY.span_line(&item.span()),
            ContainerMember::Trait(syn::TraitItem::Macro(m)) => crate::boundary::BOUNDARY.span_line(&m.span()),
            ContainerMember::Trait(item) => crate::boundary::BOUNDARY.span_line(&item.span()),
        }
    }

    fn label(self) -> (usize, String) {
        match self {
            ContainerMember::Impl(syn::ImplItem::Const(c)) => {
                (crate::boundary::BOUNDARY.span_line(&c.span()), c.ident.to_string())
            }
            ContainerMember::Impl(syn::ImplItem::Fn(f)) => {
                (crate::boundary::BOUNDARY.span_line(&f.span()), f.sig.ident.to_string())
            }
            ContainerMember::Impl(syn::ImplItem::Type(t)) => {
                (crate::boundary::BOUNDARY.span_line(&t.span()), t.ident.to_string())
            }
            ContainerMember::Impl(item) => (crate::boundary::BOUNDARY.span_line(&item.span()), "?".to_string()),
            ContainerMember::Trait(syn::TraitItem::Const(c)) => {
                (crate::boundary::BOUNDARY.span_line(&c.span()), c.ident.to_string())
            }
            ContainerMember::Trait(syn::TraitItem::Fn(f)) => {
                (crate::boundary::BOUNDARY.span_line(&f.span()), f.sig.ident.to_string())
            }
            ContainerMember::Trait(syn::TraitItem::Type(t)) => {
                (crate::boundary::BOUNDARY.span_line(&t.span()), t.ident.to_string())
            }
            ContainerMember::Trait(item) => (crate::boundary::BOUNDARY.span_line(&item.span()), "?".to_string()),
        }
    }
}

impl StructuralRule {
    fn matches_import(self, node: &syn::ItemUse) -> bool {
        match self {
            StructuralRule::ImportNoGlob => !UseTreeView(&node.tree).has_glob(),
            _rule_not_for_import => false,
        }
    }

    fn matches_non_static_const(self) -> bool {
        matches!(self, StructuralRule::ConstantNoStaticMut)
    }

    fn matches_static(self, node: &syn::ItemStatic) -> bool {
        match self {
            StructuralRule::ConstantNoStaticMut => {
                !matches!(node.mutability, syn::StaticMutability::Mut(_))
            }
            _rule_not_for_constant => false,
        }
    }

    fn matches_module(self, _node: &syn::ItemMod) -> bool {
        match self {
            StructuralRule::ModuleNoPathAttr => true,
            _rule_not_for_module => false,
        }
    }

    fn matches_container<I, F>(self, grammar: &Grammar, kind_of: F, items: &[I]) -> bool
    where
        F: Fn(&I) -> Option<KindName>,
    {
        match self {
            StructuralRule::InteriorsClassify => items
                .iter()
                .all(|it| !kind_of(it).is_some_and(|k| grammar.condemned().contains(&k))),
            _rule_not_for_container => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Receiver {
    None,
    RefSelf,
    RefMutSelf,
    ByValueSelf,
    Other,
}

struct SigView<'a>(&'a syn::Signature);

impl SigView<'_> {
    fn receiver_form(self) -> Receiver {
        match self.0.inputs.first() {
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
}

struct Bodyless<'a>(Option<&'a syn::Block>);

impl Bodyless<'_> {
    fn ok_or(self, pred: impl FnOnce(&syn::Block) -> bool) -> bool {
        self.0.is_none_or(pred)
    }
}

#[derive(Clone, Copy)]
enum BodyBan {
    ControlFlow,
    Await,
    Unsafe,
}

#[derive(Copy, Clone)]
struct BlockBody<'a>(&'a syn::Block);

impl BlockBody<'_> {
    fn contains(self, ban: BodyBan) -> bool {
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
        v.visit_block(self.0);
        v.found
    }

    fn composition_root_ok(self) -> bool {
        if self.contains(BodyBan::ControlFlow) || self.contains(BodyBan::Await) {
            return false;
        }
        let Some((last, prefix)) = self.0.stmts.split_last() else {
            return false;
        };
        for stmt in prefix {
            let syn::Stmt::Local(local) = stmt else {
                return false;
            };
            let Some(init) = &local.init else {
                return false;
            };
            if init.diverge.is_some() {
                return false;
            }
            if !FnCallExpr(&init.expr).is_call() {
                return false;
            }
        }
        match last {
            syn::Stmt::Expr(expr, None) => FnCallExpr(expr).is_call(),
            _not_a_tail_call => false,
        }
    }
}

struct FnCallExpr<'a>(&'a syn::Expr);

impl FnCallExpr<'_> {
    fn is_call(self) -> bool {
        match self.0 {
            syn::Expr::Call(_) | syn::Expr::MethodCall(_) => true,
            syn::Expr::Try(t) => FnCallExpr(&t.expr).is_call(),
            syn::Expr::Paren(p) => FnCallExpr(&p.expr).is_call(),
            syn::Expr::Group(g) => FnCallExpr(&g.expr).is_call(),
            _not_a_call => false,
        }
    }
}

struct UseTreeView<'a>(&'a syn::UseTree);

impl UseTreeView<'_> {
    fn has_glob(self) -> bool {
        let mut stack = vec![self.0];
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
}

struct FieldsView<'a>(&'a syn::Fields);

impl FieldsView<'_> {
    fn all_private(self) -> bool {
        self.0.iter().all(|f| matches!(f.vis, syn::Visibility::Inherited))
    }
}

struct ReturnTypeView<'a>(&'a syn::ReturnType);

impl ReturnTypeView<'_> {
    fn resolves_to_self(self, self_ty: Option<&syn::Type>, allow_result_option: bool) -> bool {
        let syn::ReturnType::Type(_, ty) = self.0 else {
            return false;
        };
        if SelfTypeView(ty).matches(self_ty) {
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
            syn::GenericArgument::Type(t) => SelfTypeView(t).matches(self_ty),
            _not_a_type_arg => false,
        })
    }
}

struct SelfTypeView<'a>(&'a syn::Type);

impl SelfTypeView<'_> {
    fn matches(self, self_ty: Option<&syn::Type>) -> bool {
        let syn::Type::Path(tp) = self.0 else {
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
}

// ---------------------------------------------------------------------------
// generic fixture test: pass classifies as exactly the construct; deny is
// refused by the SAME construct's own rule (not a neighbor's).
// ---------------------------------------------------------------------------

/// Typed test refusal — file-level so `total_refusal` indexes it as a workspace
/// enum (tip 777). Nested inside `mod fixture_tests` was `not-workspace-enum`.
#[cfg(test)]
#[derive(Debug)]
enum ClassifyProofRefuse {
    ReadGrammar,
    ReadBite,
    Tempfile,
    WriteFixture,
    LoadGrammar,
    Parse,
    MissingItem,
    Aliases,
    PassFixtureReadable,
    PassFixtureParses,
    PassFixtureHasItem,
    PassMustClassify,
    DenyFixtureReadable,
    DenyFixtureParses,
    DenyFixtureHasItem,
    DenyMustRefuse,
    Tip689CaseCount,
    Tip689PassReadable,
    Tip689PassParses,
    Tip689Aliases,
    Tip689PassMustSilent,
    Tip689DenyReadable,
    Tip689DenyParses,
    Tip689DenyExact,
    Tip689VacuousSeat,
    CondemnedLawMissing,
    CondemnedDenyReadable,
    VerbatimDenyNamesWhy,
    CondemnedDenyParses,
    CondemnedDenyMustHit,
    ConstMustBeSeated,
    StaticMutMustDeny,
    PathMatcher,
    PathAttrMustHit,
    PathModuleMustSeat,
    GlobUseMustDeny,
    ImplMacroMustHit,
    DenyShapeMustHit,
    BoxSelfMustUnclass,
    MutSelfMustUnclass,
    SmuggledMustUnclass,
    BareAsyncMustUnclass,
    DeclaredFnDenyReadable,
    DeclaredFnDenyParses,
    DeclaredFnDenyEmpty,
    DeclaredFnDenyNotUnclass,
    ScopedBanMustSeat,
    AwaitMatcher,
    NestMatcher,
    AwaitMatcherHit,
    NestMatcherHit,
    AdmissionDoorMustSeat,
    AdmissionDoorMustSilent,
    AttackLockAdmissionDoor,
    HelperMustSilentGreen,
    NestedBleedHelper,
    NestedBleedMethodSwept,
    NestedResultHelper,
    NestedTraitHelper,
    NestedFreeHelper,
    NestedFreeOuter,
    CompositionRootMustRefuse,
    FnSkeletonExactlyOne,
    MultiFieldTupleRed,
    PubTupleFieldRed,
    PubNamedFieldRed,
    StructConstructExactlyOne,
    StructMustBeSeatedNotCondemned,
    StructMustBeSeated,
    UniqueConstructName,
    AliasStringStructRed,
    UseAsStringStructRed,
    ExprNestFnExact,
    ExprNestFnOuter,
    ExprNestStringStructExact,
    ExprNestUnitStillGreen,
    MatchArmNestExact,
    ExpressionNestExact,
    RestrictStructClean,
}
#[cfg(test)]
impl ClassifyProofRefuse {
    fn require(self, cond: bool) -> Result<(), ClassifyProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}


#[cfg(test)]
mod fixture_tests {
    use super::{
        classify_file, ClassifyProofRefuse, Ctx, Hit, KindName, RelPath, SourceFile,
        StructuralRule,
    };
    use crate::boundary::Label;
    use crate::grammar::Grammar;
    use std::path::PathBuf;

    type TestResult = std::result::Result<(), ClassifyProofRefuse>;

    /// Receiver for classify fixture-test helpers (tip 806/896).
    struct ClassifyProofs;

    impl ClassifyProofs {
        fn real_grammar(&self) -> std::result::Result<Grammar, ClassifyProofRefuse> {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let text = std::fs::read_to_string(manifest.join("grammar.toml"))
                .map_err(|_| ClassifyProofRefuse::ReadGrammar)?;
            let bite_src = std::fs::read_to_string(manifest.join("tests/bite_proofs.rs"))
                .map_err(|_| ClassifyProofRefuse::ReadBite)?;
            let mut f = tempfile::NamedTempFile::new().map_err(|_| ClassifyProofRefuse::Tempfile)?;
            std::io::Write::write_all(&mut f, text.as_bytes())
                .map_err(|_| ClassifyProofRefuse::WriteFixture)?;
            Grammar::load(f.path(), &bite_src, &manifest.join("fixtures"))
                .map_err(|_| ClassifyProofRefuse::LoadGrammar)
        }

        /// `declared-fn`'s seats bind to the FIXTURE FILE's own repo-root-relative
        /// path (grammar.toml declares seats against exactly these paths); every
        /// other construct's rule is path-independent, so a generic placeholder
        /// stands in for `rel`.
        fn rel_for(&self, construct: &str) -> &'static str {
            match construct {
                "composition-root" => "crates/probe/src/main.rs",
                _generic => "crates/probe/src/lib.rs",
            }
        }

        fn probe_matches(
            &self,
            grammar: &Grammar,
            rel: &str,
            rule: StructuralRule,
            first_item: &syn::Item,
        ) -> bool {
            // Container rules judge the Impl/Trait item itself. Fn-skeleton
            // rules that live inside an impl are probed against the first
            // interior fn (fixtures start with `struct …; impl … { fn … }`).
            let empty = crate::alias::AliasTable::empty();
            let rel = RelPath::admit(rel);
            if matches!(rule, StructuralRule::InteriorsClassify) {
                let ctx = Ctx {
                    rel: &rel,
                    grammar,
                    aliases: &empty,
                    self_ty: None,
                    in_container: false,
                };
                return ctx.rule_matches_item(rule, first_item);
            }
            match first_item {
                syn::Item::Impl(imp) => {
                    let ctx = Ctx {
                        rel: &rel,
                        grammar,
                        aliases: &empty,
                        self_ty: Some(&imp.self_ty),
                        in_container: true,
                    };
                    match imp.items.first() {
                        Some(syn::ImplItem::Fn(f)) => ctx.fn_matches(rule, &f.sig, Some(&f.block), f),
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
                        rel: &rel,
                        grammar,
                        aliases: &empty,
                        self_ty: None,
                        in_container: false,
                    };
                    ctx.rule_matches_item(rule, other)
                }
            }
        }

        fn parse_file(&self, src: &str) -> std::result::Result<syn::File, ClassifyProofRefuse> {
            syn::parse_file(src).map_err(|_| ClassifyProofRefuse::Parse)
        }

        fn aliases_for(
            &self,
            f: &SourceFile,
        ) -> std::result::Result<crate::alias::AliasTable, ClassifyProofRefuse> {
            crate::alias::AliasTable::build(&[f]).map_err(|_| ClassifyProofRefuse::Aliases)
        }

        fn classify_src(&self, src: &str) -> std::result::Result<Vec<Hit>, ClassifyProofRefuse> {
            let grammar = self.real_grammar()?;
            let f = SourceFile::admit(
                "crates/probe/src/lib.rs".to_string(),
                src.to_string(),
                self.parse_file(src)?,
            );
            let aliases = self.aliases_for(&f)?;
            Ok(classify_file(&grammar, &f, &aliases))
        }

        fn require_hit_count(&self, src: &str, n: usize, refuse: ClassifyProofRefuse) -> TestResult {
            let hits = self.classify_src(src)?;
            refuse.require(hits.len() == n)
        }

        /// Exact adversary — soft any(contains("unclassified")) is FORBIDDEN.
        fn require_exact_constructs(
            &self,
            src: &str,
            want: &[&str],
            refuse: ClassifyProofRefuse,
        ) -> TestResult {
            let hits = self.classify_src(src)?;
            let mut got: Vec<String> = hits.iter().map(|h| h.construct().to_string()).collect();
            got.sort();
            let mut want_s: Vec<String> = want.iter().map(|s| (*s).to_string()).collect();
            want_s.sort();
            refuse.require(got == want_s)
        }

        fn hit_constructs_for(&self, hits: &[Hit], name: &str) -> Vec<String> {
            hits.iter()
                .filter(|h| h.construct().contains(name))
                .map(|h| h.construct().to_string())
                .collect()
        }

        /// Tip 650 nest surfaces — each costume must emit exactly
        /// `unclassified-fn:nested_hide`. Empty hits = walk blind soft drain.
        fn require_expression_nest_exact(&self, src: &str) -> TestResult {
            let hits = self.classify_src(src)?;
            let nested = self.hit_constructs_for(&hits, "nested_hide");
            ClassifyProofRefuse::ExpressionNestExact
                .require(nested == vec!["unclassified-fn:nested_hide".to_string()])
        }
    }

    const C: ClassifyProofs = ClassifyProofs;

    #[test]
    fn every_construct_pass_classifies_and_deny_is_refused_by_its_own_rule() -> TestResult {
        let grammar = C.real_grammar()?;
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for c in grammar.constructs() {
            let rel = if c.name() == "declared-fn" {
                "crates/bs-detector/fixtures/declared-fn.pass.rs"
            } else {
                C.rel_for(c.name())
            };
            let pass_path = manifest.join("fixtures").join(format!("{}.pass.rs", c.name()));
            let pass_src = std::fs::read_to_string(&pass_path)
                .map_err(|_| ClassifyProofRefuse::PassFixtureReadable)?;
            let pass_ast = syn::parse_file(&pass_src)
                .map_err(|_| ClassifyProofRefuse::PassFixtureParses)?;
            let first = pass_ast
                .items
                .first()
                .ok_or(ClassifyProofRefuse::PassFixtureHasItem)?;
            ClassifyProofRefuse::PassMustClassify.require(C.probe_matches(&grammar, rel, c.rule(), first))?;

            if c.rule().deny_exempt() {
                continue;
            }
            let deny_rel = if c.name() == "declared-fn" {
                "crates/bs-detector/fixtures/declared-fn.deny.rs"
            } else {
                C.rel_for(c.name())
            };
            let deny_path = manifest.join("fixtures").join(format!("{}.deny.rs", c.name()));
            let deny_src = std::fs::read_to_string(&deny_path)
                .map_err(|_| ClassifyProofRefuse::DenyFixtureReadable)?;
            let deny_ast = syn::parse_file(&deny_src)
                .map_err(|_| ClassifyProofRefuse::DenyFixtureParses)?;
            let first = deny_ast
                .items
                .first()
                .ok_or(ClassifyProofRefuse::DenyFixtureHasItem)?;
            ClassifyProofRefuse::DenyMustRefuse.require(!C.probe_matches(&grammar, deny_rel, c.rule(), first))?;
        }
        Ok(())
    }

    /// Tip 689: every hard `unclassified-<kind>` check that can fire has a
    /// DENY fixture (exact construct) and a PASS fixture (zero hits under
    /// that prefix). Reuses construct seat fixtures where they already prove
    /// the kind — gap-fill files only for missing adversaries.
    #[test]
    fn tip_689_every_unclassified_kind_deny_and_pass() -> TestResult {
        let grammar = C.real_grammar()?;
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");

        /// One seated kind's tip-689 proof pair.
        /// `deny` is `None` only when the seat is vacuous (check cannot fire).
        struct Case {
            kind: Label,
            /// fixtures/ relative path — must emit exactly `unclassified-{kind}:{label}`
            deny: Option<(Label, Label)>,
            /// fixtures/ relative path — must emit ZERO `unclassified-{kind}:*`
            pass: Label,
            /// admit path (declared-fn seats bind to the fixture's own path)
            pass_rel: Label,
            deny_rel: Label,
        }

        impl Case {
            fn new(
                kind: &'static str,
                deny: Option<(&'static str, &'static str)>,
                pass: &'static str,
                pass_rel: &'static str,
                deny_rel: &'static str,
            ) -> Self {
                Self {
                    kind: kind.into(),
                    deny: deny.map(|(file, want)| (file.into(), want.into())),
                    pass: pass.into(),
                    pass_rel: pass_rel.into(),
                    deny_rel: deny_rel.into(),
                }
            }
        }

        let cases: &[Case] = &[
            // --- reuse construct fixtures (already prove under classify) ---
            Case::new(
                "enum",
                Some(("sum-type.deny.rs", "unclassified-enum:SumString")),
                "sum-type.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "fn",
                Some(("declared-fn.deny.rs", "unclassified-fn:proof_fn")),
                "declared-fn.pass.rs",
                "crates/bs-detector/fixtures/declared-fn.pass.rs",
                "crates/bs-detector/fixtures/declared-fn.deny.rs",
            ),
            Case::new(
                "impl",
                Some(("impl-container.deny.rs", "unclassified-impl:T")),
                "impl-container.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "static",
                Some(("constant.deny.rs", "unclassified-static:G")),
                "constant.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "struct",
                Some(("newtype-scalar.deny.rs", "unclassified-struct:NotNewtype")),
                "newtype-scalar.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "trait",
                Some(("trait-container.deny.rs", "unclassified-trait:T")),
                "trait-container.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "type",
                Some(("alias.deny.rs", "unclassified-type:AliasString")),
                "alias.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "use",
                Some(("import.deny.rs", "unclassified-use:use")),
                "import.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "impl-fn",
                Some(("admission-door.deny.rs", "unclassified-impl-fn:new")),
                "admission-door.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            // mod: ModuleNoPathAttr seats every mod — check cannot fire.
            Case::new(
                "mod",
                None,
                "module.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            // --- tip 689 gap-fill (dedicated unclassified-* fixtures) ---
            Case::new(
                "const", // ConstantNoStaticMut is vacuous for Item::Const
                None,
                "unclassified-const.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "impl-const", // vacuous ConstantNoStaticMut on ImplItem::Const
                None,
                "unclassified-impl-const.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "trait-const", // vacuous ConstantNoStaticMut on TraitItem::Const
                None,
                "unclassified-trait-const.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "impl-type",
                Some(("unclassified-impl-type.deny.rs", "unclassified-impl-type:X")),
                "unclassified-impl-type.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "trait-type",
                Some(("unclassified-trait-type.deny.rs", "unclassified-trait-type:X")),
                "unclassified-trait-type.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
            Case::new(
                "trait-fn",
                Some(("unclassified-trait-fn.deny.rs", "unclassified-trait-fn:f")),
                // trait-container.pass's `fn f(&self)` seats as derivation
                "trait-container.pass.rs",
                "crates/probe/src/lib.rs",
                "crates/probe/src/lib.rs",
            ),
        ];

        ClassifyProofRefuse::Tip689CaseCount.require(cases.len() == 16)?;

        for case in cases {
            let prefix = format!("unclassified-{}:", case.kind);
            let pass_src = std::fs::read_to_string(fixtures.join(case.pass.as_str()))
                .map_err(|_| ClassifyProofRefuse::Tip689PassReadable)?;
            let pass_ast = syn::parse_file(&pass_src)
                .map_err(|_| ClassifyProofRefuse::Tip689PassParses)?;
            let pass_f = SourceFile::admit(case.pass_rel.to_string(), pass_src, pass_ast);
            let pass_hits = classify_file(&grammar, &pass_f, &C.aliases_for(&pass_f)?);
            let pass_unclass: Vec<&str> = pass_hits
                .iter()
                .map(|h| h.construct())
                .filter(|c| c.starts_with(&prefix))
                .collect();
            ClassifyProofRefuse::Tip689PassMustSilent.require(pass_unclass.is_empty())?;

            match &case.deny {
                Some((deny_file, want)) => {
                    let deny_src = std::fs::read_to_string(fixtures.join(deny_file.as_str()))
                        .map_err(|_| ClassifyProofRefuse::Tip689DenyReadable)?;
                    let deny_ast = syn::parse_file(&deny_src)
                        .map_err(|_| ClassifyProofRefuse::Tip689DenyParses)?;
                    let deny_f = SourceFile::admit(case.deny_rel.to_string(), deny_src, deny_ast);
                    let deny_hits = classify_file(&grammar, &deny_f, &C.aliases_for(&deny_f)?);
                    let got: Vec<String> = deny_hits
                        .iter()
                        .map(|h| h.construct().to_string())
                        .filter(|c| c.starts_with(&prefix))
                        .collect();
                    ClassifyProofRefuse::Tip689DenyExact.require(got == vec![want.to_string()])?;
                }
                None => {
                    // Vacuous seat: the check cannot fire. Adversary shapes that
                    // look "open" must still seat — a detonating DENY here would
                    // be fabricated fake-up.
                    ClassifyProofRefuse::Tip689VacuousSeat.require(matches!(
                            case.kind.as_str(),
                            "const" | "mod" | "impl-const" | "trait-const"
                        ))?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn every_condemned_kind_deny_fixture_is_red_under_its_own_law() -> TestResult {
        let grammar = C.real_grammar()?;
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for kind in grammar.condemned() {
            let law = kind
                .condemned_law_name()
                .ok_or(ClassifyProofRefuse::CondemnedLawMissing)?;
            let path = manifest
                .join("fixtures")
                .join(format!("{}.deny.rs", kind.kebab()));
            let src = std::fs::read_to_string(&path)
                .map_err(|_| ClassifyProofRefuse::CondemnedDenyReadable)?;
            // Verbatim cannot be authored inside a file syn::parse_file accepts —
            // by definition it is what syn could not interpret. Presence is the
            // load law; live-tree Verbatim is the classify path. Skip parse-exec
            // for that one kind only, named here so it is not silent.
            if *kind == KindName::Verbatim {
                ClassifyProofRefuse::VerbatimDenyNamesWhy.require(src.contains("Item::Verbatim") || src.contains("verbatim"))?;
                continue;
            }
            let ast = syn::parse_file(&src)
                .map_err(|_| ClassifyProofRefuse::CondemnedDenyParses)?;
            let f = SourceFile::admit(
                format!("crates/bs-detector/fixtures/{}.deny.rs", kind.kebab()),
                src,
                ast,
            );
            let hits = classify_file(&grammar, &f, &C.aliases_for(&f)?);
            ClassifyProofRefuse::CondemnedDenyMustHit.require(hits.iter().any(|h| h.construct() == law))?;
        }
        Ok(())
    }

    #[test]
    fn item_1_proof_const_kind_neither_seated_nor_condemned_would_be_a_load_error() -> TestResult {
        // Covered directly in grammar.rs's own load tests (removing the
        // `const` seat entry refuses to load); re-asserted here at the
        // classify boundary: a kind with NO disposition is treated as a
        // hit, never a silent pass, if it ever reached the classifier.
        let grammar = C.real_grammar()?;
        ClassifyProofRefuse::ConstMustBeSeated.require(grammar.disposition(KindName::Const).is_some())
    }

    #[test]
    fn item_1_proof_static_mut_is_denied() -> TestResult {
        let grammar = C.real_grammar()?;
        let f = SourceFile::admit(
            "crates/probe/src/lib.rs".to_string(),
            "static mut G: u64 = 0;".to_string(),
            C.parse_file("static mut G: u64 = 0;")?,
        );
        let hits = classify_file(&grammar, &f, &C.aliases_for(&f)?);
        ClassifyProofRefuse::StaticMutMustDeny.require(hits.len() == 1)
    }

    #[test]
    fn item_1_proof_path_attr_mod_is_denied() -> TestResult {
        // Item 5: #[path] is bans_attribute only — module still seats;
        // the attribute matcher is the one door.
        let m = crate::engines::shape::MATCHER_LOOKUP.by_name("path")
            .ok_or(ClassifyProofRefuse::PathMatcher)?;
        let f = SourceFile::admit(
            "crates/probe/src/lib.rs".to_string(),
            "#[path = \"x.rs\"]\nmod m;".to_string(),
            C.parse_file("#[path = \"x.rs\"]\nmod m;")?,
        );
        let hits = m.run(&f);
        ClassifyProofRefuse::PathAttrMustHit.require(hits.len() == 1)?;
        ClassifyProofRefuse::PathModuleMustSeat.require(C.classify_src("#[path = \"x.rs\"] mod m;")?.len() == 0)
    }

    #[test]
    fn item_1_proof_glob_use_is_denied() -> TestResult {
        C.require_hit_count("use crate::foo::*;", 1, ClassifyProofRefuse::GlobUseMustDeny)
    }

    #[test]
    fn item_1_proof_impl_macro_is_denied() -> TestResult {
        let hits = C.classify_src("struct T; impl T { some_macro!{} }")?;
        ClassifyProofRefuse::ImplMacroMustHit.require(hits.iter().any(|h| h.construct() == "impl_item_macro"))
    }

    #[test]
    fn anti_fraud_a_deny_shape_never_slips_through_a_neighboring_seat() -> TestResult {
        C.require_hit_count(
            "struct Leaky { name: String }",
            1,
            ClassifyProofRefuse::DenyShapeMustHit,
        )
    }

    // -----------------------------------------------------------------------
    // item 2 proofs (executed — presence is not proof)
    // -----------------------------------------------------------------------

    #[test]
    fn item_2_proofs_red_shapes_are_unclassified() -> TestResult {
        C.require_exact_constructs(
            "impl S { fn f(self: Box<Self>) {} }",
            &["unclassified-impl-fn:f"],
            ClassifyProofRefuse::BoxSelfMustUnclass,
        )?;
        C.require_exact_constructs(
            "impl S { fn with_x(mut self) -> Self { self.x = 1; self } }",
            &["unclassified-impl-fn:with_x"],
            ClassifyProofRefuse::MutSelfMustUnclass,
        )?;
        C.require_exact_constructs(
            "fn smuggled() {}",
            &["unclassified-fn:smuggled"],
            ClassifyProofRefuse::SmuggledMustUnclass,
        )?;
        C.require_exact_constructs(
            "async fn bare_async() {}",
            &["unclassified-fn:bare_async"],
            ClassifyProofRefuse::BareAsyncMustUnclass,
        )?;
        let grammar = C.real_grammar()?;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/declared-fn.deny.rs");
        let src = std::fs::read_to_string(&path)
            .map_err(|_| ClassifyProofRefuse::DeclaredFnDenyReadable)?;
        let f = SourceFile::admit(
            "crates/bs-detector/fixtures/declared-fn.deny.rs".to_string(),
            src.clone(),
            syn::parse_file(&src).map_err(|_| ClassifyProofRefuse::DeclaredFnDenyParses)?,
        );
        let hits = classify_file(&grammar, &f, &C.aliases_for(&f)?);
        let mut got: Vec<String> = hits.iter().map(|h| h.construct().to_string()).collect();
        got.sort();
        ClassifyProofRefuse::DeclaredFnDenyEmpty.require(!got.is_empty())?;
        for g in &got {
            ClassifyProofRefuse::DeclaredFnDenyNotUnclass.require(g.starts_with("unclassified-"))?;
        }
        Ok(())
    }

    #[test]
    fn item_5_scoped_bans_classify_then_matcher_hits() -> TestResult {
        // Await / nested_place inside a matching skeleton: classify clean,
        // construct-scoped matcher still detonates (one jurisdiction).
        let grammar = C.real_grammar()?;
        let await_src = "impl S { fn get(&self) -> u64 { async { 1u64 }.await } }";
        let nest_src = "impl S { fn into_x(mut self) -> u64 { self.a.b = 1; self.x } }";
        for (src, rule) in [
            (await_src, StructuralRule::DerivationBans),
            (nest_src, StructuralRule::ConsumingVerbBans),
        ] {
            let ast = C.parse_file(src)?;
            let first = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
            ClassifyProofRefuse::ScopedBanMustSeat.require(C.probe_matches(&grammar, "crates/probe/src/lib.rs", rule, first))?;
        }
        let m_await = crate::engines::shape::MATCHER_LOOKUP.by_name("await")
            .ok_or(ClassifyProofRefuse::AwaitMatcher)?;
        let m_nest = crate::engines::shape::MATCHER_LOOKUP.by_name("nested_place_assign")
            .ok_or(ClassifyProofRefuse::NestMatcher)?;
        let f_await = SourceFile::admit(
            "crates/probe/src/lib.rs".to_string(),
            await_src.to_string(),
            C.parse_file(await_src)?,
        );
        let f_nest = SourceFile::admit(
            "crates/probe/src/lib.rs".to_string(),
            nest_src.to_string(),
            C.parse_file(nest_src)?,
        );
        ClassifyProofRefuse::AwaitMatcherHit.require(m_await.run(&f_await).len() == 1)?;
        ClassifyProofRefuse::NestMatcherHit.require(m_nest.run(&f_nest).len() == 1)
    }

    #[test]
    fn item_2_proof_admission_door_classifies() -> TestResult {
        let grammar = C.real_grammar()?;
        let src = "impl S { fn new() -> Result<Self, ()> { Ok(S) } }";
        let rel = "crates/probe/src/lib.rs";
        let ast = C.parse_file(src)?;
        let first = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
        ClassifyProofRefuse::AdmissionDoorMustSeat.require(C.probe_matches(&grammar, rel, StructuralRule::AdmissionDoorBans, first))?;
        let f = SourceFile::admit(rel.to_string(), src.to_string(), ast);
        let hits = classify_file(&grammar, &f, &C.aliases_for(&f)?);
        ClassifyProofRefuse::AdmissionDoorMustSilent.require(hits.is_empty())
    }

    /// Adversary 1: the drain shape is REAL — an impl-associated
    /// receiverless `-> Self` fn matches admission-door. If this ever goes
    /// false, the nested-bleed story is fiction and the suite must stop.
    #[test]
    fn anti_fraud_impl_associated_self_fn_still_matches_admission_door_rule() -> TestResult {
        let grammar = C.real_grammar()?;
        let src = "impl S { fn helper() -> Self { S } }";
        let ast = C.parse_file(src)?;
        let first = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
        ClassifyProofRefuse::AttackLockAdmissionDoor.require(C.probe_matches(
                &grammar,
                "crates/probe/src/lib.rs",
                StructuralRule::AdmissionDoorBans,
                first,
            ))?;
        let hits = C.classify_src(src)?;
        let helper = C.hit_constructs_for(&hits, "helper");
        ClassifyProofRefuse::HelperMustSilentGreen.require(helper.is_empty())
    }

    /// Adversary 2: nested Item::Fn inside a method body must NOT inherit
    /// the impl seat. The soft drain was: empty hits (false green). This
    /// test detonates if helper is missing from hits OR is anything other
    /// than unclassified-fn:helper.
    #[test]
    fn anti_fraud_nested_self_fn_inside_method_body_must_be_unclassified() -> TestResult {
        let src = "impl S { fn method(&self) { fn helper() -> Self { S } } }";
        let hits = C.classify_src(src)?;
        let helper = C.hit_constructs_for(&hits, "helper");
        ClassifyProofRefuse::NestedBleedHelper.require(helper == vec!["unclassified-fn:helper".to_string()])?;
        // Method itself is derivation — must not be swept into the helper's guilt.
        ClassifyProofRefuse::NestedBleedMethodSwept
            .require(!hits.iter().any(|h| h.construct().contains("method")))
    }

    /// Adversary 3: Result<Self,_> nest — same bleed costume, different return.
    #[test]
    fn anti_fraud_nested_result_self_fn_inside_method_must_be_unclassified() -> TestResult {
        let src = "impl S { fn method(&self) { fn helper() -> Result<Self, ()> { Ok(S) } } }";
        let hits = C.classify_src(src)?;
        let helper = C.hit_constructs_for(&hits, "helper");
        ClassifyProofRefuse::NestedResultHelper.require(helper == vec!["unclassified-fn:helper".to_string()])
    }

    /// Adversary 4: trait default body nest — second container bleed surface.
    #[test]
    fn anti_fraud_nested_self_fn_inside_trait_default_must_be_unclassified() -> TestResult {
        let src = "trait T { fn method(&self) { fn helper() -> Self { todo!() } } }";
        let hits = C.classify_src(src)?;
        let helper = C.hit_constructs_for(&hits, "helper");
        ClassifyProofRefuse::NestedTraitHelper.require(helper == vec!["unclassified-fn:helper".to_string()])
    }

    /// Adversary 5: free nested fn inside a free fn — never had in_container;
    /// must still be unclassified (no silent pass via a new costume).
    #[test]
    fn anti_fraud_nested_fn_inside_free_fn_must_be_unclassified() -> TestResult {
        let src = "fn outer() { fn helper() {} }";
        let hits = C.classify_src(src)?;
        let helper = C.hit_constructs_for(&hits, "helper");
        ClassifyProofRefuse::NestedFreeHelper.require(helper == vec!["unclassified-fn:helper".to_string()])?;
        let outer = C.hit_constructs_for(&hits, "outer");
        ClassifyProofRefuse::NestedFreeOuter.require(outer == vec!["unclassified-fn:outer".to_string()])
    }

    #[test]
    fn item_2_proof_composition_root_positive_body_refuses_non_call_let() -> TestResult {
        // The honesty gap closed here: negative-only (!control_flow) would
        // green `let x = 1; finish(x)`. Positive law reds it.
        let grammar = C.real_grammar()?;
        let src = "fn main() { let x = 1; finish(x) }";
        let rel = "crates/probe/src/main.rs";
        let ast = C.parse_file(src)?;
        let first = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
        ClassifyProofRefuse::CompositionRootMustRefuse.require(!C.probe_matches(&grammar, rel, StructuralRule::CompositionRootBody, first))
    }

    #[test]
    fn item_2_anti_fraud_fn_matches_at_most_one_skeleton() -> TestResult {
        let grammar = C.real_grammar()?;
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
            .filter(|c| matches!(c.kind(), crate::grammar::ConstructFamily::Fn))
            .map(|c| c.rule())
            .collect();
        for (rel, src) in cases {
            let ast = C.parse_file(src)?;
            let first = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
            let n = fn_rules
                .iter()
                .filter(|r| C.probe_matches(&grammar, rel, **r, first))
                .count();
            ClassifyProofRefuse::FnSkeletonExactlyOne.require(n == 1)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // item 3 proofs — disjoint construct rules
    // -----------------------------------------------------------------------

    #[test]
    fn item_3_proof_multi_field_tuple_and_pub_field_are_red() -> TestResult {
        // Build text: multi-field tuple or any pub field → red.
        C.require_exact_constructs(
            "struct Multi(u64, u64);",
            &["unclassified-struct:Multi"],
            ClassifyProofRefuse::MultiFieldTupleRed,
        )?;
        C.require_exact_constructs(
            "struct Open(pub u64);",
            &["unclassified-struct:Open"],
            ClassifyProofRefuse::PubTupleFieldRed,
        )?;
        C.require_exact_constructs(
            "struct Open { pub a: u64 }",
            &["unclassified-struct:Open"],
            ClassifyProofRefuse::PubNamedFieldRed,
        )
    }

    #[test]
    fn item_3_anti_fraud_struct_matches_at_most_one_construct() -> TestResult {
        let grammar = C.real_grammar()?;
        let cases = [
            "struct Newtype(u64);",
            "struct Sealed { a: u64 }",
            "struct Unit;",
        ];
        let struct_rules: Vec<StructuralRule> = grammar
            .constructs()
            .iter()
            .filter(|c| matches!(c.kind(), crate::grammar::ConstructFamily::Struct))
            .map(|c| c.rule())
            .collect();
        for src in cases {
            let ast = C.parse_file(src)?;
            let first = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
            let n = struct_rules
                .iter()
                .filter(|r| C.probe_matches(&grammar, "crates/probe/src/lib.rs", **r, first))
                .count();
            ClassifyProofRefuse::StructConstructExactlyOne.require(n == 1)?;
        }
        Ok(())
    }

    #[test]
    fn item_3_classification_emits_unique_construct_name() -> TestResult {
        // Seat match returns the unique name (not a bool from `.any()`).
        let grammar = C.real_grammar()?;
        let src = "struct Newtype(u64);";
        let ast = C.parse_file(src)?;
        let item = ast.items.first().ok_or(ClassifyProofRefuse::MissingItem)?;
        let empty = crate::alias::AliasTable::empty();
        let rel = RelPath::admit("crates/probe/src/lib.rs");
        let ctx = Ctx {
            rel: &rel,
            grammar: &grammar,
            aliases: &empty,
            self_ty: None,
            in_container: false,
        };
        let seats = match grammar.disposition(KindName::Struct) {
            Some(crate::grammar::Disposition::Seated(s)) => s,
            Some(crate::grammar::Disposition::Condemned { .. }) => {
                return Err(ClassifyProofRefuse::StructMustBeSeatedNotCondemned);
            }
            None => return Err(ClassifyProofRefuse::StructMustBeSeated),
        };
        ClassifyProofRefuse::UniqueConstructName.require(ctx.seat_matches_item(item, seats) == Some("newtype-scalar"))
    }

    // -----------------------------------------------------------------------
    // item 4 proofs — string rule + alias fixpoint
    // -----------------------------------------------------------------------

    #[test]
    fn item_4_proof_type_alias_to_string_struct_is_red() -> TestResult {
        C.require_exact_constructs(
            "type Name = String; struct S { n: Name }",
            &["unclassified-struct:S", "unclassified-type:Name"],
            ClassifyProofRefuse::AliasStringStructRed,
        )
    }

    #[test]
    fn item_4_proof_use_as_string_struct_is_red() -> TestResult {
        C.require_exact_constructs(
            "use std::string::String as Text; struct T { t: Text }",
            &["unclassified-struct:T"],
            ClassifyProofRefuse::UseAsStringStructRed,
        )
    }

    /// Adversary 6a: expression-nested FREE FN — unit struct was a false
    /// specimen (unit-marker seats green). A receiverless nested fn cannot
    /// seat; if the if-body walk is blind, this is []. Exact construct only.
    #[test]
    fn anti_fraud_expression_nested_fn_must_be_exact_unclassified() -> TestResult {
        let hits = C.classify_src("fn f() { if true { fn nested_hide() {} } }")?;
        let nested = C.hit_constructs_for(&hits, "nested_hide");
        ClassifyProofRefuse::ExprNestFnExact.require(nested == vec!["unclassified-fn:nested_hide".to_string()])?;
        ClassifyProofRefuse::ExprNestFnOuter.require(hits.iter().any(|h| h.construct() == "unclassified-fn:f"))
    }

    /// Adversary 6b: expression-nested STRING STRUCT — cannot seat as
    /// sealed/newtype/unit. Exact construct; detonates on walk blindness.
    #[test]
    fn anti_fraud_expression_nested_string_struct_must_be_exact_unclassified() -> TestResult {
        let hits = C.classify_src("fn f() { if true { struct NestedHide { name: String } } }")?;
        let nested = C.hit_constructs_for(&hits, "NestedHide");
        ClassifyProofRefuse::ExprNestStringStructExact.require(nested == vec!["unclassified-struct:NestedHide".to_string()])
    }

    /// Adversary 6c: FALSE SPECIMEN LOCK — unit struct in if-body IS
    /// unit-marker (lawful green). If this goes red, we over-fixed.
    #[test]
    fn anti_fraud_expression_nested_unit_struct_still_seats_as_unit_marker() -> TestResult {
        let hits = C.classify_src("fn f() { if true { struct NestedHide; } }")?;
        let nested = C.hit_constructs_for(&hits, "NestedHide");
        ClassifyProofRefuse::ExprNestUnitStillGreen.require(nested.is_empty())
    }

    #[test]
    fn anti_fraud_match_arm_nested_fn_must_be_exact_unclassified() -> TestResult {
        let hits = C.classify_src("fn f() { match 0 { _ => { fn h() {} } } }")?;
        let nested: Vec<String> = hits
            .iter()
            .filter(|hit| hit.construct().ends_with(":h"))
            .map(|hit| hit.construct().to_string())
            .collect();
        ClassifyProofRefuse::MatchArmNestExact.require(nested == vec!["unclassified-fn:h".to_string()])
    }

    #[test]
    fn anti_fraud_loop_body_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { loop { fn nested_hide() {} break; } }")
    }

    #[test]
    fn anti_fraud_while_body_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { while true { fn nested_hide() {} break; } }")
    }

    #[test]
    fn anti_fraud_for_body_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { for _ in 0..1 { fn nested_hide() {} } }")
    }

    #[test]
    fn anti_fraud_closure_body_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { let _c = || { fn nested_hide() {} }; }")
    }

    #[test]
    fn anti_fraud_async_block_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { let _a = async { fn nested_hide() {} }; }")
    }

    #[test]
    fn anti_fraud_unsafe_block_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { unsafe { fn nested_hide() {} } }")
    }

    /// Tip 650: const/static *item* RHS blocks may contain nested items
    /// (legal Rust). recurse_into_item treated Const/Static as
    /// non-containers — silent-green drain.
    #[test]
    fn anti_fraud_const_item_rhs_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("const X: i32 = { fn nested_hide() {} 1 };")
    }

    #[test]
    fn anti_fraud_static_item_rhs_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("static X: i32 = { fn nested_hide() {} 1 };")
    }

    #[test]
    fn anti_fraud_nested_const_item_rhs_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { const X: i32 = { fn nested_hide() {} 1 }; }")
    }

    #[test]
    fn anti_fraud_const_block_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { const { fn nested_hide() {} }; }")
    }

    #[test]
    fn anti_fraud_inline_const_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() { let _x = const { fn nested_hide() {} 1 }; }")
    }

    /// Adversary 16: impl-associated const RHS nest — container walk only
    /// recursed ImplItem::Fn, so Const value expr was a silent-green drain.
    #[test]
    fn anti_fraud_impl_const_rhs_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("impl S { const X: i32 = { fn nested_hide() {} 1 }; }")
    }

    /// Adversary 17: trait-associated const default RHS nest.
    #[test]
    fn anti_fraud_trait_const_rhs_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("trait T { const X: i32 = { fn nested_hide() {} 1 }; }")
    }

    /// Tip 686: enum discriminant expr nest — recurse_into_item treated
    /// Item::Enum as `_not_a_container` (walk blind soft drain).
    #[test]
    fn anti_fraud_enum_discriminant_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("enum E { V = { fn nested_hide() {} 1 } }")
    }

    /// Tip 686: type-position array-len nest on a type alias.
    #[test]
    fn anti_fraud_type_alias_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("type T = [u8; { fn nested_hide() {} 1 }];")
    }

    /// Tip 686: type-position array-len nest on a struct field.
    #[test]
    fn anti_fraud_struct_field_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("struct S { f: [u8; { fn nested_hide() {} 1 }] }")
    }

    /// Tip 686: type-position array-len nest on an enum variant field.
    #[test]
    fn anti_fraud_enum_field_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("enum E { V([u8; { fn nested_hide() {} 1 }]) }")
    }

    /// Tip 686: type-position array-len nest on a free-fn return type
    /// (block walk alone does not visit the signature).
    #[test]
    fn anti_fraud_fn_return_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f() -> [u8; { fn nested_hide() {} 1 }] { loop {} }")
    }

    /// Tip 686: type-position array-len nest on a free-fn arg type.
    #[test]
    fn anti_fraud_fn_arg_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("fn f(_x: [u8; { fn nested_hide() {} 1 }]) {}")
    }

    /// Tip 686: type-position array-len nest on impl associated type.
    #[test]
    fn anti_fraud_impl_type_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact(
            "struct S; impl S { type T = [u8; { fn nested_hide() {} 1 }]; }",
        )
    }

    /// Tip 686: type-position array-len nest on trait associated type default.
    #[test]
    fn anti_fraud_trait_type_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("trait Tr { type T = [u8; { fn nested_hide() {} 1 }]; }")
    }

    /// Tip 686: type-position array-len nest on impl self_ty.
    #[test]
    fn anti_fraud_impl_self_ty_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact(
            "struct S<const N: usize>; impl S<{ { fn nested_hide() {} 1 } }> {}",
        )
    }

    /// Tip 686: type-position array-len nest on const item's type annotation
    /// (RHS expr walk alone does not visit the type).
    #[test]
    fn anti_fraud_const_ty_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("const X: [u8; { fn nested_hide() {} 1 }] = [0; 1];")
    }

    /// Tip 686: trait supertrait bound nest — Item::Trait walked generics +
    /// members only; `supertraits` was a silent-green drain.
    #[test]
    fn anti_fraud_trait_supertrait_bound_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("trait T: From<[u8; { fn nested_hide() {} 1 }]> {}")
    }

    /// Tip 686: trait associated-type bound nest — default RHS was walked,
    /// but `bounds` after `:` were not.
    #[test]
    fn anti_fraud_trait_type_bound_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact(
            "trait Tr { type T: From<[u8; { fn nested_hide() {} 1 }]>; }",
        )
    }

    /// Tip 686: trait-alias bound nest — Item::TraitAlias was `_not_a_container`.
    #[test]
    fn anti_fraud_trait_alias_bound_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact("trait Alias = From<[u8; { fn nested_hide() {} 1 }]>;")
    }

    /// Tip 686: foreign-fn arg type-position nest — ForeignMod interiors were
    /// never walked (block condemned, nested items silent-green).
    #[test]
    fn anti_fraud_foreign_fn_arg_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact(
            "extern \"C\" { fn f(_x: *const [u8; { fn nested_hide() {} 1 }]); }",
        )
    }

    /// Tip 686: foreign-static type-position nest.
    #[test]
    fn anti_fraud_foreign_static_ty_array_len_nested_fn_must_be_exact_unclassified() -> TestResult {
        C.require_expression_nest_exact(
            "extern \"C\" { static X: [u8; { fn nested_hide() {} 1 }]; }",
        )
    }

    #[test]
    fn item_4_proof_restrict_struct_is_clean() -> TestResult {
        C.require_hit_count(
            "struct R { r: Restrict }",
            0,
            ClassifyProofRefuse::RestrictStructClean,
        )
    }
}
