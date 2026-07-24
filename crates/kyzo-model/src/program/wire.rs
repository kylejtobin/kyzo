/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Seat-59 program-IR wire envelopes — ONE authority for "persist fields,
//! mint empty span/trivia on decode".
//!
//! Domain types keep span/trivia as live truth; wire twins omit them.
//! No `#[serde(skip)]` / `#[serde(default)]` on the domain type (those are
//! `serde_default_skip`); no `macro_rules!` Item::Macro. Each envelope is a
//! named wire seat with `From` lifts, matching [`super::rule::InputProgram`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::SourceSpan;
use crate::program::expr::Expr;
use crate::program::query::InputRelationHandle;
use crate::program::rule::{
    FixedRuleApply, FixedRuleArg, FixedRuleHandle, FixedRuleOptions, HeadAggrSlot, InputAtom,
    InputInlineRule, InputNamedFieldRelationApplyAtom, InputRelationApplyAtom, InputRuleApplyAtom,
    SearchFilter, SearchInput, SearchModalityOptions, Trivia, Unification, ValidityClause,
};
use crate::program::symbol::Symbol;
use crate::schema::relation::StoredRelationMetadata;

// ── InputRelationHandle ──────────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct InputRelationHandleWire {
    name: Symbol,
    metadata: StoredRelationMetadata,
    key_bindings: Vec<Symbol>,
    dep_bindings: Vec<Symbol>,
}

impl From<&InputRelationHandle> for InputRelationHandleWire {
    fn from(v: &InputRelationHandle) -> Self {
        Self {
            name: v.name.clone(),
            metadata: v.metadata.clone(),
            key_bindings: v.key_bindings.clone(),
            dep_bindings: v.dep_bindings.clone(),
        }
    }
}

impl From<InputRelationHandleWire> for InputRelationHandle {
    fn from(w: InputRelationHandleWire) -> Self {
        Self {
            name: w.name,
            metadata: w.metadata,
            key_bindings: w.key_bindings,
            dep_bindings: w.dep_bindings,
            span: SourceSpan::empty(),
        }
    }
}

impl Serialize for InputRelationHandle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        InputRelationHandleWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputRelationHandle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(InputRelationHandleWire::deserialize(deserializer)?.into())
    }
}

// ── InputInlineRule ──────────────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct InputInlineRuleWire {
    head: Vec<Symbol>,
    aggr: Vec<HeadAggrSlot>,
    body: Vec<InputAtom>,
}

impl From<&InputInlineRule> for InputInlineRuleWire {
    fn from(v: &InputInlineRule) -> Self {
        Self {
            head: v.head.clone(),
            aggr: v.aggr.clone(),
            body: v.body.clone(),
        }
    }
}

impl From<InputInlineRuleWire> for InputInlineRule {
    fn from(w: InputInlineRuleWire) -> Self {
        Self {
            head: w.head,
            aggr: w.aggr,
            body: w.body,
            span: SourceSpan::empty(),
            trivia: Trivia::empty(),
        }
    }
}

impl Serialize for InputInlineRule {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        InputInlineRuleWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputInlineRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(InputInlineRuleWire::deserialize(deserializer)?.into())
    }
}

// ── FixedRuleApply ───────────────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct FixedRuleApplyWire {
    fixed_handle: FixedRuleHandle,
    rule_args: Vec<FixedRuleArg>,
    options: FixedRuleOptions,
    head: Vec<Symbol>,
    arity: usize,
}

impl From<&FixedRuleApply> for FixedRuleApplyWire {
    fn from(v: &FixedRuleApply) -> Self {
        Self {
            fixed_handle: v.fixed_handle.clone(),
            rule_args: v.rule_args.clone(),
            options: v.options.clone(),
            head: v.head.clone(),
            arity: v.arity,
        }
    }
}

impl From<FixedRuleApplyWire> for FixedRuleApply {
    fn from(w: FixedRuleApplyWire) -> Self {
        Self {
            fixed_handle: w.fixed_handle,
            rule_args: w.rule_args,
            options: w.options,
            head: w.head,
            arity: w.arity,
            span: SourceSpan::empty(),
            trivia: Trivia::empty(),
        }
    }
}

impl Serialize for FixedRuleApply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        FixedRuleApplyWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FixedRuleApply {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(FixedRuleApplyWire::deserialize(deserializer)?.into())
    }
}

// ── SearchInput ──────────────────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct SearchInputWire {
    relation: Symbol,
    index: Symbol,
    bindings: BTreeMap<Symbol, Expr>,
    query: Expr,
    filter: SearchFilter,
    modality: SearchModalityOptions,
}

impl From<&SearchInput> for SearchInputWire {
    fn from(v: &SearchInput) -> Self {
        Self {
            relation: v.relation.clone(),
            index: v.index.clone(),
            bindings: v.bindings.clone(),
            query: v.query.clone(),
            filter: v.filter.clone(),
            modality: v.modality.clone(),
        }
    }
}

impl From<SearchInputWire> for SearchInput {
    fn from(w: SearchInputWire) -> Self {
        Self {
            relation: w.relation,
            index: w.index,
            bindings: w.bindings,
            query: w.query,
            filter: w.filter,
            modality: w.modality,
            span: SourceSpan::empty(),
        }
    }
}

impl Serialize for SearchInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SearchInputWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SearchInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(SearchInputWire::deserialize(deserializer)?.into())
    }
}

// ── InputRuleApplyAtom ───────────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct InputRuleApplyAtomWire {
    name: Symbol,
    args: Vec<Expr>,
}

impl From<&InputRuleApplyAtom> for InputRuleApplyAtomWire {
    fn from(v: &InputRuleApplyAtom) -> Self {
        Self {
            name: v.name.clone(),
            args: v.args.clone(),
        }
    }
}

impl From<InputRuleApplyAtomWire> for InputRuleApplyAtom {
    fn from(w: InputRuleApplyAtomWire) -> Self {
        Self {
            name: w.name,
            args: w.args,
            span: SourceSpan::empty(),
        }
    }
}

impl Serialize for InputRuleApplyAtom {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        InputRuleApplyAtomWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputRuleApplyAtom {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(InputRuleApplyAtomWire::deserialize(deserializer)?.into())
    }
}

// ── InputNamedFieldRelationApplyAtom ─────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct InputNamedFieldRelationApplyAtomWire {
    name: Symbol,
    args: BTreeMap<Symbol, Expr>,
    validity: Option<ValidityClause>,
}

impl From<&InputNamedFieldRelationApplyAtom> for InputNamedFieldRelationApplyAtomWire {
    fn from(v: &InputNamedFieldRelationApplyAtom) -> Self {
        Self {
            name: v.name.clone(),
            args: v.args.clone(),
            validity: v.validity.clone(),
        }
    }
}

impl From<InputNamedFieldRelationApplyAtomWire> for InputNamedFieldRelationApplyAtom {
    fn from(w: InputNamedFieldRelationApplyAtomWire) -> Self {
        Self {
            name: w.name,
            args: w.args,
            validity: w.validity,
            span: SourceSpan::empty(),
        }
    }
}

impl Serialize for InputNamedFieldRelationApplyAtom {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        InputNamedFieldRelationApplyAtomWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputNamedFieldRelationApplyAtom {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(InputNamedFieldRelationApplyAtomWire::deserialize(deserializer)?.into())
    }
}

// ── InputRelationApplyAtom ───────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct InputRelationApplyAtomWire {
    name: Symbol,
    args: Vec<Expr>,
    validity: Option<ValidityClause>,
}

impl From<&InputRelationApplyAtom> for InputRelationApplyAtomWire {
    fn from(v: &InputRelationApplyAtom) -> Self {
        Self {
            name: v.name.clone(),
            args: v.args.clone(),
            validity: v.validity.clone(),
        }
    }
}

impl From<InputRelationApplyAtomWire> for InputRelationApplyAtom {
    fn from(w: InputRelationApplyAtomWire) -> Self {
        Self {
            name: w.name,
            args: w.args,
            validity: w.validity,
            span: SourceSpan::empty(),
        }
    }
}

impl Serialize for InputRelationApplyAtom {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        InputRelationApplyAtomWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputRelationApplyAtom {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(InputRelationApplyAtomWire::deserialize(deserializer)?.into())
    }
}

// ── Unification ──────────────────────────────────────────────────────────

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct UnificationWire {
    binding: Symbol,
    expr: Expr,
    one_many_unif: bool,
}

impl From<&Unification> for UnificationWire {
    fn from(v: &Unification) -> Self {
        Self {
            binding: v.binding.clone(),
            expr: v.expr.clone(),
            one_many_unif: v.one_many_unif,
        }
    }
}

impl From<UnificationWire> for Unification {
    fn from(w: UnificationWire) -> Self {
        Self {
            binding: w.binding,
            expr: w.expr,
            one_many_unif: w.one_many_unif,
            span: SourceSpan::empty(),
        }
    }
}

impl Serialize for Unification {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        UnificationWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Unification {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(UnificationWire::deserialize(deserializer)?.into())
    }
}
