/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The resolved index-search atom: `~rel:idx{ bindings | parameters }` after
//! the catalog has proven it.
//!
//! Below this tier's boundary a search is a *claim* ([`SearchInput`]: names
//! and raw expressions, purely syntactic); above it, *proof*: a
//! [`SearchAtom`] holds the live base and index relation handles, the
//! decoded manifest, the engine's parameter struct, and the exact output
//! frame (`own_bindings`) the RA tier will append to each parent row. One
//! resolution site ([`resolve_search`]), called from the body normalizer,
//! where the catalog is available — a bad relation name, a missing index, a
//! mistyped parameter, or a binding that is not a plain variable is a typed,
//! spanned refusal at that boundary, never a downstream surprise.
//!
//! A search atom evaluates as "a search is a join": for each parent row the
//! query expression is evaluated against that row, the engine's
//! [`RelationIndexSearch`](crate::project::projection::RelationIndexSearch)
//! door runs once, and each result row (the full base row plus the
//! engine's appended columns, in the engine's fixed order) extends the
//! parent row. The atom *binds* `own_bindings` and *requires* the variables
//! of its query expression — the well-ordering pass places it exactly like a
//! unification with those dataflow facts. Resolved [`SearchConfig`] variants
//! dispatch only through that trait seam (P103) — never an empty marker.

use std::collections::BTreeMap;
use std::sync::Arc;

use miette::{Diagnostic, Result, bail};
use thiserror::Error;

use crate::project::dedup::lsh::{HashPermutations, Lsh, LshSearchParams, LshSearchRequest};
use crate::project::projection::RelationIndexSearch;
use crate::project::text::fts::{Fts, FtsScoreKind, FtsSearchParams, FtsSearchRequest};
use crate::project::text::tokenizer::TextAnalyzer;
use crate::project::vector::hnsw::{Hnsw, HnswKnnParams, HnswSearchRequest};
use crate::session::catalog::{IndexKind, RelationHandle};
use crate::store::ReadTx;
use kyzo_model::SourceSpan;
use kyzo_model::program::expr::Expr;
use kyzo_model::program::rule::{SearchFilter, SearchInput, TempSymbGen};
use kyzo_model::program::symbol::Symbol;
use kyzo_model::value::{DataValue, SearchHits, Vector};

/// A search atom the catalog has proven: live handles, decoded manifest,
/// engine parameters, and the output frame. Carried by
/// `NormalFormAtom::Search` and `MagicAtom::Search`; compiled into
/// `RelAlgebra::Search`.
#[derive(Clone, Debug)]
pub struct SearchAtom {
    pub(crate) cfg: SearchConfig,
    /// The query expression, evaluated against each PARENT row. Its
    /// variables are this atom's dataflow inputs.
    pub(crate) query: Expr,
    /// The columns this atom appends to each parent row, in order: one
    /// symbol per base-relation column (bound name or a generated ignored
    /// binding), then the engine's appended columns that were asked for.
    pub(crate) own_bindings: Vec<Symbol>,
    /// Residual predicate over the FULL output row (parent ++ own), pushed
    /// into the engine's candidate walk where the engine supports it.
    pub(crate) filter: Option<Expr>,
    /// The session's cooperative kill flag (design Q5): the RA node polls
    /// it once per search invocation, and the engines poll it per scanned
    /// node inside a single search — both refuse with the typed
    /// cancellation error, never a silent short read.
    pub(crate) cancel: crate::rules::contract::CancelFlag,
    pub(crate) span: SourceSpan,
}

/// The engine-specific half of a resolved search atom.
#[derive(Clone)]
pub(crate) enum SearchConfig {
    Hnsw(HnswSearch),
    Fts(FtsSearch),
    Lsh(LshSearch),
}

impl SearchConfig {
    pub(crate) fn base(&self) -> &RelationHandle {
        match self {
            SearchConfig::Hnsw(c) => &c.base,
            SearchConfig::Fts(c) => &c.base,
            SearchConfig::Lsh(c) => &c.base,
        }
    }
}

impl HnswSearch {
    /// Dispatch one HNSW k-NN through [`RelationIndexSearch::search_relation`].
    pub(crate) fn search_relation(
        &self,
        tx: &impl ReadTx,
        q: &Vector,
        filter: &Option<Expr>,
        cancel: &crate::rules::contract::CancelFlag,
    ) -> Result<SearchHits> {
        Hnsw::search_relation(
            tx,
            HnswSearchRequest {
                q,
                manifest: &self.manifest,
                base: &self.base,
                idx: &self.idx,
                params: &self.params,
                filter_expr: filter,
                cancel,
            },
        )
    }
}

impl FtsSearch {
    /// Dispatch one FTS search through [`RelationIndexSearch::search_relation`].
    pub(crate) fn search_relation(
        &self,
        tx: &impl ReadTx,
        query: &str,
        filter: &Option<Expr>,
        cancel: &crate::rules::contract::CancelFlag,
        n_total: usize,
    ) -> Result<SearchHits> {
        Fts::search_relation(
            tx,
            FtsSearchRequest {
                cancel,
                query,
                base: &self.base,
                idx: &self.idx,
                params: &self.params,
                filter_code: filter,
                tokenizer: self.analyzer.as_ref(),
                n_total,
            },
        )
    }
}

impl LshSearch {
    /// Dispatch one LSH candidate search through
    /// [`RelationIndexSearch::search_relation`].
    pub(crate) fn search_relation(
        &self,
        tx: &impl ReadTx,
        query: &DataValue,
        filter: &Option<Expr>,
        cancel: &crate::rules::contract::CancelFlag,
    ) -> Result<SearchHits> {
        Lsh::search_relation(
            tx,
            LshSearchRequest {
                cancel,
                q: query,
                manifest: &self.manifest,
                base: &self.base,
                idx: &self.idx,
                params: &self.params,
                filter_code: filter,
                perms: self.perms.as_ref(),
                tokenizer: self.analyzer.as_ref(),
            },
        )
    }
}

impl std::fmt::Debug for SearchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, base, idx) = match self {
            SearchConfig::Hnsw(c) => ("hnsw", &c.base.name, &c.idx.name),
            SearchConfig::Fts(c) => ("fts", &c.base.name, &c.idx.name),
            SearchConfig::Lsh(c) => ("lsh", &c.base.name, &c.idx.name),
        };
        write!(f, "SearchConfig::{kind}({base}:{idx})")
    }
}

/// A resolved HNSW k-nearest-neighbours search.
#[derive(Clone)]
pub(crate) struct HnswSearch {
    pub(crate) base: RelationHandle,
    pub(crate) idx: RelationHandle,
    pub(crate) manifest: crate::project::vector::hnsw::HnswIndexManifest,
    pub(crate) params: HnswKnnParams,
}

/// A resolved full-text search. The analyzer is built once, at resolution —
/// a manifest that no longer builds is a refusal here, not mid-scan.
#[derive(Clone)]
pub(crate) struct FtsSearch {
    pub(crate) base: RelationHandle,
    pub(crate) idx: RelationHandle,
    pub(crate) params: FtsSearchParams,
    pub(crate) analyzer: Arc<TextAnalyzer>,
}

/// A resolved MinHash-LSH candidate search (a candidate SET, not a
/// similarity ranking — see the engine's module docs).
#[derive(Clone)]
pub(crate) struct LshSearch {
    pub(crate) base: RelationHandle,
    pub(crate) idx: RelationHandle,
    pub(crate) manifest: crate::project::dedup::lsh::MinHashLshIndexManifest,
    pub(crate) params: LshSearchParams,
    pub(crate) analyzer: Arc<TextAnalyzer>,
    pub(crate) perms: Arc<HashPermutations>,
}

// ─────────────────────────────────────────────────────────────────────────
// Typed refusals
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Diagnostic)]
#[error("relation '{0}' has no index named '{1}'")]
#[diagnostic(code(query::search_index_not_found))]
pub(crate) struct SearchIndexNotFound(
    pub(crate) Symbol,
    pub(crate) Symbol,
    #[label] pub(crate) SourceSpan,
);

#[derive(Debug, Error, Diagnostic)]
#[error("index '{0}' is a plain or temporal index; the search atom serves HNSW/FTS/LSH")]
#[diagnostic(code(query::search_over_plain_index))]
#[diagnostic(help(
    "plain and temporal indices are chosen automatically by the planner; query the relation"
))]
pub(crate) struct SearchOverPlainIndex(pub(crate) Symbol, #[label] pub(crate) SourceSpan);

#[derive(Debug, Error, Diagnostic)]
#[error("search binding for '{0}' must be a plain variable")]
#[diagnostic(code(query::search_binding_not_variable))]
pub(crate) struct SearchBindingNotVariable(pub(crate) Symbol, #[label] pub(crate) SourceSpan);

#[derive(Debug, Error, Diagnostic)]
#[error("'{0}' is not a column of relation '{1}'")]
#[diagnostic(code(query::search_column_not_found))]
pub(crate) struct SearchColumnNotFound(
    pub(crate) Symbol,
    pub(crate) Symbol,
    #[label] pub(crate) SourceSpan,
);

#[derive(Debug, Error, Diagnostic)]
#[error("search parameter '{0}' is required")]
#[diagnostic(code(query::search_param_required))]
pub(crate) struct SearchParamRequired(pub(crate) &'static str, #[label] pub(crate) SourceSpan);

#[derive(Debug, Clone, Copy, Error)]
pub(crate) enum SearchParamInvalidReason {
    #[error("must be a constant")]
    MustBeConstant,
    #[error("must be a positive integer")]
    MustBePositiveInteger,
    #[error("must be a number")]
    MustBeNumber,
    #[error("must be 'tf' or 'tf_idf'")]
    MustBeTfOrTfIdf,
    #[error("is not a parameter of this index kind")]
    UnknownParameter,
}

#[derive(Debug, Error, Diagnostic)]
#[error("search parameter '{0}' {1}")]
#[diagnostic(code(query::search_param_invalid))]
pub(crate) struct SearchParamInvalid(
    pub(crate) Symbol,
    pub(crate) SearchParamInvalidReason,
    #[label] pub(crate) SourceSpan,
);

#[derive(Debug, Error, Diagnostic)]
#[error("a search atom cannot be negated")]
#[diagnostic(code(query::negated_search_unsupported))]
#[diagnostic(help(
    "bind the search results and negate on the bound rows instead: a search \
     is a ranked/candidate join, and 'not near' has no single sound meaning"
))]
pub(crate) struct NegatedSearchUnsupported(#[label] pub(crate) SourceSpan);

// ─────────────────────────────────────────────────────────────────────────
// Resolution
// ─────────────────────────────────────────────────────────────────────────

trait ExprAsSearchBinding {
    fn as_search_binding_var(
        &self,
        name: impl AsRef<str>,
        span: SourceSpan,
    ) -> Result<Symbol>;
}

impl ExprAsSearchBinding for Expr {
    /// Extract a plain variable from a binding/parameter expression, refusing
    /// anything computed.
    fn as_search_binding_var(
        &self,
        name: impl AsRef<str>,
        span: SourceSpan,
    ) -> Result<Symbol> {
        match self {
            Expr::Binding { var, .. } => Ok(var.clone()),
            Expr::Const { .. }
            | Expr::Apply { .. }
            | Expr::UnboundApply { .. }
            | Expr::Cond { .. }
            | Expr::Lazy { .. } => {
                bail!(SearchBindingNotVariable(
                    Symbol::new(name.as_ref(), span),
                    span
                ))
            }
        }
    }
}

/// Ephemeral resolve context: owns the modality option bag for one
/// [`resolve_search`] call after [`SearchInput::modality`] is lowered.
struct SearchResolve {
    span: SourceSpan,
    params: BTreeMap<Symbol, Expr>,
}

impl SearchResolve {
    fn new(params: BTreeMap<Symbol, Expr>, span: SourceSpan) -> Self {
        Self { span, params }
    }

    fn take_const(&mut self, name: &Symbol) -> Result<Option<DataValue>> {
        match self.params.remove(name) {
            None => Ok(None),
            Some(e) => {
                let v = e.eval_to_const().map_err(|_| {
                    SearchParamInvalid(
                        name.clone(),
                        SearchParamInvalidReason::MustBeConstant,
                        self.span,
                    )
                })?;
                Ok(Some(v))
            }
        }
    }

    fn take_pos_int(&mut self, name: &Symbol) -> Result<Option<usize>> {
        match self.take_const(name)? {
            None => Ok(None),
            Some(DataValue::Num(n)) => {
                let i = n.as_int().ok_or(SearchParamInvalid(
                    name.clone(),
                    SearchParamInvalidReason::MustBePositiveInteger,
                    self.span,
                ))?;
                if i <= 0 {
                    bail!(SearchParamInvalid(
                        name.clone(),
                        SearchParamInvalidReason::MustBePositiveInteger,
                        self.span
                    ));
                }
                let n = match usize::try_from(i) {
                    Ok(v) => v,
                    Err(_neg_or_overflow) => {
                        bail!(SearchParamInvalid(
                            name.clone(),
                            SearchParamInvalidReason::MustBePositiveInteger,
                            self.span
                        ));
                    }
                };
                Ok(Some(n))
            }
            Some(_) => bail!(SearchParamInvalid(
                name.clone(),
                SearchParamInvalidReason::MustBePositiveInteger,
                self.span,
            )),
        }
    }

    fn take_var(&mut self, name: &Symbol) -> Result<Option<Symbol>> {
        match self.params.remove(name) {
            None => Ok(None),
            Some(e) => Ok(Some(e.as_search_binding_var(&**name, self.span)?)),
        }
    }

    fn finish(self) -> Result<()> {
        if let Some((name, _)) = self.params.into_iter().next() {
            bail!(SearchParamInvalid(
                name,
                SearchParamInvalidReason::UnknownParameter,
                self.span,
            ));
        }
        Ok(())
    }
}

impl RelationHandle {
    /// The base relation's output frame: one symbol per column (keys then
    /// non-keys), taking the user's variable where the column is bound and a
    /// generated ignored binding where it is not. Consumes `bindings`; a
    /// leftover key names a column that does not exist — refused.
    fn base_frame(
        &self,
        mut bindings: BTreeMap<Symbol, Expr>,
        symb_gen: &mut TempSymbGen,
        span: SourceSpan,
    ) -> Result<Vec<Symbol>> {
        let mut frame = Vec::new();
        for col in self
            .metadata
            .keys
            .iter()
            .chain(self.metadata.non_keys.iter())
        {
            match bindings.remove(&col.name) {
                Some(e) => frame.push(e.as_search_binding_var(&*col.name, span)?),
                None => frame.push(symb_gen.next_ignored(span)),
            }
        }
        if let Some((name, _)) = bindings.into_iter().next() {
            bail!(SearchColumnNotFound(
                name,
                self.name.clone(),
                span
            ));
        }
        Ok(frame)
    }
}

/// Resolve a parsed search atom against the catalog. `handle` looks a
/// relation up by name (the body normalizer's session view).
pub(crate) fn resolve_search(
    handle: &dyn Fn(&str) -> Result<RelationHandle>,
    inp: SearchInput,
    symb_gen: &mut TempSymbGen,
    cancel: crate::rules::contract::CancelFlag,
) -> Result<SearchAtom> {
    let span = inp.span;
    let base = handle(&inp.relation.name())?;
    let idx_ref = base
        .indices
        .iter()
        .find(|r| r.name == inp.index)
        .ok_or_else(|| {
            SearchIndexNotFound(
                base.name.clone(),
                inp.index.clone(),
                span,
            )
        })?
        .clone();
    let idx = handle(idx_ref.relation_name(&base.name).as_str())?;

    let query = inp.query;
    let filter = match inp.filter {
        SearchFilter::Unfiltered => None,
        SearchFilter::Pred(e) => Some(e),
    };
    let mut params = SearchResolve::new(inp.modality.into_map(), span);
    let mut own_bindings = base.base_frame(inp.bindings, symb_gen, span)?;

    let cfg = match idx_ref.kind {
        IndexKind::Plain { .. } | IndexKind::Temporal => {
            bail!(SearchOverPlainIndex(inp.index.clone(), span))
        }
        IndexKind::Hnsw(manifest) => {
            let k_sym = Symbol::new("k", span);
            let k = params
                .take_pos_int(&k_sym)?
                .ok_or(SearchParamRequired("k", span))?;
            let ef = match params.take_pos_int(&Symbol::new("ef", span))? {
                Some(v) => v,
                None => k,
            }
            .max(k);
            let radius_sym = Symbol::new("radius", span);
            let radius = match params.take_const(&radius_sym)? {
                None => None,
                Some(v) => Some(v.get_float().ok_or(SearchParamInvalid(
                    radius_sym,
                    SearchParamInvalidReason::MustBeNumber,
                    span,
                ))?),
            };
            let bind_field = params.take_var(&Symbol::new("bind_field", span))?;
            let bind_field_idx = params.take_var(&Symbol::new("bind_field_idx", span))?;
            let bind_distance = params.take_var(&Symbol::new("bind_distance", span))?;
            let bind_vector = params.take_var(&Symbol::new("bind_vector", span))?;
            // One bind encoding (P038): HnswBindSlot sum pack for the engine;
            // symbols for the RA frame — both from the same Option set.
            use crate::project::vector::hnsw::HnswBindSlot;
            let slot = |o: &Option<_>| {
                if o.is_some() {
                    HnswBindSlot::Append
                } else {
                    HnswBindSlot::Omit
                }
            };
            let bind = crate::project::vector::hnsw::HnswBindPack {
                field: slot(&bind_field),
                field_idx: slot(&bind_field_idx),
                distance: slot(&bind_distance),
                vector: slot(&bind_vector),
            };
            let p = HnswKnnParams {
                k,
                ef,
                radius,
                bind,
            };
            // The engine appends these IN THIS ORDER
            // (`RelationIndexSearch` / Hnsw search_relation contract).
            own_bindings.extend(
                [bind_field, bind_field_idx, bind_distance, bind_vector]
                    .into_iter()
                    .flatten(),
            );
            SearchConfig::Hnsw(HnswSearch {
                base,
                idx,
                manifest,
                params: p,
            })
        }
        IndexKind::Fts(manifest) => {
            let k_sym = Symbol::new("k", span);
            let k = params
                .take_pos_int(&k_sym)?
                .ok_or(SearchParamRequired("k", span))?;
            let score_kind_sym = Symbol::new("score_kind", span);
            let score_kind = match params.take_const(&score_kind_sym)? {
                None => FtsScoreKind::TfIdf,
                Some(DataValue::Str(s)) if s == "tf_idf" => FtsScoreKind::TfIdf,
                Some(DataValue::Str(s)) if s == "tf" => FtsScoreKind::Tf,
                Some(_) => bail!(SearchParamInvalid(
                    score_kind_sym,
                    SearchParamInvalidReason::MustBeTfOrTfIdf,
                    span
                )),
            };
            let bind_score = params.take_var(&Symbol::new("bind_score", span))?;
            let analyzer = manifest.tokenizer.build(&manifest.filters).map(Arc::new)?;
            let p = FtsSearchParams {
                k,
                score_kind,
                bind_score: if bind_score.is_some() {
                    crate::project::text::fts::FtsBindScore::Append
                } else {
                    crate::project::text::fts::FtsBindScore::Omit
                },
            };
            own_bindings.extend(bind_score);
            SearchConfig::Fts(FtsSearch {
                base,
                idx,
                params: p,
                analyzer,
            })
        }
        IndexKind::Lsh { manifest, .. } => {
            let k = params.take_pos_int(&Symbol::new("k", span))?;
            let analyzer = manifest.tokenizer.build(&manifest.filters).map(Arc::new)?;
            let perms = Arc::new(manifest.get_hash_perms()?);
            own_bindings // LSH appends nothing beyond the base row.
                .shrink_to_fit();
            SearchConfig::Lsh(LshSearch {
                base,
                idx,
                manifest,
                params: LshSearchParams { k },
                analyzer,
                perms,
            })
        }
    };

    params.finish()?;

    Ok(SearchAtom {
        cfg,
        query,
        own_bindings,
        filter,
        cancel,
        span,
    })
}
