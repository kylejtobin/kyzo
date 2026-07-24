/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Closed four-way engine refusal taxonomy (#271 T1 / epic #184).
//!
//! Every engine-visible refusal lowers into [`EngineRefusal`]: wrong-query,
//! exceeded-budget, unsafe-shape, or stratification-failure. Layer enums
//! ([`ModelRefuse`], [`ExecRefuse`], [`SessionRefuse`], [`HostRefuse`]) are
//! the small per-tier doors. The store tier's closed ledger remains
//! [`crate::store::failure::StoreRefuse`] — T2+ classifies each ledger
//! variant into these four; T1 does not mint a second store enum.
//!
//! Source-born refusals carry [`RefusalLocus::At`]; conflict / budget-barrier /
//! kill / format-version refusals use [`RefusalLocus::Exempt`] (lib.rs: those
//! have no query text to point at).

use kyzo_model::program::span::SourceSpan;
use miette::Diagnostic;
use thiserror::Error;

/// Why a refusal has no query-text span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpanExempt {
    /// SSI / write-set conflict — no single query span owns the race.
    Conflict,
    /// Barrier budget dimension (derived-tuples / epochs / deadline).
    BudgetBarrier,
    /// Explicit kill / cancel.
    Kill,
    /// On-disk / wire format identity mismatch.
    FormatVersion,
    /// Host-clock / mono-time door (no script span).
    HostClock,
    /// Store-ledger refuse with no script locus.
    StoreLedger,
}

/// Span or typed exemption — every refusal carries exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalLocus {
    At(SourceSpan),
    Exempt(SpanExempt),
}

impl RefusalLocus {
    pub const fn at(span: SourceSpan) -> Self {
        Self::At(span)
    }

    pub const fn exempt(reason: SpanExempt) -> Self {
        Self::Exempt(reason)
    }
}

/// Engine top-type — closed four-way refusal space.
///
/// A new variant is a compile error at every exhaustive match site. Layer
/// enums and the oracle's [`kyzo_oracle::Rejection`] (via trials /
/// `EngineRefusal::from_oracle_rejection`) lower into these four only.
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum EngineRefusal {
    /// Ill-formed / unsafe / precondition-failed query or door use.
    #[error("wrong query")]
    #[diagnostic(code(refuse::wrong_query))]
    WrongQuery {
        locus: RefusalLocus,
    },

    /// Structured cost-vs-ceiling — type-distinct from safety refuses.
    #[error("exceeded budget: spent {spent} of ceiling {ceiling}")]
    #[diagnostic(code(refuse::exceeded_budget))]
    ExceededBudget {
        locus: RefusalLocus,
        spent: u64,
        ceiling: u64,
    },

    /// Evaluation / fold / shape that cannot be answered safely.
    #[error("unsafe shape")]
    #[diagnostic(code(refuse::unsafe_shape))]
    UnsafeShape {
        locus: RefusalLocus,
    },

    /// Program is not stratifiable.
    #[error("stratification failure")]
    #[diagnostic(code(refuse::stratification_failure))]
    StratificationFailure {
        locus: RefusalLocus,
    },
}

/// Model / parse / program-IR layer refuse — lowers into [`EngineRefusal`].
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum ModelRefuse {
    #[error("malformed program shape")]
    #[diagnostic(code(refuse::model::malformed))]
    Malformed { locus: RefusalLocus },

    #[error("unsafe rule shape")]
    #[diagnostic(code(refuse::model::unsafe_rule))]
    UnsafeRule { locus: RefusalLocus },
}

impl From<ModelRefuse> for EngineRefusal {
    fn from(r: ModelRefuse) -> Self {
        match r {
            ModelRefuse::Malformed { locus } | ModelRefuse::UnsafeRule { locus } => {
                EngineRefusal::WrongQuery { locus }
            }
        }
    }
}

/// Exec / plan / fixpoint layer refuse — lowers into [`EngineRefusal`].
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum ExecRefuse {
    #[error("query budget exceeded: spent {spent} of ceiling {ceiling}")]
    #[diagnostic(code(refuse::exec::budget))]
    Budget {
        locus: RefusalLocus,
        spent: u64,
        ceiling: u64,
    },

    #[error("program is not stratifiable")]
    #[diagnostic(code(refuse::exec::unstratifiable))]
    Unstratifiable { locus: RefusalLocus },

    #[error("unsafe evaluation shape")]
    #[diagnostic(code(refuse::exec::unsafe_shape))]
    UnsafeShape { locus: RefusalLocus },

    #[error("wrong query at exec door")]
    #[diagnostic(code(refuse::exec::wrong_query))]
    WrongQuery { locus: RefusalLocus },
}

impl From<ExecRefuse> for EngineRefusal {
    fn from(r: ExecRefuse) -> Self {
        match r {
            ExecRefuse::Budget {
                locus,
                spent,
                ceiling,
            } => EngineRefusal::ExceededBudget {
                locus,
                spent,
                ceiling,
            },
            ExecRefuse::Unstratifiable { locus } => {
                EngineRefusal::StratificationFailure { locus }
            }
            ExecRefuse::UnsafeShape { locus } => EngineRefusal::UnsafeShape { locus },
            ExecRefuse::WrongQuery { locus } => EngineRefusal::WrongQuery { locus },
        }
    }
}

/// Session / Engine door refuse — lowers into [`EngineRefusal`].
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum SessionRefuse {
    #[error("session door refused the request")]
    #[diagnostic(code(refuse::session::wrong_query))]
    WrongQuery { locus: RefusalLocus },

    #[error("session evaluation shape refused")]
    #[diagnostic(code(refuse::session::unsafe_shape))]
    UnsafeShape { locus: RefusalLocus },
}

impl From<SessionRefuse> for EngineRefusal {
    fn from(r: SessionRefuse) -> Self {
        match r {
            SessionRefuse::WrongQuery { locus } => EngineRefusal::WrongQuery { locus },
            SessionRefuse::UnsafeShape { locus } => EngineRefusal::UnsafeShape { locus },
        }
    }
}

/// Host / binary composition refuse — lowers into [`EngineRefusal`].
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum HostRefuse {
    #[error("host door refused")]
    #[diagnostic(code(refuse::host::wrong_query))]
    WrongQuery { locus: RefusalLocus },

    #[error("host format or clock refuse")]
    #[diagnostic(code(refuse::host::format))]
    Format { locus: RefusalLocus },
}

impl From<HostRefuse> for EngineRefusal {
    fn from(r: HostRefuse) -> Self {
        match r {
            HostRefuse::WrongQuery { locus } => EngineRefusal::WrongQuery { locus },
            HostRefuse::Format { locus } => EngineRefusal::WrongQuery { locus },
        }
    }
}

/// Oracle [`kyzo_oracle::Rejection`] discriminant names — kept as a pure
/// lowering vocabulary so kyzo-core does not depend on kyzo-oracle.
///
/// Trials (and any future oracle→engine bridge) map live `Rejection` values
/// into this shape, then into [`EngineRefusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleRejectionKind {
    Unsafe,
    Unstratifiable,
    Malformed,
    AggrError,
    BudgetExceeded { spent: u64, ceiling: u64 },
}

impl EngineRefusal {
    /// Lower an oracle rejection kind into the four-way top type.
    pub fn from_oracle_rejection(kind: OracleRejectionKind) -> Self {
        let locus = RefusalLocus::exempt(SpanExempt::BudgetBarrier);
        match kind {
            OracleRejectionKind::Unsafe | OracleRejectionKind::Malformed => {
                EngineRefusal::WrongQuery {
                    locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
                }
            }
            OracleRejectionKind::Unstratifiable => EngineRefusal::StratificationFailure {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            },
            OracleRejectionKind::AggrError => EngineRefusal::UnsafeShape {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            },
            OracleRejectionKind::BudgetExceeded { spent, ceiling } => {
                EngineRefusal::ExceededBudget {
                    locus,
                    spent,
                    ceiling,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_enums_lower_into_four_way_only() {
        let cases: [EngineRefusal; 8] = [
            ModelRefuse::Malformed {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            }
            .into(),
            ModelRefuse::UnsafeRule {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            }
            .into(),
            ExecRefuse::Budget {
                locus: RefusalLocus::exempt(SpanExempt::BudgetBarrier),
                spent: 3,
                ceiling: 2,
            }
            .into(),
            ExecRefuse::Unstratifiable {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            }
            .into(),
            ExecRefuse::UnsafeShape {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            }
            .into(),
            ExecRefuse::WrongQuery {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            }
            .into(),
            SessionRefuse::WrongQuery {
                locus: RefusalLocus::exempt(SpanExempt::StoreLedger),
            }
            .into(),
            HostRefuse::Format {
                locus: RefusalLocus::exempt(SpanExempt::FormatVersion),
            }
            .into(),
        ];
        for r in cases {
            match r {
                EngineRefusal::WrongQuery { .. }
                | EngineRefusal::ExceededBudget { .. }
                | EngineRefusal::UnsafeShape { .. }
                | EngineRefusal::StratificationFailure { .. } => {}
            }
        }
    }

    #[test]
    fn oracle_kinds_lower_into_four_way() {
        assert!(matches!(
            EngineRefusal::from_oracle_rejection(OracleRejectionKind::Unstratifiable),
            EngineRefusal::StratificationFailure { .. }
        ));
        assert!(matches!(
            EngineRefusal::from_oracle_rejection(OracleRejectionKind::BudgetExceeded {
                spent: 9,
                ceiling: 8,
            }),
            EngineRefusal::ExceededBudget {
                spent: 9,
                ceiling: 8,
                ..
            }
        ));
        assert!(matches!(
            EngineRefusal::from_oracle_rejection(OracleRejectionKind::AggrError),
            EngineRefusal::UnsafeShape { .. }
        ));
    }
}
