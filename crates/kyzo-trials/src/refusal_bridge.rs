/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Oracle [`Rejection`] → engine [`EngineRefusal`] lowering (#271 T1).
//!
//! kyzo-core cannot depend on kyzo-oracle; trials owns both deps and is the
//! bridge seat until a shared model-layer vocabulary is allowlisted.

use kyzo::{EngineRefusal, OracleRejectionKind};
use kyzo_oracle::Rejection;

/// Lower a live oracle rejection into the closed four-way engine top type.
pub fn engine_refusal_from_oracle(rejection: &Rejection) -> EngineRefusal {
    let kind = match rejection {
        Rejection::Unsafe(_) => OracleRejectionKind::Unsafe,
        Rejection::Unstratifiable(_) => OracleRejectionKind::Unstratifiable,
        Rejection::Malformed(_) => OracleRejectionKind::Malformed,
        Rejection::AggrError(_) => OracleRejectionKind::AggrError,
        Rejection::BudgetExceeded(b) => OracleRejectionKind::BudgetExceeded {
            spent: b.spent,
            ceiling: b.ceiling,
        },
    };
    EngineRefusal::from_oracle_rejection(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyzo_oracle::{AggrFail, BudgetAxis, BudgetExceeded, Rel};

    #[test]
    fn oracle_five_lower_into_four() {
        let rel = Rel::from("r");
        assert!(matches!(
            engine_refusal_from_oracle(&Rejection::Unstratifiable(rel.clone())),
            EngineRefusal::StratificationFailure { .. }
        ));
        assert!(matches!(
            engine_refusal_from_oracle(&Rejection::AggrError(AggrFail::Fold)),
            EngineRefusal::UnsafeShape { .. }
        ));
        assert!(matches!(
            engine_refusal_from_oracle(&Rejection::BudgetExceeded(BudgetExceeded {
                axis: BudgetAxis::Epochs,
                spent: 2,
                ceiling: 1,
            })),
            EngineRefusal::ExceededBudget {
                spent: 2,
                ceiling: 1,
                ..
            }
        ));
        assert!(matches!(
            engine_refusal_from_oracle(&Rejection::Malformed(rel)),
            EngineRefusal::WrongQuery { .. }
        ));
    }
}
