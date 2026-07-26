#!/usr/bin/env bash
# Discharge the canonical encoder's order law.
#
# Pinned: Verus 0.2026.07.18.3a4d30b, Z3 4.12.5, rust 1.96.0.
# Exits non-zero with a counterexample if any obligation fails.
set -euo pipefail

VERUS="${VERUS_HOME:-$HOME/.local/verus/verus-x86-linux}/verus"
TARGET="crates/kyzo-model/src/value/canonical.rs"

if [ ! -x "$VERUS" ]; then
  echo "verus not found at $VERUS; set VERUS_HOME" >&2
  exit 2
fi

"$VERUS" --crate-type=lib "$TARGET" --triggers-mode silent
