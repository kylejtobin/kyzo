---
law_format: 1
assignment: deprecated
zone: boundary
destination: proof
globs:
  - "crates/kyzo-core/src/session/footprint.rs"
description: "Deprecated. A seventeen-type vocabulary with sole-mint discipline, sitting inside the admission path."
purity:
  - set: rust
    version: "0.1.0"
capabilities: []
---

# Deprecated: a vocabulary inside the admission path

`session/footprint.rs` is 580 lines exporting seventeen public types, and its own
header states what it owns: `AskShape`, `Footprint`, `Frontier`, `EdgePredicate`,
the accelerator contract, the footprint index, overlap adjudication, and
`FootprintClearEvidence` with a sole mint through
`LiveFootprintTable::prove_epoch_clear`.

That is a vocabulary and its constructors, which is Proof. It reaches no
capability. It carries Boundary's clause set today because it sits in the one
admission path and adjudicates what may be admitted; the destination is Proof,
and the migration is extracting the types and their mints from the adjudication
that uses them.

Deprecated is not a softer posture: Boundary's full clause set governs it now, and
the destination suppresses nothing on the way.
