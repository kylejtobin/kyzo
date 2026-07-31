---
law_format: 1
assignment: deprecated
zone: boundary
destination: core
globs:
  - "crates/kyzo-core/src/exec/op/temporal.rs"
  - "crates/kyzo-core/src/exec/stdlib/nondet.rs"
  - "crates/kyzo-core/src/rules/rng.rs"
  - "crates/kyzo-core/src/rules/algo/k_core.rs"
  - "crates/kyzo-core/src/rules/algo/label_propagation.rs"
  - "crates/kyzo-core/src/rules/algo/random_walk.rs"
  - "crates/kyzo-core/src/react/standing.rs"
  - "crates/kyzo-core/src/parse/sys.rs"
description: "Deprecated. Computation that reaches a capability: it belongs in Core and takes the effect as an argument."
purity:
  - set: rust
    version: "0.1.0"
capabilities: [filesystem, process, time, randomness]
---

# Deprecated: effects inside computation

Each of these is responsible for computing over proven values, which is Core, and
each reaches something Core forbids. They carry Boundary's clause set today
because that is what governs code holding a capability. The destination is Core,
and the migration is the same in every case: the effect becomes an argument.

| path | reaches |
| --- | --- |
| `exec/op/temporal.rs` | `std::fs`, `std::env` |
| `exec/stdlib/nondet.rs` | `SystemTime` |
| `rules/rng.rs` | ambient generator |
| `rules/algo/k_core.rs` | ambient generator |
| `rules/algo/label_propagation.rs` | ambient generator |
| `rules/algo/random_walk.rs` | ambient generator |
| `react/standing.rs` | ambient generator |
| `parse/sys.rs` | `std::fs` |

Deprecated is not a softer posture. These carry Boundary's full clause set, and
the destination suppresses nothing on the way.

Why this is not cosmetic: the engine's contract is that a replay reproduces a run
exactly and a query answered twice answers the same. An evaluation operator that
reads the filesystem, a stdlib function that reads the clock, and a graph
algorithm that draws from an ambient generator each break that, and each breaks it
silently — the run succeeds and returns a different answer. `exec/op/temporal.rs`
is the sharpest: temporal evaluation is exactly where an environment read changes
what a query means.

`store/sweep.rs` reads `std::env` while sitting in a zone that declares filesystem
and time. That is a capability finding rather than a misplacement, so it stays
assigned to Boundary and the clause fires there.
