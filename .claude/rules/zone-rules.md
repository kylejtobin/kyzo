---
paths:
  - "crates/kyzo-core/src/rules/**/*.rs"
---

# Zone: Rules — algorithms as rules

The invocable library: graph algorithms and utility rules.

## Required

- Every rule declares its determinism; all randomness flows from the one
  seed-reproducible generator — same seed, same output, every host.
- Inputs and outputs are relations. A rule touches storage and projections
  only through its typed graph/relation view, never directly.
- One algorithm per file, named for the algorithm, citing its source
  (paper or standard) in the module doc.
- Limits and options are typed and validated at construction.

- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- One AUTHORITY per file. A file that needs two is split before merge.
- One algorithm per file. `CITATION` required. Relation I/O only.

## Forbidden

- Direct storage scans, projection internals, or session state.
- Unseeded or thread-timing-dependent randomness.
- A second in-memory graph representation — the one typed view serves all.
- Panics on any user-supplied option or degenerate graph shape.

## Dual-authority debt

| path | fused |
| --- | --- |
| `contract.rs` | FixedRule + SessionFixedRule + CancelFlag + adapter |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.
