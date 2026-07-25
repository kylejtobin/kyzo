---
paths:
  - "crates/kyzo-core/src/exec/**/*.rs"
---

# Zone: Exec — derived truth

One machine that turns proven programs into answers, deterministically.

## Required

- ONE execution currency: packed interned codes. Dedup and identity inside a
  fixpoint key on codes, never durable canonical bytes.
- Every raw-code compare or spend happens under same-domain admission; codes
  are unforgeable (no public raw constructors).
- ONE production expression evaluator. Expression semantics are defined in the
  model; they are evaluated here and in the oracle, nowhere else.
- Deterministic everything: no randomized-iteration collections, no unseeded
  randomness, no wall clock; parallel evaluation produces byte-identical
  results (rows AND order) at any thread count.
- Stdlib functions are pure and total over typed values; partiality is a typed
  error. Aggregations and sketches are deterministic folds — merge order must
  not change the result.
- Stratification is proven before evaluation. Termination arguments are
  recorded where recursion or iteration is unbounded by construction.
- Provenance seams are load-bearing: an operator that cannot attribute its
  output to its inputs is incomplete. Non-idempotent annotations never run on
  the idempotent fixpoint.
- Every operator's semantics must be expressible naively — if the oracle
  cannot state it, it does not land.
- Plan transforms (magic sets, reordering, pushdown) change demand and cost,
  never result semantics — proven by the oracle differential.
- The execution currency never persists: codes, rows, and columns die with
  their epoch; nothing serializes them and no code leaves an encoded key.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- One execution currency of epoch-scoped codes. Query-semantic order is defined here, never by importing model `Ord` as query law. Codes never persist.

## Forbidden

- Canonical encoding in a hot loop (the counter law gates this).
- Allocation in the per-row hot path.
- A second batch container, expression evaluator, or dedup identity.
- Host `dyn CustomOp` / foreign expression registration — sealed stdlib only;
  host-minted expression meaning is Unconstructible.
- Reaching into projections' internals — candidates come through the search
  operator seam.

## Comment ontology

| kind | form | placement |
| --- | --- | --- |
| authority | `//! AUTHORITY: ` | file head; one Spec organ |
| seat | `//! SEAT: ` | under AUTHORITY; `zone-<name>/<role>` |
| file_kind | `//! FILE_KIND: ` | under SEAT; id from File template |
| citation | `//! CITATION: ` | when FILE_KIND requires |
| construct | `// CONSTRUCT: ` | above seated item; `<grammar> <Ident>` |
| order_law | `// ORDER_LAW: ` | above ordered/encoded type |
| claim | `// CLAIM: ` | `Unconstructible\|Refused\|Unexposed — <state>` |
| engine_edit | `// ENGINE_EDIT: ` | vendor divergence only |
| refuse_doc | `/// Refuse(` | error variants |
| api_doc | `/// ` | public contract nouns only |

This table is total; not listed = red.

Comments name Spec surface only. Motive, apology, history, metacommentary, and performative language are red.

## File template

Path touch loads this rule. Obey FILE_KIND rows below. Markers: `// --- zone-file:<id> ---` with ids imports, types, construction, order_encode, decode, verbs, state, adapters, refusals, wiring, tests. Absent section = no marker.

| FILE_KIND | section order | required | forbid |
| --- | --- | --- | --- |
| `rel_op` | I T C V R X | provenance; oracle-expressible | durable code encode |
| `rel_op_spine` | I T C V R X | total constructors | |
| `plan_node` / `plan_rewrite` / `plan_compile` | I T C V R X | semantics-preserving CLAIM on rewrite | |
| `fixpoint_engine` | I T S V R X | epoch currency; stratification | persist codes |
| `expr_eval` | I T V R X | one production evaluator | second evaluator |
| `stdlib_kernel` | I T C V R X | pure total | host CustomOp |
| `stdlib_bind` | I T C V R X | sole BoundOp mint | |
| `provenance_engine` | I T C V R X | load-bearing provenance | |
| `fold_aggr` / `fold_sketch` | I T C V R X | merge-order irrelevant | |
| `result_sort` | I T V R X | query-semantic order here | model Ord as query law |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: <one RelAlgebra operator>
//! SEAT: zone-exec/op/<name>
//! FILE_KIND: rel_op

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:construction ---
// --- zone-file:verbs ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

## Dual-authority debt

| path | fused |
| --- | --- |
| `op/mod.rs` | constructors + invariants + dispatch + explain |
| `stdlib/bind.rs` | BoundOp mint + registry |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.

