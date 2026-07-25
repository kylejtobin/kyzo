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

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- One algorithm per file. `CITATION` required. Relation I/O only.

## Forbidden

- Direct storage scans, projection internals, or session state.
- Unseeded or thread-timing-dependent randomness.
- A second in-memory graph representation — the one typed view serves all.
- Panics on any user-supplied option or degenerate graph shape.

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
| `fixed_rule_algo` | I T C V R X | CITATION; determinism-as-data | Store/projection internals |
| `fixed_rule_contract` | I T V R X | | |
| `fixed_rule_view` | I T V R X | one typed view | second graph |
| `fixed_rule_io` | I T C V R X | relation I/O | |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: <algorithm> as FixedRule
//! SEAT: zone-rules/algo/<name>
//! FILE_KIND: fixed_rule_algo
//! CITATION: <paper or standard>

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
| `contract.rs` | FixedRule + SessionFixedRule + CancelFlag + adapter |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.

