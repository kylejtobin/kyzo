---
paths:
  - "crates/kyzo-oracle/**/*.rs"
---

# Zone: Oracle — the reference semantics

The engine's naive twin. The law here is INVERTED.

## Required

- Slow is correct: obviousness outranks performance, always. The value of this
  zone is that it is too simple to share a bug with the engine.
- Complete over the whole language: an `unsupported` answer is a coverage hole
  to close, never a boundary to accept. The oracle owns its OWN expression
  evaluator, its own temporal semantics, its own reference provenance.
- Small enough to hostile-review line by line.
- Checkers re-derive from scratch over the model; they never trust
  intermediate engine state.
- Depends on the model (the shared vocabulary) ONLY.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Naive complete semantics. Model dependency only. Obviousness outranks speed.

## Forbidden

- Optimization. A performance improvement here is a defect.
- Importing anything from the engine: no evaluator code, no execution
  currency, no clever algorithms — not even the ideas. The crate wall makes
  the import impossible; the review keeps the ideas out.
- Sharing helper code with what it judges.

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
| `oracle_eval` | I T C V R X | naive complete; model only | engine import |
| `oracle_check` | I T V R X | re-derive | engine intermediates |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: reference expression/program evaluator
//! SEAT: zone-oracle/eval
//! FILE_KIND: oracle_eval

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:construction ---
// --- zone-file:verbs ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

