---
paths:
  - "crates/kyzo-core/src/react/**/*.rs"
---

# Zone: React — derived truth kept current

Standing queries, incremental maintenance, change feeds.

## Required

- Every incremental result is provably equal to full recomputation — the
  differential proof ships with the feature, not as an afterthought test.
- The ordered write log is the ONLY feed source; there is no second change
  authority.
- The engine owns what an event IS and snapshot-consistency and emits the
  ordered record-event log; subscriber fan-out, backpressure, and durable-
  resume DELIVERY are the fabric's (NATS/JetStream), never built in this zone.
- Delivery is snapshot-consistent: a subscriber can never observe a state the
  log never contained, and delivery order is deterministic.
- Registration, cancellation, and failure of a standing query are typed
  lifecycle states.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Ordered write log is the only feed. Delivery is fabric carriage. Incremental equals full recompute by shipped proof.

## Forbidden

- Recompute-and-diff masquerading as incremental maintenance (except as the
  proof's reference side).
- Callbacks or triggers that can mutate state outside the one admission path.
- Buffering that silently drops or reorders events — backpressure is typed
  and visible.

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
| `react_standing` | I T C S V R X | typed lifecycle; residency≠durability CLAIM | peer dial |
| `react_incremental` | I T S V R X | differential proof shipped | second change authority |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: standing query lifecycle
//! SEAT: zone-react/standing
//! FILE_KIND: react_standing

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:construction ---
// --- zone-file:state ---
// --- zone-file:verbs ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

