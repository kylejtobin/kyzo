---
paths:
  - "crates/kyzo-core/src/project/**/*.rs"
---

# Zone: Project — projections

Rebuildable speed over canonical truth. Never truth itself.

## Required

- The projection law is absolute: every structure here is rebuildable from
  canonical facts, byte-identically, at any time. If canonical storage cannot
  regenerate it, it is misplaced authority and a red gate.
- Projections serve CANDIDATES to exec's search operators; they never answer
  queries directly. Exactness and recall contracts are declared types.
- Maintenance is commit-coupled and generation-stamped; staleness is
  detectable by type, never silent.
- A projection's building form and its queryable form are distinct types
  joined by exactly one consuming seal: the building type exposes no search
  method at all (querying an unsealed index is absent from the interface, not
  a runtime error), and the sealed generation is part of the type-visible
  contract.
- Deterministic construction and search: same facts, same seed, same
  projection, same candidates — on every host.
- Every engine follows the uniform shape: its maintenance, its search, its
  law, one directory per genuinely distinct projection kind.
- A decode failure crossing an engine boundary becomes a TYPED engine
  corruption error — a raw decode error never leaks where the contract says
  index corruption.
- Manifests and per-engine metadata carry config only, never value
  authority, through the store's one ruled metadata door.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Building type exposes no search. Sealed type carries generation. Candidates only. One directory per projection kind.

## Forbidden

- Writing canonical state, ever, from anywhere in this zone.
- A projection consulted as a source of truth (existence, counts, or values).
- Scaffolding, harnesses, or hostile batteries shipped as engine siblings —
  batteries live in the module's test submodule; campaigns live in trials.
- Un-owned foreign code: every file in this zone carries our module doc and
  our type discipline, vendored lineage or not.
- Dual-seating Gazetteer (or any projection kind) in `rules/` — rules invoke
  through the typed view; the rebuildable index lives only here.
- In-place reinterpretation of an AcceptedReplica — LocalProjection is a
  rebuildable cache over the origin certificate, never Record meaning.

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
| `projection_engine` | I T C S V R X | Building→seal→Sealed; CLAIM query-on-Building | Store write |
| `projection_index` | I T C S V R X | candidates only; two-axis if durable | truth answers |
| `projection_contract` | I T V R X | trait boundary | |
| `fts_analyzer` | I T C V R X | deterministic | Store write |
| `local_projection` | I T C S V R X | rebuildable over certificate; CLAIM reshape Unconstructible | |

This table is total; not listed = red.

State section order inside `projection_engine`: Building → seal door → Sealed. Reverse is red.

### Dominant skeleton

```rust
//! AUTHORITY: <projection kind> build/seal lifecycle
//! SEAT: zone-project/<kind>
//! FILE_KIND: projection_engine

// --- zone-file:imports ---
// --- zone-file:types ---
// Building (no search)
// --- zone-file:construction ---
// --- zone-file:state ---
// --- zone-file:verbs ---
// CONSTRUCT: consuming-verb seal
// Sealed (search only here)
// CLAIM: Unconstructible — query on Building
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

## Dual-authority debt

| path | fused |
| --- | --- |
| `projection.rs` | build + seal + query lifecycle |
| `text/fts.rs` | index + query |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.

