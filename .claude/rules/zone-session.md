---
paths:
  - "crates/kyzo-core/src/session/**/*.rs"
  - "crates/kyzo-core/src/lib.rs"
---

# Zone: Session — the one door

Everything between a caller and the truth: entry, admission, catalog,
observers, operations, the verify summons.

## Required

- ALL writes pass through the one admission path; there is no second way for
  data to reach storage from outside.
- Constraints gate admission as denial rules with typed witnesses — a refusal
  is a value naming the constraint and the offending rows, never an error string.
- Every catalog mutation is atomic across all its rows, with validity
  generations bumped in the same transaction.
- Public doors are enumerable and each is deliberate: adding a public surface
  (a `::` op, an API method, an envelope field) is an operator ruling.
- Every failure that reaches a caller is typed. The parsed grammar surface and
  the executable surface agree: parsed-but-unowned operations are explicitly
  owned typed refusals.
- `::verify` summons the oracle crate; it never reimplements any semantics.
- Relation triggers and their semantics are ours; post-commit external
  NOTIFICATION delivery is a publish-on-commit to the fabric (NATS), never an
  outbound delivery mechanism built in this zone.
- CompositionId is client-rooted; OperationKey + OperationOutcome is the one
  idempotency organ — Engine-minted CompositionId is Unconstructible.
- Catalog generations are the one meaning-clock for projection freshness.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- All external writes through one admission path. `lib.rs` is `sealed_door` only. CompositionId is client-rooted.

## Forbidden

- `unwrap`/`expect` on any path reachable from a caller.
- Engine semantics implemented here (evaluation, encoding, projection logic
  belong below; this zone routes, admits, and administers).
- A bypass door for tests, tools, or convenience — corruption/bypass tests
  construct through storage directly and are named as such.

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
| `admit_door` | I T C V R X | admission-door; typed denial; CLAIM bypass | order_encode; eval bodies |
| `footprint_algebra` | I T C V R X | Fenced forbids Underivable | durable lock organ |
| `catalog_seat` | I T S V R X | interpreter; no byte sink | |
| `engine_compose` | I T S V R X | holds capabilities; CLAIM fused Db | |
| `composition_id` | I T C V R X | client-rooted; Engine-mint Unconstructible | |
| `system_ops` | I T V A R X | enumerable doors | |
| `sealed_door` | I W X | re-exports only (`lib.rs`) | domain mint |
| `normalize_door` | I T C V R X | | |
| `observe_hooks` | I T S V R X | | |
| `capacity_budget` | I T V R X | typed refuse; no silent stall | |
| `verify_door` | I T V R X | summons oracle | reimplement semantics |
| `constraint_check` | I T C V R X | typed witnesses | |
| `projection_session_door` | I T V R X | routes to project | projection internals |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: Record admission door
//! SEAT: zone-session/admit
//! FILE_KIND: admit_door

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:construction ---
// CONSTRUCT: admission-door admit
// CLAIM: Unconstructible — bypass write path
// --- zone-file:verbs ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

## Dual-authority debt

| path | fused |
| --- | --- |
| `db.rs` | Engine compose + SessionView + Normalizer |
| `footprint.rs` | AskShape + Footprint + Frontier |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.

