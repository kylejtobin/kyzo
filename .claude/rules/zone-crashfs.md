---
paths:
  - "crates/kyzo-crashfs/**/*.rs"
---

# Zone: Crashfs — the fault injector

A standalone instrument that makes the filesystem lie on command, so the crash
matrix in trials can prove the store survives it. Its nature dictates three
parts and no more: a plan, an application, a mount.

## Required

- Every fault decision is a pure function of the seed: the same seed reproduces
  the identical fault schedule, byte-for-byte, on every host and every run.
- Three parts, one nature — a fault PLAN (what fails and when, decided only by
  the seed), an APPLICATION (the passthrough filesystem that enacts the plan
  over a backing directory), and a MOUNT lifecycle (capability detection,
  setup, teardown).
- The instrument injects faults; it never judges outcomes. The verdict lives in
  `kyzo-trials`' crash matrix that drives this; a green run here means nothing
  by itself.
- Capability detection is explicit: where the platform cannot mount, the
  harness refuses with a typed reason — never a silent degrade to a no-op that
  reports success.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Plan, application, mount. Faults pure in seed. No engine dependency. No verdict ownership.

## Forbidden

- Any nondeterminism in fault selection — wall clock, thread timing, unseeded
  randomness. A fault that cannot be replayed from its seed is a defect.
- A dependency into the engine crates: the injector stands beside the
  filesystem, not inside the database. `kyzo-trials` depends on it; it depends
  on nothing of ours above the fault plane.
- `unwrap`/`expect` on any path reachable from a running campaign — a crashed
  injector is a lost counterexample, not a result.

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
| `fault_plan` | I T C V R X | seed-pure | engine dep |
| `fault_application` | I T S V R X | | |
| `fault_mount` | I S V R W X | typed capability refuse | silent no-op success |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: seed-pure fault schedule
//! SEAT: zone-crashfs/plan
//! FILE_KIND: fault_plan

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:construction ---
// --- zone-file:verbs ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

