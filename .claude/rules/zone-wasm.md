---
paths:
  - "crates/kyzo-wasm/**/*.rs"
---

# Zone: Host, WASM — the runtime envelope

The real engine inside foreign hosts: browser, edge, embedded runtimes.

## Required

- ONE envelope: typed request in, typed result or typed error out. Every
  foreign host consumes this same surface — playground, demo, and production
  are the same build.
- The panic boundary is typed by construction: an engine panic crosses only
  as the typed error, never as host corruption.
- Determinism is the product: the same input produces serialized results
  byte-identical to a native build — this is a standing proof, not a hope.
- No clock, no randomness, no IO enters the engine except through typed,
  deterministic envelope inputs.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- One envelope. Same engine build. Panic crosses as typed error. No `order_encode`.

## Forbidden

- A toy or reduced engine build — what runs here is the engine.
- A second request/response shape beside the envelope, for any consumer.
- Host-JS logic that interprets results beyond envelope decoding.
- `unwrap`/`expect` anywhere the host can reach.

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
| `wasm_envelope` | I T A R W X | one envelope; panic→typed | second shape; order_encode |
| `composition_root` | I W X | | domain mint |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: WASM host envelope
//! SEAT: zone-wasm/envelope
//! FILE_KIND: wasm_envelope

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:adapters ---
// --- zone-file:refusals ---
// --- zone-file:wiring ---
// --- zone-file:tests ---
```

## Path hole

ZONE_PATH_HOLE: `target-arch.md` currently lists zero wasm paths. FILE_KINDs above remain mandatory for any wasm `.rs` that lands.

