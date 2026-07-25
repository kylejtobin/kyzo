---
paths:
  - "crates/kyzo-bin/**/*.rs"
---

# Zone: Host, Native — CLI, REPL, and marshal-only network adapters

A way to reach the engine. Never a place engine meaning lives.

Max purity: one sealed typed door. Hosts only marshal. Network carriage is the Kyzo
envelope over the fabric (NATS subject grammar / request-reply). HTTP/gRPC as a
second public product protocol is deleted — optional thin white-label skin may wrap
the same envelope for a density; it never invents verbs, authz, or meaning.

## Required

- Consumes the sealed public contract only; results are rendered and routed
  through the envelope vocabulary.
- No panic escapes a request handler or REPL command: every failure renders
  as a typed error to the caller with the engine's reason and span intact.
  Panic containment is at the typed envelope on every host — not incidental to
  one transport.
- Every entry path passes the auth/capability gate; the surface is enumerable
  and each path is deliberate.
- Streaming and subscribe surfaces preserve the engine's delivery guarantees —
  the host never reorders, dedups, or drops. Delivery, fan-out, and durable
  resume are the fabric's (NATS/JetStream), never a second delivery mechanism
  built here.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Marshal and render only. No host shadow state. No `order_encode` / `admit_door` / eval sections.

## Forbidden

- Importing engine internals — a host that needs a private door is evidence
  the public contract is missing something; fix the contract.
- Interpreting or transforming results beyond envelope rendering — no
  host-side semantics, filtering, or "helpful" coercions.
- `unwrap`/`expect` on any request path.
- State of its own that the engine cannot account for (caches of results,
  shadow catalogs).
- Treating HTTP/REST/gRPC as architecture or a second meaning door beside the
  sealed envelope / NATS carriage.

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
| `composition_root` | I W X | config-once | domain types |
| `route_marshal` | I A R X | envelope only | order_encode, admit_door |
| `render_envelope` | I A X | reason+span intact | interpretation |
| `host_engine_hold` | I T W X | holds Engine | fused Db |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: native host composition root
//! SEAT: zone-bin/main
//! FILE_KIND: composition_root

// --- zone-file:imports ---
// --- zone-file:wiring ---
// CONSTRUCT: composition-root main
// --- zone-file:tests ---
```

