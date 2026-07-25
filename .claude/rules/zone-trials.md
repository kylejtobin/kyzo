---
paths:
  - "crates/kyzo-trials/**/*.rs"
---

# Zone: Trials — the campaigns

Attacks on published claims, rerunnable by strangers.

## Required

- Every trial attacks a PUBLIC claim through the public surface with published
  seeds — a stranger can rerun everything from the committed artifacts.
- The verdict space is binary: zero counterexamples, or the claim retracts.
  There is no "mostly passed."
- Corpora, harnesses, and seeds are versioned artifacts; a trial that cannot
  be reproduced proves nothing.
- Determinism trials compare bytes, not summaries. Differential trials judge
  against the oracle, never against the engine's own second opinion.
- The storage conformance kit is public: any backend (ours or a stranger's)
  can run it unmodified.
- Every expected value is independently derived — hand derivation, an
  independent test-only encoder, or a byte-by-byte comment — never captured
  from the engine's own output.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Public claim, public surface, published seeds. Binary verdict. Independently derived expected values.

## Forbidden

- Testing internals — that is the job of unit/hostile tests living beside the
  code inside its authority. A trial needing a private door means the public
  surface is missing something; fix the surface.
- Weakened assertions to keep a campaign green; goldens copied from output.
- A trial whose failure is survivable narrative — a red trial blocks the claim
  it attacks, mechanically.

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
| `campaign` | I T C V X | AUTHORITY names claim under attack | private doors; captured goldens |
| `conformance_kit` | I T V X | public kit | |
| `compile_fail_campaign` | I X | Unconstructible proof | |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: attack claim <seat-or-claim-id>
//! SEAT: zone-trials/<campaign>
//! FILE_KIND: campaign

// --- zone-file:imports ---
// --- zone-file:types ---
// --- zone-file:construction ---
// --- zone-file:verbs ---
// --- zone-file:tests ---
```

