---
paths:
  - "crates/kyzo-lsp/**/*.rs"
---

# Zone: Host, LSP — the language server

Editor tooling over the language, not over the engine.

## Required

- Speaks the model's parse tier only: diagnostics, spans, and completions come
  from the same lift and refusals users get at runtime — one grammar, one
  truth about what parses.
- Every diagnostic carries the parse tier's reason and span verbatim; the LSP
  invents no judgments of its own.
- Degrades gracefully: a file that does not parse still gets best-effort
  spans, never a crash.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Parse tier only. Diagnostics carry model refuse reason and span verbatim.

## Forbidden

- Depending on the engine (storage, execution, session) — the language server
  needs the language, not the database.
- A private parse door or a second grammar — if the LSP needs something the
  parse tier does not expose, extend the parse tier's public surface.
- Editor-side reimplementation of formatting — the canonical formatter is the
  one formatter.

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
| `lsp_translate` | I A R X | reason+span verbatim | engine imports; order_encode |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: parse-tier diagnostic translation
//! SEAT: zone-lsp/translate
//! FILE_KIND: lsp_translate

// --- zone-file:imports ---
// --- zone-file:adapters ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

