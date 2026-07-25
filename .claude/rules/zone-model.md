---
paths:
  - "crates/kyzo-model/**/*.rs"
  - "crates/kyzo-model/**/*.pest"
  - "crates/kyzo-core/src/model/**/*.rs"
  - "crates/kyzo-core/src/model/**/*.pest"
---

# Zone: Model — the shared vocabulary

What the engine, its judges, and its hosts must all agree on before execution
exists: values, schemas, programs, the parse lift, the wire envelopes.

## Required

- Pure data only. The zone's verbs are construct, compare, encode, decode.
- Every decode returns a typed `Result`; every refusal names its reason and span.
- Every parse and decode is total over every byte sequence: recursive descent
  carries a typed depth bound, no input-declared size reaches an allocator
  unbounded or as an infallible reservation, and no matching path admits
  catastrophic backtracking. Adversarial totality is proven by fuzzing, never
  asserted by review.
- Every value kind defines its identity and order law BEFORE its bytes; the
  canonical encoding is the ONLY byte authority for values, everywhere.
- Vector dimensionality is schema- and data-determined per row, never pinned
  into the value type as a const generic — the value plane cannot carry it as
  a type-level fact; where a kernel needs a fixed dimension, that guarantee is
  minted once at admission and consumed downstream without re-checking.
- Constructors enforce identity laws; unchecked constructors are private to
  their module; compile-time absence proofs seal the doors.
- A value lifted at a boundary carries its proof forward as a branded fact; no
  downstream site re-checks what a constructor already proved — a redundant
  re-check is dead code or a missing type.
- One `Tag` is the only type-discriminant and cross-type order authority;
  comparison flows through the one prefix doctrine.
- `Expr` and the program tiers define MEANING as data — no evaluator here.
- Wire codecs (JSON, Arrow) are total, round-trip-proven views; they add no
  meaning the value plane lacks.
- The grammar advertises nothing unowned: every grammar rule has an owner or
  an explicitly owned typed refusal.
- The model's order is STRUCTURAL (storage and identity); query-semantic
  comparison belongs to evaluation and is defined separately — the two must
  never be conflated at any site.
- Unboundedness is a shape, not a sentinel: an unbounded endpoint is a
  distinct typed variant, byte-distinct and round-trip-distinct from every
  finite instant. No sentinel value ever carries meaning, and no sentinel
  leaks through a public API.
- `capacity::admit` is the one allocation-admission seam for input-declared
  sizes — no site invents its own `.min(available)` reserve cap.
- Staged builders use typestate markers so missing required fields fail to
  compile; sealed products have private constructors.
- Program tiers (Input / Normal / Stratified / Magic) are meaning-as-data here;
  evaluation of those tiers is exec/oracle only.
- CanonicalTranscript encoding checklist + golden vectors own sealed artifact
  bytes that are not value-plane (grants, certificates, seals).

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Pure data. `ORDER_LAW` before any `Ord` or canonical encode. Decode is total. No IO, eval, or store sections.

## Forbidden

- IO, clocks, randomness, storage access, evaluation, allocation-heavy cleverness.
- A second serialization of any value, anywhere, for any reason.
- String-typed names or kinds surviving past the parse boundary.
- Dependencies on any other crate of ours.
- Changing a RELEASED byte format without a FormatVersion decision and
  round-trip + ordering tests: byte order MUST equal semantic value order.

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
| `value_kind` | I T C O D V R X | ORDER_LAW; private encode; CLAIM | state, wiring |
| `order_tag` | I T C O R X | Tag order = cross-type law | state, wiring, adapters |
| `order_encode` | I T C O D R X | one encode path; FormatVersion | state, wiring |
| `program_ir` | I T C V R X | meaning-as-data | order_encode, decode, state, wiring |
| `parse_lift` | I T C D R X | owned rule or refuse; span | order_encode, state, wiring |
| `parse_grammar` | pest file | every production owned | — |
| `wire_envelope` | I T C D A R X | total round-trip; no new meaning | order_encode, state, wiring |
| `schema_vocab` | I T C V R X | schema vocabulary | order_encode, state, wiring |
| `typestate_builder` | I T C V R X | missing field compile-fail | state, wiring |
| `value_arena` | I T C S V R X | epoch currency; CLAIM bare Code | order_encode, wiring |
| `zone_mod` / `crate_root` | I W X | re-exports only | domain mint |

I=imports T=types C=construction O=order_encode D=decode V=verbs S=state A=adapters R=refusals W=wiring X=tests.

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: <one value-plane organ>
//! SEAT: zone-model/<role>
//! FILE_KIND: value_kind

// --- zone-file:imports ---
// --- zone-file:types ---
// CONSTRUCT: newtype-scalar <Ident>
// ORDER_LAW: <predicate>
// CLAIM: Unconstructible — <illegal state>
// --- zone-file:construction ---
// --- zone-file:order_encode ---
// --- zone-file:decode ---
// --- zone-file:verbs ---
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

## Dual-authority debt

| path | fused |
| --- | --- |
| `value/arena.rs` | intern + observers + Admission/Denial |
| `value/number.rs` | numeric kinds + encode |
| `parse/search.rs` | FTS AST + search-atom lift |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.

