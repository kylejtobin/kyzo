# TEMP.md — the build list after demolition

Written 2026-07-31, mid-refactor, on `epic/205-kyzorecord-accountable-unit`.
The tree does not compile and is not meant to. This file is what gets built
once the demolition and the detector cleanup are done.

---

## 0. State of the tree right now

**Deleted (demolition, staged):**

| file | gone |
| --- | --- |
| `data/statement.rs` | `OntokKind::{Entity, Event, State, Role}` |
| `data/statement.rs` | `StatementSubject`, `StatementPredicate`, `StatementValue`, `ValidityTime` |
| `data/statement.rs` | `StatementRefuse` (its only variant served the deleted predicate) |
| `data/statement.rs` | `construct::{entity, state, event, role}` |
| `session/admit_lowering.rs` | `dimensions_entailed(kind)` |
| `session/admit_lowering.rs` | `crossing_kind_from_ontok` |
| `store/replica.rs` | `CrossingKind`, its `from_wire`/`as_wire`, `From<CrossingKind> for u8` |

**Still standing and now dangling:** `StatementBody` (six fields, four of whose
types no longer exist), the eight surviving `construct::*` helpers, every
`CrossingEnvelope` / `CrossingEnvelopeParts` site naming `CrossingKind`, and
every test fixture building a subject from a `DataValue`.

---

## 1. `Reference` — the one address

One newtype over 32 bytes. Everything addressable is a record: a concept, an
artifact, a context, a claim, a derivation, a pack. What a reference points at
is found by following it, never by reading its type.

- Private field. Construction only from a proven content digest.
- Fixed width, so memcomparable by construction, no encoding branch.

**Illegal state removed:** a subject or predicate that is a string, and
therefore a graph whose node identity depends on spelling.

## 2. `StatementValue = Edge | Attribute`

```
Edge(Reference)
Attribute(Literal)

Literal = Text(Words)
        | Whole(Count, Unit)
        | Fraction(Magnitude, Unit)
        | Instant(Micros)
        | Truth(bool)
```

The edge/attribute cut goes at the **outer** constructor, not as one tag among
six, because that is the distinction the graph exists for. `Unit` is a
`Reference` — units are Concepts shipped in packs, not an enum the engine owns.

**Illegal state removed:** a graph edge whose target is prose; a magnitude with
no unit; a unit vocabulary the engine grows every time a pack ships.

## 3. `entailed_dimensions(&StatementValue)`

Replaces the deleted twelve-arm `dimensions_entailed(kind)`.

```
Edge(_)                        -> [Identity, Relationship, Time, Source]
Attribute(Text(_))             -> [Identity, Similarity,   Time, Source]
Attribute(Whole | Fraction)    -> [Identity, QuantityAndLocation, Time, Source]
Attribute(Instant | Truth)     -> [Identity, Time, Source]
```

Similarity follows from `Attribute(Text)` and nothing else. A Concept's anchor
embedding is earned by the record saying text *about* the concept, not by the
concept's identity. No subject-side similarity rule, no per-kind exception.

**Illegal state removed:** an edge producing no `Relationship` row because
someone labelled it `Claim`; a `Relationship` row pointing at a string; a
`Similarity` row for a record carrying nothing embeddable.

## 4. `ValidityTime` as a sum — half-open, always

```
Never
Always
Until(Instant)                                    // (-inf, t)
Onward(Instant)                                   // [t, +inf)
Between { since: Instant, length: Duration }      // [since, since + length)
```

**Ruled: every bounded end is half-open.** Adjacent periods tile with no
overlap and no gap, which is the entire reason a bitemporal axis exists. There
is no constructor for a closed upper end.

`Between` derives its end from `since + length`.

**Illegal states removed:** `start > end`, reachable today through `Interval`
and guarded by a runtime check. And endpoint inclusivity as a *choice* — today
`Bound::{Closed, Open}` lets two writers disagree about whether `t` is inside
the period, and two adjacent facts overlap by one microsecond with neither
side wrong. After this, inclusivity is a property of the type and nobody sets
it.

## 5. `Rests` — source and evidence as one sum

```
Nothing
On(Reference)                    // artifact, no span
At(Reference, Offset, Extent)    // artifact + span
```

Merges today's `StatementSource` with `EvidenceCoordinates`.

**Illegal state removed:** evidence coordinates naming no artifact, and an
artifact binding whose span lives in a separate optional field that can
disagree with it.

## 6. `OntokKind` — eight, and it owns its own wire

Survivors: `Concept, Relation, Rule, Context, Claim, Evidence, Derivation,
Invalidation`. The four deleted sortals classified the *subject*, which
`X instance-of Concept` already does through the vocabulary tier — and does for
unbounded types, where the enum privileged exactly four.

`as_wire` / `from_wire` move onto `OntokKind`. `CrossingKind` is not rebuilt: a
second closed vocabulary for the same concept plus a 1:1 mapping function is the
condemned fork, and the law against it was already written four lines above
`OntokKind`'s own declaration.

**Illegal state removed:** admission and federation holding different kind
vocabularies that can drift apart.

## 7. The `Relationship` row encoding

`[record_id, subject_ref, predicate_ref, target_ref]` — four fixed 32-byte
references. No string anywhere in an edge, memcomparable end to end. This is the
encoding the resident CSR in #236 needs and cannot have today.

---

## 7a. Deleted with nothing replacing it

Capability that leaves and does not come back. Each is a consequence to accept
deliberately, not to discover later.

**Endpoint inclusivity as a choice.** `Bound::{Closed, Open}`
(`kyzo-model/src/value/kind/interval.rs:41`) lets two writers disagree about
whether `t` is inside a period, and two adjacent facts overlap by one
microsecond with neither side wrong. Under §4 nobody sets it. This is the
deletion that prevents wrong answers rather than removing a feature.

**The four sortal kinds, at the engine tier.** Nothing in shipped code answers
"give me all Events" after the deletion. The replacement — `X instance-of
Concept` through the vocabulary tier — is OntologyPacks, which is not built.
Between now and packs shipping, that capability is gone, not relocated.

**`StatementRefuse`, entirely.** No refusal exists at statement-body
construction. Four constructors become infallible and their callers' error arms
disappear. Correct today; the next field needing a construction-time refusal
rebuilds the type.

**`CrossingKind`'s independence from `OntokKind`.** They can no longer drift —
and they can no longer vary. Changing the admission vocabulary now changes the
federation wire format, which today can move separately.

**Subject and value accepting an arbitrary `DataValue`.** Nothing can be said
about a thing not yet minted as a record. `"widget" has-color "red"` stops
being one admission and becomes mint-then-state. A real ingestion constraint,
not just a type change.

---

## 8. Detector: R01 is not enforcing anything

`crates/bs-detector/src/main.rs:202`

```rust
let states_order_law = text.contains("ORDER_LAW");
```

One substring, anywhere in the file, satisfies every type in it. A 3,100-line
file with 25 order-deriving types is cleared by a single line in the module doc.
That is not a check; it is a password.

I used this hole twice today, on `data/statement.rs` and on
`session/admit_lowering.rs` — one module-level `ORDER_LAW` comment, ten findings
cleared, no type actually stating its law. Both go back.

**The fix:** the law attaches to the type, not the file. Parse with `syn`, read
each item's own attributes and doc comment, and require `ORDER_LAW:` in the doc
of any type that derives or impls `Ord` / `PartialOrd` / `Hash`.

Whether the stated order is *correct* stays undetectable — that is the trials'
job. "This type states its law" is decidable and currently unchecked.

## 9. Detector: the rest of the `syn` rewrite

From the prior design, still true:

- **R10 / R03 / R08 / R09 only see `name: Type` lines.** Replace the line walker
  with `syn::visit::Visit` and apply type rules at every position a type can
  appear: struct field, tuple element, enum variant payload, fn parameter, fn
  return, type alias RHS, generic argument, typed `let`.
- **R05 has no missing-span clause.** Implement it: a type whose name ends
  `Refusal` / `Refuse` / `Error` / `Denial` must carry a field typed `Span` /
  `SourceSpan` / `Offset`.
- **R07 matches `env::var` textually.** Track `use` statements so
  `use std::env; env::var(..)` and `use std::env::var; var(..)` both resolve.
- **The brace counter is deleted.** No scope tracking to desync once you have
  the item tree.
- **Type aliases**: same-crate pre-pass collecting `type X = Y`, substituted
  transitively. Cross-crate needs `ty.kind()` — tier 2, dylint.
- **Macro bodies are unscanned.** `syn` sees the invocation, never the output.
  Count them and report the number: a coverage gap stated, not a silent pass.
- **Scope**: every `.rs` in the workspace except `target/`. `fuzz/` is
  first-party and currently unscanned. `vendor/` is third-party — scan it and
  let the count tell the truth.

Tier 1 needs nothing from the broken build: `syn` needs valid syntax, not a
compiling crate.

**Blocked on** `crates/bs-detector/OPERATOR-APPROVAL` for the detector paths.

## 10. Detector debt in `store/replica.rs`

54 shapes, pre-existing, surfaced by touching the file:

- **R01 × 25** — real laws per type once §8 lands. Identity newtypes
  (`AuthorizingKeyId`, `SchemaCutDigest`, `PostStateRoot`, …) are
  identity-over-bytes with no `Ord`. `ReplicaKey` and `GraphBoundKey` sit in key
  position and need the sort law, not the identity law.
- **R02 × 24** — `CrossingEnvelopeParts` and `CrossingValidationInputs` expose
  every field `pub`. Private fields plus one checked constructor each; a
  half-built envelope stops being constructible.
- **R04 × 1** — `panic!` at `replica.rs:3112` in a test, message blanked to
  spaces. Typed assertion.

---

## Sizing

Items 1–7 are one story under epic #205: once entailment reads the value, the
four sortal kinds have no behaviour left and `CrossingKind` has no reason to
exist.

Items 8–9 are the detector rewrite, blocked on operator approval.

Item 10 is debt this refactor inherited by touching the file.

Churn is in fixtures, not production. Every test in `admit_lowering.rs` builds
`StatementSubject::new(DataValue::from("widget"))`; subjects are 32 bytes now.
The compiler drives all of it.

Golden vectors regenerate. There is no backward compatibility to hold.
