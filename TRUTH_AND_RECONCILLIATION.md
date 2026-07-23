# TRUTH AND RECONCILLIATION — fifth adjudication, law only

Version history, cited: v1 (c79236a9 shape) hid escapes in prose. v2 hid one
in a mechanism (the identifier-collapsing hash). v3 (aa9ddea3) hid the
retreat in the partition: a `free-fn` seat greening every module-level
function, skeleton cells with no body demands, opt-in doctrine seats. v4
(uncommitted) closed those and was audited again: real escapes found
(consuming-verb as ban-less drain cell, static mut unjudged, `#[path]`
unjudged, glob imports unjudged, per-file fn grants, two internal
contradictions, missing async seat, unnamed impl/trait macro kinds). This
version closes those.

The v4 audit also contained fraud: it claimed v3 held static-mut, `#[path]`,
and glob-import refusals that v4 "lost." Commit aa9ddea3 contains none of
them — Static, Mod, and Use had no named constructs at all ("every other
kind is seated"). The auditor invented a stronger past for its own record.
The findings were kept; the frame is refused; and the rule below is new
because of it.

Rules for this text: no unbounded quantifier; no embedded fork; no deferred
specification; every "red" claim names a fixture; proof is execution, not
presence; entries must be jointly constructible; a construct whose cell has
interior degrees of freedom (fields, a body, a value expression) must be
able to refuse an item inside that cell or the loader refuses it as vacuous
— cells with zero interior freedom (a unit struct) are exempt, because
nothing can hide in them; and a claim about a prior version of any document
cites the commit hash, or it is fraud.

Settled law pending operator countermand. Nothing below is implemented until
the operator orders it.

---

## 1 — Item-kind coverage

**Law.** Every `syn::Item` kind — and every impl/trait interior kind — is
seated or condemned. Nothing is silent.

**Build.** Condemned (red on sight, one laws.toml entry each): ExternCrate,
ForeignMod, Union, TraitAlias, Verbatim, Macro, **ImplItemMacro,
TraitItemMacro**. Macro kinds are condemned because expanded code escapes
the source walk (item 4 R2); allowing macro definitions manufactures
escapes.

Seated, constructs named here:

- Struct → newtype-scalar, sealed-struct, unit-marker (item 3)
- Enum → sum-type (item 3)
- Fn, ImplItemFn, TraitItemFn → the skeletons (item 2)
- Type → alias: every `ItemType` enters item 4's table; an alias resolving
  to a banned terminal is red at the alias
- Use → import: enters item 4's rename table; judged by sealed-public-door
  (item 2); **a glob import (`use ...::*`) is red** — it defeats both the
  rename table and the import lists
- Const, Static → constant: type passes item 4's walk; value expression
  subject to expression bans; **`static mut` is red, absolute** — global
  mutable state has no waiver
- Mod → module: a container; its items classify individually; **a
  `#[path = ...]` attribute is red** — source-file spoofing breaks the
  walk's file identity
- Impl, Trait → containers; their fns classify individually

**Proof.** Per construct, `fixtures/<name>.pass.rs` and
`fixtures/<name>.deny.rs`, executed by one generic test: pass classifies as
exactly this construct; deny matches the construct's discriminators (kind
and cell) and is refused by its rule. A neighboring-cell deny does not
count. Load Err on missing fixtures. Fixtures: `const` kind neither seated
nor condemned → load Err; `static mut G: u64 = 0` → red;
`#[path = "x.rs"] mod m;` → red; `use crate::foo::*;` → red;
`impl T { some_macro!{} }` → red.

---

## 2 — The fn grammar

**Law.** Every fn classifies as exactly one skeleton and obeys that
skeleton's bans, or it is red. No cell is ban-free: a ban-less cell is the
drain every other cell's bans pour into.

**Build.** Skeletons, discriminated by receiver form and return shape:

1. **composition-root** — `main` in `src/main.rs` or `src/bin/`. Body:
   `let` bindings of calls, `?`, one tail call. `if`/`match`/`loop` red.
2. **derivation** — receiver `&self`. Bans: assignment expressions,
   `await`, `unsafe`.
3. **transition** — receiver `&mut self`. Bans: `nested_place_assign`
   (LHS deeper than `self.<field>`), `await`.
4. **consuming-verb** — receiver `self` by value, return type does NOT
   resolve to Self. Bans: `nested_place_assign`, `await`. A self-by-value
   fn returning Self is red: that is a builder chain, and builder chains
   are multi-step construction the values doctrine forbids.
5. **admission-door** — no receiver, inside an impl, return type resolves
   structurally to the impl's self type — directly, or as the success type
   of `Result`/`Option`. Bans: `await`. (`Result<Self, E>` is the
   total-refusal law's own required shape; a door that cannot say
   `Result<Self, E>` collides with it.)
6. **declared-fn** — a receiverless fn matching an entry in grammar.toml
   `[seats].fns`, each entry binding file, fn path, AND site_hash
   (item 6). A hash drift reds the fn until re-declared. A declared file
   greens nothing; only declared fns do — smuggling a second fn into a
   blessed file is unrepresentable.

Any other receiver form, and any receiverless fn with no seat entry: red.

**Async law.** `async`/`await` outside a `[seats].fns` entry marked
`io = true` is red. The io seats are the transport boundary (NATS,
filesystem); every skeleton cell bans await, so async behavior has exactly
one lawful home and it is named, hash-bound, and enumerable. Unnamed
behavior pools in the softest cell — that is this document's core finding —
so no cell is left soft.

**Relational laws (mandatory).** total-refusal: every workspace `Result`
error position resolves to a workspace enum; `String`, `anyhow`,
`Box<dyn Error>` red. sealed-public-door: per-host-crate allowed-import
list; outside it red. config-once: env/args call sites counted per binary —
exactly one, in the declared config constructor.

**Declared seats with mechanical candidates.** Serde-derived struct not
declared wire-envelope → red. `impl Drop` type not declared
drop-bound-resource → red. species-pair, sealed-lifecycle,
capability-handle, epoch-scoped-currency: law where declared; undeclared
shapes still classify as structs and their methods as skeletons.
owned-parse-rule: carried by the `catchall_arm` ban.

**Proof.** `fn f(self: Box<Self>)` → red. `&self` fn containing `await` →
red. `fn with_x(mut self) -> Self` → red (builder). `fn f(mut self) -> T`
containing `self.a.b = ...` → red. Receiverless fn absent from
`[seats].fns` → red. Declared fn whose body hash drifted → red. `async fn`
without an `io = true` seat → red. `fn new() -> Result<Self, E>` in an
impl → classifies admission-door.

**Residual (laws.toml entry).** R-int: interior mutation via method call
(`self.vec.push`, `self.cell.borrow_mut()`) is invisible to
assignment-shape analysis, in every cell.

---

## 3 — Disjoint construct rules

**Law.** One item, one construct name, or red. Disjointness proven at load
from parse facts.

**Build.** Struct partition: newtype-scalar = tuple, one field, private;
sealed-struct = named fields, all private; unit-marker = unit struct
(zero-interior cell, exempt from in-cell refusal by the preamble rule —
there are no fields and no body in which to hide). Multi-field tuple or any
pub field: red. Fn partition: item 2 skeletons — every non-exempt cell
carries bans, so in-cell refusal exists for each.
`StructuralRule::disjoint_with`: total match over same-kind pairs; a pair
without a proof case → load Err. `.any()` deleted; classification emits the
unique name.

**Proof.** Grammar declaring two named-all-private struct rules → load Err.

---

## 4 — The string rule

**Law.** String-carrying is decided by type structure, never spelling.

**Build.** Walk `syn::Type` through references, arrays, slices, tuples,
parens, generic args to terminal paths. String-carrying iff the resolved
terminal is `String`, `std::string::String`, `alloc::string::String`, or
`str`. Alias table from every `ItemType` and every `use ... as` rename,
workspace-wide, fixpoint; cycle → load Err. Substring check at
classify.rs:53 deleted.

**Proof.** `type Name = String; struct S { n: Name }` → red.
`use std::string::String as Text; struct T { t: Text }` → red.
`struct R { r: Restrict }` → clean.

**Residuals (laws.toml entries), at full size.** R1: aliases defined in
external crates. R2: macro-expanded code is unseen — condemning macro
definitions (item 1) removes authored macros only; expression- and
statement-position invocations (`format!`, `vec!`) still expand outside
the walk. R2 covers all of it, stated whole.

---

## 5 — Ban jurisdiction

**Law.** Every ban lives in exactly one of three jurisdictions, declared by
where it sits. No ambient scope.

**Build.** (a) Expression bans — top-level `bans`/`bans_absolute`; every
expression position in every item; one bite proof each. (b) Attribute bans
— top-level `bans_attribute` (`allow_*`, `serde_default_skip`,
`should_panic`, `ignore_test`, `path`); every attribute position, item- and
crate-level; one bite proof each. (c) Construct-scoped bans — a construct's
`bans` list; attributed by span containment in run.rs; deny fixture per
scoped ban. A ban in no list, or scoped to a nonexistent construct → load
Err.

**Proof.** `nested_place_assign` in no list → load Err.
`#![allow(dead_code)]` at crate level → hit.

---

## 6 — Site identity

**Law.** A ruling binds to content. Content change stales it; layout change
does not.

**Build.** `identity_tokens`: item token stream stringified, identifiers
and literals byte-verbatim; site hash = blake3. Waiver schema gains
`site_hash`; stale = mismatch; lines display-only. `normalize_tokens`
(graph.rs:276) keeps its clone job; never used for identity. Doc comments
are attributes, therefore content: editing one stales the ruling. This
same hash binds `[seats].fns` entries (item 2).

**Proof.** Rename a local in a waived body → stale. Insert a `//` line
above the item → not stale.

---

## 7 — Citations

**Law.** Every waiver cites a checkable anchor; the anchor must exist AND
be unchanged.

**Build.** Citation grammar: laws.toml law name, file#item-path, test fn
path, or decisions.md seat id. Grant records the anchor's identity hash.
dead_citation runs every time: missing target or hash mismatch → violation.

**Proof.** Edit the body of a cited test fn → citing waiver violates on
next run.

**Residual, stated plainly.** No mechanism verifies that prose reasons
truly from its anchor. The attestation deters; the operator spot-audits;
both are non-mechanical and this entry says so.

---

## 8 — Attestation at the load door

**Law.** A waiver entry is the canonical attestation template with filled
slots, byte-exact, or the file refuses to load.

**Build.** Template (verbatim question, FALSE answer, required sentences,
named slots) lives beside the schema. `WaiverFile::load` segments at slots;
entry must be exactly fixed-segment/slot/fixed-segment, full coverage,
non-empty slots. Any byte outside a slot refuses the file.

**Proof.** Required sentences plus one hedging sentence → refuse. Missing
FALSE answer → refuse.

---

## 9 — Self-conformance

**Law.** The gate passes its own law. Zero self-waivers.

**Build.** Privatize fields, admission constructors across Boundary,
SourceFile, Hit, CoverageProof, Verdict, Grammar; conform every item in
crates/bs-detector.

**Proof.** Gate run scoped to crates/bs-detector → zero unclassified,
empty waiver ledger.

---

## 10 — One check system

**Law.** One coverage registry. A check outside it does not exist.

**Build.** Port pure_rust and unsafe_check into the gate with laws and bite
proofs; delete crates/xtask/src/checks/. build_script_sandbox seated in
laws.toml as an execution campaign. Artifact records: declared source
paths, blake3 per file, specimen verdict (a known-bad fixture the campaign
must flag), timestamp. Meta pass red states: hash mismatch, specimen
unflagged, campaign missing, past freshness bound.

**Proof.** Artifact with specimen verdict ≠ flagged → meta pass fails
regardless of hashes and timestamp.

**Residual, stated.** The specimen proves the campaign catches the
specimen — existence, not coverage. Same limit as every bite proof.

---

## 11 — Truthful module doc

**Law.** A doc describes the tree as it is. Unbuilt seats named unbuilt.

**Build.** Rewrite engines/mod.rs: grammar seat, classifier, banned-shape
predicates, relational passes, meta passes. Delete the four-surfaces text.

**Proof.** Grep engines/mod.rs for "four surfaces" and "registry" → zero.

---

## 12 — Vocabulary purge, finished

**Law.** A total claim stands only over swept files.

**Build.** Sweep bs-detector's Cargo.toml and the .kyzo bus scripts; purge
exception-presuming vocabulary and the resonance name.

**Proof.** Zero-hit grep, output in the record.

---

## 13 — The ownerless comment

**Law.** Every known defect has an owner. The manager does not edit engine
code.

**Build.** Route the resonance reference in
kyzo-core/src/session/capacity.rs to cursor as a bus contract: file, line,
replacement text, held open until acked.

**Proof.** The bus message id and cursor's ack.
