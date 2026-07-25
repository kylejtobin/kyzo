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

In force. The operator ordered this built completely, to maximum purity, as
fast as possible, with no hesitation. The detector's goal is MAXIMUM
detection: catch every real violation in the tree, and never hide, costume,
seat, or weaken one away to shrink a number. An item is done only when the
detector, run on the committed code, catches everything it should for that
item — deny fixtures go red, pass fixtures classify, and no real violation
escapes. A low count is not the goal and is not a completion; a written claim
is not a completion. Only the run counts.

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


## Build Attestation

For each of the above upon completion create an H3 sub-section with a build
attestation.

### 0. Build Attestation Template

BUILD ATTESTATION — item {N}
law: commit {law hash} | build: commit {build hash}

I attest my implementation of item {N} matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: {fixture paths + test run output line}
- Pass fixtures classified as their construct: {fixture paths}
- The weakest satisfier I personally constructed against my own build
  was: {the attack} — and it goes red because {mechanism}.
- My implementation is weaker than this document's text in exactly:
  {NONE | laws.toml residual entry name}.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 1. Build Attestation

BUILD ATTESTATION — item 1
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit 6401f2625ff6cd52cafa8568d284fa4be22d2728

I attest my implementation of item 1 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: crates/bs-detector/fixtures/{newtype-scalar,sealed-struct,sum-type,alias,import,constant,module,impl-container,trait-container,composition-root,derivation,transition,consuming-verb,admission-door,declared-fn}.deny.rs plus condemned crates/bs-detector/fixtures/{extern-crate,foreign-mod,union,trait-alias,macro,impl-macro,trait-macro}.deny.rs — test classify::fixture_tests::every_construct_pass_classifies_and_deny_is_refused_by_its_own_rule ... ok; classify::fixture_tests::every_condemned_kind_deny_fixture_is_red_under_its_own_law ... ok; item_1_proof_{static_mut,path_attr_mod,glob_use,impl_macro}_is_denied ... ok (verbatim.deny.rs is presence-only: a true Item::Verbatim cannot be authored in a file syn::parse_file accepts; named in the test).
- Pass fixtures classified as their construct: crates/bs-detector/fixtures/{newtype-scalar,sealed-struct,unit-marker,sum-type,alias,import,constant,module,impl-container,trait-container,composition-root,derivation,transition,consuming-verb,admission-door,declared-fn}.pass.rs — same every_construct_pass… test ... ok.
- The weakest satisfier I personally constructed against my own build
  was: `struct Leaky { name: String }` (named fields, private, but string-terminal — if any struct seat were too loose it would classify) — and it goes red because sealed-struct's NamedAllPrivateNoStringTerminal refuses string terminals, and neither newtype-scalar nor unit-marker matches named multi-field shape (anti_fraud_a_deny_shape_never_slips_through_a_neighboring_seat ... ok).
- My implementation is weaker than this document's text in exactly:
  string-carrying judgment uses direct terminal names only (item 4's
  alias-fixpoint walk is unbuilt); verbatim condemned deny fixture is
  presence-only as stated above.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 2. Build Attestation

BUILD ATTESTATION — item 2
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit f6d9b32633a5211f538365433cda643f00ed8728

I attest my implementation of item 2 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: crates/bs-detector/fixtures/{composition-root,derivation,transition,consuming-verb,admission-door,declared-fn}.deny.rs — test classify::fixture_tests::every_construct_pass_classifies_and_deny_is_refused_by_its_own_rule ... ok; item_2_proof_{box_self_receiver,ref_self_await,builder_chain_self_by_value_returning_self,consuming_verb_nested_place_assign,receiverless_absent_from_seats,declared_fn_hash_drift,async_fn_without_io_seat,composition_root_positive_body_refuses_non_call_let}_is_red/_classifies ... ok; engines::graph::tests::{total_refusal_reds_string_anyhow_and_box_dyn,sealed_public_door_reds_import_outside_allowlist,config_once_demands_exactly_one_site_in_declared_ctor} ... ok.
- Pass fixtures classified as their construct: crates/bs-detector/fixtures/{composition-root,derivation,transition,consuming-verb,admission-door,declared-fn}.pass.rs — same every_construct_pass… test ... ok; item_2_proof_admission_door_classifies ... ok; item_2_anti_fraud_fn_matches_at_most_one_skeleton ... ok.
- The weakest satisfier I personally constructed against my own build
  was: `fn main() { let x = 1; finish(x) }` under `crates/probe/src/main.rs` (matches composition-root path+name, lacks if/match/loop — the negative-only body law would green it) — and it goes red because composition_root_body_ok demands let-bindings of calls plus one tail call (item_2_proof_composition_root_positive_body_refuses_non_call_let ... ok).
- My implementation is weaker than this document's text in exactly:
  R-int.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 3. Build Attestation

BUILD ATTESTATION — item 3
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit 380b5844da1fb563b9f0e8a6fdfd896e16eef792

I attest my implementation of item 3 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: crates/bs-detector/fixtures/{newtype-scalar,sealed-struct,sum-type}.deny.rs — test classify::fixture_tests::every_construct_pass_classifies_and_deny_is_refused_by_its_own_rule ... ok; item_3_proof_multi_field_tuple_and_pub_field_are_red ... ok.
- Pass fixtures classified as their construct: crates/bs-detector/fixtures/{newtype-scalar,sealed-struct,unit-marker,sum-type}.pass.rs — same every_construct_pass… test ... ok; item_3_anti_fraud_struct_matches_at_most_one_construct ... ok; item_3_classification_emits_unique_construct_name ... ok.
- The weakest satisfier I personally constructed against my own build
  was: a grammar.toml declaring two constructs both bound to
  named-all-private-no-string-terminal (sealed-struct + sealed-struct-twin)
  — and Grammar::load refuses (item_3_proof_two_named_all_private_struct_rules_is_a_load_error ... ok).
- My implementation is weaker than this document's text in exactly:
  NONE.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 4. Build Attestation

BUILD ATTESTATION — item 4
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit f9ee16e4862223c374d8571e98e16e18734ace22

I attest my implementation of item 4 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny proofs executed red: `type Name = String; struct S { n: Name }` and
  `use std::string::String as Text; struct T { t: Text }` —
  classify::fixture_tests::item_4_proof_{type_alias_to_string_struct_is_red,use_as_string_struct_is_red} ... ok;
  alias::tests::item_4_proof_{type_alias_to_string_carries,use_as_string_carries} ... ok.
- Pass proof clean: `struct R { r: Restrict }` —
  item_4_proof_restrict_struct_is_clean ... ok; item_4_proof_restrict_does_not_carry ... ok.
- The weakest satisfier I personally constructed against my own build
  was: `type A = B; type B = A;` — AliasTable::build refuses
  (item_4_proof_alias_cycle_is_a_load_error ... ok).
- My implementation is weaker than this document's text in exactly:
  R1, R2.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 5. Build Attestation

BUILD ATTESTATION — item 5
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit 3d0babe209d6afecdea5a4c787857125163ad6ae

I attest my implementation of item 5 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: crates/bs-detector/fixtures/{nested_place_assign,assignment,await}.deny.rs; transition.deny.rs refuses via asyncness; derivation.deny.rs refuses via BodyBan unsafe — grammar::tests::item_5_proof_{nested_place_assign_in_no_list,ban_in_two_jurisdictions,cross_mechanism_dual}_is_* ... ok; bite_{path,nested_place_assign,assignment,await,allow_dead_code} ... ok; item_1_proof_path_attr_mod_is_denied (bans_attribute only; module seats) ... ok; item_5_scoped_bans_classify_then_matcher_hits ... ok.
- Pass fixtures classified as their construct: every_construct_pass… ... ok (module deny-exempt).
- The weakest satisfier I personally constructed against my own build
  was: nested_place_assign removed from every construct.bans list while
  still registered as a matcher — Grammar::load refuses (no list). Second:
  unwrap in both bans and bans_attribute — load refuses. Third:
  TransitionBans.body_bans_enforced_in_classify() is empty so
  nested_place/await cannot dual-fire with classify BodyBan
  (item_5_proof_cross_mechanism_dual_is_refused ... ok).
- Measured dry-run (post-bounce): assignment:119 nested_place_assign:118
  path:17 await:1 (GATE total 5838).
- My implementation is weaker than this document's text in exactly:
  NONE.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 6. Build Attestation

BUILD ATTESTATION — item 6
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit 30372eef9e22bc79e7bc78a1e6a9647acef8f8c8

I attest my implementation of item 6 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny proofs executed red: rename a local in a waived body changes
  site_hash and stales the waiver —
  identity::tests::item_6_proof_rename_local_changes_site_hash ... ok;
  engines::meta::tests::stale_waiver_is_reported_when_its_site_dies ... ok
  (rename branch); declared-fn body hash drift still reds via the same
  identity::site_hash binding —
  classify::fixture_tests::item_2_proofs_red_shapes_are_unclassified ... ok.
- Pass proofs not stale: insert a `//` line above the item keeps
  site_hash —
  identity::tests::item_6_proof_line_comment_above_item_keeps_site_hash ... ok;
  engines::meta::tests::item_6_proof_line_comment_above_does_not_stale_waiver ... ok;
  identity::tests::item_6_waiver_matches_by_site_hash_not_line ... ok;
  identity::tests::item_6_identity_keeps_identifiers_verbatim_unlike_clone_normalize ... ok;
  identity::tests::layout_change_keeps_identity_and_content_change_breaks_it ... ok
  (doc comment is content).
- The weakest satisfier I personally constructed against my own build
  was: bind a waiver by line only (or hash via graph::normalize_tokens,
  which collapses idents to `id`) so a local rename at the same editor
  line would keep applying — and it goes red/stale because matching is
  identity::waiver_matches_hit on blake3(identity_tokens), never line
  and never normalize_tokens (item_6_proof_rename_local_changes_site_hash
  + stale_waiver_is_reported_when_its_site_dies rename branch ... ok).
- Measured dry-run (post-build 30372eef): GATE total 5785
  (unclassified:4833 total_refusal:338 sealed_public_door:232
  assignment:118 nested_place_assign:116 …).
- My implementation is weaker than this document's text in exactly:
  NONE.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 7. Build Attestation

BUILD ATTESTATION — item 7
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit 3d71139edc3163e804294503d6bdcef600f83a76

I attest my implementation of item 7 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny proofs executed red: edit the body of a cited test fn → citing
  waiver is dead_citation —
  citation::tests::item_7_proof_edit_cited_test_fn_is_dead_citation ... ok;
  missing decisions seat fails resolve —
  citation::tests::law_name_and_decisions_seat_resolve ... ok;
  file#item-path identity drift —
  citation::tests::file_item_path_hashes_with_identity_tokens ... ok;
  production expect at citation parse removed (bounce 615) —
  cargo run -p bs-detector -- --only expect --dry-run → GATE: PASS
  (= 0 violations); zero FAIL under crates/bs-detector for expect.
- Pass / grammar: citation::tests::citation_grammar_parses_four_forms ... ok;
  the_real_grammar_and_laws_load_and_bind_to_this_file ... ok (dead_citation
  required). cfg(test) expects in citation.rs tests module are
  ProductionOnly-unscanned (confirmed).
- The weakest satisfier I personally constructed against my own build
  was: a waiver whose citation still names a live file but whose
  anchor_hash is stale after a one-ident rename inside the cited test fn
  — and it goes red because dead_citations compares blake3 of the live
  item's identity_tokens to the recorded anchor_hash, and citation_live
  gates waiver application (item_7_proof_edit_cited_test_fn_is_dead_citation
  ... ok). Second attack (bounce 615): prior-check contains('#') then
  .expect — banned token; now typed Err via let-else.
- Measured dry-run (post-build 3d71139e): GATE total 5738; expect:0
  tree-wide including crates/bs-detector; dead_citation:0 (empty ledger).
- My implementation is weaker than this document's text in exactly:
  R-citation-prose.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 8. Build Attestation

BUILD ATTESTATION — item 8
law: commit 4e4c070d1cf9b47fcc4562f80f60b5072d7cd386 | build: commit 23651f88ae7bd3a6020a26aba4b025e1e7fe73a4

I attest my implementation of item 8 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny proofs executed red: required sentences plus one hedging sentence
  → WaiverFile::load refuses —
  waiver::tests::item_8_proof_required_sentences_plus_hedge_refuses ... ok;
  missing FALSE (TRUE substituted) → refuse —
  waiver::tests::item_8_proof_missing_false_answer_refuses ... ok;
  empty slot → refuse —
  waiver::tests::item_8_empty_slot_refuses ... ok;
  freeform pre-attestation justification → refuse (no grandfathering) —
  waiver::tests::freeform_pre_attestation_justification_refuses ... ok.
- Pass / load: empty ledger with both keys stated loads —
  waiver::tests::empty_waiver_ledger_loads_when_both_keys_stated ... ok;
  filled canonical template loads and binds —
  waiver::tests::a_real_waiver_loads_and_binds_to_its_check ... ok;
  cargo test -p bs-detector → 69 lib + 56 bite_proofs ... ok;
  production loader (pre-cfg(test)) has zero expect/unwrap/panic!.
- The weakest satisfier I personally constructed against my own build
  was: append " I believe this is mostly fine." after a fully valid
  filled template — and it goes red because AttestationTemplate::segment
  requires pos == why.len() after the final fixed segment, so leftover
  bytes are outside every slot (item_8_proof_required_sentences_plus_hedge_refuses
  ... ok).
- Measured dry-run (post-build 23651f88): GATE total 5758; empty waiver
  ledger; attestation_form seated in laws.toml.
- My implementation is weaker than this document's text in exactly:
  NONE.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 11. Build Attestation

BUILD ATTESTATION — item 11
law: commit a03721f679bd50e6e73197b769f3217f8238b0ae | build: commit 7cbe7ef8099dacf8db467e9675bc7cdda3306b92

I attest my implementation of item 11 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: N/A for doc-only item (no deny fixture cell).
- Pass fixtures classified as their construct: N/A for doc-only item.
- The weakest satisfier I personally constructed against my own build
  was: restoring the phrase "four surfaces" or "registry" into
  crates/bs-detector/src/engines/mod.rs — and it goes red because the
  proof is grep zero:
  `rg -n 'four surfaces|registry' crates/bs-detector/src/engines/mod.rs`
  → no matches (PROOF_ZERO); cargo test -p bs-detector --lib → 124 passed.
- My implementation is weaker than this document's text in exactly:
  NONE.
Every sentence above is checkable against the build commit. If one is false, I lied.


### 9. Build Attestation

**STATUS: INCOMPLETE — BOUNCED tip 755.** Attestation below is NOT a completion claim.
Proof target: the detector obeys its own bans in its own real code (no unwrap,
expect, string errors, etc. in detector logic) and waives itself zero times.
Its deny fixtures and bite specimens MUST stay red — they are the proof it
bites, never a count to drive down. Done means self-clean code plus an empty
self-waiver ledger, not a low self-red number.


BUILD ATTESTATION — item 9
law: commit 1abeff0f9cb33c4b75aa4ad2d638485686065e56 | build: commit 3d2decd797e7eece6603090a3403425c183f5bc9

I attest my implementation of item 9 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: tip689 unclassified-* deny fixtures still
  execute red under bite_proofs (cargo test -p bs-detector --test bite_proofs
  → 76 passed).
- Pass / construction: named §9 structs privatized with admit —
  SourceFile, Hit, Boundary, CoverageProof, UnparsedFile, Verdict+GateColor,
  Grammar cluster, AliasTable, ScopedConstructSpan (commits e17f2a68 +
  3d2decd7); cargo test -p bs-detector --lib → 129 passed.
- The weakest satisfier I personally constructed against my own build
  was: leaving Matcher/Cli/Waiver* as pub/unseated — and it goes red as
  unclassified-struct (self-unclassified residual remains; not zero).
- My implementation is weaker than this document's text in exactly:
  self-unclassified residual (Matcher, Cli, Waiver*, test/fn reds, fixtures);
  proof target "zero unclassified" not yet met.
Every sentence above is checkable against the build commit. If one is false, I lied.

### 10. Build Attestation

BUILD ATTESTATION — item 10
law: commit 1abeff0f9cb33c4b75aa4ad2d638485686065e56 | build: commit 3d2decd797e7eece6603090a3403425c183f5bc9

I attest my implementation of item 10 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: bite_pure_rust, bite_unsafe_check,
  bite_campaign_artifact, bite_build_script_sandbox in
  cargo test -p bs-detector --test bite_proofs → 76 passed.
- Pass: cargo run -p bs-detector -- --only pure_rust --dry-run → GATE: PASS;
  --only campaign_artifact → GATE: PASS; crates/xtask/src/checks/ deleted.
- The weakest satisfier I personally constructed against my own build
  was: artifact with specimen verdict not flagged — meta goes red
  (campaign_specimen_unflagged) regardless of hashes/timestamp.
- My implementation is weaker than this document's text in exactly:
  NONE (specimen proves existence not coverage — residual stated in law).
Every sentence above is checkable against the build commit. If one is false, I lied.

### 12. Build Attestation

BUILD ATTESTATION — item 12
law: commit 1abeff0f9cb33c4b75aa4ad2d638485686065e56 | build: commit 2b709174920b026efdd4d5e3c4218074def5b1d0

I attest my implementation of item 12 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: N/A (vocabulary sweep).
- Pass: rg -i resonance over swept set → zero; rg exception-presuming
  vocabulary over swept set → zero (commit 2b709174920b026efdd4d5e3c4218074def5b1d0).
- The weakest satisfier I personally constructed against my own build
  was: restoring "resonance" into .kyzo/bus_msg.py default — and it goes
  red under the zero-hit grep proof in the attestation record.
- My implementation is weaker than this document's text in exactly:
  NONE for the swept set (Cargo.toml + .kyzo bus scripts only).
Every sentence above is checkable against the build commit. If one is false, I lied.

### 13. Build Attestation

BUILD ATTESTATION — item 13
law: commit 1abeff0f9cb33c4b75aa4ad2d638485686065e56 | build: commit (no engine edit; bus 739)

I attest my implementation of item 13 matches this document, at the law
commit above, at audited strength. TRUE or FALSE: there exists an input —
any code shape, any file, any reading of the law text — on which my
implementation passes where the law says red, or goes red where the law
says pass.

FALSE. Evidence, each anchor checkable:
- Deny fixtures executed red: N/A (ownership routing).
- Pass: bus contract id 739 posted [TO: cursor-m1]; capacity.rs not edited
  by detector-parent; replacement already on tree at b3462830.
- The weakest satisfier I personally constructed against my own build
  was: closing the item without cursor-m1 ACK of 739 — refused; held open.
- My implementation is weaker than this document's text in exactly:
  awaiting cursor-m1 ACK of bus 739 (proof incomplete until ack).
Every sentence above is checkable against the build commit. If one is false, I lied.
