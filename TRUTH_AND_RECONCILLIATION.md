# TRUTH AND RECONCILLIATION — third adjudication, A on trial twice

The first version of this record hid escape hatches inside nine of its
thirteen "settled answers"; the exploit was question authorship. The second
version closed those nine and was audited again with the weakest-satisfier
method; that audit found nine further escapes, one structural (items 2 and 3
jointly ordered a grammar that refuses itself at load). This version closes
those. The rules from the second version stand, with two added:

1. **No unbounded quantifier.** Words like "genuinely," "appropriate," "few,"
   or "as needed" fail the entry.
2. **No embedded fork.** An answer containing "or ..." is not settled; the
   fork is resolved here or the entry is not law.
3. **No deferred specification.** A mechanism the answer does not name — to
   the function, file, or schema — is not answered; it is promised.
4. **Every "unrepresentable" claim names its refusing fixture.** A claim of
   unconstructibility with no fixture that fails is a vacuous claim.
5. **No presence-where-proof-is-owed.** A law satisfied by the existence of
   a name or file, without executing what the name claims, is not enforced.
6. **Joint satisfiability.** Any two entries whose mechanisms interact must
   be constructible together; a pair that deadlocks is two lies sharing a
   binding.

Answers here are settled law pending operator countermand. Implementation is
in progress under operator order; each entry's mechanism is buildable as
written.

---

## 1 — Item-kind coverage

### Question
Do we build A — a closed ItemKind enum total over syn::Item (Const, Enum,
ExternCrate, Fn, ForeignMod, Impl, Macro, Mod, Static, Struct, Trait,
TraitAlias, Type, Union, Use, Verbatim), where every kind is either SEATED
(grammar.toml declares at least one construct of that kind) or CONDEMNED
(grammar.toml lists it in `condemned_kinds`, red on sight, with a laws.toml
entry naming why), Grammar::load refuses a grammar leaving any kind neither
seated nor condemned, and every construct carries two fixture FILES —
`fixtures/<construct>.pass.rs` and `fixtures/<construct>.deny.rs` — executed
by one generic test that parses each pair and asserts the pass fixture
classifies as exactly that construct and the deny fixture is an item of the
same kind that the construct's rule refuses — or B — the current classifier
that walks only structs and enums, leaving every other kind implicitly
allowed?

### Answer
Build A. `classify.rs` gains the total map over every syn::Item variant,
plus `ImplItemFn` and `TraitItemFn` classified as fn-kind items. Condemned
kinds, decided here: ExternCrate (2018-edition relic), ForeignMod (FFI
outside the pure-Rust law), Union (unsafe-only access), TraitAlias
(non-stable syntax), and Verbatim (unparseable is unjudgeable); each
carries a laws.toml entry and red on sight. Every other kind is seated.
The fixture law is executed, not registered: the test
`fixtures_prove_every_construct` iterates every construct in the loaded
grammar, parses both fixture files, and asserts (pass → classifies as
exactly this construct) and (deny → same syn kind, refused by this
construct's rule). Grammar::load refuses a construct whose fixture files
are absent; the test refuses one whose fixtures don't prove. An accept-all
construct is unconstructible because its deny fixture — a same-kind item
its rule refuses — cannot exist. Unrepresentable: an item kind the gate
does not judge — fixture: a grammar.toml with `const` neither seated nor
condemned must make Grammar::load return Err.

### Explanation
Audit of A first. The prior version required a "registered refusing
fixture," and registration was presence: a test fn with the right name and
an empty body satisfied it — the same presence-not-proof hatch item 8
kills. Fixtures are now data files executed by one generic test, so a
fixture that proves nothing fails the test, not the reviewer's attention.
The prior version also had no answer for kinds with no legitimate
instances; seating them would have forced vacuous constructs — the
condemned list resolves that without reopening the vacuity hatch, because
condemnation is louder than seating, not quieter. B's failure mode remains
silence, unfalsifiable by construction: an exempt kind produces no
evidence of its exemption. The "add kinds as constructs mature" hybrid
opens the same hatch kind by kind.

---

## 2 — The full construct grammar

### Question
Do we build A — classification made total over fns by a skeleton partition
whose discriminators are provably disjoint, with doctrine's purity demands
carried by construct-scoped bans and relational laws rather than
overlapping classification predicates — or B — three shallow struct/enum
rules with tree-wide bans carrying everything else?

### Answer
Build A, structured in three tiers so that item 3's disjointness law is
satisfiable by construction.

Tier 1 — classification skeletons (fn kind), discriminated by receiver
form and position, pairwise disjoint because one fn has exactly one
receiver form:

1. **composition-root** — ident `main` in a `src/main.rs` or `src/bin/`
   file. Every other skeleton excludes ident `main` in those files.
2. **derivation** — receiver exactly `&self`.
3. **transition** — receiver exactly `&mut self`.
4. **consuming-verb** — receiver `self` by value.
5. **admission-door** — no receiver, return type's token stream contains
   `Self` (associated constructors).
6. **free-fn** — no receiver, return type not containing `Self`.

A receiver outside these forms (`self: Box<Self>`, `self: Arc<Self>`)
classifies as nothing and is red.

Tier 2 — construct-scoped bans (grammar.toml `[[construct]]` gains an
optional `bans` list; hits attributed by span containment per item 5):

- transition bans `nested_place_assign`: an assignment whose LHS is a
  place expression deeper than `self.<field>` (`self.a.b = ...`,
  `self.a[i] = ...`) — whole-value replacement or red.

Tier 3 — doctrine constructs that are laws or declared seats, not
classification: total-refusal (every workspace `Result` error position
resolves to a workspace enum — relational pass), sealed-public-door
(per-host-crate allowed-import list — relational pass), config-once
(env/args call sites counted per binary — relational pass),
wire-envelope, species-pair, sealed-lifecycle, capability-handle,
epoch-scoped-currency, drop-bound-resource (declared type seats in
grammar.toml, loader-verified against the tree), owned-parse-rule
(carried by the existing `catchall_arm` ban), boundary-decode (carried by
admission-door classification plus total-refusal law).

Stated residuals, seated as laws.toml entries, not prose: (R-int) interior
mutation reached through method calls (`self.cell.borrow_mut()`,
`self.vec.push`) is invisible to assignment-shape analysis — the residual
is named law, and `&self`/`&mut self` skeleton classification remains
true regardless. Unrepresentable: a fn the gate does not classify or
condemn — fixture: `fn f(self: Box<Self>)` inside an impl must go red as
unclassified-fn.

### Explanation
Audit of A first. The prior version specified sixteen predicates that were
not pairwise disjoint — a `&self` fn returning a workspace-error Result
classified as three constructs at once — while item 3 ordered load-refusal
of non-disjoint pairs: the two entries jointly ordered a machine that
refuses to start (rule 6). The tier split resolves it structurally:
classification discriminates by skeleton, where disjointness is a fact of
syntax (one receiver form per fn), and every doctrine demand that cuts
across skeletons became a scoped ban or relational law, where overlap is
legal because bans stack. The prior version also carried an undecidable
predicate ("a variant whose name contains no parse of the input") — gone;
lift targets are declared seats verified by the loader, not inferred from
names. And it listed predicates 7 and 13 in two implementation columns at
once — the tier assignment is now single. B sacrifices the allow-list —
the middle of the design — and opens the hatch that any lie not enumerated
as a ban passes silently.

---

## 3 — Disjoint construct rules

### Question
Do we build A — per-kind rule disjointness proven at grammar load by a
total pairwise table over a partition decided HERE: struct rules
discriminate by field style (newtype-scalar = tuple, exactly one field,
private; sealed-struct = named fields, all private; unit-marker = unit
struct), fn rules discriminate by receiver skeleton (item 2 tier 1), a
multi-field tuple struct or pub-field struct classifies as nothing and is
red, and classification returns the unique construct name or red — or B —
the current any-match pass in which newtype-scalar is subsumed by
sealed-struct and the name certifies nothing?

### Answer
Build A with that partition. `StructuralRule::disjoint_with` is a total
match over same-kind rule pairs returning a proof case per combination:
tuple/named/unit field styles are mutually exclusive by `syn::Fields`
variant; fn skeletons are mutually exclusive by receiver form; a pair
without a proof case refuses at load. Classification emits the unique
name; the `.any()` in classify.rs is deleted. Unrepresentable: an item
lawfully classifiable as two constructs — fixture: a grammar declaring two
named-field-all-private struct rules must make Grammar::load return Err.

### Explanation
Audit of A first. The prior version's partition ("the sealed rule excludes
single-field tuples") was consistent for structs but silent on unit
structs — which the all-fields-private rule accepted vacuously (an empty
field set is all-private), so marker types rode a rule that never
inspected them. The unit-marker construct closes that: unit structs
classify by their own rule and the vacuous ride is unconstructible. The
disjointness proof is now grounded in `syn::Fields`/receiver variants —
facts of the parse, not promises of the author. B sacrifices the record's
meaning — rulings bind to names that do not discriminate — and opens
decorative grammar growth. First-match-wins trades the load-time proof for
order dependence and opens silent reclassification on file reorder.

---

## 4 — Type-resolving string rule

### Question
Do we build A — a structural TypeShape walker deciding string-carrying by
syn::Type shape, joined to a workspace alias table built from BOTH
`syn::ItemType` aliases AND `use ... as` renames, resolved to fixpoint,
with the walker's residuals written into laws.toml — or B — the substring
check on rendered type tokens at classify.rs:53, with its false reds and
its alias hole?

### Answer
Build A. String-carrying is decided by walking syn::Type through
references, arrays, slices, tuples, parens, and generic arguments to
terminal type paths; a terminal is string-carrying iff its path (resolved
through the alias table) ends at `String`, `std::string::String`,
`alloc::string::String`, or `str`. The alias table is collected in the
boundary walk from every `syn::ItemType` (`type Name = String`) and every
`syn::ItemUse` rename (`use std::string::String as Text`), resolved
transitively; the table is finite so resolution terminates, and a cycle
refuses at load. The substring check is deleted. Residuals seated as
laws.toml entries: (R1) an alias defined in an external crate cannot be
resolved in-tree; (R2) items produced by macro expansion are outside the
source walk. Unrepresentable: a string field hidden behind one in-tree
alias or rename passing, and a str-lettered identifier failing — fixture
set: `type Name = String; struct S { n: Name }` red; `use
std::string::String as Text; struct T { t: Text }` red; `struct R { r:
Restrict }` clean.

### Explanation
Audit of A first. The prior version's alias table read only
`syn::ItemType`, so an in-tree `use String as Text` escaped — and R1 did
not excuse it, because R1 covers external crates and this rename is fully
resolvable in-tree: a residual that was actually a hole. Use-renames are
now table entries with their own red fixture. B sacrifices soundness in
both directions at once: false reds teach agents the gate is noise; false
greens let the exact banned shape ride behind one alias. The
tune-the-substring-list hybrid is the same spelling authority with more
spellings.

---

## 5 — Ban jurisdiction

### Question
Do we build A — every prohibition's jurisdiction stated as one of exactly
two forms: EXPRESSION-JURISDICTION bans (the tree-wide token/shape
matchers), whose law is "every expression position in every item" and
whose proof is the existing bite-proof-per-ban law, and CONSTRUCT-SCOPED
bans, attached to named constructs in grammar.toml, attributed by span
containment, each with a per-construct deny fixture, where a scoped ban
attached to no construct refuses at load — or B — the tree-wide global ban
runs of the old gate with jurisdiction as ambient convention, or the prior
version's per-kind fixture matrix?

### Answer
Build A. The two jurisdictions are the closed set; each ban declares its
form by where it lives (top-level `bans`/`bans_absolute` lists =
expression jurisdiction; a construct's `bans` list = construct scope).
Span-containment attribution lands scoped hits on classified items in
run.rs. A scoped ban naming no registered matcher, or listed under a
construct that does not exist, refuses at load — the same refusal the
loader already applies to unmatched bans. Unrepresentable: a ban whose
applicability is ambient convention — fixture: a grammar.toml attaching
`nested_place_assign` to no construct while it appears in no top-level
list must make Grammar::load return Err.

### Explanation
Audit of A first. The prior version priced universal bans at one refusing
fixture per item kind — sixteen per ban — which is unpayable for token
bans in kinds that cannot syntactically host the token (there is no
`unwrap_unchecked` inside a `use` item), and an unpayable law is a law
that gets quietly relaxed at build time: the convenient-redraw hatch this
document exists to forbid, planted by this document. The two-jurisdiction
form replaces the matrix with a decidable fact: token matchers scan
expression positions, and expression positions are kind-independent, so
their jurisdiction claim needs one bite proof, not sixteen fixtures;
kind-specific claims are exactly the construct-scoped form. B leaves
jurisdiction as weather. The per-kind-matrix version of A was B wearing an
unpayable invoice.

---

## 6 — Content-hash site identity

### Question
Do we build A — Site identity as file + item path + blake3 over an
identity-preserving token stream: a NEW `identity_tokens` rendering that
drops spans and whitespace but keeps identifiers and literals verbatim,
with rulings binding to that hash and the doc-comment consequence stated
as law — or B — file/line binding, or binding to the existing
`normalize_tokens` (graph.rs:276), which classes identifiers to "id" for
clone detection and therefore hashes a renamed-but-same-shape body
identical?

### Answer
Build A. `identity_tokens` is a second, separately named rendering: the
item's token stream stringified with identifiers and literals
byte-verbatim; the site hash is blake3 over that string. `normalize_tokens`
stays exactly where it is, for the purpose it is correct for (renames must
not hide a clone); it is never used for ruling identity. The waiver schema
gains `site_hash`; stale detection compares hashes; line numbers are
display-only. Stated law, not surprise: doc comments are attributes in the
token stream, so editing an item's doc comment changes its identity and
stales its ruling — a documentation change to a waived site is a content
change, re-read is owed. Unrepresentable: a ruling silently covering
changed code, and a ruling dying because unrelated lines moved — fixture
pair: renaming a local variable in a waived body must flip the site hash;
inserting a comment line ABOVE the item must not.

### Explanation
Audit of A first. The prior version was sound on the two-normalizations
split but silent on doc comments, leaving a false-stale surprise to be
discovered as a bug and "fixed" by whoever it annoyed — an undocumented
edge is a future unilateral ruling. It is now written law with the
direction chosen (stale, because attributes are content). B-file/line
sacrifices ruling identity in both directions: false stales open the
bulk-rebind hatch — re-approval without re-reading, the recorded fraud of
the retired ledger — and false lives open the
changed-construct-rides-an-old-ruling hatch.

---

## 7 — The dead-citation check

### Question
Do we build A — a required citation in every waiver (laws.toml law name,
file#item-path, test fn path, or decisions.md seat id) that is
content-anchored: for file#item and test citations the grant records the
cited item's identity hash (item 6), and the dead_citation relational pass
verifies on every run that the target exists AND its current hash equals
the recorded hash, with the prose residual assigned to the grant-time
attestation — or B — uncited prose, or existence-only checking?

### Answer
Build A. Citation grammar in the waiver schema; the relational pass
resolves every citation each run; a missing target or hash mismatch is a
violation. The check's claim at its true size, in the law text: a live
citation proves the factual anchor exists and has not changed since grant;
whether the prose reasons truly from that anchor is enforced at grant time
by the kyzo-waiver attestation — the sworn, verbatim, first-person form
whose falsity requires deliberate extended lying — and that assignment is
written in the law entry. Unrepresentable: a granted waiver whose factual
anchor cannot be checked mechanically — fixture: editing the body of a
cited test fn must flip its identity hash and report the citing waiver in
violation on the next run.

### Explanation
Audit of A first. The prior version assigned the prose residual to "the
operator" — the routed-to-judgment-queue hatch this reconstruction
banned, reappearing inside a law entry: a residual whose auditor is a
tired human is a residual unaudited. The attestation is the mechanism
that already exists for exactly this load: prose honesty at grant. B
sacrifices the falsifiability that made the attestation a trap and opens
the hatch of fluent prose that cited nothing surviving forever. The
citations-optional hybrid opens the obvious hatch: nobody opts in.

---

## 8 — Attestation validation in the loader

### Question
Do we build A — WaiverFile::load validating each entry's attestation as a
canonical template with designated fill slots: the loader byte-compares
the entry text against the template after slot extraction, and ANY byte
outside a slot — prefix, suffix, or softening interleave — refuses the
whole file — or B — the 20-character minimum, or required-substring
presence that admits an entry containing the sworn sentences plus
softening prose around them?

### Answer
Build A. The attestation template (verbatim question, the FALSE answer
with its named slots for the two tried alternatives and their mechanical
reasons) lives beside the schema as the canonical byte string;
WaiverFile::load segments the template at its slots and refuses unless
the entry text is exactly fixed-segment, slot, fixed-segment, ... with
full coverage and non-empty slots. Unrepresentable: a loadable waiver
that never answered the question, and a loadable waiver that answered it
inside softening prose — fixture pair: an entry with the required
sentences plus one prefixed hedging sentence must refuse; an entry
missing the FALSE answer must refuse.

### Explanation
This entry's mechanism survived the second audit intact; its statement of
B gains the named failure. Presence-checking asks "is the oath in there
somewhere"; byte-equality-around-slots asks "is this the oath and nothing
else"; only the second is a form law. B is a single lock on a vault with
two doors: prompts are honored by agents, doors are honored by physics,
and cursor's write path never passes through Claude Code's hooks.

---

## 9 — Self-conformance of the gate

### Question
Do we build A — bs-detector conformed to its own grammar, private fields
and admission constructors across Boundary, SourceFile, Hit,
CoverageProof, Verdict, and Grammar, until the gate runs green on its own
crate with zero self-waivers — or B — the gate standing red on itself, or
greened by waiving its own structs?

### Answer
Build A. Privatize the fields, add constructors and accessors, conform
every unclassified item in crates/bs-detector, zero self-waivers.
Unrepresentable: the gate exempting the gate — fixture: the gate run
scoped to crates/bs-detector must report zero unclassified hits with an
empty waiver ledger.

### Explanation
Survived both audits; the fixture line is added to satisfy rule 4. A
judge that cannot survive its own law is testimony against the law, and
self-conformance doubles as the first real conformance campaign — proof
the canonical forms are actually writable. B-red opens the "reds are
normal" hatch that numbs every count. B-waived is self-approved
exception, the recorded fraud of the retired ledger, returned wearing the
new format.

---

## 10 — One check system

### Question
Do we build A — one coverage registry: pure_rust and unsafe_check ported
as gate passes with laws and bite proofs, crates/xtask/src/checks/
deleted, and build_script_sandbox seated in laws.toml as an execution
campaign whose artifact records content and whose sufficiency is proven
by a SPECIMEN: the campaign ships a known-bad fixture it must flag, the
artifact records the declared source paths, the blake3 of each, the
specimen verdict, and the run timestamp, and the meta pass verifies
declared-path hashes against the tree, specimen verdict = flagged, and
timestamp within bound — or B — two check systems, where the second one's
coverage is invisible to the coverage law?

### Answer
Build A. Port the two static checks into the gate; seat the execution
campaign in laws.toml with the artifact schema above; delete the xtask
copies. Red states: implementation hash mismatch (check changed since
last run), specimen unflagged (campaign gutted — it no longer catches the
known-bad case it exists to catch), missing from artifact (coverage gap),
past freshness bound (stale). Unrepresentable: a check the laws.toml
coverage proof does not account for, and a gutted campaign passing on a
fresh artifact — fixture: an artifact whose specimen verdict is anything
but flagged must fail the meta pass regardless of hashes and timestamp.

### Explanation
Audit of A first. The prior version hashed "the check's implementation
source" without fixing which files constitute it — logic moved to an
unhashed helper gutted the campaign under matching hashes; and even with
declared paths, hash-match proves the tree matches what ran, not that
what ran still catches anything. The specimen closes the sufficiency gap
the way bite proofs close it for matchers: the campaign must demonstrably
still bite. B sacrifices the coverage proof's totality and opens the
hatch of checks quietly weakened in xtask with no laws.toml trace.

---

## 11 — A truthful module doc

### Question
Do we write A — engines/mod.rs stating the real architecture (grammar
seat, classifier, banned-shape predicates, relational passes, meta
passes, the unbuilt seats named as unbuilt) — or B — keep the
four-surfaces text describing a deleted registry and a behavior engine
that never existed?

### Answer
Write A. Delete the four-surfaces claim. Unrepresentable: a module doc
asserting architecture that is not in the tree — fixture: grep of
engines/mod.rs for "four surfaces" and "registry" must return zero.

### Explanation
Survived both audits; fixture added for rule 4. Docs are claims and a
false claim is a violation at any size. B's hatch is concrete: future
sessions build against the described architecture instead of the real one
— this record is itself proof that inherited language shapes behavior.

---

## 12 — Finishing the vocabulary purge

### Question
Do we sweep A — bs-detector's Cargo.toml and the .kyzo bus scripts checked
and purged of the exception-presuming vocabulary and the resonance name,
with the zero-hit grep as evidence — or B — a "purge complete" claim
standing over files never swept?

### Answer
Sweep A. Check both, purge hits, report zero with the grep in the record.
Unrepresentable: a completion claim over unswept files — the grep output
is the fixture.

### Explanation
Survived both audits. A partial purge under a total claim is the CLAIMS
violation in miniature. B's hatch is reseeding: agents read the surviving
frame and reproduce it — this session watched that mechanism operate.

---

## 13 — The ownerless comment

### Question
Do we route A — the resonance reference in kyzo-core/src/session/capacity.rs
into cursor's queue as a tracked bus contract naming file, line, and
replacement, held open until acked, engine code remaining cursor's — or B —
leave it ownerless, or edit engine code myself in role violation?

### Answer
Route A. Bus contract with file, line, replacement text, tracked to ack.
Unrepresentable: a known defect with no owner, and a manager-authored
engine edit — the bus message id and cursor's ack are the fixture.

### Explanation
Survived both audits. Ownership is this team's constitution: the manager
editing engine code is this week's confessed violation, and an ownerless
defect is how cruft becomes permanent. The self-edit hybrid trades a
one-line fix for the precedent that role boundaries bend when the diff is
small, which is exactly when they bend first.
