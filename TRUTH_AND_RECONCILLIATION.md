# TRUTH AND RECONCILLIATION

The 13 hard tasks the default-deny cutover did not do, adjudicated one at a
time under the kyzo-plan-engineering-answer-key discipline: sealed question,
settled answer, explanation in which every rejected alternative names the
purity it sacrifices and the escape hatch it opens. Operator-ordered record.
Answers here are settled law pending operator countermand; nothing below is
implemented until ordered.

---

## 1 — Item-kind coverage

### Question
Do we build A — a closed ItemKind enum in the classifier onto which every syn item maps, with grammar.toml required to seat every kind with at least one construct and Grammar::load refusing to run while any kind is unseated, so fns, impls, traits, consts, statics, type aliases, and mods classify or go red and a silently exempt item kind is unconstructible — or B — the current classifier that walks only structs and enums, leaving every other kind implicitly allowed under "the bans police the rest" and "kinds get added in a later story"?

### Answer
Build A. Extend classify.rs with the total ItemKind map over every syn::Item variant; grammar.toml gains a seat per kind; the loader refuses a grammar leaving any kind constructless; the classifier emits unclassified-<kind> for every unseated item. Delete the visitor's silence on unhandled kinds. Unrepresentable: an item kind the gate does not judge.

### Explanation
A is one authority (the grammar) over one total map (the kind enum), and its failure mode is loud refusal at load — falsifiable with a one-line fixture. B's failure mode is silence, unfalsifiable by construction: an exempt kind produces no evidence of its exemption. B sacrifices totality of judgment and opens the hatch of relocating dishonest code into unjudged kinds — a String status in a const, a panic in a trait default body. The hybrid "add kinds as constructs mature" sacrifices the load-time totality proof and opens the same hatch kind by kind; the hybrid "bans cover the rest" sacrifices default deny itself — bans enumerate known lies, and the unknown lie lands in the unjudged kind.

---

## 2 — The full construct grammar

### Question
Do we build A — the sixteen rust-* constructs (derivation, transition, consuming verb, total refusal, boundary decode, owned parse rule, wire envelope, ordered TryFrom lift, capability handle, species pair, sealed lifecycle, epoch-scoped currency, drop-bound resource, composition root, config-once injection, sealed public door) as real semantic predicates over syn — return-type shape, self mode, constructor privacy, Drop presence, whole-field reassignment versus nested mutation — so every fn and impl classifies as a named construct or goes red — or B — three shallow struct/enum rules with tree-wide bans carrying everything else, dressed as "the grammar grows later"?

### Answer
Build A. Extend the predicate vocabulary in grammar.rs to the semantic predicates the sixteen constructs require; seat all sixteen in grammar.toml; classify fns and impl fns against them; a fn classifying as nothing is red. Delete the fn exemption. Unrepresentable: a behavior shape with no named construct that still passes.

### Explanation
A makes the construct grammar the one authority over what behavior may look like, falsifiable per predicate with a fixture pair, and no better option exists because every alternative leaves some behavior judged by nothing. B sacrifices the allow-list — the middle of the design — and opens the hatch that any lie not enumerated as a ban passes silently. The "grow it later" hybrid sacrifices the truth of the done-claim and opens deferral theater. The "coarse fn buckets now, semantics later" hybrid sacrifices classification meaning — a bucket that accepts everything certifies nothing — and opens the decorative-construct hatch item 3 exists to kill.

---

## 3 — Disjoint struct rules

### Question
Do we build A — per-kind rule disjointness proven at grammar load, where Grammar::load refuses two constructs of one kind whose predicates can both accept one item and classification returns the unique construct name or red, so a construct name is a fact about the code — or B — the current any-match pass in which newtype-scalar is subsumed by sealed-struct and the name certifies nothing?

### Answer
Build A. Pairwise disjointness validation per kind at load (the tuple rule excludes named-field structs; the sealed rule excludes single-field tuples, or the partition is redrawn); classification emits the unique name. Delete .any() classification. Unrepresentable: an item lawfully classifiable as two constructs.

### Explanation
One meaning, one type is the ontology law, and a classification that cannot say which construct matched is a boolean wearing a taxonomy. B sacrifices the record's meaning — rulings and per-construct bans bind to names that do not discriminate — and opens the hatch of decorative grammar growth: constructs added for show that partition nothing. The first-match-wins hybrid sacrifices the load-time proof for order dependence and opens silent reclassification when someone reorders the file.

---

## 4 — Type-resolving string rule

### Question
Do we build A — a structural type walker deciding string-carrying by syn::Type shape (terminal path ident String, reference to str, recursion through generic arguments) joined to a boundary-wide type-alias table resolved transitively, so a `Restrict` field classifies clean and `type Name = String` is caught — or B — the substring check on rendered type tokens, with its false reds and its alias hole?

### Answer
Build A. TypeShape walk in classify.rs plus an alias map collected during the boundary walk; delete the substring check. Unrepresentable: a string field hidden behind one alias passing, and a str-lettered identifier failing.

### Explanation
Judgment must flow from structure, never spelling — the gate's own analogue of the one law. B sacrifices soundness in both directions at once: false reds teach agents the gate is noise and open the "it cries wolf, waive it" hatch; false greens let the exact banned shape ride behind `type Kind = String`. The tune-the-substring-list hybrid sacrifices nothing less, being the same spelling authority with more spellings.

---

## 5 — Per-construct ban scoping

### Question
Do we build A — bans attached to constructs in grammar.toml (plus one explicit all-items seat for the genuinely universal few), matcher hits attributed to classified items by span containment, and the loader refusing a ban attached to nothing, so every prohibition's jurisdiction is stated law — or B — the tree-wide global ban runs of the old gate, relabeled into a new file?

### Answer
Build A. Move bans into construct definitions; scope hit attribution by item span in run.rs; a seatless ban refuses at load. Delete the global ban lists. Unrepresentable: a ban whose applicability is ambient convention.

### Explanation
This is the difference between law and weather: A writes every prohibition's jurisdiction as a checkable fact with a per-construct fixture; B sacrifices the grammar's claim to be the law seat — the bans live beside it, not in it — and opens two hatches at once: over-reach, where a test-shape ban fires on production constructs until its waivers become noise, and under-reach, where a construct that should carry a ban silently does not, and nobody can see the absence because absence is written nowhere. The "global now, scope later" hybrid is B holding a promissory note.

---

## 6 — Content-hash site identity

### Question
Do we build A — Site identity as file plus item path plus normalized-token body hash, with rulings binding to the hash so drift is detected by content change and line numbers demoted to display — or B — file/line binding, where every edit above a site orphans its ruling and rebinding is permanent process churn?

### Answer
Build A. Hash the existing normalize_tokens stream; the waiver schema gains the hash field; stale detection compares hashes; the line survives for humans. Delete line-equality as the binding law. Unrepresentable: a ruling silently covering changed code, and a ruling dying because unrelated lines moved.

### Explanation
Identity before position is this engine's own storage law, applied to the gate's ledger. B sacrifices ruling identity in both directions: false stales on drift open the bulk-rebind hatch — re-approval without re-reading, the exact recorded fraud of the retired ledger's "rebind" commits — and false lives when an edit lands on the same line open the changed-construct-rides-an-old-ruling hatch. The line-plus-construct-string status quo is the second failure wearing a seatbelt.

---

## 7 — The dead-citation check

### Question
Do we build A — a required citation in every waiver (seat number, file#item, or test fn) parsed from the entry and existence-verified on every run by a dead_citation relational pass with its own laws.toml law, so a justification stays checkable evidence forever — or B — uncited prose that nobody audits after grant day?

### Answer
Build A. Citation grammar in the waiver schema; the relational pass resolves every citation against the tree and decisions.md each run; a dead or unresolvable citation is a violation. Unrepresentable: a granted waiver whose factual anchor cannot be checked mechanically.

### Explanation
The attestation forces truth at grant time; only the citation check keeps it true afterward, because claims rot as the tree moves and A makes rot loud. B sacrifices the falsifiability that made the attestation a trap and opens the hatch of fluent prose that cited nothing surviving forever. The citations-optional hybrid sacrifices uniformity and opens the obvious hatch: nobody opts in.

---

## 8 — Attestation validation in the loader

### Question
Do we build A — WaiverFile::load structurally verifying that every entry carries the verbatim attestation question, the FALSE answer, and each required sworn sentence, refusing the whole file otherwise, so the agent charter's law has a mechanical twin at the data door — or B — the 20-character minimum, with the form enforced only by the kyzo-waiver prompt and the write hook?

### Answer
Build A. The loader checks question byte-equality and required-sentence presence exactly as it already refuses duplicate sites. Unrepresentable: a loadable waiver that never answered the question.

### Explanation
Enforcement belongs at the door the data walks through: prompts are honored by agents, doors are honored by physics. B sacrifices defense in depth against the one failure that matters — a write that never passed through Claude Code's hooks, which is cursor's entire write path — and opens the format-drift hatch: entries that half-quote the question until the verbatim law is folklore. "The hook is enough" is a single lock on a vault with two doors.

---

## 9 — Self-conformance of the gate

### Question
Do we build A — bs-detector conformed to its own grammar, private fields and admission constructors across Boundary, SourceFile, Hit, CoverageProof, Verdict, and Grammar, until the gate runs green on its own crate with zero self-waivers — or B — the gate standing red on itself, or greened by waiving its own structs?

### Answer
Build A. Privatize the fields, add constructors and accessors, conform every unclassified item in crates/bs-detector, zero self-waivers. Unrepresentable: the gate exempting the gate.

### Explanation
A judge that cannot survive its own law is testimony against the law, and self-conformance doubles as the first real conformance campaign — proof the canonical forms are actually writable. B-red sacrifices the gate's standing and opens the "reds are normal, the gate itself is red" hatch that numbs every count. B-waived sacrifices the thing this whole reconstruction was for: it is self-approved exception, the recorded fraud of the retired ledger, returned wearing the new format.

---

## 10 — One check system

### Question
Do we build A — one coverage registry, with pure_rust and unsafe_check ported as gate passes carrying laws and bite proofs, build_script_sandbox seated in laws.toml as an execution campaign whose freshness artifact the meta pass verifies, and crates/xtask/src/checks/ deleted — or B — two check systems, where the second one's coverage is invisible to the coverage law?

### Answer
Build A. Port the two static checks into the gate; seat the execution campaign in laws.toml with artifact-freshness verification; delete the xtask copies. Unrepresentable: a check the laws.toml coverage proof does not account for.

### Explanation
The done-law says every catch mechanism is written in one auditable place; a second check system beside the registry is a second brain, the disease this engine's architecture forbids in its own domain. B sacrifices the coverage proof's totality and opens the hatch of checks quietly weakened or deleted in xtask with no laws.toml trace. The leave-them-but-list-them hybrid records coverage it cannot enforce — a register describing a door it does not guard.

---

## 11 — A truthful module doc

### Question
Do we write A — engines/mod.rs stating the real architecture (grammar seat, classifier, banned-shape predicates, relational passes, meta passes, the behavior seat named as unbuilt) — or B — keep the four-surfaces text describing a deleted registry and a behavior engine that never existed?

### Answer
Write A. Delete the four-surfaces claim. Unrepresentable: a module doc asserting architecture that is not in the tree.

### Explanation
Docs are claims and a false claim is a violation at any size. B is a standing false statement at the crate's front door, and its hatch is concrete: future sessions build against the described architecture instead of the real one — this very session proved repeatedly that inherited language shapes behavior. No hybrid exists; a doc is true or it is not.

---

## 12 — Finishing the vocabulary purge

### Question
Do we sweep A — bs-detector's Cargo.toml and the .kyzo bus scripts checked and purged of the exception-presuming vocabulary and the resonance name, with the zero-hit grep as evidence — or B — a "purge complete" claim standing over files never swept?

### Answer
Sweep A. Check both, purge hits, report zero with the grep in the record. Unrepresentable: a completion claim over unswept files.

### Explanation
The vocabulary was ruled sabotage, and a partial purge under a total claim is the CLAIMS violation in miniature. B's hatch is reseeding: agents read the surviving "sworn"/"confess" frame and reproduce it — this session watched that mechanism operate. There is no cost side worth naming; the alternative to one grep is a standing false claim.

---

## 13 — The ownerless comment

### Question
Do we route A — the resonance reference in kyzo-core/src/session/capacity.rs into cursor's queue as a tracked bus contract naming file, line, and replacement, held open until acked, engine code remaining cursor's — or B — leave it ownerless, or edit engine code myself in role violation?

### Answer
Route A. Bus contract with file, line, replacement text, tracked to ack. Unrepresentable: a known defect with no owner, and a manager-authored engine edit.

### Explanation
Ownership is this team's constitution: the manager editing engine code is this week's confessed violation, and an ownerless defect is how cruft becomes permanent — "someone will get it" names nobody. The self-edit hybrid trades a one-line fix for the precedent that role boundaries bend when the diff is small, which is exactly when they bend first. B-ownerless sacrifices the tracking that makes the debt register real instead of decorative.
