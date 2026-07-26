# Cleanup Report — cut to the named types, build up from there

Second pass. The first pass measured this tree against cozo's size and reported
"89,427 excess lines" as the headline. That was the wrong ruler and the wrong
unit, and this document says so before it says anything else.

Every number below came from a command in this repository. Estimates are
labelled ESTIMATE and carry their basis.

---

## 0. What the first pass got wrong

**It made a line count the goal.** "Architecture excess: 89,427 lines" is not a
purity measure. It cannot be acted on and it cannot be checked. It also pushed
the one cut that needed a method (Cut 4, "judgment per node") into being the
largest and least defensible number in the document.

**It used cozo as a floor instead of as a control.** Cozo answers exactly one
question: *what does delivering Datalog, semi-naive evaluation, graph, vector,
FTS and LSH cost when you carry no accountability law?* It has no Record
admission, no bitemporality, no capability lattice, no crypto. Applying it to
`store/` produced "8.9x" — a number that then took a full paragraph to excuse,
item by item. A comparator you have to excuse is a comparator scoped wrong.

**It measured reachability and called it purity.** "574 types mentioned in no
other file" finds unreferenced code. Unreferenced code is hygiene. A type
referenced from forty files can still be a hole, and that is the more expensive
kind.

**It never opened `docs/STORAGE-ARCH-STRIPPED.md`.** That document is not a
feature list. It is a constructor specification: 35 rows of nouns that must stay
distinct, roughly 40 enumerated `Unconstructible` / `Refused` claims, 56 matrix
pairs with named joint proofs, and 27 adversarial campaigns declared as merge
gates. It is the ruler this tree is supposed to be cut to. The first pass
measured against a different codebase instead.

---

## 1. The ruler, extracted from the law (measured)

`STORAGE-ARCH-STRIPPED.md` names a **closed set of nouns**. Extracted
mechanically — backticked and bolded identifiers, minus prose words:

| | count |
| --- | ---: |
| substantive law nouns named by the architecture | **62** |
| declared as a `struct` / `enum` / `trait` / `type` in `crates/` | 38 |
| present as an enum variant | 19 |
| mentioned but with no declaration | 4 |
| absent entirely | 1 |

The four mention-only nouns are `Location`, `ResultValue`, `StagingTTL`,
`TagOrdered`. The absent one is `Presentation` — which the order law calls
outermost-only and says "join or range over Presentation is a construction
error", a claim nothing in the tree can currently make.

**The law's vocabulary is essentially all here.** 57 of 62 nouns exist in some
form. This is the finding that redirects the whole cut: nothing important is
missing. The problem is entirely what grew beside it.

### The ratio that matters

| | count |
| --- | ---: |
| type names the law names | 62 |
| type names declared in `crates/` | **1,491** |
| declared types that are not a law noun | **1,429** |

That is the cut, stated exactly. Not "89,427 lines above cozo" — **1,429
declarations that the governing law does not name.** Each one has to answer a
question with a default answer of *delete*.

---

## 2. Claim strength — the highest-value finding (measured)

`STORAGE-ARCH-STRIPPED.md` sets the ladder and the penalty in one sentence:

> **Unconstructible** — No path through the sealed Rust type and crate boundary
> constructs the illegal state. […] Inflating Unexposed to Unconstructible is
> Spec fraud.

So for every law noun, one question is decidable from the code: **can a caller
outside the declaring module mint one?** Measured over the 36 law nouns that
resolve to a `struct` or `enum`, by inspecting each type's own `impl` blocks for
a public function that takes no `self` and returns `Self`:

| enforcement | count | types |
| --- | ---: | --- |
| **Sealed** — no public path returns one | **13** | `AdmissionCertificate` `AuditKey` `CheckpointSeal` `Committed` `IncarnationId` `IncarnationMintCap` `LocalProjection` `MergeProof` `PermanenceCandidate` `Repair` `ShredSalt` `StoreOpen` `WriteAuthority` |
| **Ratcheted** — derivable only from an existing one | **3** | `CommitOrdinal` `IntentOrdinal` `OpenOrdinal` |
| **Free** — any caller mints one from raw parts | **20** | `AncestorReadGrant` `AskShape` `CanonicalTranscript` `CompositionId` `CryptoDomain` `Downgrade` `Entropy` `FenceEpoch` `ForkGenerationWitness` `ForkGrant` `Frontier` `ObjectDurabilityClass` `OperationKey` `PermanenceWitness` `RecoveryGrant` `RecoveryMatrix` `ReplicaKey` `SnapshotFork` `StableCommitCap` `WrappedShredSalt` |

**16 of 36 carry the claim in the type. 20 do not.**

The sealed thirteen are the proof that this is achievable in this codebase, by
these people, in these files — `store/authority.rs` seals `WriteAuthority` and
leaves `RecoveryMatrix::new` open, in the same file. The discipline exists; it
is applied unevenly.

Several of the twenty are named `Unconstructible` in the architecture text:

- `PermanenceWitness::from_sealed` is public, against "`PermanenceWitness::mint(cut)`
  is Unconstructible when `cut ≥ expires_at` — late confirmation has no constructor."
- `CompositionId::derive` is public, against "Engine-mint Unconstructible;
  CompositionId is client-rooted."
- `ForkGrant::new` and `RecoveryGrant::new` are public, against "divergent
  successors Unconstructible" and "second grant for same predecessor epoch →
  equivocation poison."
- `StableCommitCap` is a `pub enum` with `from_arm`, against "production
  `Committed` without a sealed arm is Unconstructible."

This is the same defect shape as `ShapedKey::mint -> Option` — a runtime check
standing under an Unconstructible header. It is not a one-off. **It is the
dominant defect in this tree, and no line count would ever have found it.**

---

## 3. Nouns that must stay distinct (measured)

35 rows in the architecture, each of the form "X is not Y", each annotated that
collapsing the pair recreates a named production bug. Checked for a distinct
declared type on the load-bearing side:

- **31 rows resolve to a distinct type.** No fusion found among them.
- **4 rows have no type at all**: `Store identity`, `Location`, `State root`,
  `StagingTTL`. A noun the law says must stay distinct, with nothing to keep it
  distinct, is the fusion waiting to happen. `StagingTTL` is the sharpest:
  the law denominates it in `CommitOrdinal`s specifically so wall-clock cannot
  become the expiry authority, and there is no type holding that.

Retained from the first pass, still true and still measured:

- **`OntokPredStmt` ≡ `StatementBody`**, field for field, at
  `session/admit.rs:1195` while `data/statement.rs:217` owns the kernel and its
  own doc forbids exactly this fork. Sibling `OntokValueStmt` is the same fork
  minus `predicate`. *One noun, two types* — the mirror image of a fusion, and
  equally a law violation.
- The zone rules' declared **`dual-authority debt`** table: 19 files fusing two
  authorities (`authority.rs`, `commit_cap.rs`, `contract.rs`, `db.rs`,
  `epoch.rs`, `failure.rs`, `footprint.rs`, `grants.rs`, `objects.rs`,
  `op/mod.rs`, `parse/search.rs`, `projection.rs`, `seal.rs`, `stdlib/bind.rs`,
  `sweep.rs`, `text/fts.rs`, `value/arena.rs`, `value/number.rs`, `wal.rs`).
  Note the overlap with §2: `grants.rs`, `objects.rs`, `commit_cap.rs`,
  `epoch.rs` and `footprint.rs` appear in both lists. Fused authority and open
  constructors are the same defect seen from two sides.

---

## 4. Campaigns — the merge gates the law declares (measured, weakly)

The architecture names **27 adversarial DST campaigns** and calls them merge
gates: "Every future change must cite a **failed campaign** or a **failed matrix
row**."

Searching test, trial and `#[test]`-bearing code for each campaign's distinctive
token: **25 of 27 produce a match; 2 produce none** — `forged-manifest` and
`old-session resurrection` (the `WriteSessionDead` resurrection campaign).

**This measurement is weak and must be read as weak.** A token match says a name
appears somewhere in test code. It does not say the campaign runs, injects the
fault, or would fail if the law broke. Establishing that is a per-campaign read.
What it does establish is a floor: two named merge gates have no trace at all.

This reframes the 49,917 lines of test code. The first pass excused them as
"evidence, judged by whether they can contradict us" and cut nothing. The right
question is narrower and answerable: **which of the 27 required campaigns do
these lines actually run?** A test that runs no campaign and pins no law claim
is as deletable as any other node.

---

## 5. Where cozo is the right control (measured, rescoped)

Cozo is kept, scoped to the concerns it shares. It is the answer to "what does
this capability cost without accountability law", and nothing else.

| concern | cozo | kyzo | ratio |
| --- | ---: | ---: | ---: |
| query / eval | 6,830 | 31,538 | 4.6x |
| projections (incl. HNSW, LSH) | 4,578 | 21,610 | 4.7x |
| fixed rules | 4,416 | 12,281 | 2.8x |
| value model | 10,992 | 16,182 | 1.5x |
| parse | 3,189 | 5,688 | 1.8x |

These five deliver `FEATURES.md`'s "Query language & evaluation", "Graph — 21
algorithms" and "Projections", and cozo delivers the same list. Here 4.6x is a
real question.

`store/`, `session/` and the accountability surface are **not** in this table.
Cozo has no counterpart, so it produces no number, and the first pass's "8.9x"
was measuring the presence of the law rather than any excess. Those modules are
judged in §2 and §3 — by whether their types carry the claims the architecture
makes — which is the harder standard, not the softer one.

Totals from the first pass, retained as measured and now demoted from headline
to context: 133,856 kyzo architecture lines against 44,429 cozo, both excluding
vendored data tables (25,952 / 25,932, the same two MIT stopword files) and
inline `#[cfg(test)]` (49,917 / 3,550).

---

## 6. The cut, as a procedure

Every declared type gets exactly one verdict. First match wins. **The default is
delete**, and that default is what makes this converge — the first pass had no
default, which is why its largest cut was an estimate instead of a procedure.

1. **Law noun.** `STORAGE-ARCH-STRIPPED.md` or `decisions.md` names it. **Keep**,
   then rule on its claim strength (§2): if the law says Unconstructible, seal
   the constructor or downgrade the claim in the document. One or the other,
   never neither.
2. **Constructor or witness for a law noun.** It exists so a law noun cannot be
   built wrong. **Keep.**
3. **Projection or adapter on a `FEATURES.md` line.** The query, graph, vector,
   FTS, spatial and temporal machinery. **Keep**, and §5 is the cost control.
4. **Carriage.** Moves values, decides nothing. **Keep only if it cannot be a
   function.** Carriage that decides is a law violation, not a keep.
5. **Unnamed.** No law noun, no feature line, no constructor duty. **Delete.**

Verdict 5 is the mass. The 1,429 non-law declarations enter here and most leave.

### Order — follow the law's dependency, not module size

The architecture states its own closure rule: "new seat × all existing; changed
row reopens adjacent." Cutting bottom-up therefore wastes the work, because a
kernel change reopens everything below it.

1. **Kernel.** `StatementBody` and the `OntokPredStmt` / `OntokValueStmt` fork;
   `CanonicalTranscript`; Tag order. Everything inherits shape from here.
2. **The four unheld nouns.** Give `Store identity`, `Location`, `State root`,
   `StagingTTL` types before anything above them is cut, so the cut has
   something to check against.
3. **The 20 open constructors.** Seal or downgrade, one at a time. Each seal
   invalidates the call sites that were minting freely — that is the cut doing
   its work, and it is why this comes before the bulk pass.
4. **The three doors.** `Store` / `Catalog` / `Engine` and the 19 dual-authority
   files.
5. **Bulk verdict pass** over what remains, procedure above.
6. **Campaign audit** last, when the surviving nodes are known.

The first pass put the kernel cut second and justified it by size ("small, and
first among the duplicate work anyway"). Right answer, wrong reason.

---

## 7. What to report instead of a line count

Four ratios, all re-runnable by script, all falsifiable:

| metric | now |
| --- | --- |
| law nouns enforced at the strength the document claims | **16 / 36** |
| distinct-noun rows with a type holding the distinction | **31 / 35** |
| named merge-gate campaigns with any trace in test code | **≤ 25 / 27** |
| declared types on a path to a named noun or feature line | **unmeasured — this is the work** |

Lines fall out of these. They are not the target, and the first pass reporting
them as the target is what made its conclusion uncheckable.

**ESTIMATE, stated as an estimate and not as a goal:** verdict 5 applied to
1,429 non-law declarations, at the tree's measured mean of 92 architecture lines
per type, discounted heavily because unnamed types skew small — **40,000–70,000
lines.** This number is a consequence, and if the four ratios above reach their
denominators with more lines than that, the ratios win.

---

## What this investigation did not establish

- **No per-node verdict was run.** §6 is a procedure, not a result. The 1,429
  figure is a population, not a finding, and the line ESTIMATE rests on it.
- **The claim-strength audit is structural, not semantic.** It asks whether a
  public function returns the type; it does not read whether that function's
  arguments already constitute the proof. Some of the twenty may be sound
  constructors over already-sealed inputs. Each needs a read. **Twenty is
  therefore a ceiling on the defect and a floor on the work.**
- **Campaign coverage is a token match** (§4) and is the weakest number here.
  25 of 27 means 25 names appear, not 25 campaigns run.
- **The 62-noun law set was extracted mechanically** from one document.
  `decisions.md` L1–L14 will add nouns and may reclassify some of the 1,429.
  The set is a floor.
- **`FEATURES.md` was used as a keep-list, not audited.** Whether each line is
  actually delivered is a separate question this does not touch.
- **Cozo's own quality was not audited.** It is a cost reference for delivered
  capability in five modules, nothing more.
