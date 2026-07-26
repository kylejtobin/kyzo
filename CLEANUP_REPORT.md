# Cleanup Report — one cut

Investigation run against `../cozo` as the reference floor and `FEATURES.md` as the
ceiling. Every number below came from a command in this repository or in `../cozo`.
Estimates are labelled ESTIMATE and carry their basis. Nothing here is a guess
presented as a measurement.

---

## 1. The two reference points (measured)

|                                   |     cozo |     kyzo | ratio |
| --------------------------------- | -------: | -------: | ----: |
| total `.rs`                       |   73,911 |  209,725 | 2.84x |
| less vendored data tables         |   47,979 |  183,773 | 3.83x |
| less inline `#[cfg(test)]`        | **44,429** | **133,856** | **3.01x** |

Vendored data tables excluded from both sides: cozo 25,932 (`fts/tokenizer/
stop_word_filter/stopwords.rs` 21,885 + `ascii_folding_filter.rs` 4,047, MIT,
stopwords-iso); kyzo 25,952 (the same two files, rehomed under
`project/text/tokenizer/`). These are data, not architecture, and counting them
flatters neither side.

Inline test code separated because tests are **evidence**, judged by whether they
can contradict us, not by purity. kyzo 49,917 (24% of the tree); cozo 3,550 (5%).

**Architecture excess over the floor: 89,427 lines.**

The floor is real: 44,429 lines of cozo architecture already deliver Datalog,
semi-naive evaluation, stratified negation, magic sets, relational + graph +
vector (HNSW) + FTS + LSH. Anything we spend above that has to be bought by a
line in `FEATURES.md`.

## 2. Volume is a function of the node count (measured)

| | cozo | kyzo | ratio |
|---|---:|---:|---:|
| type declarations (`struct`/`enum`/`trait`) | 453 | 1,504 | 3.32x |
| unique type names | — | 1,451 | |

3.32x nodes against 3.01x architecture lines. The two track. **This is the whole
basis of the cut: judging 1,451 declarations is tractable, judging 133,856 lines
is not, and the lines follow the nodes.**

## 3. The roots exist and are sound (verified by reading)

`crates/kyzo-core/src/data/statement.rs`, 504 lines: `OntokKind` with the twelve
variants over one `StatementBody` of six typed seats — subject, predicate, value,
validity_time, context, source. Its own doc condemns per-variant record forks:
"ONTOK variants are constructions over this kernel — never a second record type
and never a nullable mega-struct fork."

`KyzoRecord` (`session/admit.rs`) is privately constructed with no public
constructor, one `RecordContentDigest` as identity.

**The ontology is not the problem.** The root is small, typed and correct. The
89,427 lines are what grew beside it.

## 4. Nodes with no edge (measured)

574 of 1,451 unique type names (40%) are mentioned in no file but the one that
declares them. Excluding tests: **527 leaf types, 313 of them `pub`.**

| module | leaves | of which `pub` |
| --- | ---: | ---: |
| `kyzo-core/src/exec` | 120 | 81 |
| `kyzo-core/src/project` | 82 | 61 |
| `kyzo-core/src/store` | 71 | 54 |
| `kyzo-core/src/session` | 67 | 47 |
| `kyzo-model/src/parse` | 42 | 6 |
| `kyzo-core/src/rules` | 39 | 14 |
| `kyzo-model/src/program` | 27 | 9 |
| `kyzo-model/src/value` | 16 | 11 |
| all other | 63 | 30 |

A `pub` type mentioned nowhere but its own file is a node with no edge — it
answers neither "which ONTOK primitive is it" nor "which feature is it on the
path to". 313 of those.

## 5. Duplicate authorities (measured)

**5a. Already declared.** The zone rules carry a `dual-authority debt` table
naming 19 files that fuse two authorities. That work is already done and was not
redone here:

`authority.rs`, `commit_cap.rs`, `contract.rs`, `db.rs`, `epoch.rs`,
`failure.rs`, `footprint.rs`, `grants.rs`, `objects.rs`, `op/mod.rs`,
`parse/search.rs`, `projection.rs`, `seal.rs`, `stdlib/bind.rs`, `sweep.rs`,
`text/fts.rs`, `value/arena.rs`, `value/number.rs`, `wal.rs`

**5b. Structural duplicates.** 37 groups of structs share an identical field-type
signature. Most are distinct error facts sharing `(SourceSpan, String)` and are
not duplicates. Two are real:

- **`OntokPredStmt` ≡ `StatementBody`** — field for field, the same six typed
  seats, declared at `session/admit.rs:1195` while `data/statement.rs:217` owns
  the kernel and its doc forbids exactly this. *A duplicate authority at the
  ontology root.* Sibling `OntokValueStmt` is the same fork minus `predicate`.
- **`CryptoDomain` / `EpochGrant` / `IntentClear`** — all `(FenceEpoch, StoreId)`,
  in `epoch.rs`, which 5a already names.

**5c. Naming.** The confessing-name detector (`*Manager`, `*Helper`, `*Util`,
`*Impl`, `*V2`, `*Legacy`) returns 3 hits in non-test code. **Naming discipline
here is good.** The bloat is structural, not sloppy. This matters: it means the
cut cannot be done by grepping for bad names, and anyone who claims it can is
not looking.

## 6. Ratio diff against cozo, module by module (measured)

cozo's vector and LSH live under `runtime/`, so the comparison assigns
`hnsw.rs` (1,035) and `minhash_lsh.rs` (389) to projections, and removes
`runtime/tests.rs` (1,614) from session.

| concern | cozo | kyzo | ratio | excess |
| --- | ---: | ---: | ---: | ---: |
| storage | 3,106 | 27,688 | 8.9x | 24,582 |
| query / eval | 6,830 | 31,538 | 4.6x | 24,708 |
| projections | 4,578 | 21,610 | 4.7x | 17,032 |
| session | 4,531 | 19,616 | 4.3x | 15,085 |
| fixed rules | 4,416 | 12,281 | 2.8x | 7,865 |
| value model | 10,992 | 16,182 | 1.5x | 5,190 |
| parse | 3,189 | 5,688 | 1.8x | 2,499 |

**The largest ratio is not the target.** `store/` at 8.9x is almost entirely
bought by `FEATURES.md`: `replica.rs` (Replication), `merkle.rs` (Merkle
verification walks), `grants.rs` (Capability grants), `transcript.rs`
(Transcripts), `sweep.rs` (Sweep/GC with retention certificates), `backup.rs`
(Backup/export/restore), `crypto.rs` (encryption at rest by default),
`objects.rs` (Object store seam), `failure.rs` (typed failure lattice), `wal.rs`.
Every one names a feature. Storage is the model of a subsystem that earned its
size.

`value model` at 1.5x is the cheapest in the tree and is where the one law lives.

That leaves **exec / project / session** as the mass without a matching feature
count: 56,825 lines against a 15,939-line floor, and 269 leaf types among them.

---

## Proposed cut

Ordered so the tree is a scaffold at each step, not rubble. Red between steps is
expected. Savings are ESTIMATE unless marked measured.

### Cut 1 — the 313 public leaf nodes
**Measured population:** 313 `pub` types, non-test, mentioned in no other file.
**Method:** delete the type; the functions that exist only to move values into and
out of it die with it.
**ESTIMATE 18,000–26,000 lines**, basis: 313 types × the tree's measured mean of
92 architecture lines per type (133,856 / 1,451), discounted 35–50% because leaf
types skew smaller than the mean. Requires no judgment about features — a node
with no edge is dead by construction.

### Cut 2 — collapse `OntokPredStmt` / `OntokValueStmt` into `StatementBody`
**Measured:** two forks of the ontology root, `session/admit.rs`.
**ESTIMATE 400–900 lines**, basis: the two declarations plus the twelve
`admit_kind` arms that thread them.
Small, and first among the duplicate work anyway: it is the root. Every node
below inherits its shape from this one, so the cut order runs downward from here.

### Cut 3 — the 19 declared dual-authority files
**Measured:** the 19 files, 24,000+ lines combined (`replica.rs` 3,195,
`grants.rs` 2,653, `sweep.rs` 2,045, `contract.rs` 2,413, `db.rs` 2,270, …).
**Method:** split each into its two authorities, keep the typed one, delete the
untyped one.
**ESTIMATE 8,000–14,000 lines**, basis: one of two fused authorities per file is
typically the thinner adapter; 30–50% of the combined mass.

### Cut 4 — `exec/`, `project/`, `session/` to their feature paths
**Measured:** 56,825 lines, floor 15,939, 269 leaf types, 189 of them `pub`.
**Method:** step 7 of the method — every surviving node names its ONTOK primitive
and its `FEATURES.md` line, default DELETE.
**ESTIMATE 25,000–40,000 lines.** This is the largest and the only one requiring
judgment per node. It is also where `#[cfg(test)]` density should be re-checked
after, because deleting a node deletes its tests.

### Not cut
- **`store/`** — feature-bought, item by item, above.
- **`value model`** — 1.5x, holds the one law.
- **`data/statement.rs`** — the root.
- **The 49,917 lines of test/evidence** — judged by whether they can contradict
  us. Cut only where the node under test is cut.
- **Vendored tables (25,952)** — data, and cozo carries the same.

### Total
**ESTIMATE 51,000–81,000 lines**, against a measured architecture excess of
89,427. The midpoint (66,000) lands the tree near 68,000 architecture lines —
1.5x cozo's floor, carrying bitemporality, accountability, crypto, replication
and the proof harness, which is a defensible ratio.

**Reaching cozo's 44,429 is not achievable by cutting alone** and this report
does not claim it. The remaining gap is feature-bought and the honest way to
shrink it further is Cut 4 going deeper than estimated, not a bigger number here.

---

## What this investigation did not establish

- **No per-node feature mapping was built.** Cut 4's estimate is the weakest
  number in this document. It rests on the ratio diff and the leaf count, not on
  a node-by-node ruling against `FEATURES.md`. That ruling is the work.
- **Reachability was computed by name mention, not by resolved import graph.** A
  type named in a doc comment or a string counts as mentioned. This biases the
  leaf count *down*, so 527 is a floor, not a ceiling.
- **Cozo's own quality was not audited.** It is used as a size reference for
  delivered capability, not as a purity model.
- **Whether the 89,427 lines are recoverable at all** depends on Cut 4's
  judgment pass, which has not been run.
