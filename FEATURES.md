# KyzoDB / Kyzo — feature inventory

## Query language & evaluation
- KyzoScript (Datalog) — one program spanning relational, graph, vector, text, spatial, temporal
- Semi-naive evaluation
- Stratified negation
- Magic-set rewriting
- Recursion
- Aggregation / folds
- Joins as shared variables (no `JOIN` keyword)
- Fixed rules
- Query planning, compilation to relational algebra, normalization, stratification
- `::explain`
- Budgets: epoch ceilings, derived-tuple ceilings, in-flight materialization guards, deadlines, cooperative cancellation
- Typed refusals carrying source spans

## Graph — 21 algorithms
BFS · DFS · Dijkstra · A* · all-pairs shortest path · shortest-path BFS · Yen k-shortest · PageRank · degree centrality · Louvain · label propagation · k-core · cliques · triangles · strongly connected components · topological sort · Kruskal · Prim · max-flow · random walk · reorder-sort

## Projections (access paths, never truth)
- **Vector** — HNSW, with the filter *inside* the search so `k` counts matches and filtered ANN cannot come back empty
- **Full-text** — FTS with tokenizer chain: stopword filter, ASCII folding
- **Sparse** — sparse index
- **Spatial** — spatial index, space-filling-curve mapping
- **Dedup** — LSH
- **Gazetteer**
- **Current-state** — dense decoded binary-searchable residency cache
- Watermark discipline: a projection may serve only when it provably matches the reader's snapshot
- `::vec_idx`, `::fts_idx`, `::lsh_idx`, `::index_create`, `::index_create_adv`, `::index_drop`, `::list_indices`

## Time
- Real bitemporal: valid time (application-assertable, retroactive) + system time (engine-stamped, unforgeable)
- As-of reads as index seeks, not log replay
- Version keys sort newest-first within each fact
- Supersession / correction — never overwrite
- Interval algebra derived at read time from point events
- Append-only point events (assertions and retractions)
- Deterministic replay: identical inputs reconstruct byte-identical state

## Proof & correctness
- Reference oracle — a deliberately naive evaluator speaking the whole language
- `::verify` — match, budgeted refusal, or reproducible mismatch bundle
- Determinism — byte-identical answers and refusals across thread counts
- Provenance — derived facts name their premises, re-checked by an independent checker that imports nothing from the evaluator
- DST campaigns (`kyzo-trials`)
- Crash-testing filesystem (`kyzo-crashfs`)
- Property tests, corruption harnesses, continuous fuzzing on the encoding law
- Conformance kit for second backends

## Accountability
- **KyzoRecord** — the mandatory accountable unit of every durable user-visible write; no second durable write door
- SHA-256 content digest as identity, from a single sealed serializer
- Domain-separated RFC-6962 Merkle StateRoot
- Append-only RootChain
- Forge wall — storage bytes cannot be interpreted as a record
- Deterministic lowering: record → relational rows, graph edges, embeddings, text spans, temporal facts, provenance links
- Every projection resolves to a source `RecordId`
- Supersession and invalidation as records, never flags
- Record-level verification distinct from storage verification

## ONTOK — the ontology kernel
Ten primitives: Entity · Event · State · Role · Relation · Claim · Evidence · Context · Concept · Rule
Twelve record variants: the ten plus Derivation and Invalidation
- Standing: proposed → supported → accepted → contradicted → superseded → invalidated → rejected → expired
- Typed authority, typed provenance, typed context scope, typed time scopes
- Evidence = source artifact id + exact byte/char coordinates + content hash (chunks banned as truth)
- Three layers: source artifact / evidence coordinates / interpreted knowledge

## KyzoOntology / OntologyPacks
- Domain concepts embedded as fixed anchors in the same vector space as records — turns similarity into classification
- Records arrive situated on four axes: structure, meaning, law, time — with zero model calls
- Packs are records, not files: provenance, version, authority, update cadence; upgrade is a typed diff
- Three flavors: **compiled** (transpiled from MeSH/SNOMED/ICD/GO), **authored** (operator overlay, sovereign over base), **mined** (repeated judgments become candidate rules)
- Layered composition: base under overlay, tombstones disable, collisions refuse, unfireable law refused at load with the offender named
- Every measurement stamped with the digest of the pack that took it
- The judgment ladder: structure → precedent → judgment primitive → agent → operator, each rung strictly cheaper
- Pack marketplace: standard packs, steward packs, community

## Storage
- fjall LSM (vendored, pure Rust, no C/C++)
- Memcomparable encoding — binary order equals semantic order for every type
- WAL as sole commit-order authority in the retained suffix
- Serializable transactions, SSI-class conflict detection
- Crash recovery on a real filesystem
- Hash-chained log — tear, reorder, and splice mechanically detectable across segment boundaries
- Replication
- Merkle verification walks
- Transcripts
- Sweep / GC with retention certificates
- Backup / export / restore — "leave is free"
- Crypto: encryption at rest by default, one path, no plaintext mode
- Capability grants
- Object store seam
- Scoped quarantine, poison fail-stop, typed failure lattice
- Compaction with deterministic pace from commit debt
- KV separation, tombstone ceilings, reclaimable-bytes bounds

## Operational surface
- Constraints: `::constraint_create` / `_drop` / `_list`
- Triggers: `::trigger_put` / `_replace` / `_rm` / `_relation` / `_show`
- Access levels
- `::running`, `::kill`
- `::compact`
- `::describe_relation`, `::list_relations`, `::list_columns`, `::list_fixed_rules`
- `::remove_relations`, `::rename_relations`
- Store health as queryable data on a sealed operator surface

## Standing queries / reactivity
- Standing queries
- Incremental view maintenance
- Residency and catalog-generation pinning (never durability)

## Hosts
- Embedded — a database is a file handle, SQLite-style
- Server
- REPL
- LSP server + VSCode extension
- Arrow interop
- Browser over OPFS *(planned)*
- Edge / Cloudflare Durable Objects *(planned)*
- WASM *(planned)*

## Ruled in `decisions.md`, not yet built
- Capability-based authority (#190) — replaces today's bind-address heuristic
- `WriteAuthority` as an affine signing capability; `StoreOpen` as TAG-ratcheted capability
- SweepDoor commit architecture: `IntentOrdinal` vs `CommitOrdinal`, `StableCommitCap` arms
- `IncarnationId`, pipelined `NonceLease`, `CheckpointSeal`
- Key-committing AEAD (CMT-1)
- Crypto-shred: `ShredSalt` / `WrappedShredSalt`
- FROST (RFC 9591) threshold recovery — `RecoveryMatrix`
- `ForkGrant` / `RecoveryGrant` / `EpochGrant` / `AncestorReadGrant`
- Zero-access sync — hosting operator cannot decrypt
- NATS federation: `AdmissionCertificate`, replica custody, `ReplicaKey`, anchored-sparse arrival
- Signed state-root heads, consistency proofs, split-view detection
- `ObjectSlot` / `ObjectRef`, staging TTL in commit ordinals, `ObjectDurabilityClass` with dominance-checked repair
- `CanonicalTranscript` with golden and negative test vectors
- RaBitQ as a `ProvenBound` accelerator over exact-float truth
- Cross-store composition: `BestEffort` / `Saga` / `ReadAt`, `CompositionId`, `OperationKey`
- Placement / residency policy enforcement
