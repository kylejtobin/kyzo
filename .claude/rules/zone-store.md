---
paths:
  - "crates/kyzo-core/src/store/**/*.rs"
---

# Zone: Store — fact persistence

The one substrate: ordered keys, transactions, time in the key, crash safety.

## Required

- Everything transactional: no write path outside a transaction; commits are
  consuming (the type is spent); conflicts are typed values.
- Keys are memcomparable-ordered; time lives in the key per the bitemporal law
  (one fact key answers a two-axis question).
- Species invariants held by TYPES: a reader cannot write; never move an
  invariant down the enforcement ladder to runtime checks or convention.
- A cursor's validity is tied by type to the snapshot or transaction it was
  opened against; a cursor escaping its snapshot is a borrow-check error, not a
  runtime guard.
- Every acquired resource — open cursor, lock, scratch store, live transaction
  — releases through `Drop` bound to its scope; an unfinished protocol whose
  silent drop would corrupt an invariant is a drop-bomb (a safe terminal
  default or a named panic), never a forgettable call site.
- Any input from disk decodes to typed refusal on corruption — no panic on any
  byte sequence.
- The skip-scan walk has ONE implementation, generic over its driver.
- The state root is deterministic over the ordered keyspace.
- Commit survives a process crash; durable commit survives a power cut —
  both proven, never assumed.
- The commit clock is a monotone watermark, and stamp minting takes the open
  snapshot as an argument so mint-before-snapshot is unrepresentable.
- Any non-value serialization boundary (catalog metadata, manifests) is a
  single ruled door: config only, never a value, its own FormatVersion,
  typed corruption behavior. "Metadata only" is never an argument for a
  second value authority.
- The store owns the portable dump/load FORMAT only; replication is
  NATS/JetStream replay of the ordered write log against engine determinism —
  provably-equal replicas, never a replicator written in this zone.
- Commit door is SweepDoor: IntentOrdinal orders contenders (may gap);
  CommitOrdinal is dense history assigned only at the durable event.
- WriteAuthority signs; IncarnationId separates write-session nonce space;
  NonceLease is pipelined (durable before ciphertext).
- Sealed artifacts use one CanonicalTranscript; AdmissionCertificate /
  AcceptedReplica verify — never reshape origin-cut meaning.
- ObjectDurabilityClass is a product under dominance; Repair/Downgrade typed.
- Claim tags: Unconstructible / Refused / Unexposed — never soft folklore.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Bytes and commit doors only. Decode yields storage currency, never `KyzoRecord`. Species by types.

## Forbidden

- Interpreting values beyond their order (the store consumes canonical bytes;
  meaning lives in the model).
- A second storage backend without an operator ruling plus conformance-kit
  passage — never as a convenience.
- C/C++ anywhere in the dependency tree.
- Nondeterministic iteration or timing-dependent behavior on any path that
  affects committed state.
- Minting history at admission; encrypting under a volatile NonceLease;
  in-place reinterpretation of a certified replica record.

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
| `sweep_door` | I T C S V R X | consuming Committed; Intent≠Commit CLAIM | Record mint |
| `wal_format` | I T C D S V R X | hash chain; total replay | Record mint |
| `write_authority` | I T C S V R X | affine WA; claim tags | eval |
| `store_open` | I T C V R X | private StoreOpen; path-only success Unconstructible | |
| `object_slot` | I T C S V R X | Pending/Durable; StagingTTL in CommitOrdinal | wall-clock expiry |
| `crypto_pipeline` | I T C V R X | KeyCommit via CanonicalTranscript | plaintext mode |
| `replica_cert` | I T C D V R X | verify→custody; no reshape | |
| `nonce_lease` | I T C S V R X | reserve-before-encrypt | volatile reserve |
| `seal_checkpoint` | I T C V R X | truncate consumes seal | |
| `order_keys` | I T C O D R X | ORDER_LAW; two-axis keys | |
| `commit_cap` | I T C V R X | SnapshotFork declared | |
| `store_grants` | I T C V R X | materialize pure/idempotent | |
| `store_epoch` | I T C V R X | CryptoDomain | |
| `store_refuse` | I T R X | closed lattice | LKG serve |
| `store_driver` | I T S V R X | adapter only | product telos |
| `compact_policy` | I T C V R X | MergeProof; pace=f(debt) | wall-clock pace |
| `skip_walk` | I T S V R X | live seek | drop+rebuild-only |
| `write_tx` | I T S V R X | species; consuming commit | |
| `transcript_format` | I T C D R X | goldens; second path Unconstructible | |
| `backup_restore` | I T C V R X | leave-is-free; no WA in packs | |
| `idempotency_memo` | I T C V R X | OperationOutcome | |
| `store_contract` | I T V R X | trait boundary | |

This table is total; not listed = red.

### Dominant skeleton

```rust
//! AUTHORITY: SweepDoor commit history
//! SEAT: zone-store/sweep
//! FILE_KIND: sweep_door

// --- zone-file:imports ---
// --- zone-file:types ---
// CONSTRUCT: sealed-struct SweepDoor
// CLAIM: Unconstructible — timer coalesce / early ack / volatile NonceLease
// --- zone-file:construction ---
// --- zone-file:state ---
// --- zone-file:verbs ---
// CONSTRUCT: consuming-verb commit
// --- zone-file:refusals ---
// --- zone-file:tests ---
```

## Dual-authority debt

| path | fused |
| --- | --- |
| `authority.rs` | WA + Incarnation + RecoveryMatrix + fence |
| `sweep.rs` | SweepDoor + IntentionQueue + ordinals + Committed |
| `wal.rs` | segment + replay + floors |
| `seal.rs` | CheckpointSeal + truncate + verify |
| `epoch.rs` | FenceEpoch + CryptoDomain + EpochGrant + IntentClear |
| `failure.rs` | StoreRefuse + lattice + debt + operator surface |
| `objects.rs` | ObjectSlot + staging + permanence + GC |
| `commit_cap.rs` | StableCommitCap + SnapshotFork + witness |
| `grants.rs` | Fork/Recovery materialize + AncestorReadGrant |
| `replica.rs` | AdmissionCertificate + verify + ReplicaCustody |
| `nonce.rs` | NonceLease + MintDomain + DomainCounter + pure fn |
| `compact.rs` | pace + MergeProof + classifier |

This table is total for named duals in this zone; not listed here may still be dual in `path-kinds.csv`.

