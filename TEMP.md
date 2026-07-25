# TEMP — decisions.md salvage (staging, not the document)

Preserves the strengthening content added to `docs/decisions.md` after its initial commit, with status / planning / `[research-open]` / milestone language removed. New QAE triplets are kept as clean Q/A/E. Content additions are kept under the existing triplet they belong to. Nothing here is authored net-new; it is the salvage of what already strengthened the document.

---

## New QAE triplets (status/planning removed)

### Key-committing AEAD (CMT-1) — CanonicalTranscript commitment

- **Q:** How does Store close Partitioning-Oracle / two-key acceptance on misuse-resistant-but-not-key-committing AEAD arms — what exactly is bound into the commitment — which serialization path mints it — and what makes a hand-rolled commit-byte layout or CMTD-4 (nonce+aad+tag in C) Unconstructible?
- **A:** Every AEAD site declares **`KeyCommitment ∈ posture: on`** (per-site declaration; omission is not exclusion). On for all sites (encrypt path and shred-salt wrap). Construction is **CMT-1 key-commitment**, not CMTD-4: after base AEAD seal, append `C = H_canonical(KEY_COMMIT domain-label, key-id, CryptoDomain)` where `H_canonical` is SHA-256 over the sealed bytes of the ONE `CanonicalTranscript` constructor (`encode_key_commitment`: artifact kind KeyCommit, key-id as digest32, CryptoDomain as StoreId digest + FenceEpoch u64, domain-label `KEY_COMMIT`). The AEAD tag already binds nonce+aad+message; **C adds only the missing key-binding**. Open: verify base AEAD, then constant-time-compare presented `C`; mismatch → `Refuse(KeyCommitmentMismatch)` and **never release plaintext**. Hand-rolled layouts (`KEY_COMMIT_DOMAIN_v1 ‖ key ‖ nonce ‖ len‖aad ‖ tag`) and any second serialization path for C are **Unconstructible**. Golden vectors for `SealedArtifactKind::KeyCommit` are the proof — implementation matches vectors, never the reverse.
- **E:** Misuse-resistance ≠ key-commitment; without C, one (ct‖tag) can open under two keys (Partitioning Oracle / invisible salamanders). Binding nonce+aad+tag into C duplicates the AEAD tag and invents a second byte law. Soft "AEAD is enough" fails crypto-shred / wrapped-DEK / RecoveryQuorum key-material exposure. Proof: `gcm_arm_is_not_key_committing` opens under K1 and refuses under K2 through production `open_arm` with `KeyCommitmentMismatch`; KeyCommit golden vector pin; mutation campaign includes KeyCommit.

### Machine-checked protocol spec above the simulation layer — Quint + TLC/Apalache

- **Q:** Above the simulation layer, what language and checkers own the commit / recovery / epoch-advance / custody protocol models — what impl↔spec claim is deleted as Spec fraud — and what is the honest proof stack?
- **A:** Protocol specs above the simulation layer are authored in **Quint**. Model-check with **TLC + Apalache** — epoch / version / ordinal domains are Apalache's symbolic sweet spot; TLC remains the exhaustive finite-state checker for bounded interleavings. **Stateright** is named the Rust-native alternative when shortest spec↔impl distance outweighs Quint's checker ecosystem — never a silent second law; pick is per-protocol with the Quint path as default. A Spec or marketing claim of **machine-checked impl == spec refinement** (implementation proven equal to the model) is **Refused** — inflating "model green + tests green" into refinement is Spec fraud. The honest proof stack is: verified low-level Quint spec (TLC and/or Apalache green on named invariants) + generated conformance tests from the model + simulation campaigns + host-failure witness — no fourth organ pretending to close the refinement gap. Soft prose-only protocol and soft "model-check the code by staring" are deleted.
- **E:** Simulation alone cannot state the bounded-interleaving invariants the commit door claims; a second informal English protocol forks authority. Soft "we model-checked the impl" without a refinement proof is the exact fraud this triplet refuses.

### Decimal / BigInt tags — ELEN encoding; Num stays closed

- **Q:** When arbitrary-precision numeric kinds (Decimal, BigInt) earn Tag membership, which order-preserving byte scheme do those new tags adopt — may they extend the fixed-width `Num` layout — and is the existing `Num` identity-first NaN-collapse / `-0` normalize a defect against IEEE 754-2019 totalOrder payload fidelity?
- **A:** Future Decimal / BigInt Tag encodings adopt the **SQLite4 / CockroachDB `E(exp)` + base-100 self-terminating-mantissa** scheme — the production form of **ELEN section 7** (variable-length, lexicographic order equals numeric order, self-delimiting mantissa). They are **new Tag kinds** in reserved tag space with their own identity / order laws under the one-law frame. They are **not** an extension, widen, or second layout of the fixed-width `Num` key (`[class][exponent 2B][fraction 9B][repr]`): that byte layout is permanent FormatVersion law; inventing a "big Num" that reuses or stretches those fields is **Unconstructible**. The identity-first divergence is intentional: all NaN bit patterns collapse to one canonical NaN, `-0.0` → `+0.0` at construction, so no reviewer can "fix" `Num` toward strict totalOrder payload fidelity (distinct NaN payloads / signed zero as distinct stored identities).
- **E:** Soft "extend Num's fixed-width key for bigints" permanently forks the keyspace and breaks golden vectors. Soft inventing a home-grown variable-length numeric encode when SQLite4/Cockroach already ship the ELEN production form recreates a second order authority. Soft "fixing" NaN/`-0` toward strict IEEE totalOrder payload fidelity splits equal things under dedup.

### One-substrate join — Free-Join evaluator + live `seek`

- **Q:** What evaluator class makes graph=relational asymptotically optimal on cyclic queries (not merely expressible), what Store primitive that evaluator requires, and what CozoDB binary-join defect motivates the ruling?
- **A:** Target evaluator is **Free-Join-class** (unifies binary join + worst-case-optimal join). Pure WCOJ alone is **Refused** as the sole shape — it regresses acyclic plans. Live `seek(key)` on one positioned cursor is Store / `SkipCursor` law — production door is fjall `SeekIter` / `TrackedSeekIter` via `FjallSkipCursor::seek`. Drop-and-rebuild of a fixed-bound range as the *only* advance is **Unconstructible** as the join/scan advance law (backends may still open once via `open_skip_cursor`; thereafter advance is `seek`). CozoDB's binary-join tree is provably suboptimal on cyclic queries (AGM bound / triangle); graph=relational without WCOJ-class asymptotics is marketing. Both "binary-join-tree forever" and "WCOJ-only replaces the tree" are deleted.
- **E:** Soft "graph is relational because we can write paths in Datalog" without seek + WCOJ-class join leaves the AGM triangle as a permanent silent tax — thesis without theorem. Soft claiming AGM optimality without the planner and CI theorem is Spec fraud.

---

## Content additions to existing triplets

### → WriteAuthority / RecoveryMatrix triplet

- **Real threshold-crypto recovery quorum.** `RecoveryMatrix` seals a **FROST (RFC 9591) group verifying key** plus threshold metadata via the ZcashFoundation `frost-ed25519` reference impl — real threshold crypto, **never home-rolled** N-of-M ed25519 signature counting. `RecoveryQuorumProof` verifies **one aggregate** under the sealed group key over the predecessor `FenceEpoch`; below-threshold or wrong-share aggregates **refuse**; the signer subset is **not recoverable** from the proof bytes. FROST verify is strict by construction — `Ed25519Group::deserialize` rejects the identity element and every non-torsion-free point before a group key or signature can exist, so a degenerate-but-deserializable key + forged aggregate cannot reach a green verify the way small-order ed25519 keys could under a permissive `.verify`.
- **Gossip split-view detection.** A split-view / equivocating Store (divergent histories shown to two peers) is **Detected-on-gossip** via enforced signed-state-root-head (STH) gossip + consistency-proof checking on the NATS JetStream fabric (Certificate Transparency / RFC-6962 model) — **before the chains meet**; `SplitViewDetected` refuse. The soft "Unexposed-until-chains-meet" for that federation non-equivocation surface is deleted. (STH gossip detects lineage split-view, never AEAD keystream reuse.)

### → Chained state-root / replica-equivalence triplets

- **STH gossip non-equivocation.** Each commit tip (and as-of cut) yields a compact **state-root head**; consistency proofs over contiguous chain segments prove a newer head extends an older one (RFC-6962 analogue). Two peers' observed heads for one Store are cross-checked; same-ordinal divergent roots or a failing extension proof → **Detected-on-gossip** (`SplitViewDetected`) before the full chains meet. Peer-delivered roots stay non-authoritative for equivalence (recompute-and-compare still rules cut equality).

### → Custody / manifest-resolution triplet

- **Split-view in the closed refuse sum.** The manifest-resolution refuse sum gains `SplitViewDetected` and `SthConsistencyProofRequired` — no reshape. **STH gossip obligation (enforced):** origin publishes signed state-root heads to a NATS JetStream subject on a cadence; designated peers/auditors pull and cross-check with consistency proofs; carriage is fabric-only, never a peer-dial; the soft "Unexposed-until-chains-meet" is deleted.

### → Ordered store / Candidates triplet

- **RaBitQ accelerator with proven bound.** RaBitQ (Gao & Long, SIGMOD 2024) is the ruled vector accelerator — D-bit quantization whose Theorem 3.2 inner-product estimator is unbiased with a sharp **probabilistic** absolute error bound `P{|est−⟨o,q⟩| > bound(ε₀)} ≤ 2e^(−c₀ε₀²)`. Approximate seals that probabilistic bound (ε₀ / algorithm identity / build and query parameters) as typed provenance when one exists, else a benchmark-qualified identity — **never a per-query recall promise**, never absolute certainty at the paper-default ε₀. Exact float components remain authority and truth; the quantized code is accelerator only (candidate generation and bounded distance estimation — never a second vector identity).

### → CanonicalTranscript triplet

- **KeyCommit in the golden-vector set.** `SealedArtifactKind::KeyCommit` (CMT-1 key-commitment) is added to the in-repo golden-vector artifact list the CanonicalTranscript mutation campaign asserts against.

---

## THESE ARE OPEN

Two unresolved engineering questions. Not answered. Do not treat as settled.

### Open 1 — The one law: byte order == semantic order

- **Q:** For every stored value, lexicographic order of its privately-constructed canonical encoding must equal its semantic storage `Ord`, everywhere it is stored or compared, with no second encoder and no derive-bypass. Identify the architecture that makes byte-order ≠ semantic-order **unconstructible** — not fuzzed, not proven-and-caught, not one-authority-projected-twice, not reconciled by any campaign — a single storage-order authority where a disagreeing encoder has no constructor.

- **A (last submitted, still open):** The storage layer's ONLY comparand and ONLY encode-output is one opaque `OrderCode` newtype; storage keys, prefix comparison, and cross-kind ordering all operate on `OrderCode` bytes by memcmp — nothing else is ever compared or serialized for storage. `OrderCode` is minted ONLY by a closed monotone-shape algebra over one definitional atom (`u8` big-endian, memcmp == value by positional notation). `Tag` is absorbed as the mandatory leading `u8`-atom segment. No storage type carries its own `Ord` or byte-emitter; compile-time `assert_not_impl!` seals every storage-reachable type against `Ord`.

- **Surviving heresy (why it is still open):** `crates/kyzo-model/src/value/number.rs` — `impl Ord for Num` (line 458, structural via `sign_magnitude`) and `Num::encode_key` (line 193, hand-emits exp_key + frac72) are two independent order authorities for one value, reconciled only by `one_law_holds_at_int_float_boundary`. That is own-order + own-byte-emitter kept equal by a check, at the int/float boundary — the hardest case. The four-combinator algebra (`u8 atom + then + Reverse + tag segment`) does not make the IEEE-754 totalOrder float embedding monotone by construction; it is a nontrivial theorem. The second numeric authority is relocated, not dissolved.

### Open 2 — [one more — question text to be supplied by operator]
