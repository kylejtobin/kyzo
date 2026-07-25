# TEMP — what did not land in `docs/decisions.md`

The seven ruled items (A1, A2, B1–B5) are landed. This file now holds only three things: what is **quarantined**, what is **parked on a dependency**, and what is **open**. Nothing here is settled.

---

## QUARANTINED — claim inflation, do not reintegrate as written

Both clauses claim gossip **deletes** an honest `Unexposed`. It does not. STH gossip adds earlier detection for a Store whose heads are observed; a partitioned holder that gossips to nobody keeps the residual, and gossip never reaches the AEAD half at all. The honest form landed in seat 2 as a *narrowing*, and in seats 56/58 as detection.

Verified by full-text sweep of the pre-trim salvage (`87087952:TEMP.md`): **exactly two clauses**, not "several."

1. **B1 gossip half** — verbatim: *"The soft 'Unexposed-until-chains-meet' for that federation non-equivocation surface is deleted."*
2. **B3 custody half** — verbatim: *"the soft 'Unexposed-until-chains-meet' is deleted."*

The rest of B1's gossip paragraph was **dropped, not quarantined**: it restated the same mechanism already seated at 56/58, which would have put three copies of "STH gossip exists" across seats 2, 56/58, and 69. Seat 56/58 owns the mechanism; seat 2 carries one narrowing sentence.

**The inflation is also in engine code, not only in this file.** `crates/kyzo-core/src/store/replica.rs:37` bans *"leaving federation non-equivocation Unexposed-until-chains-meet"* in its module law — i.e. the engine currently treats the honest tag as the error. That is a contract for the dev team, not a doc edit.

---

## PARKED — blocked on a dependency, not ruled

### A3 — Decimal / BigInt tags; ELEN encoding — **blocked on Open 1**

Rests on the `Num` byte layout, which is the surviving heresy in Open 1. Its internal picks are sound; it cannot be seated on an open foundation. It is an addition to an unruled seat, not a new seat.

- **Q:** When arbitrary-precision numeric kinds (Decimal, BigInt) earn Tag membership, which order-preserving byte scheme do those new tags adopt — may they extend the fixed-width `Num` layout — and is the existing `Num` identity-first NaN-collapse / `-0` normalize a defect against IEEE 754-2019 totalOrder payload fidelity?
- **A:** Future Decimal / BigInt Tag encodings adopt the **SQLite4 / CockroachDB `E(exp)` + base-100 self-terminating-mantissa** scheme — the production form of **ELEN section 7** (variable-length, lexicographic order equals numeric order, self-delimiting mantissa). They are **new Tag kinds** in reserved tag space with their own identity / order laws under the one-law frame. They are **not** an extension, widen, or second layout of the fixed-width `Num` key (`[class][exponent 2B][fraction 9B][repr]`): that byte layout is permanent FormatVersion law; inventing a "big Num" that reuses or stretches those fields is **Unconstructible**. The identity-first divergence is intentional: all NaN bit patterns collapse to one canonical NaN, `-0.0` → `+0.0` at construction, so no reviewer can "fix" `Num` toward strict totalOrder payload fidelity (distinct NaN payloads / signed zero as distinct stored identities).
- **E:** Soft "extend Num's fixed-width key for bigints" permanently forks the keyspace and breaks golden vectors. Soft inventing a home-grown variable-length numeric encode when SQLite4/Cockroach already ship the ELEN production form recreates a second order authority. Soft "fixing" NaN/`-0` toward strict IEEE totalOrder payload fidelity splits equal things under dedup.

### A4 — One-substrate join: Free-Join evaluator + live `seek` — **split verdict**

The **live-`seek` half is a valid storage seat** (cursor-advance law, near seat 48) and can be seated once written as one. The **Free-Join / WCOJ half is out of scope** for this document — `decisions.md` is *Storage Decisions*, and query-engine evaluator class is not a Store seat. It needs its own document, not a landing here.

- **Q:** What evaluator class makes graph=relational asymptotically optimal on cyclic queries (not merely expressible), what Store primitive that evaluator requires, and what CozoDB binary-join defect motivates the ruling?
- **A:** Target evaluator is **Free-Join-class** (unifies binary join + worst-case-optimal join). Pure WCOJ alone is **Refused** as the sole shape — it regresses acyclic plans. Live `seek(key)` on one positioned cursor is Store / `SkipCursor` law — production door is fjall `SeekIter` / `TrackedSeekIter` via `FjallSkipCursor::seek`. Drop-and-rebuild of a fixed-bound range as the *only* advance is **Unconstructible** as the join/scan advance law (backends may still open once via `open_skip_cursor`; thereafter advance is `seek`). CozoDB's binary-join tree is provably suboptimal on cyclic queries (AGM bound / triangle); graph=relational without WCOJ-class asymptotics is marketing. Both "binary-join-tree forever" and "WCOJ-only replaces the tree" are deleted.
- **E:** Soft "graph is relational because we can write paths in Datalog" without seek + WCOJ-class join leaves the AGM triangle as a permanent silent tax — thesis without theorem. Soft claiming AGM optimality without the planner and CI theorem is Spec fraud.

---

## THESE ARE OPEN

Two unresolved engineering questions. Not answered. Do not treat as settled.

### Open 1 — The one law: byte order == semantic order

- **Q:** For every stored value, lexicographic order of its privately-constructed canonical encoding must equal its semantic storage `Ord`, everywhere it is stored or compared, with no second encoder and no derive-bypass. Identify the architecture that makes byte-order ≠ semantic-order **unconstructible** — not fuzzed, not proven-and-caught, not one-authority-projected-twice, not reconciled by any campaign — a single storage-order authority where a disagreeing encoder has no constructor.

- **A (last submitted, still open):** The storage layer's ONLY comparand and ONLY encode-output is one opaque `OrderCode` newtype; storage keys, prefix comparison, and cross-kind ordering all operate on `OrderCode` bytes by memcmp — nothing else is ever compared or serialized for storage. `OrderCode` is minted ONLY by a closed monotone-shape algebra over one definitional atom (`u8` big-endian, memcmp == value by positional notation). `Tag` is absorbed as the mandatory leading `u8`-atom segment. No storage type carries its own `Ord` or byte-emitter; compile-time `assert_not_impl!` seals every storage-reachable type against `Ord`.

- **Surviving heresy (why it is still open):** `crates/kyzo-model/src/value/number.rs` — `impl Ord for Num` (line 458, structural via `sign_magnitude`) and `Num::encode_key` (line 193, hand-emits exp_key + frac72) are two independent order authorities for one value, reconciled only by `one_law_holds_at_int_float_boundary`. That is own-order + own-byte-emitter kept equal by a check, at the int/float boundary — the hardest case. The four-combinator algebra (`u8 atom + then + Reverse + tag segment`) does not make the IEEE-754 totalOrder float embedding monotone by construction; it is a nontrivial theorem. The second numeric authority is relocated, not dissolved.

### Open 2 — [one more — question text to be supplied by operator]
