# TEMP — open engineering questions

Two unresolved engineering questions. Not answered. Do not treat as settled.

## THESE ARE OPEN

### Open 1 — The one law: byte order == semantic order

- **Q:** For every stored value, lexicographic order of its privately-constructed canonical encoding must equal its semantic storage `Ord`, everywhere it is stored or compared, with no second encoder and no derive-bypass. Identify the architecture that makes byte-order ≠ semantic-order **unconstructible** — not fuzzed, not proven-and-caught, not one-authority-projected-twice, not reconciled by any campaign — a single storage-order authority where a disagreeing encoder has no constructor.

- **A (last submitted, still open):** The storage layer's ONLY comparand and ONLY encode-output is one opaque `OrderCode` newtype; storage keys, prefix comparison, and cross-kind ordering all operate on `OrderCode` bytes by memcmp — nothing else is ever compared or serialized for storage. `OrderCode` is minted ONLY by a closed monotone-shape algebra over one definitional atom (`u8` big-endian, memcmp == value by positional notation). `Tag` is absorbed as the mandatory leading `u8`-atom segment. No storage type carries its own `Ord` or byte-emitter; compile-time `assert_not_impl!` seals every storage-reachable type against `Ord`.

- **Surviving heresy (why it is still open):** `crates/kyzo-model/src/value/number.rs` — `impl Ord for Num` (line 458, structural via `sign_magnitude`) and `Num::encode_key` (line 193, hand-emits exp_key + frac72) are two independent order authorities for one value, reconciled only by `one_law_holds_at_int_float_boundary`. That is own-order + own-byte-emitter kept equal by a check, at the int/float boundary — the hardest case. The four-combinator algebra (`u8 atom + then + Reverse + tag segment`) does not make the IEEE-754 totalOrder float embedding monotone by construction; it is a nontrivial theorem. The second numeric authority is relocated, not dissolved.

### Open 2 — [one more — question text to be supplied by operator]
