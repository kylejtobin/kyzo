# Plan

## Cold start — read this before anything else

### The stance

You are not the judge. Verus is. Your job is to put every piece of work somewhere
that can contradict you, then go where the contradiction points.

This works. It produced, in one session: a 1,783-line hand-written encoder deleted,
165 machine-checked theorems in its place, 80,348 adversarial checks passing, and
three real defects nobody knew about — a JSON object-key ambiguity that returns a
wrong answer silently, an Interval upper bound where +∞ sorts below every finite
value, and `DataValue::cmp` being a mirror of the bytes it is supposed to check.
None of those came from reading the code. All three came from an obligation
refusing to close.

Move fast and delete hard. The work is not fragile. You have a verifier; use it as
a probe, not just a gate. Try the aggressive version first — it either verifies or
tells you exactly why not, and "why not" is usually the design answer.

### Four rules, in order of power

1. **Put the work where it fails loudly and early.** Structural, not motivational.
   Never in the scratchpad. Never behind a summary.
2. **Delete first, and let the gate go red.** Nothing is built beside the thing it
   replaces — if both exist at once there is a moment where it verifies with the old
   one present, and that moment is where the old one survives. Red is the forcing
   function, not a problem to route around. Callers breaking is correct; they were
   eating a door that shouldn't exist.
3. **The oracle exists before the work starts.** If you cannot state what would
   prove you wrong, you are about to layer on.
4. **Transcribe nothing.** The spec is TCB. A proof of a copied spec launders the
   copy into authority — strictly worse than no proof. Derive from what the thing
   *is*, not from what the old code did. Reading `DataValue::cmp` to decide new
   bytes is still transcription, one remove out.

### Your failure signature

One shape, every time: **you reach for the move that looks like progress and defer
the thing that can fail.** Tells, all observed:

- About to work in the scratchpad → you are avoiding the tree.
- Writing "found", "fixed", "previously", "we changed" in a comment → that is a
  commit message. Comments are specification: what is true now, for someone about
  to change the code.
- About to say "this needs a decision/ruling" → check whether there is actually
  only one correct answer. If there is, decide it.
- Fixing two bugs instead of doing the deletion you were told to do → substitution.
- Adding one case per kind → the cases are values of a smaller algebra. Find the
  composition; check whether you already proved the composition theorem.
- A proof flips red on an unrelated edit → it is a duplicate of something. Fragility
  clusters where two implementations of one idea exist. Do not add triggers four
  times like you did.
- Writing a recap instead of doing the next thing → stop and do the next thing.

Kyle caught most of these, not you. Two questions with no good evasion, ask them of
yourself at every boundary: **"Is this different from the code we had before?"** and
**"Did you build that by reading the old code?"**

### How to answer

High-signal, low-hedge, imperative, specific. Yes/no questions get yes or no —
then at most two sentences, and only if a distinction changes what happens next.
No performance, no ritual self-criticism, no dressing up a miss. Say the thing
plainly and keep moving. Do the work inside the assigned scope without asking; ask
only when the answer changes the scope.

### Machine facts

```
verus     /home/kyle/.local/verus/verus-x86-linux/verus   (0.2026.07.18, Z3 4.12.5)
toolchain rust 1.96.0 (required by Verus)
gate      ./xtask/verify-canonical.sh          -> "165 verified, 0 errors"
trials    cargo run -p canonical-trials        -> "all 80348 checks passed"
target    export CARGO_TARGET_DIR=<private dir>  (cannot write ./target)
```

- `vstd = "=0.0.0-2026-07-12-0122"` is a normal cargo dependency. Plain `cargo build`
  erases the ghost code; the binary is ordinary Rust. `crates/kyzo-model/build.rs`
  declares the `verus_*` cfgs.
- `cargo verus verify` is broken here (published vstd vs release binary skew). Use
  `verus --crate-type=lib <file> --triggers-mode silent` directly. That is what the
  gate script does.
- **The `GATE ALARM: 46018 violations` hook is stale.** `bs-detector/src/main.rs` is
  deleted; that number cannot have been recomputed. Ignore it. It is the argument
  against scores, arriving on cue.

### Standing orders

- Do not edit `decisions.md` without explicit permission.
- Do not touch the on/off switch in `crates/bs-detector/pester-hook.txt`.
- `crates/bs-detector/` is BSL-1.1. No MPL headers there.
- Deletes mean deletes. Rebuilding while deleting is a violation of orders.

### What is true right now

- `crates/kyzo-model/src/value/canonical.rs` — 165 theorems, green. HEAD `06d7c8c7`.
- `kyzo-model` **does not compile**: 16 call sites import `encode`, `encode_owned`,
  `decode`, `decode_one`, `skip_one`, `append_canonical`, `Datum`, `DecodeError`,
  `prefix4` — all deleted, no shim. They need a verified decoder, which does not exist.
- Open, from your own list: `Set` ordering is still not enforced by the encoder;
  `json_storage_cmp` is unread; `DataValue::cmp` is still the circular mirror.
- Next work is the Shape rewrite below. Start at step 1 and do not ask first.

## What We've Been Doing And Learned
## What we started doing

We stopped asserting the order law and started discharging it. Surface change: 1,783 hand-written lines out, Verus in, Z3 as the judge. Real change: **the acceptance criterion moved outside my judgment.**

## What I was failing at

Specifically, not vaguely:

- **I added types on top of untyped foundations.** Types compile whether or not they mean anything, so a newtype always *looked* like progress. Three rounds of decoration.
- **I counted instead of fixing.** 46,018 — a number nobody can act on, that never moved, and that is still firing stale in this conversation from a deleted binary.
- **I produced categories, not defects.** bs-detector classified shapes. It never once produced an input that returns a wrong answer.
- **My meter was a proxy I controlled.** "Does this resemble one of thirteen constructs" is arguable. I could always win the argument.
- **I kept the old thing while adding the new thing.** That is the entire mechanism of layering, and I did it every round.

## What's better, and why

The verifier can contradict me. That's it. Not focus, not caring more — I had the same intent in the rounds that produced sludge.

Three consequences that matter:

**Failure became located.** "`lemma_json_obj_of_pairs` won't close at `k[0] != STRUCT_END`" is a coordinate. I had *read that file's format header earlier the same session* and not seen the bug. Reading doesn't find these; a refused obligation does.

**Stubs stopped being possible.** `#[verifier::type_invariant]` doesn't compile unless every constructor establishes it.

**Deletion became mandatory.** You can't half-delete and still get `0 errors`. The old encoder wasn't incrementally salvageable, so the option that ruined every prior round was removed for me.

And the thing I didn't expect: **proving kept finding the design.** The object-key ambiguity, the Interval `Hi` marker, `DataValue::cmp` being circular — none came from reading. They came from having to state something precisely enough to prove, and watching it refuse.

## How I avoid the failure modes

My drift has exactly one shape: **I reach for the move that looks like progress and defer the thing that can fail.** Every slip tonight was that — scratchpad instead of the tree, changelog comment instead of specification, the FormatVersion hedge instead of a decision, finding two bugs instead of deleting the table you told me to delete.

What actually works, in order of power:

1. **Put the work where it fails loudly and early.** Structural, not motivational.
2. **Delete first.** If the old thing survives the round, I will build on it.
3. **The oracle exists before the work starts.** If I can't say what would prove me wrong, I'm about to layer.
4. **Transcribe nothing.** The spec is TCB. A proof of a copied spec launders the copy into authority — that's strictly worse than no proof.

Honest limit: the drift-catching tonight was mostly *yours*. "Is this different than the code we had before?" and "did you build that by reading the old code?" have no good evasion, and I didn't ask them of myself. The fix isn't me promising vigilance — it's making drift cost something immediately.

## How I got to Shape

Not cleverness. **I read repetition as a signal instead of as work.**

Three tells, all of which I'd been staring at:

- The same two proofs flipped four separate times, and *only* those two.
- I had proven `lemma_concat_order` and never used it in the format layer.
- `EscapedThenFlags` is literally `Product(Escaped, Fixed(1))` and I made it a new enum variant.

Two rules generalize out of that:

**When a proof is fragile, ask what it's a duplicate of.** Fragility clusters where two implementations of one idea exist — duplicated proofs re-derive the same quantifier structure and nobody keeps the copy clean. The flipping was a duplication detector. I read it as "needs triggers" four times.

**When the case list grows once per kind, the cases are values of a smaller algebra.** Eight shapes each needing their own lemma means the shapes aren't primitive. Find the composition — then check whether you already proved the composition theorem. I had, and hadn't used it.

Recipe: *repetition + fragility + an unused general theorem = you built the special cases of something you already own.*

---

Still open, so the arc isn't a success story yet: `Shape` isn't built, `kyzo-model` doesn't compile, the decoder doesn't exist, and `DataValue::cmp` is still a mirror of the bytes it's supposed to check.

## How Shape is built at max purity

The whole game is two structural predicates. Everything else falls out.

```rust
// CONSTRUCT: ClosedSum Shape
pub enum Shape {
    Fixed(nat),                        // n payload bytes
    Delimited,                         // escaped, 0x00 0x00 terminated
    Product(Box<Shape>, Box<Shape>),
    Sum(Map<u8, Shape>),               // one lead byte selects
    Row(Box<Shape>),                   // elements, STRUCT_END terminated
}

pub open spec fn shape_end(s: Shape, p: Seq<u8>) -> int   // ONE recursive reader
```

**Predicate 1 — self-delimiting.** `Fixed` and `Delimited` are; `Product(a,b)` is iff both are; `Sum` is iff every branch is; `Row` always is.

**Predicate 2 — lead byte above the terminator.** Needed only where a reader decides "element or terminator": `Row`'s element shape, and every `Sum` key.

```rust
pub open spec fn wf(s: Shape) -> bool   // conjunction of the two, structurally
```

Then **one** locality lemma by structural induction on `Shape`:

```rust
proof fn lemma_shape_local(s: Shape, a: Seq<u8>, b: Seq<u8>)
    requires wf(s), is_prefix(a, b), 0 <= shape_end(s, a) <= a.len()
    ensures shape_end(s, b) == shape_end(s, a)
```

Its `Product` case **is `lemma_concat_order`** — already proven, finally used. Its `Delimited` case is `lemma_esc_end_local` — already proven. `Fixed` is trivial. `Sum` and `Row` are one step each.

`Shape` carries `wf` as a type invariant with private constructors, so an ill-formed grammar is unconstructible rather than refused. `GrammarLaws` stops being a marker and becomes the grammar itself.

## What that deletes in canonical.rs

The entire grammar becomes **one `Shape` value**, and `scan(p) = shape_end(GRAMMAR, p)`.

- `shape_of`, the eight-arm `key_end`, `lemma_kind_local`'s eight-arm match → one function, one lemma
- `esc_end`, `num_end`, `interval_end`, `lo_bound_end`, `hi_bound_end` → `Delimited`, `Sum{0x01→Fixed(13), 0x02→Fixed(2), 0x03→Fixed(13)}`, `Sum{...}` — **data, not code**
- `class_led_width`, `lemma_num_end_local`, `lemma_interval_end_local` → gone
- Seven `KindKey` mints → one `ShapedKey`
- `scan_num`, `scan_interval`, `lo_end`, `hi_end`, `scan_escaped` → one `shape_scan`

**JSON becomes a sub-map of the same `Sum`.** Not a parallel grammar — the same grammar restricted to `{Null, Bool, Num, Str, List, Map}`. That deletes `json_end`, `json_arr`, `json_obj`, their three locality lemmas, `lemma_json_arr_of_row`, `lemma_json_obj_of_pairs`, `JsonValueBytes` and its six builders, `scan_json`/`_arr`/`_obj`, and the `JSTR`-marker special case (an object is a `Row(Product(Str, Value))` and Str already opens with `0x18`). **Every proof that flipped tonight is in that list.**

`SeqTag` splits into `ListTag`/`SetTag` — different mints, different input types, no validator.

Rough shape of it: ~1,400 lines out, ~400 in.

## Where it reaches outward

A `Shape` is a self-delimiting, order-preserving binary grammar. The program lays bytes down that way in more places than the value plane:

| site                                     | today                                                                            | becomes                      |
| ---------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------- |
| storage key layout                       | hand-rolled relation-id + tuple + version                                        | `Product(Fixed, Row, Fixed)` |
| bitemporal version keys                  | hand-rolled descending 8 bytes                                                   | `Fixed(8)`                   |
| WAL / hash-chained log framing           | hand-rolled framing                                                              | `Row(Product(...))`          |
| `CanonicalTranscript`                    | a **second** encoding checklist with its own golden vectors (zone-model says so) | Shapes                       |
| index key layouts (vector, FTS, spatial) | hand-rolled per index                                                            | Shapes                       |
| `prefix4`, `skip_one`, `decode_one`      | scattered key-walking helpers                                                    | one `shape_end` cursor       |

`CanonicalTranscript` is the sharpest: the zone rules *document* it as a separate byte authority with its own checklist. That's a declared second authority for exactly this problem.

And it closes the circularity: with one `Shape` and one reader, `DataValue::cmp` is *defined* as comparing encodings, and the hand-written 60-line mirror — the thing that hid the Interval bug — deletes.

## Order: demolition first

Nothing is built beside something it replaces. If both grammars are in the file at
once there is a moment where it verifies with the old one still present, and that
moment is where the old one survives. The gate goes red and stays red until the
replacement lands. Red is the forcing function; it is not a problem to route around.

1. **Delete the JSON layer.** `json_end`, `json_arr`, `json_obj`, their three
   locality lemmas, `lemma_json_arr_of_row`, `lemma_json_obj_of_pairs`,
   `JsonValueBytes` and its six builders, `scan_json`/`_arr`/`_obj`, the `JSTR`
   key marker, `JsonKey`. This needs no `Shape` — an object is a `Row` of
   (Str, value) and the existing `scan_row_bytes` already reads that. Biggest
   single deletion, kills every proof that flipped.
2. **Delete the format layer.** `shape_of`, the eight-arm `key_end`,
   `lemma_kind_local`'s eight arms, `esc_end`/`num_end`/`interval_end`/
   `lo_bound_end`/`hi_bound_end`, `class_led_width`, the per-shape locality lemmas,
   all seven `KindKey` mints, `scan_num`/`scan_interval`/`lo_end`/`hi_end`/
   `scan_escaped`. The file is now red and holds only the proof machinery:
   `lex_le`, `lemma_concat_order`, `theorem_prefix_code`, the escape layer, the
   row layer, `theorem_value_order`.
3. **Build `Shape` + `wf` + `shape_end` + one locality lemma + one prefix-code
   theorem.** If the `Product` case does not fall straight out of
   `lemma_concat_order`, the algebra is wrong, not the proof.
4. **The grammar as one `Shape` constant**, JSON a restriction of it, one
   `ShapedKey`, one `shape_scan`. Gate returns to green.
5. `ListTag`/`SetTag` split.
6. `DataValue::cmp` defined from bytes; delete the 60-line mirror. This is where
   the second authority dies.
7. Outward: store key layout, WAL framing, transcript.

Start at 1. Do not ask first, and do not build anything until 1 and 2 are done.