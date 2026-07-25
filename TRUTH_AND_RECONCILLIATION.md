# TRUTH AND RECONCILLIATION — what bs-detector actually is

## The law

A max-purity Rust program is made of a closed set of constructs. Anything not in that set is red. The detector does not hunt bad patterns; it enumerates the only shapes that may exist and refuses everything else.

The set is app-independent. It is the same list for a database and a payment processor. Purity is a property of the type discipline, not of the domain.

## The two rules — this is the entire detector

1. **Totality.** Every item under `crates/` classifies as exactly one construct in the closed set, or it is red. Already built as `unclassified-*`. It is the whole gate.
2. **Interior discipline.** Each construct declares what may not appear inside its cell. A construct that cannot refuse anything inside itself is vacuous and is refused at load.

Nothing else is the detector. `laws.toml`'s 91 entries are the coverage receipt for the retired 46-check gate — a receipt, not law.

## The closed set

Exists:

1. Newtypes over primitives — no bare `String`/`u64`/`bool`/`usize` crosses a boundary
2. Closed sums — every variant reachable, no catch-all arm, no `#[non_exhaustive]`
3. Sealed structs — private fields, no public field access, no `Default`
4. Smart constructors — `Result<Self, TypedRefusal>`, the only way in
5. Typestate — distinct types for distinct states
6. Consuming verbs — `self` by value where an operation spends something
7. Capability tokens — unforgeable, affine, passed as arguments, never ambient
8. Closed typed-refusal enums — one per door
9. Sealed traits — boundaries, not extension points
10. Lifetime/brand confinement — a handle cannot escape its scope

Does not exist, anywhere, ever:

`unwrap` / `expect` / panic on a reachable path · `bool` as a mode · `Option` as "not initialized" · primitive fields on domain types · validate / check / verify / is_valid functions · a public constructor that just takes the fields · `impl Default` on a domain type · catch-all arms · `#[allow(…)]` · mutable globals · downcasting · getters and setters · any two functions that must be called in order without the type enforcing it

## No waivers

The waiver concept is deleted. The question is never "is this instance justified here" — that is matching code. It is "is this a max-purity shape." If it is not, it is red, and it stays red until the code changes.

Delete: `waiver.rs`, `citation.rs`, `waivers.toml`, `attestation_template.toml`, the `kyzo-waiver` agent, and the `stale_waivers` / `dead_citation` / `attestation_form` checks. `bans` and `bans_absolute` collapse into one list. `identity.rs` stays — `site_hash` pins `declared-fn` bodies.

Every case that looked like it needed a waiver is a missing type. 36 `hand_layout` digests want a `KdfDomain` type. 108 `copy_detector` hits want one function or two real types. `unwrap` on an unreachable path wants the path to be unrepresentable. None wanted an exception; all wanted the work.

## One source

The law is currently stated three times — the rust skills (~2000 lines, six success/failure pairs), the 14 zone rules, and `grammar.toml`. Three hand-maintained copies drift; drift between the zone rules and the template plan is already proven.

The skills are the best-written and already state the closed set: *"the five proven shapes for a kyzo domain fact — newtype scalar, value object, concept struct, proven collection, sum type — the only representations for data inside the engine."*

`grammar.toml` is generated from the skills. The zone rules are generated from the skills. Hand-editing a generated copy is red.

## Open — do not close these by argument

1. **`.cursor/rules/` is empty.** Cursor writes every line of engine code and receives zero path-loaded rules. The pre-write mechanism does not exist for the team that writes.
2. **Cursor has 12 of 30 skills.** Missing `kyzo-architecture-standards`, `anti-sabotage-mode`, `ontology-first-construction`, `name-and-seat-construct`, `closure-check`, `rtfm`, `approved-testing-policy`. The developers do not have the standard they are judged against.
3. **Soft verbs inside the success skills.** `rust-state-success:43` "legal only where genuine shared/concurrent access is a real requirement … escalate only with a stated concurrency need"; `rust-order-success:52` "prefer not implementing `Hash`"; `rust-adapters-success:53` "expected to sometimes legitimately fail." Unfalsifiable judgment calls inside a closed inventory — the waiver concept with no ledger and no judge.
4. **The detector has one opinion about types and it is about strings.** 16 structural rules, all syntactic. `String`/`str` are the only banned terminals. `u64`, `bool`, `usize`, `Vec<u8>`, `Option<T>` are unjudged, so a primitive-obsessed struct with a rubber-stamp constructor passes green.
5. **`run.rs:120` `waivable()` tails at `true`.** Default open. Dies with the waiver system.
6. **`module` is the only container kind with no `interiors-classify`.** `impl-container` and `trait-container` have it. `module` has `bans = []`. Its deny-exemption is already stripped and the detector will not load until the seat can refuse something.
7. **No jurisdiction over comments.** 495 contract-law lines sit in `//` where nothing reads them. Doc comments are tokens and are unexamined.

## Rules of engagement

- Partially done is not a thing. Done or not done.
- A blessing that is wrong fails loud. A waiver that is wrong fails silent. This is why there are no waivers.
- The gate going red is the correct outcome. Baseline is zero, forever. There is no goal to be green before the detector is finished.
- Detecting more is never a cost. Any argument that a check is "too strict" is the defect.
- No item here is closed by explanation. It is closed by a construct that makes the illegal state unbuildable.
