# bs-detector

Refuses the fifteen forbidden shapes.

A blacklist, not a whitelist. It does not decide what good code is — it names
shapes that are wrong every time, and counts them.

## The one design constraint

**Every rule is decidable from syntax alone.** No type resolution, no macro
expansion, no call graph.

That constraint is the lesson from the machine this replaces. It hand-rolled
tree-walking and type resolution, and 68% of its reported number was
`unproven receiver` (19,743), `unproven macro` (6,799), `unproven path` (3,084)
and `unproven foreign` (1,641) — a parser without types reporting its own
blindness as findings about the tree. Its count could not move, so nobody acted
on it.

**Every rule is also absolute, and every rule has the same scope.** "unwrap on
input-reachable paths" is undecidable; "no unwrap" is trivial. The moment a rule
needs a clause like "…where a domain fact belongs", or its own list of exempt
files, it stops being absolute and does not belong here. Rules that need
judgment are enforced by review.

**One scope: all of `crates/`, or the single path you aim at.** No rule carries
a private carve-out — not for tests, not for vendored data, not for the crate
the rule is inconvenient in. `#![forbid(unsafe_code)]` in a lib root does not
reach that crate's `tests/` directory, and that is exactly the kind of gap a
per-rule exemption hides.

This is the floor, not the ceiling. It catches shapes. It cannot catch a runtime
check that should have been a constructor, an `Option` standing for meaningful
absence, or two types carrying one fact under different field names. Those cost
more, and only a reader finds them.

## The fifteen

| | forbidden |
| --- | --- |
| R01 | `Ord`/`PartialOrd`/`Hash` with no `ORDER_LAW` stated in the file |
| R02 | `pub` field on a newtype, or a public unchecked constructor |
| R03 | bare `Vec`/`HashMap`/`HashSet` as a `pub` field |
| R04 | `unwrap`/`expect`/`panic!` |
| R05 | `String`-typed error, or a refusal carrying no span |
| R06 | `todo!`/`unimplemented!`/`unreachable!` stub |
| R07 | `env::var` read outside the composition root |
| R08 | `String`-typed `kind`/`status`/`type`/`name` field |
| R09 | `bool` field carrying a domain decision |
| R10 | bare primitive field outside a newtype |
| R11 | `RefCell`/`Cell`/`Mutex`/`RwLock` field in a domain type |
| R12 | `f32`/`f64` field in a type that derives an order |
| R13 | `unsafe` block / fn / impl |
| R14 | `allow(unsafe_code)` — a lint-lowering on the strongest standard |
| R15 | crate root with no `#![forbid(unsafe_code)]` |

## Two modes, and they are not the same thing

**Gate** — the harness the pester hook reads.

```
cargo run --release -p bs-detector -- --root .
```

Walks `crates/`. Prints per-rule counts, every declared exemption, and a total.
Exits non-zero when anything is found. Called by `crates/xtask/gate.sh`, which
reads this output and is the sole writer of `crates/xtask/gate.log` and
`gate-counts.txt` — the detector writes no files in either mode. It reports what
is in the tree; deciding the tree's state also needs to know whether the tree
compiles, and only `gate.sh` holds both facts.

**Aim** — one file or directory, reported and nothing more.

```
cargo run --release -p bs-detector -- crates/kyzo-model/src/value/canonical.rs
cargo run --release -p bs-detector -- crates/kyzo-core/src/store
```

Prints `file:line: RULE detail` and a total. A verdict about one file is not a
verdict about the tree, and a harness that could be satisfied by narrowing its
scope is not a harness.

This is also what the `PostToolUse(Edit|Write)` hook runs — same binary, same
rules, same command shape — against whatever file was just written. Any
forbidden shape in that file **blocks the agent**, including shapes it did not
introduce. A file you touched is a file you own; leaving a known violation
because it predates you is how the count stays where it is.

## Exemptions

A shape that must stay is declared at the site, on the line directly above it:

```rust
// BS-EXEMPT: R10 — bench harness counter, not a domain fact
n: usize,
```

The marker must name a real rule and give a reason. A marker naming no rule, or
no reason, or one appearing inside a string or a doc comment, exempts nothing.

Exemptions live at the site and never in a list here. A list of exempt paths in
this crate is a carve-out by another name: invisible in review, and growing.
Every exemption is printed on every run and counted in the gate headline
(`… , 3 exempt`), so a tree at zero violations with exemptions never reads the
same as a tree with none. The post-edit hook blocks an edit that *adds* a
marker: an exemption is not a fix, and the operator signs for it, not the agent.

Rust's `#[expect(lint, reason = "…")]` is the better mechanism where it applies
— rustc warns when an expectation goes unfulfilled, so it expires itself — and
it is deliberately not used here. It works on real lints, and of the fifteen
rules exactly one (`unsafe_code`) is a real lint; a tool namespace for the other
fourteen is nightly-only. Accepting it for the one would also hand R14 its own
escape hatch: R14 forbids lowering the unsafe lint, and an accepted
`#[expect(unsafe_code)]` is that lowering at the front door.

## The verdict is a record, not a switch

`gate.log` says what the detector found. `ACKNOWLEDGE` appears when the count
reaches zero and by no other means. Editing it to change the count is the fraud
the gate exists to catch.

The operator arms and disarms the pester hook in `pester-hook.txt` — first
non-comment line, `on` or `off`. Agents do not touch it.

## Scope

All of `crates/`, skipping only `target/`. Nothing else is exempt: not tests,
not vendored data, not the detector itself. It scans itself and reports itself.

R13–R15 exist because the guarantee they protect is not what it looks like.
`#![forbid(unsafe_code)]` is a *crate-root* attribute, so it says nothing about
that crate's `tests/` directory — a separate crate root. The only `unsafe` in
this tree lives exactly there.
