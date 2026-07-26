# bs-detector

Refuses the twelve forbidden shapes.

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

**Every rule is also absolute.** "unwrap on input-reachable paths" is
undecidable; "no unwrap outside tests" is trivial. The moment a rule needs a
clause like "…where a domain fact belongs", it stops being scriptable and does
not belong here. Rules that need judgment are enforced by review.

This is the floor, not the ceiling. It catches shapes. It cannot catch a runtime
check that should have been a constructor, an `Option` standing for meaningful
absence, or two types carrying one fact under different field names. Those cost
more, and only a reader finds them.

## The twelve

| | forbidden |
| --- | --- |
| R01 | `Ord`/`PartialOrd`/`Hash` with no `ORDER_LAW` stated in the file |
| R02 | `pub` field on a newtype, or a public unchecked constructor |
| R03 | bare `Vec`/`HashMap`/`HashSet` as a `pub` field |
| R04 | `unwrap`/`expect`/`panic!` outside tests |
| R05 | `String`-typed error, or a refusal carrying no span |
| R06 | `todo!`/`unimplemented!`/`unreachable!` stub |
| R07 | `env::var` read outside a config seat |
| R08 | `String`-typed `kind`/`status`/`type`/`name` field |
| R09 | `bool` field carrying a domain decision |
| R10 | bare primitive field outside a newtype |
| R11 | `RefCell`/`Cell`/`Mutex`/`RwLock` field in a domain type |
| R12 | `f32`/`f64` field in a type that derives an order |

## Two modes, and they are not the same thing

**Gate** — the harness the pester hook reads.

```
cargo run --release -p bs-detector -- --root .
```

Walks `crates/`. Writes `crates/xtask/gate.log` (`GATE: ALARM …` or
`GATE: ACKNOWLEDGE`) and `crates/xtask/gate-counts.txt` (per-rule counts). Exits
non-zero when anything is found. Called by `crates/xtask/gate.sh` and by
`cargo xtask gate`.

**Aim** — one file or directory, reported and nothing more.

```
cargo run --release -p bs-detector -- crates/kyzo-model/src/value/canonical.rs
cargo run --release -p bs-detector -- crates/kyzo-core/src/store
```

Prints `file:line: RULE detail` and a total. **Never writes the verdict.** A
verdict about one file is not a verdict about the tree, and a harness that could
be satisfied by narrowing its scope is not a harness.

## The verdict is a record, not a switch

`gate.log` says what the detector found. `ACKNOWLEDGE` appears when the count
reaches zero and by no other means. Editing it to change the count is the fraud
the gate exists to catch.

The operator arms and disarms the pester hook in `pester-hook.txt` — first
non-comment line, `on` or `off`. Agents do not touch it.

## Scope

Scans `crates/`, skipping `target/` and the two vendored MIT data tables
(`stopwords.rs`, `ascii_folding_filter.rs`), which are data, not architecture.
Test code — `#[cfg(test)]` blocks, `#[test]` fns, and the trials / oracle /
crashfs crates — is exempt from the token rules, because a test that cannot
panic cannot assert.

A workspace member on purpose: the detector scans itself, and reports itself.
