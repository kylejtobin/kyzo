# bs-detector

Refuses the fifteen forbidden shapes.

A blacklist, not a whitelist. It does not decide what good code is — it names
shapes that are wrong every time, and counts them.

## The one design constraint

**Every rule is decidable from syntax alone.** No type resolution, no macro
expansion, no call graph.

Two passes, unioned — never one substituted for the other:

- **Tokens, per line.** The only pass that sees inside a macro body, because no
  parser expands one. `unsafe`, `panic!`, `todo!`, `env::var` are found here.
- **The item tree, via `syn`.** Every position a type can appear: named field,
  tuple element, enum variant payload, function parameter, return type, alias
  right-hand side, typed `let`. The pass this replaced read `name: Type` lines
  and tracked scope with a brace counter, so a shape one column off its expected
  form was invisible.

Replacing the token pass with the parser would silently drop every shape written
inside a macro. A rewrite that *lowers* the count on unchanged code has narrowed
a rule, not fixed a tree — that is the number to watch when either pass changes.

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

**One scope: the whole workspace, or the single path you aim at.** No rule
carries a private carve-out — not for tests, not for vendored code, not for the
crate the rule is inconvenient in. `#![forbid(unsafe_code)]` in a lib root does
not reach that crate's `tests/` directory, and that is exactly the kind of gap a
per-rule exemption hides.

The walk used to start at `crates/`. `fuzz/` is first-party and was never
scanned; `vendor/fjall` and `vendor/lsm-tree` are forks we publish under our own
names. A boundary in the walker is an exemption list wearing a different hat, so
the per-tree subtotals in the report exist instead — `vendor/` is large enough
to hide movement in the engine behind a single number.

This is the floor, not the ceiling. It catches shapes. It cannot catch a runtime
check that should have been a constructor, an `Option` standing for meaningful
absence, or two types carrying one fact under different field names. Those cost
more, and only a reader finds them.

## The fifteen

| | forbidden |
| --- | --- |
| R01 | `Ord`/`PartialOrd`/`Hash` on a type that does not state its `ORDER_LAW` |
| R02 | `pub` field, or a public constructor that cannot refuse |
| R03 | bare `Vec`/`HashMap`/`HashSet` as a `pub` field |
| R04 | `unwrap`/`expect`/`panic!` |
| R05 | `String`-typed error, or a refusal carrying no span |
| R06 | `todo!`/`unimplemented!`/`unreachable!` stub |
| R07 | `env::var` — process environment read as a value |
| R08 | `String`-typed `kind`/`status`/`type`/`name` field |
| R09 | `bool` field carrying a domain decision |
| R10 | bare primitive field outside a newtype |
| R11 | `RefCell`/`Cell`/`Mutex`/`RwLock` field in a domain type |
| R12 | `f32`/`f64` field in a type that derives an order |
| R13 | the `unsafe` keyword, anywhere on a line |
| R14 | `allow(unsafe_code)` — a lint-lowering on the strongest standard |
| R15 | crate root with no `#![forbid(unsafe_code)]` |

## Two modes, and they are not the same thing

**Gate** — the harness the pester hook reads.

```
cargo run --release -p bs-detector -- --root .
```

Walks the workspace. Prints per-rule counts, per-tree subtotals, and a total.
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

## There is no exemption

No marker. No attribute. No list of exempt paths. A rule that can be waived at
the site is a rule with a hole, and the hole gets used under exactly the
pressure the rule exists to resist.

Rust's `#[expect(lint, reason = "…")]` is the better mechanism where it applies
— rustc warns when an expectation goes unfulfilled, so it expires itself — and
it is deliberately not used here. It works on real lints, and of the fifteen
rules exactly one (`unsafe_code`) is a real lint; a tool namespace for the other
fourteen is nightly-only. Accepting it for the one would also hand R14 its own
escape hatch: R14 forbids lowering the unsafe lint, and an accepted
`#[expect(unsafe_code)]` *is* that lowering, at the front door.

The one legitimate reason to write a forbidden shape is to prove a rule fires on
it. That shape is test data, not program text, so it lives in `fixtures/` with a
`.rsfix` extension: not compiled, and invisible to a walker that reads `.rs` and
nothing else. `mod law` in `src/main.rs` runs the scanner over those fixtures
and asserts each rule fires at the line that carries it — including a test that
none of the four markers people reach for (`BS-EXEMPT`, `#[expect]`,
`#[allow]`, `// SAFETY:`) suppresses anything. If an exemption is ever
reintroduced, that test is what fails.

## The verdict is a record, not a switch

`gate.log` says what the detector found. `ACKNOWLEDGE` appears when the count
reaches zero and by no other means. Editing it to change the count is the fraud
the gate exists to catch.

The operator arms and disarms the pester hook in `pester-hook.txt` — first
non-comment line, `on` or `off`. Agents do not touch it.

## What it cannot see, stated rather than passed over

Two numbers print next to the findings, and they are part of the report:

- **macro bodies.** `syn` sees an invocation, never its output. The token pass
  reaches inside for `unsafe`, `panic!`, `todo!` and `env::var`; R01, R02, R09,
  R10 and the rest of the type rules cannot. Currently 10,617.
- **files the parser refused.** Their token findings still count; their item
  findings are absent. Currently 0.
- **cross-crate type aliases.** Same-crate `type X = Y` is resolved before the
  rules run, so a rename cannot hide what a binding holds. An alias declared in
  another crate needs resolved types and is not seen.

A parser that skips a construct in silence is reporting a tree it never read.
That was the failure mode of the machine this replaces — 68% of its number was
its own blindness, filed as findings — so the blindness is a count here instead,
kept out of the violation total.

This also bit the fixtures: `forbidden.rsfix` held bare statements at file scope,
so it did not parse, so the item pass was skipped on it, so seven rules were
unproven while the suite reported green. `the_fixture_parses` is now a test.

## Scope

The whole workspace, skipping only `target/` and `.git/`. Nothing else is
excluded: not tests, not `fuzz/`, not `vendor/`, not the detector itself. It
scans itself and reports itself. Aim mode has no scope restriction at all — it
checks whatever path you give it.

R13 matches the bare `unsafe` keyword at a token boundary, not just the line
forms. Matching only `unsafe fn` / `unsafe impl` / a line *starting* with
`unsafe {` leaves the strongest rule steppable by writing `let x = unsafe { *p
};`, which is the shape most likely to be reached for. `unsafe_code` is a
different token and does not match it; R14 owns that one.

R13–R15 exist because the guarantee they protect is not what it looks like.
`#![forbid(unsafe_code)]` is a *crate-root* attribute, so it says nothing about
that crate's `tests/` directory — a separate crate root. The only `unsafe` in
this tree lives exactly there.
