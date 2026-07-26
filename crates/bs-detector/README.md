# bs-detector

Enumerates the only shapes a max-purity Rust program may contain, and refuses everything else.

It never asks "is this instance justified here" — that is matching code. It asks whether an item satisfies the conditions of an approved pattern, and if it does not, it is a violation until the code changes.

## One rule

Every item under `crates/` satisfies the conditions of exactly one construct in the closed set, or it is a violation. One category, one number.

Conditions are not a blacklist. They are what make an item that construct at all. There is no good newtype and bad newtype: there is newtype, and there is not-a-newtype.

## The closed set — `src/construct.rs`

Thirteen seats. App-independent: the same list for a database and a payment processor, because these are the forms the type system offers, not the things a domain models.

| construct | conditions |
|---|---|
| `newtype` | one private unnamed field wrapping a terminal (primitive or container); no `Default`; not `pub`; generics proven |
| `sealed-product` | named fields, all private; no bare primitive, `Option`, container, or reference; not `pub`; generics proven |
| `closed-sum` | not `#[non_exhaustive]`; no variant carries a bare primitive, `Option`, or container; no `Default`; not `pub`; generics proven |
| `marker` | zero size — unit struct or `PhantomData` only; no `Default`; not `pub` |
| `mint` | no receiver; `Result<Self, E>` where `E` is a closed sum declared in the tree and not duplicated; pure body; never calls into the type it is building |
| `derivation` | `&self`; lawful return; no `&mut` anywhere; pure body; not a bare field read; not `unsafe`, not `async` |
| `transition` | `self` by value; lawful return; no `&mut` parameters; pure body |
| `sealed-trait` | sealed by a supertrait; methods only; no predicate; no prose refusal; not `pub`; not `unsafe` |
| `composition-root` | a free, private, argument-less `fn main` yielding nothing or `ExitCode`/`Result` |
| `import` | one name, uppercase leaf; no glob, rename, group, `pub`, or attribute |
| `module` | private; file-only, never inline; doc attributes only — no `#[cfg]`, no `#[path]` |
| `confinement` | exactly one lifetime parameter, whatever it is called; every reference field bound to it; a `PhantomData` carrying it; private fields |
| `impl-block` | non-empty; not blanket; trait declared in the tree *and* seating as `sealed-trait`; generics proven; not `unsafe` |

## The proof is a fact about the tree

`Scope` is built once over every file under `crates/`, and every cross-item claim resolves against it. The unit of proof is the tree, not the file: a call that crosses a module boundary is still a call, and refusing it for ignorance said nothing about the callee's body.

- A `Result`'s `Err` must name an enum the tree declares that itself seats as `closed-sum`. Not a capitalisation test.
- An `impl` may only implement a trait the tree declares *and* which itself seats as `sealed-trait`. Declaration alone authorises nothing.
- Every type parameter must be bounded — inline or in a `where` clause — and every bound must name a trait proven the same way.

**A duplicate name proves nothing.** A type or trait declared more than once anywhere in the tree is refused for every purpose, whether or not the declarations agree: two enums named `Refusal` that both seat as `closed-sum` are still two refusal sets, and `Result<_, Refusal>` cannot say which one it answers with.

Imports are the exception, and deliberately so: a `use` is a fact about one file. `use std::env as e` in one file says nothing about the name `e` in another, and a glob taints only the file that wrote it.

## Effects

`fn main` is where effects are lawful. That is stated as its inverse: every effect performed anywhere else is a violation **at the site that performs it** — in a failed `main`, in a method, in a trait default body, in a nested block, inside a macro-declared item, in a `const` or `static` initialiser.

Purity is decided from the receiver's **type**, never from the method's name. A domain method called `insert` is pure; a wrapped effect called `advance` is not. A receiver whose type cannot be resolved is refused, because purity that cannot be shown is not purity.

**Purity is transitive.** Every method, trait default, free function, and associated function is surveyed for what it does directly and for what it calls; impurity then flows backwards along every call edge to a fixpoint. An effect one call away is an effect, and `Self::helper()` is a call. A method with no body cannot be shown pure and is refused.

Imports are followed: `use std::env as e`, `use std::env::var`, and `env::var` are the same finding. A glob reaching outside this crate makes every unqualified name in that file the glob's, because the file recorded nothing that could say otherwise. `crate::*`, `self::*`, and `super::*` stay inside the program by construction — still refused as imports, never called ambient.

## The foreign boundary

`syn::Item` is read in exactly one place — `Seat::of`. Everything downstream matches `Seat`, a sum this crate owns, which is exhaustive without a wildcard. `syn` is pinned exactly; `build.rs` counts `syn::Item`'s variants in the pinned source and a `const _: () = assert!` fails compilation if the mirror drifts. An unrecognised variant becomes `unknown-item-kind`, its own violation category.

## No waivers

The waiver concept is deleted. No ledger, no attestation, no scope narrowing, no exception.

Every case that ever looked like it needed a waiver is a missing type. None of them wanted an exception; all of them wanted the work.

A blessing that is wrong fails loud — one category goes quiet and you see it. A waiver that is wrong fails silent — one violation vanishes and nobody looks again.

## The fixture law

`Construct::conditions()` states every condition by name. Four tests enforce it:

- Every stated condition has a `fixtures/<seat>.deny-<condition>.fixture`. A condition written down with no proof beside it fails the build.
- Every deny fixture draws a violation **and** no longer seats as that construct — a fixture that reds for a neighbour's reason fails.
- Every pass fixture draws nothing **and** actually seats as the construct it is named for.
- `syn` is pinned exactly.

## Boundary

All of `crates/`. `target/` is the only exclusion. Files found versus files parsed is a proof; any gap is a violation. An unreadable or unparseable file is counted, never skipped.

Fixtures carry the `.fixture` extension, not `.rs` — evidence, never source — so they sit beside the crate without needing a second exclusion.

## Running it

```
cargo run --release -p bs-detector -- --root .    # full run
cargo test -p bs-detector                          # the fixture law
```

`--root` names the tree. No flag narrows scope, selects a category, or sets a baseline.

## License

Business Source License 1.1 — see `LICENSE-BSL` and `LICENSING.md`. This crate
is original agent/dev tooling, not CozoDB lineage. Change Date 2030-07-11 → MPL-2.0.

## Rules of engagement

- Partially done is not a thing. Done or not done.
- **Baseline is zero, forever.** The gate going red is the correct outcome.
- **Detecting more is never a cost.** Any argument that a check is "too strict" is the defect.
- The count is an instrument, not the goal. A lower number bought by a soft seat is sabotage; a higher number refused by leaving law unbuilt is the same sabotage wearing a disclosure costume.
- Nothing here is closed by explanation. It is closed by a condition that makes the illegal state unseatable.
