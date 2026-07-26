# bs-detector

Thirteen approved patterns. Every item under `crates/` satisfies the conditions of exactly one of them, or it is a violation.

Conditions are not a blacklist. They are what make an item that construct at all.

## Contents

`src/construct.rs` holds:

- `Construct` — the thirteen-variant closed sum, with `conditions()` naming every condition by name and `law_name()` giving each its fixture stem.
- `seat_struct`, `seat_enum`, `seat_trait`, `seat_impl`, `seat_method`, `seat_free_fn`, `seat_use`, `seat_mod`, `seat_confinement` — each returns `Option<Construct>`. `None` is a violation.
- `TypeFacts` — the trait the harness implements.
- Scope-free predicates and approval tables: `FOREIGN_PURE`, `NAKED_PRIMITIVES`, `INVARIANT_CELLS`, `PURE_ATTRS`.

There is no tree walker and no type resolver in this crate.

## Delivery: Dylint

The rules ship as [Dylint](https://github.com/trailofbits/dylint) lints — a `cdylib` crate loaded by `cargo dylint`, running as a `LateLintPass` inside `rustc`.

**Crate setup:**

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
dylint_linting = "3"
```

```rust
dylint_linting::declare_late_lint! {
    pub CONSTRUCT_LAW,
    Deny,
    "every item satisfies one of the thirteen constructs"
}
```

**Callbacks and coverage.** `LateLintPass` provides `check_item`, `check_impl_item`, `check_trait_item`, `check_field_def`, `check_variant`, `check_fn`, `check_expr`, `check_stmt`, `check_generic_param`, `check_attribute`. The compiler drives them over every node it compiled. Items in nested blocks, closures, loop bodies, match arms, const positions inside types, `where` clauses, signatures, and macro expansions all arrive through the same callbacks with no per-position handling.

**Expansion.** Lints run after macro expansion. `check_item` receives expanded items; macro invocations are not a distinct case.

**Entry point.** `tcx.entry_fn(())` returns the crate's entry `DefId`. `seat_free_fn` takes `is_entry_point: bool` from that comparison.

**Visibility.** `tcx.visibility(def_id)` returns `Visibility::Public` or `Visibility::Restricted(module)`. `is_public` reads it directly.

## Implementing `TypeFacts`

```rust
fn provenance(&self, name: &str) -> Provenance;
fn declares_trait(&self, name: &str) -> bool;
fn is_closed_sum(&self, name: &str) -> bool;
fn body_is_pure(&self, block: &syn::Block, self_ty: &str, sig: &syn::Signature) -> bool;
fn calls_into(&self, block: &syn::Block, owner: &str) -> bool;
```

Against `TyCtxt`:

- **`provenance`** — resolve the type to a `DefId`. `def_id.is_local()` → `Declared`. Non-local → check the defining crate against `FOREIGN_PURE`, else `Ambient` for `std::fs`, `std::process`, `std::net`, `std::env`, `std::io`, else `Unproven`. Unresolvable → `Unproven`.
- **`declares_trait`** — `tcx.hir_crate_items(()).definitions()` filtered to `DefKind::Trait`, matched by `tcx.item_name`.
- **`is_closed_sum`** — resolve to a `DefKind::Enum` `DefId`, then run `seat_enum` on its definition.
- **`body_is_pure`** — walk the `hir::Body`. For each `ExprKind::MethodCall`, `tcx.typeck(body_owner).type_dependent_def_id(expr.hir_id)` gives the callee; take the `provenance` of its `impl` self type. For each `ExprKind::Call` on a path, resolve the path to a `DefId` directly. Pure iff every callee is `Declared` or `ForeignPure`.
- **`calls_into`** — the same walk, testing whether any resolved callee's `DefId` has `owner`'s `DefId` as its impl parent.

`body_is_pure` and `calls_into` currently take `&syn::Block`; a HIR harness passes the `hir::Body` and the signatures change to match.

## Testing

`dylint_testing` wraps `ui_test`: a `.rs` fixture beside an expected `.stderr`. One fixture per condition named in `conditions()`, plus one passing fixture per construct.

```rust
#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
```

## Running

```
cargo dylint --lib bs_detector -- --workspace
```

Exits non-zero on any violation. `Deny` level fails the build.

## License

BSL-1.1. See `LICENSING.md`.
