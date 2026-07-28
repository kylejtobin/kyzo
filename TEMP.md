Five of the eight die the moment the scanner parses instead of reads lines. Two need resolved types. One is a walker change.

**Fixed by parsing with `syn` — and this works today, on the broken tree, because `syn` needs only valid syntax, not a compiling crate:**

**1. Only `name: Type` lines.** Replace `field()`/`type_header()`/the brace counter with a `syn::visit::Visit` impl. Apply the type rules at every position a type can appear: struct field, tuple element, enum variant payload, fn parameter, fn return, type alias RHS, generic argument, typed `let`. That single change is what makes the detector able to see its own `(String, String, bool)`.

**4. R01's substring test.** The law must attach to the type, not the file. `syn` hands you each item's attributes, so the rule becomes: *a type that derives or impls `Ord`/`PartialOrd`/`Hash` must carry `ORDER_LAW:` in its own doc comment.* `text.contains("ORDER_LAW")` currently lets one comment anywhere in a 3,000-line file satisfy every type in it. Whether the order is *correct* stays undetectable — that's the trials' job — but "this type states its law" is checkable and isn't checked.

**5. R05's missing clause.** Implement it, don't delete it. A type whose name ends in `Refusal`/`Refuse`/`Error`/`Denial` must have a field typed `Span`/`SourceSpan`/`Offset`. Decidable on the AST.

**6. `env::var` textual match.** Track the file's `use` statements so `use std::env; env::var(…)` and `use std::env::var; var(…)` both resolve to the same path.

**7. Brace counter.** Deleted. There is no scope tracking to desync when you have the item tree.

**Needs resolved types — dylint `LateLintPass`:**

**2. Type aliases.** `syn` can do a same-crate pre-pass collecting `type X = Y` and substituting transitively, which catches most of it. Cross-crate aliases need `ty.kind()`. Do the pre-pass in tier 1, get it exactly right in tier 2.

**3. Macro expansion.** `syn` sees the invocation, never the output. Only rustc expands. Until tier 2, the honest move is to **count macro bodies as unscanned and report the number** — a coverage gap stated, not a silent pass.

**One-line change:**

**8. Scope.** Walk every `.rs` in the workspace except `target/`. `fuzz/` is first-party and currently unscanned. `vendor/` is third-party — scan it and let the count tell the truth rather than burying an exemption in the walker.

**Two things that must be true of the dylint tier or it's worse than what we have:** diagnostics go through the compiler's error channel, not the lint-level machinery, so there is no level to lower and `#[allow(bs::r10)]` cannot silence a rule. And the violation-pattern tests become `ui_test` `.stderr` files — still the only place a forbidden shape is permitted to exist, same rule as the `.rsfix` fixtures.

Tier 1 is the bulk of the detection gain and needs nothing from the broken build. Starting there unless you want it in a different order.