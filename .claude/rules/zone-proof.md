---
law_format: 1
assignment: zone
zone: proof
globs:
  - "crates/kyzo-model/src/value/kind/**/*.rs"
  - "crates/kyzo-model/src/schema/**/*.rs"
  - "crates/kyzo-model/src/program/**/*.rs"
  - "crates/kyzo-model/src/typestate.rs"
  - "crates/kyzo-model/src/lib.rs"
  - "crates/kyzo-model/src/value/number.rs"
  - "crates/kyzo-model/src/value/test_rng.rs"
  - "crates/kyzo-model/src/value/admission.rs"
  - "crates/kyzo-model/src/value/arity.rs"
  - "crates/kyzo-model/src/value/bytes_qty.rs"
  - "crates/kyzo-model/src/value/canonical.rs"
  - "crates/kyzo-model/src/value/cell.rs"
  - "crates/kyzo-model/src/value/code.rs"
  - "crates/kyzo-model/src/value/codec.rs"
  - "crates/kyzo-model/src/value/column.rs"
  - "crates/kyzo-model/src/value/mod.rs"
  - "crates/kyzo-model/src/value/prefix.rs"
  - "crates/kyzo-model/src/value/proofs.rs"
  - "crates/kyzo-model/src/value/row.rs"
  - "crates/kyzo-model/src/value/search_hits.rs"
  - "crates/kyzo-model/src/value/string.rs"
  - "crates/kyzo-model/src/value/tag.rs"
  - "crates/kyzo-model/src/value/validity_coerce.rs"
  - "crates/kyzo-core/src/data/digest.rs"
  - "crates/kyzo-core/src/data/fixed_bytes.rs"
  - "crates/kyzo-core/src/data/statement.rs"
  - "crates/kyzo-core/src/refusal.rs"
  - "crates/kyzo-core/src/session/record_id.rs"
  - "crates/kyzo-core/src/project/dimension.rs"
  - "crates/kyzo-core/src/store/keys.rs"
  - "crates/kyzo-core/src/store/digest_domain.rs"
  - "crates/kyzo-core/src/store/epoch.rs"
  - "crates/kyzo-core/src/store/nonce.rs"
description: "Proof. The value vocabulary, its constructors, its order law, and its canonical bytes."
purity:
  - set: rust
    version: "0.1.0"
capabilities: []
---

# Proof

Every exported type here is constructible only through a proof. A type exported
with no constructor is a shape, not a vocabulary.

This is where the foundational invariant lives: a value's encoded bytes sort in
its semantic order. That is not a property of a function, it is a property of the
type, and `value/canonical.rs` discharges it through Verus rather than asserting
it.

`session/record_id.rs`, `project/dimension.rs` and the four `store/` key types sit
here and not with their directories. `RecordId` is the identity every reference
resolves to; which folder holds its file decides nothing about what it is
responsible for proving.

RUST-S-20 binds here and `kyzo-model` does not satisfy it: the crate declares
fifteen dependencies, among them a parser generator, a regex engine and a
serialization framework. The vocabulary both consumers bind to is currently
inside a crate that binds to a great deal. Satisfying the clause means extracting
a dependency-free vocabulary crate; nothing short of that closes it, and this
assignment is by responsibility, so the finding stands rather than being assigned
away.
