---
law_format: 1
assignment: zone
zone: boundary
globs:
  - "crates/kyzo-core/src/session/access.rs"
  - "crates/kyzo-core/src/session/admit.rs"
  - "crates/kyzo-core/src/session/admit_lowering.rs"
  - "crates/kyzo-core/src/session/admit_supersession.rs"
  - "crates/kyzo-core/src/session/capacity.rs"
  - "crates/kyzo-core/src/session/catalog.rs"
  - "crates/kyzo-core/src/session/certificate_inject.rs"
  - "crates/kyzo-core/src/session/composition.rs"
  - "crates/kyzo-core/src/session/constraint.rs"
  - "crates/kyzo-core/src/session/db.rs"
  - "crates/kyzo-core/src/session/fts.rs"
  - "crates/kyzo-core/src/session/generation.rs"
  - "crates/kyzo-core/src/session/hnsw.rs"
  - "crates/kyzo-core/src/session/host_clock.rs"
  - "crates/kyzo-core/src/session/jobs.rs"
  - "crates/kyzo-core/src/session/json.rs"
  - "crates/kyzo-core/src/session/lsh.rs"
  - "crates/kyzo-core/src/session/mod.rs"
  - "crates/kyzo-core/src/session/normalize.rs"
  - "crates/kyzo-core/src/session/normalize_tests.rs"
  - "crates/kyzo-core/src/session/observe.rs"
  - "crates/kyzo-core/src/session/ops.rs"
  - "crates/kyzo-core/src/session/test_rows.rs"
  - "crates/kyzo-core/src/session/verify.rs"
  - "crates/kyzo-core/src/store/authority.rs"
  - "crates/kyzo-core/src/store/backup.rs"
  - "crates/kyzo-core/src/store/commit_cap.rs"
  - "crates/kyzo-core/src/store/compact.rs"
  - "crates/kyzo-core/src/store/contract.rs"
  - "crates/kyzo-core/src/store/crypto.rs"
  - "crates/kyzo-core/src/store/failure.rs"
  - "crates/kyzo-core/src/store/fjall.rs"
  - "crates/kyzo-core/src/store/forge_wall.rs"
  - "crates/kyzo-core/src/store/grants.rs"
  - "crates/kyzo-core/src/store/idempotency.rs"
  - "crates/kyzo-core/src/store/merkle.rs"
  - "crates/kyzo-core/src/store/mod.rs"
  - "crates/kyzo-core/src/store/objects.rs"
  - "crates/kyzo-core/src/store/open.rs"
  - "crates/kyzo-core/src/store/replica.rs"
  - "crates/kyzo-core/src/store/retry.rs"
  - "crates/kyzo-core/src/store/scratch.rs"
  - "crates/kyzo-core/src/store/seal.rs"
  - "crates/kyzo-core/src/store/skip_walk.rs"
  - "crates/kyzo-core/src/store/sweep.rs"
  - "crates/kyzo-core/src/store/time.rs"
  - "crates/kyzo-core/src/store/transcript.rs"
  - "crates/kyzo-core/src/store/tx.rs"
  - "crates/kyzo-core/src/store/verify_walk.rs"
  - "crates/kyzo-core/src/store/wal.rs"
  - "crates/kyzo-core/src/rules/io/**/*.rs"
  - "crates/kyzo-core/src/parse/mod.rs"
  - "crates/kyzo-core/src/data/json.rs"
  - "crates/kyzo-core/src/data/mod.rs"
  - "crates/kyzo-model/src/parse/expr.rs"
  - "crates/kyzo-model/src/parse/mod.rs"
  - "crates/kyzo-model/src/parse/query.rs"
  - "crates/kyzo-model/src/parse/schema.rs"
  - "crates/kyzo-model/src/parse/script.rs"
  - "crates/kyzo-model/src/parse/search.rs"
  - "crates/kyzo-model/src/parse/sys.rs"
  - "crates/kyzo-model/src/envelope/**/*.rs"
  - "crates/kyzo-model/src/host_text.rs"
  - "crates/kyzo-model/src/value/arena.rs"
  - "crates/kyzo-model/src/value/json_convert.rs"
  - "crates/kyzo-crashfs/src/**/*.rs"
  - "vendor/fjall/src/**/*.rs"
  - "vendor/lsm-tree/src/**/*.rs"
description: "Boundary. Where unproven input becomes proven values, and where storage and clock effects happen."
purity:
  - set: rust
    version: "0.1.0"
capabilities: [filesystem, time]
---

# Boundary

Entry points take unproven input and return a proven type or a typed error.
Everything that is not an entry point is held to Core.

`session/` is the one admission path: there is no second way for data to reach
storage from outside. `store/`, `rules/io/` and the two vendored engines hold the
filesystem; `session/host_clock.rs` holds the clock. Declared here: filesystem and
time. Network, randomness and process are not declared, and reaching one fires.

A parameter may be a primitive here, because an entry point's parameters are the
unproven input it exists to convert. Return types, struct fields, and anything
passed inward are domain positions and are not exempt.

`vendor/fjall` and `vendor/lsm-tree` are first-party forks published under our own
names. They have never been held to this law and are the largest unexamined region
in the map. They are assigned rather than excluded, because a boundary in the
walker is an exemption list wearing a different hat.
