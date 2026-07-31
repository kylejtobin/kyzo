---
law_format: 1
assignment: zone
zone: core
globs:
  - "crates/kyzo-core/src/exec/expr/**/*.rs"
  - "crates/kyzo-core/src/exec/fixpoint/**/*.rs"
  - "crates/kyzo-core/src/exec/fold/**/*.rs"
  - "crates/kyzo-core/src/exec/plan/**/*.rs"
  - "crates/kyzo-core/src/exec/provenance/**/*.rs"
  - "crates/kyzo-core/src/exec/stdlib/tests/**/*.rs"
  - "crates/kyzo-core/src/exec/mod.rs"
  - "crates/kyzo-core/src/exec/sort.rs"
  - "crates/kyzo-core/src/exec/op/batch_ops.rs"
  - "crates/kyzo-core/src/exec/op/delta.rs"
  - "crates/kyzo-core/src/exec/op/join.rs"
  - "crates/kyzo-core/src/exec/op/literal.rs"
  - "crates/kyzo-core/src/exec/op/mod.rs"
  - "crates/kyzo-core/src/exec/op/neg.rs"
  - "crates/kyzo-core/src/exec/op/search.rs"
  - "crates/kyzo-core/src/exec/op/stored.rs"
  - "crates/kyzo-core/src/exec/op/transform.rs"
  - "crates/kyzo-core/src/exec/stdlib/bind.rs"
  - "crates/kyzo-core/src/exec/stdlib/bound_op.rs"
  - "crates/kyzo-core/src/exec/stdlib/collection.rs"
  - "crates/kyzo-core/src/exec/stdlib/compare.rs"
  - "crates/kyzo-core/src/exec/stdlib/convert.rs"
  - "crates/kyzo-core/src/exec/stdlib/errors.rs"
  - "crates/kyzo-core/src/exec/stdlib/geo.rs"
  - "crates/kyzo-core/src/exec/stdlib/interval.rs"
  - "crates/kyzo-core/src/exec/stdlib/metric.rs"
  - "crates/kyzo-core/src/exec/stdlib/mod.rs"
  - "crates/kyzo-core/src/exec/stdlib/numeric.rs"
  - "crates/kyzo-core/src/exec/stdlib/temporal_format.rs"
  - "crates/kyzo-core/src/exec/stdlib/text.rs"
  - "crates/kyzo-core/src/project/dedup/**/*.rs"
  - "crates/kyzo-core/src/project/sparse/**/*.rs"
  - "crates/kyzo-core/src/project/spatial/**/*.rs"
  - "crates/kyzo-core/src/project/text/**/*.rs"
  - "crates/kyzo-core/src/project/vector/**/*.rs"
  - "crates/kyzo-core/src/project/contract.rs"
  - "crates/kyzo-core/src/project/current.rs"
  - "crates/kyzo-core/src/project/gazetteer.rs"
  - "crates/kyzo-core/src/project/index_fixture.rs"
  - "crates/kyzo-core/src/project/mod.rs"
  - "crates/kyzo-core/src/project/projection.rs"
  - "crates/kyzo-core/src/project/residency.rs"
  - "crates/kyzo-core/src/project/retrieval.rs"
  - "crates/kyzo-core/src/rules/algo/all_pairs_shortest_path.rs"
  - "crates/kyzo-core/src/rules/algo/astar.rs"
  - "crates/kyzo-core/src/rules/algo/bfs.rs"
  - "crates/kyzo-core/src/rules/algo/cliques.rs"
  - "crates/kyzo-core/src/rules/algo/degree_centrality.rs"
  - "crates/kyzo-core/src/rules/algo/dfs.rs"
  - "crates/kyzo-core/src/rules/algo/dijkstra.rs"
  - "crates/kyzo-core/src/rules/algo/kruskal.rs"
  - "crates/kyzo-core/src/rules/algo/louvain.rs"
  - "crates/kyzo-core/src/rules/algo/max_flow.rs"
  - "crates/kyzo-core/src/rules/algo/mod.rs"
  - "crates/kyzo-core/src/rules/algo/pagerank.rs"
  - "crates/kyzo-core/src/rules/algo/prim.rs"
  - "crates/kyzo-core/src/rules/algo/reorder_sort.rs"
  - "crates/kyzo-core/src/rules/algo/scc.rs"
  - "crates/kyzo-core/src/rules/algo/shortest_path_bfs.rs"
  - "crates/kyzo-core/src/rules/algo/top_sort.rs"
  - "crates/kyzo-core/src/rules/algo/triangles.rs"
  - "crates/kyzo-core/src/rules/algo/yen.rs"
  - "crates/kyzo-core/src/rules/contract.rs"
  - "crates/kyzo-core/src/rules/convert.rs"
  - "crates/kyzo-core/src/rules/gazetteer.rs"
  - "crates/kyzo-core/src/rules/graph_view.rs"
  - "crates/kyzo-core/src/rules/mod.rs"
  - "crates/kyzo-core/src/rules/parallel.rs"
  - "crates/kyzo-core/src/react/incremental.rs"
  - "crates/kyzo-oracle/src/**/*.rs"
  - "crates/kyzo-model/src/format.rs"
  - "crates/kyzo-model/src/format/tests.rs"
  - "crates/kyzo-model/src/value/convert.rs"
  - "crates/kyzo-model/src/value/exec.rs"
description: "Core. Total computation over already-proven values: evaluation, projection, graph algorithms, the oracle."
purity:
  - set: rust
    version: "0.1.0"
capabilities: []
---

# Core

Every function is total: for every input its parameter types admit, it returns a
value its return type admits, without panicking and without observing anything
outside its arguments. Given the same arguments it returns the same result, on
any machine, forever.

That last clause is what this engine is judged on. A query answered twice must
answer the same, and a replay must reproduce a run exactly, so a clock read or an
ambient generator here is not a style question — it is the determinism guarantee
failing silently.

`kyzo-oracle` is Core and is deliberately naive. It is the independent judge of
`exec/`, so it computes the same answers by obviously-correct means and shares no
implementation with the thing it checks.

The globs enumerate rather than sweep because canon has no negation: `Glob::new`
rejects only the empty string, so a `!pattern` would be stored as a literal and
match nothing. Four regions inside `exec/`, `rules/` and `react/` reach a
capability Core forbids and are carried in the deprecation register instead.
