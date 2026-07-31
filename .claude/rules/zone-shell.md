---
law_format: 1
assignment: zone
zone: shell
globs:
  - "crates/kyzo-bin/src/**/*.rs"
  - "crates/kyzo-lsp/src/**/*.rs"
  - "crates/xtask/src/**/*.rs"
  - "crates/bs-detector/src/**/*.rs"
  - "crates/canonical-trials/src/**/*.rs"
  - "crates/kyzo-trials/src/**/*.rs"
  - "crates/kyzo-arrow-interop/src/**/*.rs"
  - "crates/kyzo-core/src/bench_recovery.rs"
  - "crates/kyzo-core/src/lib.rs"
  - "crates/*/tests/**/*.rs"
  - "crates/*/benches/**/*.rs"
  - "crates/*/examples/**/*.rs"
  - "crates/*/build.rs"
  - "crates/kyzo-trials/rehomed_from_core/**/*.rs"
  - "fuzz/fuzz_targets/**/*.rs"
  - "vendor/*/tests/**/*.rs"
  - "vendor/*/benches/**/*.rs"
  - "vendor/*/examples/**/*.rs"
  - "vendor/*/build.rs"
description: "Shell. Composition, marshaling, rendering, termination, and the harnesses that judge the engine."
purity:
  - set: rust
    version: "0.1.0"
capabilities: [filesystem, process, time, randomness]
---

# Shell

The process exit lives here and nowhere else. Shell converts typed verdicts into
output and exit codes by matching the error, never by formatting it and reading
the text back.

It holds no state another posture owns and constructs no domain value from
primitives itself: construction goes through a Boundary entry point. Hosts
marshal and nothing else — no engine meaning lives here.

`kyzo-trials` and `canonical-trials` are Shell because they are harnesses. They
hold the capabilities the campaigns need — seeded generators, the wall clock,
fault injection, the filesystem — and drive the engine from outside. Randomness is
declared here and only here, and it is seeded, because an unreproducible failure
is not evidence.

`bs-detector` is Shell and is not the judge. It reads text and counts shapes; it
has never produced an input that returns a wrong answer. Verus is the judge, and
the clause sets in this repository are the law it counts against.
