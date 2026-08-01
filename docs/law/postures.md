---
law_format: 1
set: rust
version: "0.1.0"
kind: postures
description: "The positions a pure Rust architecture has. What each one is, requires, declares, and may reach."
---

# Rust posture model

A Rust program built under this law has four positions. Every source file sits at exactly one.

Postures are not directories, layers, or crates. They are answers to a single question: what is this code responsible for proving? A crate can hold files at three postures, and often should.

`purity.md` states the clauses. Each clause names the postures it binds to. This file defines the postures and states what each requires beyond its clause set.

---

## Proof

**Responsible for:** establishing proof. Types, their constructors, their ordering, their representation.

**Requires:** every exported type is constructible only through a proof. A Proof module exporting a type with no constructor has exported a shape, not a vocabulary.

**Declares:** no capabilities.

**May depend on:** nothing. Not the standard library beyond core vocabulary, not other crates in the workspace, not other postures. This is stricter than Core, and it is the reason Proof is separate: the vocabulary both consumers bind to cannot bind to either.


---

## Core

**Responsible for:** total computation over already-proven values.

**Requires:** every function is total. For every input its parameter types admit, it returns a value its return type admits, without panicking and without observing anything outside its arguments. Given the same arguments it returns the same result, forever, on any machine.

**Declares:** no capabilities.

**May depend on:** Proof, Core.


---

## Boundary

**Responsible for:** converting unproven input into proven values, and performing declared effects.

**Requires:** the module names its **entry points**. An entry point takes unproven input and returns a proven type or a typed error. Everything in a Boundary module that is not an entry point is held to Core.

This is the one place in the model where a primitive is correct in a parameter position, and the reason is precise: an entry point's parameters are not domain positions. They are unproven input, which is exactly what the entry point exists to convert. Requiring proven types there would only move the boundary somewhere with no law. The obligation is unchanged, not reduced: primitives on return types, on struct fields, and on anything passed inward still fire.

**Declares:** the capabilities named in the zone's law file, and no others. Declaring one is an addition to the zone's obligations, not a removal of the rest.

**May depend on:** Proof, Core, Boundary.


---

## Shell

**Responsible for:** composition, marshaling, rendering, and termination.

**Requires:** the process exit lives here and nowhere else. Shell holds the capabilities the other postures declared and passes them down as arguments. It converts typed verdicts into output and exit codes, and it interprets nothing beyond that.

**Declares:** the capabilities named in the zone's law file. Shell is where a program's capabilities normally live, and each is named rather than assumed from the posture.

**May depend on:** Proof, Core, Boundary, Shell.


---

## Capabilities

Named, never inferred.

| Capability | Clause in Core | Constructs |
|---|---|---|
| `filesystem` | RUST-C-09 | `std::fs`, path reads and writes, filesystem crates |
| `network` | RUST-C-09 | `std::net`, socket and HTTP crates |
| `process` | RUST-C-09 | `std::process`, `std::env` |
| `time` | RUST-C-10 | `SystemTime`, `Instant`, wall-clock crates |
| `randomness` | RUST-C-11 | any generator not passed in as an argument |

Proof and Core declare none, so the Core clauses bind absolutely there. Boundary and Shell declare zero or more in the zone's law file, and RUST-B-05 and RUST-SH-02 fire on anything reached but not declared.

No capability is declared by default. No posture declares all of them.

---

## Dependency direction

| Posture | May depend on |
|---|---|
| Proof | nothing |
| Core | Proof, Core |
| Boundary | Proof, Core, Boundary |
| Shell | Proof, Core, Boundary, Shell |

Edges are evaluated at the package level and the module level. A legal package dependency does not make an illegal module import legal, and RUST-U-08 and RUST-U-09 close aliasing and re-export as routes around either.

---

## Emission contract

A zone's rule file is composed from the clauses that bind to that zone's posture. It carries each clause's `Rule` line and demo pair, this file's entry for that posture, and the zone's globs. It does not carry clauses that bind elsewhere.


A **deprecated** zone emits the same composition for its current posture, plus its destination posture and a standing notice that the correct change is migration rather than extension. Deprecation adds a notice and a destination. It removes no clause and lowers no obligation.