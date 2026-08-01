---
law_format: 1
set: rust
version: "0.1.0"
kind: violations
description: "The abstract failures this law recognizes. Each clause in purity.md produces exactly one."
---

# Rust violation set

A clause names the syntax. A violation names the failure that syntax produces.

`purity.md` carries a `Violation` line on every clause. This file defines what those names mean. The definitions are stated in the abstract, without Rust in them, because the same failure is reachable through many constructs and a reader who knows the failure can recognize a route the clause set has not closed yet.

Every clause's `Violation` line names one entry in this file. A clause naming anything else is not a valid clause. A finding carries both: the violation is what went wrong, the clause is the evidence that it did.

Violation names are stable within this major version.

---

### UncheckedFallibility

**Means:** an operation that can fail is called from a signature that does not admit the failure.


The failure does not stop existing when the type stops mentioning it. It becomes an abort the caller cannot handle, or a wrong value the caller cannot detect. Either way the signature is a claim the code does not keep.

---

### AliasEvasion

**Means:** a path this position may not reach is reached under a different name.


The obligation attaches to what the code reaches, not to what it calls it. A rename at the import and a re-export from a legal module are the same move: the edge still exists, and it exists at the renaming.

---

### UndeclaredSingleton

**Means:** a concern the law declares singular has a second implementation or a second site.


Two answers to one question, with nothing in the type system to say when they disagree. The second site is always the one that drifts, and callers of the first can never observe that it did.

---

### UnprovenConstruction

**Means:** a value of a type that carries an invariant exists without that invariant having been proven.


Either the representation is reachable without the constructor, or the constructor asserts a proof it did not perform. The type still reads as a guarantee at every call site downstream, which is what makes this failure expensive: it is invisible everywhere except where it was introduced.

---

### PostHocValidation

**Means:** a proof is offered after construction rather than performed inside it.


A check that can be skipped proves nothing about the values that skipped it. A check that cannot fail is noise the next reader will mistake for a proof. And the check's existence is itself the finding: it says the type admits values it should not, whatever any caller does about it.

---

### PrimitiveInDomainPosition

**Means:** a domain position carries a primitive or an unnamed shape instead of the type that proves it.


The meaning lives in a parameter name, a field name, or a comment, none of which the compiler reads. Two values of the same underlying type are interchangeable at every call site, and the operations the domain does not have are all still available.

---

### SentinelForAbsence

**Means:** absence is encoded as a legal value of the type that carries it.


The convention lives in the reader's memory rather than the type, so every consumer must know it and one of them will not. Absent and present-but-empty are different facts, and a representation that cannot tell them apart has already lost one.

---

### UnlawfulOrdering

**Means:** ordering, equality, or hashing is implemented without the law it must obey being stated or held.


Comparison is a law, not a convenience. Everything that sorts, ranges, deduplicates, or encodes canonically depends on it, so an unstated law is inferred by the next reader and an inconsistent one fails where no test is looking.

---

### OpenMatchOnClosedType

**Means:** a closed set is consumed as though it were open.


Exhaustiveness is the compiler offering to find every site that must change when a case is added. A wildcard declines the offer, and a type marked open where it is owned and consumed forces its own consumers to decline it too.

---

### NondeterministicIteration

**Means:** a value's encoding or output order depends on run history rather than on the value.


The same logical value produces two different results in two processes. Nothing fails at the point of the choice, so the failure surfaces in a comparison, a digest, or a diff, far from the collection that caused it.

---

### ForbiddenDependencyEdge

**Means:** a position reaches a position it may not depend on.


Reaching a position acquires its obligations and its capabilities, whatever the calling code does with them. `postures.md` states the permitted directions; this violation is what a departure from them produces.

---

### StringlyTypedDiscrimination

**Means:** a decision is made by inspecting text rather than by matching a closed type.


The type check moves to runtime and exhaustiveness is lost with it. Adding a domain case compiles cleanly and silently does nothing, which is the worst available outcome: the program is wrong and the build is green.

---

### EscapedCapability

**Means:** an effect is reached from a position that did not declare it.


The result becomes a function of a fact the signature does not mention: what was on disk, what time it was, what the generator returned. The computation is no longer testable from its arguments, and the position's declaration no longer describes what it does.

---

