# The four moves — rationale, anti-patterns, worked before/after

## Why default-deny beats a blacklist

A blacklist forbids escapes one at a time. Each hatch costs a paragraph to
forbid and a paragraph to argue, so the document grows with the number of
escapes the author could imagine — and blocks only those. The escapes nobody
imagined sail through, because the document never named them.

A whitelist plus one closure sentence is the inverse. Enumerate the lawful
things; the closure sentence — *this table is total; anything not listed is
red* — refuses everything outside the list by construction. One sentence closes
infinite hatches, including the ones no author foresaw. The document gets
shorter and stronger at the same time.

This is the same default-deny law the detector applies to code, turned on the
document that governs the detector.

## Move 1 — whitelist + closure sentence

Replace a paragraph that forbids one construct and defends the ban with the
lawful list, then the closure sentence. The closure refuses the unlisted, so no
defense is needed.

## Move 2 — tables, not essays

Anything enumerable is a table: lawful constructs, doors and what each may
write, refusal names and their triggers, verbs and the derivation each fronts.
Head each table with the closure sentence. A prose paragraph that lists members
of a set is a table that has not been written yet.

## Move 3 — rulings become rows

An adjudication needs four parts; standing law does not repeat them in prose.
One row: `pick | what it makes unrepresentable | how to falsify it | rejected
alternative (one clause)`. The rejected-alternative clause exists to stop a
future reader from re-opening the choice — it only has to *explain* the cost,
because the closure sentence already *forbids* the act. Five words ("computes
disappearance; misses the lie") stop the reader at a tenth of an essay's cost.

## Move 4 — the spec is the program

Almost everything in a spec — relations, laws, doors, refusals, verbs — is
ontology content. Put it in the data the engine actually loads (the TOML/
relation rows), so the spec and the program are one artifact. Now the spec
cannot be evaded without the diff deriving red: to weaken the law you must edit
the law the engine runs, and the gate catches that. Prose shrinks to what
genuinely is not data.

## What survives as prose

- The core laws (compressing them loses teeth).
- The closure sentences (they are the default-deny engine of the document).
- The meters — each a falsification procedure: how to prove the law broken.
- The current-state block — what is truly built versus named-and-red.

## Anti-patterns (each is a validator flag)

| anti-pattern | why it is sabotage | fix |
| --- | --- | --- |
| open table | the unlisted construct is implicitly allowed | add the closure sentence |
| foreclosure essay | forbids one hatch, blind to the rest, costs a paragraph | make it a row; keep only the meter |
| count as goal / proof | the number is the lie; it invites hiding to shrink it | delete it; lawful-or-red is the only status |
| ontology in prose | the spec and program can diverge silently | move it to the data the engine loads |
| named residual | a known escape parked as an accepted limit | tripwire it red, or the item is not done |

This table is total: a document shape not listed here is not thereby safe —
run the validator, which is the default-deny closure over the document.

## Worked before / after

**Before (blacklist).** Four foreclosure paragraphs, quoted here as a specimen:

```text
static mut is red because global mutable state defeats the analysis; a glob
import is red because it defeats the rename table; a #[path] attribute is red
because it spoofs the file walk; a macro definition is red because expanded
code escapes the source walk.
```

**After (closed table).**

| lawful item kind | seat |
| --- | --- |
| struct, enum, fn, impl, trait, const, use, mod | seated construct rules |

This table is total: a `syn::Item` kind or interior kind not seated here is red.

The four foreclosure paragraphs vanish. `static mut`, glob imports, `#[path]`,
and macro definitions are refused not because each was named, but because none
is on the list — and so is every hatch the four paragraphs never thought of.
