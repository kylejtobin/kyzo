---
name: kyzo-plan-build-spec
description: Build KyzoDB plans and specs as escape-proof default-deny declarations — closed tables shut by one closure sentence, ontology as data the engine loads, and every not-provably-lawful construct red by default. Use when writing, rewriting, or auditing a plan, spec, law or TRUTH doc, or ontology, or whenever a document forbids escapes one at a time instead of closing them all in one sentence. Turns blacklist-with-arguments prose into total tables, rulings into one-line rows, and the spec into the program so it cannot be evaded without the diff going red.
---

# kyzo-plan-build-spec

Write a spec that closes the hatches nobody imagined. A blacklist forbids escapes one at a time and blocks only the ones you named; a whitelist plus one closure sentence refuses everything outside it by construction. Default-deny, applied to the document itself.

## Critical

- **Whitelist, never blacklist.** List what is lawful, then add one closure sentence: everything not listed is red. Delete every "X is forbidden because…" paragraph — the closure already forbids it, and for free it forbids the escapes no author imagined.
- **No counts, no green.** A violation count, a pass tally, "get it to zero," "make it green" — none of these is ever a goal or a proof, and any of them in a spec is the sabotage. Assume quantity is infinite and irrelevant. The only question is: is every construct lawful, or red.
- **Max sensitivity, not clever matchers.** A construct that is not provably lawful trips the wire and lands on a bot's desk, red until cleared. Do not build advanced pattern matchers that recognize the lawful and silently pass the rest — flag the suspicious and make a bot file the paperwork.
- **The spec is the program.** Put ontology — relations, laws, doors, refusals, verbs — in data the engine loads, so the spec and the code are one artifact and cannot diverge without the diff going red.
- **Gate before done.** Run `python scripts/validate_plan.py <file>`. It is the deterministic refusal, not a suggestion. A draft it flags is not done until each flag is fixed or justified in writing.

## The four moves

1. **Whitelist + closure sentence.** Enumerate the lawful things. Close with one sentence — "this table is total; anything not listed is red." No anti-escape prose needed.
2. **Tables, not essays.** Any enumerable content (lawful constructs, who-may-write-what, refusal triggers, verbs) becomes rows under a header sentence: *total; not listed = red*. That one sentence does the work of every foreclosure paragraph at once.
3. **Rulings become rows.** One line each: `pick | what it makes unrepresentable | how to falsify it | rejected alternative (one clause)`. The clause only explains; the closure already forbids.
4. **Spec is the program.** Move the ontology into data rows (the TOML/relation form the engine actually loads). The document and the program become one artifact; evading the spec derives red.

## Steps

1. Start from `assets/plan-template.md`.
2. Convert every enumerable set to a total table + closure sentence.
3. Convert every ruling to a one-line row.
4. Move ontology (relations, doors, refusals, verbs) into data the engine loads.
5. Delete foreclosure prose. Keep only the core laws, the closure sentences, the falsification procedures (meters), and the current-state block.
6. Run `python scripts/validate_plan.py <file>`. Clear or justify every flag.

## What survives as prose

The core laws, the closure sentences, the meters (each a falsification procedure — how to prove the law broken), and the current-state block (what is truly built versus named-and-red). Everything else is a row or data.

## Quality checklist (before finalize)

- [ ] Every table ends with a closure sentence: *total; not listed = red*.
- [ ] No "X is forbidden because…" paragraph survives — each is a row or deleted.
- [ ] No count, tally, or "get to green" appears as a goal or a proof anywhere.
- [ ] Ontology (relations/laws/doors/refusals/verbs) is data the engine loads, not prose.
- [ ] Every law names its meter — the procedure that falsifies it.
- [ ] A current-state block states what is truly built versus named-and-red.
- [ ] `validate_plan.py` exits clean, or every flag is justified in writing.

## Examples

**Rewrite a blacklist into a closed table.** Four paragraphs each forbidding one construct with a reason → one table of lawful constructs + `This table is total; a construct not listed is red.` The reader who tries an unlisted construct is refused by the sentence, not by a paragraph that had to anticipate them.

**Author a new spec.** Fill the template: the laws stay prose; relations/doors/refusals/verbs go straight into data rows; each law gets a meter; the current-state block starts every unbuilt seat as named-and-red.

**Audit a doc.** Run the validator. Every open table (no closure sentence), foreclosure essay, or count-as-goal is a flag to fix.

## Troubleshooting

- **Validator flags a law line as foreclosure prose.** It matched a prohibition plus an argument in prose. Move the prohibition into a table row; keep only the meter as prose.
- **Validator flags a count.** A tally is stated as a goal or proof. Remove it — the run's lawful-or-red verdict is the only status.
- **Validator says no closure sentence.** The document has tables with no total-and-red closure. Add one per table.

See `references/four-moves.md` for the full rationale, anti-patterns, and a worked before/after.
