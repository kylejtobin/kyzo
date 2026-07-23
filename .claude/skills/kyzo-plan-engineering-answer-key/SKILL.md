---
name: kyzo-plan-engineering-answer-key
description: >-
  Produces the canonical settled engineering answer for a task using a fixed
  three-pass resolution checklist. Use when you need the correct architecture
  choice, a known-good decision, how to resolve a design fork safely, whether
  to escalate, what max-purity work looks like, the hardest decision, or the
  answer key so you do not pick the wrong option. Emits a sealed question, the
  definitive answer, and the proof that no better alternative exists.
---

# Engineering Answer Key

This is the resolution checklist. Follow it exactly. It settles the decision so
you are not left gambling on a risky option.

## Instructions

**Pattern: sequential workflow orchestration.** Three passes. One open at a
time. Do not merge passes. Do not skip gates. Do not load the next reference
until the current gate passes.

For the inserted task (or the current engineering fork if none is labeled):

### Step 1 — Question pass

1. Read only `references/pass-1-question.md`.
2. Emit **only** the sealed interrogative that file demands.
3. **Gate:** output contains exactly one question; zero answers; zero
   recommendations; zero "options include…". If anything else appears, delete
   it and redo Step 1.

### Step 2 — Answer pass

1. Only after Step 1's gate passes, read `references/pass-2-answer.md`.
2. Answer **that** question only, in the form that file demands (choose A,
   refuse B; constructible; no hedge).
3. **Gate:** Part 1 answer is present; explanation section is **absent**. If
   you explained why, strip it and redo Step 2.

### Step 3 — Explanation pass

1. Only after Step 2's gate passes, read `references/pass-3-explanation.md`.
2. Emit only the explanation that file demands.
3. **Gate:** every rejected alternative (including B and hybrids) names the
   purity it sacrifices and the escape hatch it opens. If any escape remains
   open, redo Step 3.

### Finalization

Emit the three passes in order as three labeled blocks:

```text
## Question
...
## Answer
...
## Explanation
...
```

Stop. Do not implement code in this skill unless the operator explicitly asks
after the three blocks.

## Examples

### Example 1

User: "Should we soft-pass the detector until the tree is clean?"

Actions:
1. Question pass only → sealed A vs B on soft-pass-as-design vs live red + confess/fix.
2. Answer pass → refuse soft-pass-as-design; choose live verdict + confession-only.
3. Explanation pass → why no hybrid/bootstrap/carve-out is purer.

Result: three blocks; decision settled; no implementation until asked.

## Troubleshooting

Error: Combined question and answer in one message.
Cause: Skipped the Step 1 gate.
Solution: Delete the answer; re-run Step 1 only; then Step 2.

Error: "Prefer A for now, revisit later."
Cause: Hedge / deferral theater.
Solution: Fail Step 2 gate; rewrite as choose A / refuse B with no timeline.

Error: Escalated to operator without naming two contradicting laws.
Cause: Coward's escape.
Solution: Fail Step 2/3; either decide under max purity or state both laws and
still pick A.
