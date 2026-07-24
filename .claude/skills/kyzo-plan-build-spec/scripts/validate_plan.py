#!/usr/bin/env python3
"""validate_plan.py — the deterministic refusal for a kyzo-plan-build-spec doc.

The strategy's move #4 (the spec is the program) applied to the skill itself:
this gate rejects a draft that is not a closed, default-deny declaration, so
the skill does not merely ask for the format — it refuses drafts that lack it.

Default-deny checks, sensitive by design (a flag is not a proof of malice; it
is a suspicious construct that must be fixed or justified in writing):

  open-table       a markdown table with no closure sentence after it
  no-closure       the document contains a table but no closure sentence at all
  foreclosure      prose that forbids a construct AND argues why — make it a row
  count-as-goal    a count / tally / "get to green" stated as a goal or proof

Exit 0 iff zero flags. Exit 1 otherwise, one `path:line: [check] message` per
flag. Usage: python validate_plan.py <file> [<file> ...]
"""
from __future__ import annotations

import re
import sys

# A closure sentence asserts totality AND refusal of the unlisted.
TOTALITY = re.compile(r"\b(total|exhaustive|complete(?:ly)?|closed)\b", re.I)
REFUSAL = re.compile(r"\b(red|refus\w+|reject\w+|denied|not listed|by construction)\b", re.I)

# Foreclosure prose: a prohibition together with an argument for it.
PROHIBITION = re.compile(r"\b(is red|forbidden|is banned|not allowed|must not|disallowed)\b", re.I)
ARGUMENT = re.compile(r"\b(because|the temptation|reason|why it|explains?|so that)\b", re.I)

# Count / green stated as a goal or a proof.
COUNT_AS_GOAL = re.compile(
    r"(get (it|them|this)?\s*(down |back )?to (zero|green)"
    r"|make it green|drive[ns]?\b.{0,20}\b(down|to zero)"
    r"|zero violations|gate total\s*\d|=\s*\d+\s*violations"
    r"|\b\d+\s*(violations|self-reds?)\b.{0,20}\b(to|down|left|remaining)"
    r"|\bpassed?\s+\d+\s+tests?\b)",
    re.I,
)


def is_closure(line: str) -> bool:
    return bool(TOTALITY.search(line) and REFUSAL.search(line))


def is_table_row(line: str) -> bool:
    return line.lstrip().startswith("|")


def check_file(path: str) -> list[str]:
    flags: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [f"{path}:0: [read] cannot read file: {exc}"]

    in_fence = False
    saw_table = False
    saw_closure = False
    i = 0
    n = len(lines)

    while i < n:
        raw = lines[i]
        line = raw.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("```"):
            in_fence = not in_fence
            i += 1
            continue
        if in_fence:
            i += 1
            continue

        if is_closure(line):
            saw_closure = True

        # A table block: consecutive rows starting with '|'.
        if is_table_row(line):
            saw_table = True
            start = i
            while i < n and is_table_row(lines[i].rstrip("\n")):
                i += 1
            # Look at the next up-to-3 non-blank lines for a closure sentence.
            closed = False
            look = i
            seen = 0
            while look < n and seen < 3:
                nxt = lines[look].rstrip("\n")
                if nxt.strip():
                    if is_closure(nxt):
                        closed = True
                        break
                    seen += 1
                look += 1
            if not closed:
                flags.append(
                    f"{path}:{start + 1}: [open-table] table has no closure "
                    f"sentence within 3 lines (add: total; not listed = red)"
                )
            continue

        # Foreclosure prose: prohibition + argument, outside a table, not itself
        # a closure sentence.
        if (
            stripped
            and not stripped.startswith("#")
            and not is_closure(line)
            and PROHIBITION.search(line)
            and ARGUMENT.search(line)
        ):
            flags.append(
                f"{path}:{i + 1}: [foreclosure] prohibition argued in prose — "
                f"make it a table row, keep only the meter as prose"
            )

        if COUNT_AS_GOAL.search(line):
            flags.append(
                f"{path}:{i + 1}: [count-as-goal] a count/tally/green stated as "
                f"goal or proof — remove it; lawful-or-red is the only status"
            )

        i += 1

    if saw_table and not saw_closure:
        flags.append(
            f"{path}:0: [no-closure] document has tables but no closure "
            f"sentence anywhere (total; not listed = red)"
        )

    return flags


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python validate_plan.py <file> [<file> ...]", file=sys.stderr)
        return 2
    all_flags: list[str] = []
    for path in argv[1:]:
        all_flags.extend(check_file(path))
    if all_flags:
        for f in all_flags:
            print(f)
        print(f"\nREFUSED: {len(all_flags)} flag(s). Fix each, or justify it in writing.")
        return 1
    print("clean: closed tables, no foreclosure prose, no count-as-goal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
