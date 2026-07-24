# <SPEC NAME> — default-deny declaration

## Laws

State the small number of load-bearing laws as prose. A law is a claim the
whole spec depends on; it survives as prose because compressing it loses teeth.

- **Law 1.** <the invariant, one sentence>.
- **Law 2.** <the invariant, one sentence>.
- **Closure law.** Every table below is total: a construct, door, refusal, or
  verb not listed in its table is red by default and lands on a bot's desk
  until cleared. Nothing is silent.

## Constructs

| construct | shape (how it is recognized) | meter (what falsifies it) |
| --- | --- | --- |
| <name> | <structural discriminator> | <deny fixture that must go red> |

This table is total: a construct not listed here is red.

## Doors — who may write what

| door | writes | role |
| --- | --- | --- |
| <door> | <relation(s)> | <role> |

This table is total: a write through no door listed here never derives accepted and is refused.

## Refusals

| refusal | trigger |
| --- | --- |
| <name> | <the exact condition that fires it> |

This table is total: a failure mode with no refusal listed here is a missing tripwire, not an allowance — add the row.

## Verbs

| verb | derivation it fronts |
| --- | --- |
| <verb> | <the query/derivation it runs> |

This table is total: a verb not listed here does not exist.

## Rulings

| pick | what it makes unrepresentable | how to falsify it | rejected alternative |
| --- | --- | --- | --- |
| <choice> | <the illegal state it removes> | <the meter> | <alt — one clause> |

This table is total: a design choice not recorded here is unmade and red.

## Current state

State what is truly built versus named-and-red. Default every unbuilt seat to
red; a seat is built only when its meter runs and refuses its deny fixture.

| item | state | meter run? |
| --- | --- | --- |
| <item> | built \| named-and-red | <yes: the run \| no> |

This table is total: an item not listed here is named-and-red by default.
