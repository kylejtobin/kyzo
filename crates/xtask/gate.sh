#!/usr/bin/env bash
# gate.sh — the ONE local gate caller, and the SOLE author of the verdict.
#
# Two facts decide a tree's state: does it compile, and what shapes does it
# contain. Nothing else holds both, so nothing else writes crates/xtask/gate.log
# or gate-counts.txt. The detector reports; this decides.
#
# Order is severity, not convenience. A tree that does not compile has no
# meaningful shape count — the detector reads text and will happily report
# thousands of findings about code that cannot build, which reads as "some lint
# debt" when the truth is "nothing runs". Build failure outranks findings, and
# is what the log says.
#
# This is the fast conduct loop, NOT a second gate: the full seal — build +
# clippy + all tests + detector — is
#     docker compose run --rm kyzo-dev cargo xtask gate
# There is one command shape and one authority; this is a subset of it, never a
# divergent verdict.
#
# To look at one file while working, aim the detector directly:
#     cargo run --release -p bs-detector -- <path>
# which reports to stdout and writes nothing.
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1

LOG="crates/xtask/gate.log"
COUNTS="crates/xtask/gate-counts.txt"
IN_CONTAINER=(docker compose run --rm -T kyzo-dev)

verdict() {
  # $1 = gate.log headline, $2 = gate-counts.txt body
  printf '%s\n' "$1" > "$LOG"
  printf '%s\n' "$2" > "$COUNTS"
  printf '%s\n' "$1"
}

# ---- 1. does it compile ------------------------------------------------------
build_out="$("${IN_CONTAINER[@]}" cargo check --workspace --all-targets 2>&1)"
build_rc=$?

if [ $build_rc -ne 0 ]; then
  errs="$(printf '%s' "$build_out" | grep -cE '^error(\[|:)')"
  first="$(printf '%s' "$build_out" | grep -E '^error(\[|:)' | head -n 1)"
  verdict \
    "GATE: ALARM build broken — ${errs} compile errors" \
    "$(printf 'build = %s compile errors\n%s\n' "$errs" "$first")"
  printf '%s\n' "$build_out" | tail -n 40
  exit 1
fi

# ---- 2. what shapes does it contain ------------------------------------------
det_out="$("${IN_CONTAINER[@]}" cargo run --release --quiet -p bs-detector -- --root . 2>&1)"
total_line="$(printf '%s' "$det_out" | grep -E '^total = [0-9]+ violations' | tail -n 1)"
n="$(printf '%s' "$total_line" | sed -n 's/^total = \([0-9][0-9]*\) violations.*/\1/p')"
n="${n:-?}"
per_rule="$(printf '%s' "$det_out" | grep -E '^R[0-9][0-9]  ')"

# An exemption is a shape that is still present. It never leaves the verdict:
# a tree at zero violations with declared exemptions is not the same tree as
# one with none, and the headline has to say which it is.
ex="$(printf '%s' "$det_out" | sed -n 's/^exempt = \([0-9][0-9]*\) declared$/\1/p' | tail -n 1)"
ex="${ex:-?}"

if [ "$n" = "0" ]; then
  verdict \
    "GATE: ACKNOWLEDGE — 0 violations, ${ex} exempt" \
    "$(printf '%s\nexempt = %s declared\ntotal = 0 violations\n' "$per_rule" "$ex")"
  exit 0
fi

verdict \
  "GATE: ALARM ${total_line#total = }, ${ex} exempt" \
  "$(printf '%s\nexempt = %s declared\n%s\n' "$per_rule" "$ex" "$total_line")"
printf '%s\n' "$det_out" | tail -n 20
exit 1
