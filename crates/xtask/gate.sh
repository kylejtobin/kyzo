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
# `--progress quiet` so docker's own container-lifecycle chatter does not land
# in gate.log next to the findings. It suppresses the wrapper, never the output
# of the thing being run — .claude/hooks/rust-scan-guard.sh already invokes it
# this way.
IN_CONTAINER=(docker compose --progress quiet run --rm -T kyzo-dev)

verdict() {
  # $1 = gate.log headline, $2 = gate-counts.txt body, $3 = the detail (optional)
  #
  # Line 2 stamps the tree the verdict describes. Without it a verdict is a
  # claim about no particular tree: leave an old ACKNOWLEDGE behind, change
  # anything, and the stop guard reads clearance it was never given. The stamp
  # is what makes a green verdict expire.
  #
  # $3 lands from line 3 onward: every finding, or every compile error. Before
  # this, gate.log held two lines and the findings existed nowhere an agent
  # could read — each one had to re-run a full scan to learn what was already
  # known, or take a wall of text through its context. Lines 1 and 2 are the
  # only ones .claude/hooks/gate-stop-guard.sh reads (head -n 1, sed -n 2p), so
  # the detail cannot reach the latch.
  sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    state=dirty
  else
    state=clean
  fi
  printf '%s\nat %s %s\n' "$1" "$sha" "$state" > "$LOG"
  if [ -n "${3:-}" ]; then
    printf '\n%s\n' "$3" >> "$LOG"
  fi
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
    "$(printf 'build = %s compile errors\n%s\n' "$errs" "$first")" \
    "$build_out"
  printf '%s\n' "$build_out" | tail -n 40
  exit 1
fi

# ---- 2. what shapes does it contain ------------------------------------------
det_out="$("${IN_CONTAINER[@]}" cargo run --release --quiet -p bs-detector -- --root . 2>&1)"
total_line="$(printf '%s' "$det_out" | grep -E '^total = [0-9]+ violations' | tail -n 1)"
n="$(printf '%s' "$total_line" | sed -n 's/^total = \([0-9][0-9]*\) violations.*/\1/p')"
n="${n:-?}"
per_rule="$(printf '%s' "$det_out" | grep -E '^R[0-9][0-9]  ')"

if [ "$n" = "0" ]; then
  verdict "GATE: ACKNOWLEDGE" "$(printf '%s\ntotal = 0 violations\n' "$per_rule")"
  exit 0
fi

verdict \
  "GATE: ALARM ${total_line#total = }" \
  "$(printf '%s\n%s\n' "$per_rule" "$total_line")" \
  "$det_out"
printf '%s\n' "$det_out" | tail -n 20
exit 1
