#!/usr/bin/env bash
# Stop hook: block stopping while the detector gate is dirty or mid-run.
# Only bs-detector writes gate.log; the test verbs run under `cargo xtask gate`
# (`just seal`) and are not read here.
#
# OPERATOR CONTROL: crates/bs-detector/pester-hook.txt owns this hook.
# Comment (#) and blank lines there are documentation; the first remaining
# line is the switch — anything other than "on" disables the block entirely —
# and every remaining line after it is the violation message, printed
# verbatim. This script carries no copy of the message.
set -u

MSG="${CLAUDE_PROJECT_DIR:-.}/crates/bs-detector/pester-hook.txt"
[ -f "$MSG" ] || exit 0
switch="$(grep -v '^#' "$MSG" | grep -v '^[[:space:]]*$' | head -n 1)"
if [ "$switch" != "on" ]; then
  exit 0
fi

LOG="${CLAUDE_PROJECT_DIR:-.}/crates/xtask/gate.log"
LOCK="$LOG.lock"

if [ -d "$LOCK" ]; then
  exit 0
fi

# Rate cap (operator-ordered): fire at most once per minute, so a red gate
# pesters without machine-gunning while the team's commits keep the watcher
# rewriting the verdict.
STAMP="${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/.pester-last"
now="$(date +%s)"
if [ -f "$STAMP" ]; then
  last="$(cat "$STAMP" 2>/dev/null || echo 0)"
  case "$last" in *[!0-9]*) last=0 ;; esac
  if [ $((now - last)) -lt 60 ]; then
    exit 0
  fi
fi

[ -f "$LOG" ] || exit 0
head1="$(head -n 1 "$LOG")"

case "$head1" in
  "GATE: ACKNOWLEDGE"* ) exit 0 ;;
  "GATE: ALARM"* )
    echo "$now" > "$STAMP"
    # Echo the verdict verbatim. It is authored by crates/xtask/gate.sh, the
    # only thing holding both facts; recomposing it here from the counts file
    # would be a second authority, and a bare violation count cannot say
    # "the workspace does not build".
    echo "$head1 — gate.log records what was found; it is never edited to change it" >&2
    exit 2
    ;;
  *) exit 0 ;;
esac
