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

# Clearance is one exact thing: a current ACKNOWLEDGE. Everything else blocks —
# no log, an unreadable log, a headline in a vocabulary this script does not
# know, or a green verdict describing a tree that is no longer this one. A
# default-pass here is how the guard gets disarmed by accident: a leftover
# gate.log from a deleted script once read "GATE: FAIL detector-did-not-run",
# which matched neither arm and silently cleared every stop.
head1=""
stamp2=""
if [ -f "$LOG" ]; then
  head1="$(head -n 1 "$LOG")"
  stamp2="$(sed -n '2p' "$LOG")"
fi

# "Current" is about the code, not about commits: a green verdict expires the
# moment a source file changes under it. Requiring a committed tree instead
# would nag through every working session without measuring anything more.
newer="$(find "${CLAUDE_PROJECT_DIR:-.}/crates" -name '*.rs' -newer "$LOG" -print -quit 2>/dev/null)"
if [ -n "$stamp2" ] && [ -z "$newer" ]; then
  current=yes
else
  current=no
fi

case "$head1" in
  "GATE: ACKNOWLEDGE"*)
    [ "$current" = yes ] && exit 0
    echo "$now" > "$STAMP"
        why="source has changed since it was written (${newer#"${CLAUDE_PROJECT_DIR:-.}/"})"
    [ -n "$stamp2" ] || why="it carries no stamp, so it describes no particular tree"
    echo "GATE: ACKNOWLEDGE is stale — $why. Re-run \`just gate\`; a verdict about another tree is not clearance for this one." >&2
    exit 2
    ;;
  "GATE: ALARM"*)
    echo "$now" > "$STAMP"
    # Echo the verdict verbatim. It is authored by crates/xtask/gate.sh, the
    # only thing holding both facts; recomposing it here from the counts file
    # would be a second authority, and a bare violation count cannot say
    # "the workspace does not build".
    echo "$head1 — gate.log records what was found; it is never edited to change it" >&2
    exit 2
    ;;
  "")
    echo "$now" > "$STAMP"
    echo "GATE: no verdict — crates/xtask/gate.log is missing or empty. Run \`just gate\`. An absent verdict is not a passing one." >&2
    exit 2
    ;;
  *)
    echo "$now" > "$STAMP"
    echo "GATE: unrecognised verdict '$head1'. gate.sh writes ACKNOWLEDGE or ALARM and nothing else; anything else means something other than the gate wrote this file. Run \`just gate\`." >&2
    exit 2
    ;;
esac
