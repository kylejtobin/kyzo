#!/usr/bin/env bash
# The operator's on/off switch, read in exactly one place.
#
# crates/bs-detector/pester-hook.txt owns whether the guards are armed. Two
# hooks obey it — gate-stop-guard.sh and rust-scan-guard.sh — and neither
# carries its own copy of what counts as "on". A second copy of this parse is a
# second authority: the two scripts could then disagree about the same file,
# and "is the pester armed?" would have two answers. It had two answers until
# now — the stop guard read the switch, the scan guard did not, so `off` in
# that file disarmed one of them and the other kept blocking every tool call.
#
# Comment (#) and blank lines are documentation. The first remaining line is
# the switch. Anything other than "on" disarms.
#
# Absent file means disarmed: a guard that arms itself when its control is
# missing cannot be turned off by deleting it.

pester_armed() {
  local msg="${CLAUDE_PROJECT_DIR:-.}/crates/bs-detector/pester-hook.txt"
  [ -f "$msg" ] || return 1
  local switch
  switch="$(grep -v '^#' "$msg" | grep -v '^[[:space:]]*$' | head -n 1)"
  [ "$switch" = "on" ]
}
