#!/usr/bin/env bash
# UserPromptSubmit hook: BUILD GATE notice + live BS-detector counts.
# (bs-message.txt at the repo root belongs to the STOP guard, not this hook.)
# The count line is produced by the gate itself — run_bs_detector writes
# crates/xtask/gate-counts.txt on every gate run (watcher fires on every
# crates/ change). This script only echoes that artifact; it never counts
# the tree itself — a second counting authority is the fraud the gate kills.
f="${CLAUDE_PROJECT_DIR:-.}/crates/xtask/gate-counts.txt"
if [ -f "$f" ]; then
    n="$(sed -n 's/.*= \([0-9][0-9]*\) violations.*/\1/p' "$f")"
    printf 'GATE ALARM: %s violations\n' "${n:-?}"
else
    printf 'GATE ALARM: no count yet\n'
fi
