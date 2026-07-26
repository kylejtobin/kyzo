#!/usr/bin/env bash
# UserPromptSubmit hook: echo the gate verdict.
#
# The verdict is authored by crates/xtask/gate.sh, which is the only thing that
# knows both whether the tree compiles and what it contains. This script echoes
# that headline verbatim and computes nothing — a second counting authority is
# the fraud the gate exists to catch, and a bare number cannot distinguish
# "1122 forbidden shapes" from "the workspace does not build".
f="${CLAUDE_PROJECT_DIR:-.}/crates/xtask/gate.log"
if [ -f "$f" ]; then
    head -n 1 "$f"
else
    printf 'GATE: no verdict yet — run `just gate`\n'
fi
