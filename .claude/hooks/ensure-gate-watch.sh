#!/usr/bin/env bash
# SessionStart hook: refresh the gate verdict once, in the background.
#
# Runs the ONE gate caller (crates/xtask/gate.sh -> bs-detector in the
# container), which writes crates/xtask/gate.log + gate-counts.txt that the
# stop-hook reads. Deliberately a single run, NOT a persistent file-watcher:
# a watcher that spawned a container on every save was the stuck-container /
# fuse-leak source. Re-run on demand with `just gate`.
set -u
SCRIPT="${CLAUDE_PROJECT_DIR:-.}/crates/xtask/gate.sh"
[ -x "$SCRIPT" ] || exit 0
if ! [ -d "${CLAUDE_PROJECT_DIR:-.}/crates/xtask/gate.log.lock" ]; then
  nohup "$SCRIPT" > /dev/null 2>&1 &
  disown 2>/dev/null || true
fi
exit 0
