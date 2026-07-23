#!/usr/bin/env bash
# SessionStart hook: make sure the gate file watcher is running.
set -u
SCRIPT="${CLAUDE_PROJECT_DIR:-.}/crates/xtask/gate-watch.sh"
if ! pgrep -f "xtask/gate-watch.sh" > /dev/null 2>&1; then
  nohup "$SCRIPT" > /dev/null 2>&1 &
  disown 2>/dev/null || true
fi
exit 0
