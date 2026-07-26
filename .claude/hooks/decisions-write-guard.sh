#!/usr/bin/env bash
# PreToolUse(Edit|Write|MultiEdit|NotebookEdit) + PreToolUse(Bash) hook:
# docs/kyzo-plan/decisions.md is the operator's ruling document. NO agent
# writes it — not the main session, not any subagent, not via shell
# redirection, rename, or git plumbing. There is no exemption list on
# purpose: no agent identity unlocks this file, by any route.
# Reads stay legal for everyone; the law is meant to be read.
set -euo pipefail

input=$(cat)
tool=$(printf '%s' "$input" | jq -r '.tool_name // ""')

deny() {
  jq -cn --arg m "$1" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$m}}'
  exit 0
}

msg="docs/kyzo-plan/decisions.md is operator-owned. No agent writes, renames, moves, or reverts it by any means. Propose the change to the operator in chat and stop."

# Any shell verb that could create, modify, move, or roll back the file.
write_shaped='>|(^|[^[:alnum:]_.-])(tee|mv|cp|rm|ln|install|truncate|dd|python3?|perl|patch|ed)([^[:alnum:]_.-]|$)|sed[[:space:]]+-i|awk[[:space:]]+-i|git[[:space:]]+(checkout|restore|apply|stash|reset|clean|mv|rm|revert)'

# Any spelling that reaches the ruling document.
target='decisions\.md|docs/kyzo-plan'

if [ "$tool" = "Bash" ]; then
  cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // ""')
  if printf '%s' "$cmd" | grep -Eq "$target" \
     && printf '%s' "$cmd" | grep -Eq "$write_shaped"; then
    deny "$msg"
  fi
  exit 0
fi

path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.notebook_path // ""')
case "$path" in
  *docs/kyzo-plan/*|*decisions.md)
    deny "$msg"
    ;;
esac

exit 0
