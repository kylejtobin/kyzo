#!/usr/bin/env bash
# PreToolUse(Edit|Write|MultiEdit|NotebookEdit) + PreToolUse(Bash) hook:
# the detector, the gate caller, and the hooks that enforce them are
# operator-owned. An agent may read every one of them; changing one requires
# the operator to have named that exact path in the approval file first.
#
# The reason this is a wall and not a warning: these files are the only
# independent report on whether the tree is sound. An agent that can edit its
# own invigilator can make any tree look clean, and the edit leaves no trace
# anyone would see, because the thing that would report it is the thing that
# changed. Every route is covered — editor tools, shell redirection, sed -i,
# rename, and git plumbing — because a wall with one open side is a door.
set -euo pipefail

input=$(cat)
tool=$(printf '%s' "$input" | jq -r '.tool_name // ""')
root="${CLAUDE_PROJECT_DIR:-.}"
APPROVAL="$root/crates/bs-detector/OPERATOR-APPROVAL"

deny() {
  jq -cn --arg m "$1" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$m}}'
  exit 0
}

reason() {
  cat <<MSG
Stop here and ask the operator. Name the file, say exactly what you want to change and why, and wait for an answer.

$1 is part of the machinery that reports whether this codebase is sound: the detector's rules, the gate that writes the verdict, and the hooks that enforce both. An agent that edits its own invigilator can make any tree look clean, and afterwards nothing reports the change, because the thing that would have reported it is the thing that changed. The harm is not the diff — it is the loss of the only signal anyone has.

Operator approval is a line naming this exact path in crates/bs-detector/OPERATOR-APPROVAL. Only the operator writes that file; no agent route reaches it, including this one.

If you have found a real defect here, describe it in chat: which rule, the input it mishandles, and the shape it should have produced instead. A precisely described defect is worth more to this project than a silent fix in a file nobody can audit.
MSG
}

# The protected set, as path fragments.
protected='crates/bs-detector/|crates/xtask/gate\.sh|\.claude/hooks/|\.claude/settings\.json'

# The approval file itself is never writable by an agent — an approval an agent
# can grant itself is not an approval.
approves() {
  [ -f "$APPROVAL" ] || return 1
  printf '%s' "$1" | grep -Eq 'OPERATOR-APPROVAL' && return 1
  grep -v '^[[:space:]]*#' "$APPROVAL" 2>/dev/null \
    | grep -v '^[[:space:]]*$' \
    | grep -Fxq "$1"
}

if [ "$tool" = "Bash" ]; then
  cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // ""')
  # `>` only when it redirects to a file. `2>&1` and `>&2` move a descriptor
  # onto another descriptor and create nothing, so matching a bare `>` denied
  # read-only commands — a guard that blocks reads teaches people to route
  # around it, which is the one failure mode a wall cannot afford.
  write_shaped='>[[:space:]]*[^&|[:space:]]|(^|[^[:alnum:]_.-])(tee|mv|cp|rm|ln|install|truncate|dd|python3?|perl|patch|ed)([^[:alnum:]_.-]|$)|sed[[:space:]]+-i|awk[[:space:]]+-i|git[[:space:]]+(checkout|restore|apply|stash|reset|clean|mv|rm|revert)'

  # Discarding output is not writing to the tree. /dev/null is a fixed sink
  # that cannot name a repository file, so blank those redirects before the
  # write test — otherwise `./crates/xtask/gate.sh >/dev/null` reads as an edit
  # to gate.sh, and the guard blocks the gate from running at all.
  probe=$(printf '%s' "$cmd" | sed 's#[0-9]*>[[:space:]]*/dev/null##g')

  if printf '%s' "$probe" | grep -Eq "$protected" \
     && printf '%s' "$probe" | grep -Eq "$write_shaped"; then
    # Approvals mean the same thing on both branches. The editor branch has
    # always honoured them; this one did not, so an approved path could be
    # edited but not executed alongside a redirect, and the approval file meant
    # two different things depending on which tool you reached for.
    #
    # Every protected path the command names must be approved. One unapproved
    # path denies the whole command: a command touching an approved file and an
    # unapproved one is not half allowed. A command that matched the protected
    # pattern but yields no extractable path stays denied, because an
    # unreadable command is not an approved one.
    approved_all=0
    for candidate in $(printf '%s' "$probe" \
      | grep -oE '(crates/bs-detector/[A-Za-z0-9_./-]+|crates/xtask/gate\.sh|\.claude/hooks/[A-Za-z0-9_./-]+|\.claude/settings\.json)'); do
      approves "$candidate" || approved_all=1
      [ "$approved_all" -eq 0 ] || break
    done
    if [ "$approved_all" -ne 0 ] \
       || ! printf '%s' "$probe" | grep -qE '(crates/bs-detector/[A-Za-z0-9_./-]+|crates/xtask/gate\.sh|\.claude/hooks/[A-Za-z0-9_./-]+|\.claude/settings\.json)'; then
      deny "$(reason "This command writes to gate machinery, which")"
    fi
  fi
  exit 0
fi

path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.notebook_path // ""')
[ -n "$path" ] || exit 0
rel="${path#"$root"/}"

if printf '%s' "$rel" | grep -Eq "$protected"; then
  if approves "$rel"; then
    # Never silent: an approved write says so, so the operator sees each one
    # land rather than discovering the set later.
    jq -cn --arg m "Writing $rel under operator approval (crates/bs-detector/OPERATOR-APPROVAL names this path). Change only what was approved." \
      '{hookSpecificOutput:{hookEventName:"PreToolUse",additionalContext:$m}}'
    exit 0
  fi
  deny "$(reason "$rel")"
fi

exit 0
