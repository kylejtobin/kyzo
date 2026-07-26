#!/usr/bin/env bash
# PostToolUse(Edit|Write) hook: fire bs-detector at the file that just changed.
#
# Any forbidden shape in the file blocks. Not the shapes this edit introduced —
# every shape in the file. A file you touched is a file you own. Pre-existing
# violations are not an exemption; they are the reason the count never falls.
#
# One detector, one rule set, one command shape. This is `bs-detector <path>`,
# the same aim mode a person runs by hand and the same rules the gate applies
# to the whole tree. It writes no verdict — aim mode never does.
#
# Silent when the file is clean.
set -uo pipefail

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)}"
file=$(jq -r '.tool_input.file_path // ""')
[ -n "$file" ] || exit 0

case "$file" in
  *.rs) ;;
  *) exit 0 ;;
esac

abs="$file"
[ -f "$abs" ] || abs="$root/$file"
[ -f "$abs" ] || exit 0

rel="${abs#"$root"/}"
case "$rel" in
  crates/*) ;;
  *) exit 0 ;;
esac

block() {
  jq -cn --arg r "$1" '{decision:"block",reason:$r}'
  exit 0
}

cd "$root" || exit 0

# An edit that answers a block by declaring an exemption is not a fix. The
# marker is a debt the operator signs for, so a new one stops here.
before=$(git show "HEAD:$rel" 2>/dev/null | grep -c 'BS-EXEMPT:' || true)
after=$(grep -c 'BS-EXEMPT:' "$abs" || true)
if [ "${after:-0}" -gt "${before:-0}" ]; then
  block "This edit adds a BS-EXEMPT marker to $rel. An exemption is not a fix — the shape is still there, and the gate keeps counting it. Remove the marker and fix the shape. If the shape is genuinely correct and must stay, stop and ask the operator to sign for it."
fi

# Same invocation as crates/xtask/gate.sh, so the hook and the gate cannot
# disagree about what the rules are.
out="$(docker compose --progress quiet run --rm -T kyzo-dev \
        cargo run --release --quiet -p bs-detector -- "$rel" 2>&1)"
rc=$?

# A guard that cannot run must say so. Exiting 0 here would disarm it silently,
# which is worse than the shapes it looks for.
if [ $rc -ne 0 ] && ! printf '%s' "$out" | grep -q 'forbidden shapes in'; then
  block "The shape guard could not run against $rel, so this edit is unchecked. Output:

$out

Fix the guard first — an unchecked edit is not a passing edit."
fi

[ $rc -eq 0 ] && exit 0

block "bs-detector found forbidden shapes in $rel:

$out

Fix all of them before you continue.

It does not matter whether this edit introduced them or whether they belong to
the task you are on. You touched the file; you own what is in it. Leaving a
known violation in place because it predates you is how the count stays where
it is. Fix what you find.

This is mandatory to finish, not advisory. The rules are in
crates/bs-detector/README.md. Run 'cargo run --release -p bs-detector -- $rel'
to re-check."
