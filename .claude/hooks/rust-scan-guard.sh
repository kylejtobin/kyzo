#!/usr/bin/env bash
# Hash crates/ before a tool runs, hash it after, scan whatever differs.
#
#   PreToolUse  (matcher: *)  ->  rust-scan-guard.sh before
#   PostToolUse (matcher: *)  ->  rust-scan-guard.sh after
#
# The hook this replaces matched Edit|Write and read the tool's file_path. It
# was trivially avoided: a heredoc into python3, a sed -i, a shell redirect, a
# generated script — none are Edit or Write, so none were scanned. That bypass
# was used dozens of times in one session while the guard reported nothing.
#
# Nothing here looks at the tool or the command. It compares a SHA-256 of every
# Rust file under crates/ taken before the call against one taken after. A file
# whose content changed cannot hide: not by tool choice, not by preserved
# mtimes (touch -r defeats an mtime scheme; it does not defeat a hash), not by
# writing through a script. Hashing all 357 files costs ~28ms.
#
# Findings are sticky. A file that scanned dirty stays on an outstanding list
# and is re-scanned on EVERY subsequent tool call until it comes back clean, so
# the block cannot be waited out or stepped around by doing something else.
#
# OPERATOR CONTROL: crates/bs-detector/pester-hook.txt owns this hook, the same
# switch gate-stop-guard.sh obeys, read through the one parse in
# pester-switch.sh. The check comes before both modes: while disarmed this
# hashes nothing and pins nothing, so arming it later does not dump a whole
# session of stale findings at once.
set -uo pipefail

# shellcheck source=pester-switch.sh
. "$(dirname "${BASH_SOURCE[0]}")/pester-switch.sh"
pester_armed || exit 0

mode="${1:-after}"
root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)}"
state="${TMPDIR:-/tmp}/kyzo-rust-scan-$(printf '%s' "$root" | tr -c 'A-Za-z0-9' '-')"
BEFORE="$state/before.sha"
OUTSTANDING="$state/outstanding.list"
mkdir -p "$state"
cd "$root" 2>/dev/null || exit 0

# Plain `sort` on the whole line, both sides, because `comm` compares on the
# default collation. Sorting by filename with `-k2` and then handing the result
# to `comm` reports every line as differing, which made the guard fire on calls
# that changed nothing.
manifest() {
  find crates -name '*.rs' -not -path '*/target/*' -exec sha256sum {} + 2>/dev/null | sort
}

if [ "$mode" = "before" ]; then
  manifest > "$BEFORE"
  exit 0
fi

# ---- after -------------------------------------------------------------------
[ -f "$BEFORE" ] || { manifest > "$BEFORE"; exit 0; }

# Files whose hash differs, plus files still carrying findings from earlier.
changed=$(comm -13 <(sort "$BEFORE") <(manifest) | awk '{print $2}')
outstanding=$([ -f "$OUTSTANDING" ] && cat "$OUTSTANDING" || true)
targets=$(printf '%s\n%s\n' "$changed" "$outstanding" | grep -v '^$' | sort -u)

manifest > "$BEFORE"
[ -n "$targets" ] || exit 0

# Only files that still exist; a deleted file has no shapes to report.
present=$(printf '%s\n' "$targets" | while read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done)
[ -n "$present" ] || { : > "$OUTSTANDING"; exit 0; }

block() {
  jq -cn --arg r "$1" '{decision:"block",reason:$r}'
  exit 0
}

out=$(docker compose --progress quiet run --rm -T kyzo-dev \
        cargo run --release --quiet -p bs-detector -- $present 2>&1)
rc=$?

if [ $rc -ne 0 ] && ! printf '%s' "$out" | grep -q 'forbidden shapes in'; then
  printf '%s\n' "$present" > "$OUTSTANDING"
  block "The shape scan could not run, so these changes are unchecked:

$present

$out

Fix the guard. An unchecked change is not a passing change."
fi

if [ $rc -eq 0 ]; then
  : > "$OUTSTANDING"
  exit 0
fi

# Keep exactly the files that reported, so clean ones stop being re-scanned.
printf '%s' "$out" | grep -oE '^[^:]+\.rs' | sort -u > "$OUTSTANDING"

block "<required_action>
Fix every finding in the files below before anything else. Report each change
and the illegal state it makes unconstructible.
</required_action>

<findings>
$(printf '%s' "$out" | tail -n 2)

$(cat "$OUTSTANDING")

Read them: crates/xtask/gate.log, or aim the detector at one path —
    cargo run -q --release -p bs-detector -- <path>
</findings>

<scope>
These are yours because you touched these files, not because they were your
task. Violations that survive because they predate the editor are how the
count never falls.
</scope>

<what_counts_as_fixed>
Start from the type, not the diagnostic. Binary order equals semantic order;
the invariant goes in a type, not a check, comment, or convention; untyped
surface area is removed, not documented.

If your change makes no illegal state unconstructible, it is a workaround.
A runtime check where a private constructor belongs is worse than the
finding, because it is now labelled fixed.
</what_counts_as_fixed>

<if_the_rule_is_wrong>
Say so in chat: rule, mishandled input, correct shape. Rules live in
crates/bs-detector/README.md.
</if_the_rule_is_wrong>"
