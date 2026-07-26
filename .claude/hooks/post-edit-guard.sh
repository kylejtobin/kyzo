#!/usr/bin/env bash
# PostToolUse(Edit|Write) hook: fire bs-detector at the file that just changed.
#
# Any forbidden shape in the file blocks. Not the shapes this edit introduced —
# every shape in the file. A file you touched is a file you own. Pre-existing
# violations are not an exemption; they are the reason the count never falls.
#
# There is no exemption and nothing to declare. The detector has no marker and
# no attribute that suppresses a rule, so there is no way to answer this block
# except by fixing the shape.
#
# One detector, one rule set, one command shape. This is `bs-detector <path>`,
# the same aim mode a person runs by hand and the same rules the gate applies to
# the whole tree. It writes no verdict — aim mode never does.
#
# Every path out of this script is either "clean" or "blocked". A guard that
# exits 0 because it could not do its job is a guard that is off.
set -uo pipefail

block() {
  jq -cn --arg r "$1" '{decision:"block",reason:$r}'
  exit 0
}

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)}"
file=$(jq -r '.tool_input.file_path // ""')

# Not a Rust file: the detector has no rules for it. This is the only silent
# exit, and it is a fact about the rules, not about whether the guard ran.
case "$file" in
  *.rs) ;;
  *) exit 0 ;;
esac

abs="$file"
[ -f "$abs" ] || abs="$root/$file"
[ -f "$abs" ] || block "The shape guard was told $file was written and cannot find it, so this edit is unchecked. Resolve the path and re-run: cargo run --release -p bs-detector -- <path>"

cd "$root" || block "The shape guard could not enter $root, so this edit is unchecked."
rel="${abs#"$root"/}"

# Same invocation as crates/xtask/gate.sh, so the hook and the gate cannot
# disagree about what the rules are.
out="$(docker compose --progress quiet run --rm -T kyzo-dev \
        cargo run --release --quiet -p bs-detector -- "$rel" 2>&1)"
rc=$?

# The detector exits non-zero when it finds shapes and prints its summary line.
# Non-zero without that line means it never got that far.
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

This is mandatory to finish, not advisory. There is no exemption marker and no
attribute that silences a rule — the only way past this is to change the shape.
The rules are in crates/bs-detector/README.md. Re-check with:
  cargo run --release -p bs-detector -- $rel"
