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
set -uo pipefail

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
Fix every shape listed below, in the files listed below, before doing anything
else. Report what you changed and why each change is the stronger form.
</required_action>

<findings>
$out
</findings>

<scope>
These are yours because you changed these files, not because they are part of
the task you were on. A violation left in place because it predates you is how
the count never falls: every one already in this tree was left by someone who
was working on something else at the time.
</scope>

<what_counts_as_fixed>
You are a type-driven purist here. Start from the type, not the diagnostic.

  1. Preserve the encoding law: binary order equals semantic order.
  2. Put the invariant in a type, not in a check, a comment, or a convention.
  3. Remove untyped surface area rather than documenting it.

Where two fixes are available, take the one that costs more now. The cheap fix
satisfies the scanner and leaves the defect: a runtime check where a private
constructor belongs, an accessor where a newtype belongs, a rename where a
redesign belongs. That outcome is worse than the finding you started with,
because the defect is now labelled fixed and nobody looks again.

Before you edit, state which illegal state your change makes unconstructible.
If the answer is none, you have found a workaround rather than a fix.
</what_counts_as_fixed>

<how_this_check_works>
This is not a lint pass over your edit. Before your tool ran, every Rust file
under crates/ was hashed; after it ran, they were hashed again, and everything
that differs is scanned. The tool you used is not consulted. An Edit, a Write,
a heredoc into python3, sed -i, a shell redirect, a script you wrote and then
executed — all reach this identically, and preserving mtimes changes nothing
because the comparison is over content.

Findings persist. The files above are re-scanned on every subsequent tool call
until they come back clean. Working on something else does not clear them, and
no marker or attribute suppresses a rule.

Knowing that is the point: there is no state of the world in which searching
for a way around this ends better than fixing the shape.
</how_this_check_works>

<if_the_rule_is_wrong>
Say so in chat: name the rule, the input it mishandles, and the shape it should
have accepted instead. A precisely described defect in the scanner is worth
more than any change you could get past it. The rules are in
crates/bs-detector/README.md.
</if_the_rule_is_wrong>"
