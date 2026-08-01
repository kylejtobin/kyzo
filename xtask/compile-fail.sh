#!/usr/bin/env bash
#
# AUTHORITY: to fail the build when a forgery compiles.
#
# crates/canonical-forgery/src/bin/*.rs list the ways to reach the encoder's
# authority without a door. Every one must be rejected by the compiler, and
# rejected at its own lines for the reason written above it: a forgery that
# starts compiling is a hole in the construction authority, and one that fails
# for a different reason is a test that stopped testing.
#
# Errors are matched to forgeries by line, not by error code. Codes repeat
# across forgeries, so a set comparison passes while a forgery quietly compiles.
#
# "No errors" is not evidence either way until cargo's own exit code is read: a
# build that never started emits no diagnostics, and so does a forgery that
# compiled. They are told apart below and reported differently, because one is
# a hole in the encoder and the other is a broken workspace.
set -u

cd "$(dirname "$0")/.."

status=0
total=0

for file in crates/canonical-forgery/src/bin/*.rs; do
    name=$(basename "$file" .rs)
    forgeries=$(grep -c 'FORGERY:' "$file")
    total=$((total + forgeries))

    raw=$(cargo build -p canonical-forgery --features compile-fail --bin "$name" \
        --message-format short 2>&1)
    built=$?

    printf '%s\n' "$raw" \
        | grep -o "${file}:[0-9]*:[0-9]*: error\[E[0-9]\{4\}\]" \
        | sed "s|${file}:||;s|:[0-9]*: error\[|:|;s|\]||" \
        | sort -t: -k1,1n > /tmp/compile-fail-errors.$$

    if [ "$built" -eq 0 ]; then
        echo "compile-fail: $name COMPILED. Construction authority is open."
        rm -f /tmp/compile-fail-errors.$$
        status=1
        continue
    fi

    if [ ! -s /tmp/compile-fail-errors.$$ ]; then
        echo "compile-fail: $name was not built, so no forgery was tested. cargo said:"
        printf '%s\n' "$raw" | head -5
        rm -f /tmp/compile-fail-errors.$$
        status=1
        continue
    fi

    awk -v errfile="/tmp/compile-fail-errors.$$" -v name="$name" '
        BEGIN {
            while ((getline line < errfile) > 0) {
                split(line, part, ":")
                seen[part[1]] = seen[part[1]] " " part[2]
            }
        }
        /FORGERY:/ { if (start) blocks[start] = NR - 1; start = NR; expect = "" }
        /EXPECT: E[0-9][0-9][0-9][0-9]/ {
            match($0, /E[0-9][0-9][0-9][0-9]/)
            expect = expect " " substr($0, RSTART, RLENGTH)
            wanted[start] = expect
        }
        END {
            if (start) blocks[start] = NR
            for (key in blocks) {
                from = key + 0        # subscripts are strings; compare as numbers
                found = ""
                for (line = from; line <= blocks[key] + 0; line++)
                    if (line in seen) found = found seen[line]
                if (found == "") {
                    printf "compile-fail: %s line %d COMPILED. That forgery is not rejected.\n", name, from
                    bad = 1
                    continue
                }
                for (n = split(wanted[key], want, " "); n > 0; n--) {
                    if (want[n] == "") continue
                    if (index(found, want[n]) == 0) {
                        printf "compile-fail: %s line %d expects %s, and was rejected with%s\n", name, from, want[n], found
                        bad = 1
                    }
                }
                split(found, got, " ")
                for (k in got) {
                    if (got[k] == "") continue
                    if (index(wanted[key], got[k]) == 0) {
                        printf "compile-fail: %s line %d was rejected with %s, which no forgery asked for\n", name, from, got[k]
                        bad = 1
                    }
                }
            }
            exit bad ? 1 : 0
        }
    ' "$file" || status=1

    rm -f /tmp/compile-fail-errors.$$
done

if [ "$status" -eq 0 ]; then
    echo "compile-fail: $total forgeries, all rejected"
else
    echo "compile-fail: $total forgeries, and the run above is not clean"
fi
exit $status
