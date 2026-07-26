#!/usr/bin/env bash
# gate.sh — the ONE local gate caller. Runs the bs-detector conduct pass in the
# gate container; the detector binary writes crates/xtask/gate.log and
# gate-counts.txt itself, which the Claude stop-hook reads.
#
# This is the fast conduct loop, NOT a second gate: it invokes the exact same
# detector the merge seal runs as its conduct step (crates/xtask/src/gate.rs ->
# verbs::bs_detector). The full seal — build + clippy + all tests + detector —
# is `docker compose run --rm kyzo-dev cargo xtask gate`. There is one command
# shape and one authority; this is a subset of it, never a divergent verdict.
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1

exec docker compose run --rm kyzo-dev \
  cargo run --release --quiet -p bs-detector -- --root . --now-unix "$(date +%s)"
