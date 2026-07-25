# Process entrypoints, not build config — the container is the only place
# cargo runs (docker-compose.yml, pre-bash-guard.sh). Never type the raw
# multi-line docker/cargo invocations directly into a foreground shell —
# use these recipes so the heavy runs stay backgrounded and logged.

# Fast conduct gate (bs-detector, in the container) in the background; returns immediately.
gate:
    @nohup crates/xtask/gate.sh >/dev/null 2>&1 & disown; \
    echo "gate running in background — watch crates/xtask/gate.log"

# Current gate verdict, one line.
gate-status:
    @head -1 crates/xtask/gate.log 2>/dev/null || echo "no gate.log yet"

# The full merge seal: build + fmt + clippy + detector + all tests, in the one
# container, stopping at the first failure. The single source of "green".
seal:
    docker compose run --rm kyzo-dev cargo xtask gate
