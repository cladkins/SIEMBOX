#!/bin/bash
# The shipper's Docker health check: healthy while the main loop's heartbeat
# file is fresh, unhealthy when it is missing or stale. Uses no pgrep (the
# image has no procps).
#
#   bash log-shipper/tests/test-healthcheck.sh
#
# HEALTHCHECK_SCRIPT / SHIPPER_SCRIPT override the files under test (CI points
# them at the copies baked into the image).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEALTHCHECK_SCRIPT="${HEALTHCHECK_SCRIPT:-$HERE/../shipper-healthcheck.sh}"
SHIPPER_SCRIPT="${SHIPPER_SCRIPT:-$HERE/../shipper-managed.sh}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export SHIPPER_ALIVE_FILE="$WORK/alive"
export CONFIG_POLL_INTERVAL=30
unset HEALTH_MAX_AGE

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
check() { sh "$HEALTHCHECK_SCRIPT" >"$WORK/out" 2>&1; }

check && fail "missing heartbeat file reported healthy" || pass "missing heartbeat file is unhealthy"

# The shipper's own mark_alive creates the file the check reads.
export SHIPPER_API_KEY=""
set +u
# shellcheck source=../shipper-managed.sh
source "$SHIPPER_SCRIPT"
set +e
mark_alive
[ -f "$SHIPPER_ALIVE_FILE" ] && pass "mark_alive writes the heartbeat file" || fail "mark_alive wrote nothing"
check && pass "fresh heartbeat is healthy: $(cat "$WORK/out")" || fail "fresh heartbeat unhealthy: $(cat "$WORK/out")"

# Default limit: 3 polls + 60 s = 150 s.
touch -d "@$(( $(date +%s) - 140 ))" "$SHIPPER_ALIVE_FILE"
check && pass "140 s old is still healthy (limit 150 s)" || fail "140 s old reported unhealthy"
touch -d "@$(( $(date +%s) - 400 ))" "$SHIPPER_ALIVE_FILE"
check && fail "400 s old reported healthy" || pass "stuck main loop is unhealthy: $(cat "$WORK/out")"

# A long poll interval widens the limit; HEALTH_MAX_AGE overrides it.
CONFIG_POLL_INTERVAL=300 check && pass "limit follows CONFIG_POLL_INTERVAL" || fail "limit ignores CONFIG_POLL_INTERVAL"
HEALTH_MAX_AGE=10 CONFIG_POLL_INTERVAL=300 check && fail "HEALTH_MAX_AGE ignored" || pass "HEALTH_MAX_AGE overrides the limit"

grep -v '^\s*#' "$HEALTHCHECK_SCRIPT" | grep -qw pgrep && fail "health check still calls pgrep" || pass "health check does not call pgrep"

echo
[ "$FAILURES" -eq 0 ] && { echo "All health check tests passed"; exit 0; }
echo "$FAILURES test(s) failed"; exit 1
