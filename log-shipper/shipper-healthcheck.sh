#!/bin/sh
# Docker HEALTHCHECK for the shipper: healthy while the main loop is running.
#
# The main loop (shipper-managed.sh) touches $SHIPPER_ALIVE_FILE on every pass.
# Unhealthy when the file is missing or older than HEALTH_MAX_AGE seconds
# (default: three config polls plus a minute), e.g. a loop stuck on a hung
# request. Uses only sh, date and stat (coreutils): the image has no procps.
#
# The old check, `pgrep -f shipper`, failed on every run (no pgrep in the
# image). With procps installed it would always pass instead: the check's own
# `sh -c "pgrep -f shipper ..."` command line matches "shipper".
f="${SHIPPER_ALIVE_FILE:-/tmp/siembox-shipper.alive}"
interval="${CONFIG_POLL_INTERVAL:-30}"
case "$interval" in ''|*[!0-9]*) interval=30 ;; esac
max="${HEALTH_MAX_AGE:-$((interval * 3 + 60))}"
case "$max" in ''|*[!0-9]*) max=$((interval * 3 + 60)) ;; esac

if [ ! -f "$f" ]; then
    echo "unhealthy: no heartbeat file $f (shipper main loop not started)"
    exit 1
fi
mtime=$(stat -c %Y "$f" 2>/dev/null) || { echo "unhealthy: cannot stat $f"; exit 1; }
age=$(( $(date +%s) - mtime ))
if [ "$age" -gt "$max" ]; then
    echo "unhealthy: main loop silent for ${age}s (limit ${max}s)"
    exit 1
fi
echo "healthy: main loop ran ${age}s ago"
exit 0
