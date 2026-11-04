#!/bin/bash
# Tests for the shipper's Docker read cursor, shipper id and config change
# detection. No Docker needed: fake `docker` and `nc` binaries on PATH stand in
# for the daemon and the syslog socket.
#
#   bash log-shipper/tests/test-docker-cursor.sh
#
# SHIPPER_SCRIPT overrides the script under test (CI points it at the copy
# baked into the image, /usr/local/bin/shipper).
set -u
export SHIPPER_API_KEY="${SHIPPER_API_KEY:-}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIPPER_SCRIPT="${SHIPPER_SCRIPT:-$HERE/../shipper-managed.sh}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
export FAKE_DIR="$WORK/fake"
mkdir -p "$FAKE_DIR"
SENT="$WORK/sent.log"
: > "$SENT"
export SENT

# Fake docker: one container ("app"), its log lines in $FAKE_DIR/<id>.log as
# "<RFC3339Nano> <message>". Honors --since (inclusive, like the daemon) and
# --tail 0, and exits after printing instead of following.
cat > "$WORK/bin/docker" <<'EOF'
#!/bin/bash
name_file="$FAKE_DIR/name"; id_file="$FAKE_DIR/id"; created_file="$FAKE_DIR/created"
case "$1" in
  ps) cat "$name_file" ;;
  inspect)
    shift
    while [ "$1" = "--format" ]; do shift 2; done
    [ "$1" = "$(cat "$name_file")" ] || exit 1
    printf '%s %s\n' "$(cat "$id_file")" "$(cat "$created_file")" ;;
  logs)
    shift
    since="" tail=""
    while [ $# -gt 1 ]; do
      case "$1" in
        --since) since="$2"; shift 2 ;;
        --tail) tail="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    [ "$1" = "$(cat "$id_file")" ] || { echo "no such container: $1" >&2; exit 1; }
    [ "$tail" = "0" ] && exit 0
    while IFS= read -r line; do
      ts="${line%% *}"
      if [ -n "$since" ] && [[ "$ts" < "$since" ]]; then continue; fi
      printf '%s\n' "$line"
    done < "$FAKE_DIR/$1.log" ;;
  *) exit 0 ;;
esac
EOF
# Fake nc: append the syslog line it was handed.
cat > "$WORK/bin/nc" <<'EOF'
#!/bin/bash
cat >> "$SENT"
EOF
chmod +x "$WORK/bin/docker" "$WORK/bin/nc"
export PATH="$WORK/bin:$PATH"

export SHIPPER_STATE_DIR="$WORK/state"
# shellcheck source=../shipper-managed.sh
set +u
source "$SHIPPER_SCRIPT"
set +e
SHIPPER_ID="0123abcd"

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

# Run one tailing pass for container "app" and wait for it to drain.
run_pass() {
    TAILING_PIDS=()
    tail_one_docker_container app app local0 127.0.0.1 514 2>/dev/null
    local pid
    for pid in "${TAILING_PIDS[@]}"; do wait "$pid" 2>/dev/null; done
    TAILING_PIDS=()
}

ID_A=$(printf 'a%.0s' $(seq 1 64))
ID_B=$(printf 'b%.0s' $(seq 1 64))
echo app > "$FAKE_DIR/name"
echo "$ID_A" > "$FAKE_DIR/id"

# --- 1. A container created after the shipper first ran is read in full -----
init_state_dir
echo $(( $(date -u +%s) - 3600 )) > "$SHIPPER_STATE_DIR/first-run"
date -u +%Y-%m-%dT%H:%M:%S.000000000Z > "$FAKE_DIR/created"
cat > "$FAKE_DIR/$ID_A.log" <<'EOF'
2026-10-28T20:03:31.000000001Z 2026-10-28 20:03:31 [info]: Running migration: 007_fix_vaultwarden_parser.sql
2026-10-28T20:03:31.000000002Z 2026-10-28 20:03:31 [info]: Running migration: 008_add_home_assistant_parser.sql
2026-10-28T20:03:32.500000000Z 2026-10-28 20:03:32 [info]: Server listening
EOF
run_pass
count=$(wc -l < "$SENT")
[ "$count" -eq 3 ] && pass "new container: all 3 lines sent" || fail "new container: expected 3 lines, got $count"
grep -q 'Oct 28 20:03:31 .* app\[0123abcd\]: 2026-10-28 20:03:31 \[info\]: Running migration: 007' "$SENT" \
    && pass "header carries the original timestamp and the shipper id" \
    || fail "header timestamp/shipper id wrong: $(head -1 "$SENT")"

# --- 2. Restart (and config re-apply): nothing is sent again ----------------
run_pass
run_pass
count=$(wc -l < "$SENT")
[ "$count" -eq 3 ] && pass "restart: no duplicate lines" || fail "restart: expected 3 lines total, got $count"

# --- 3. New lines after a restart are sent exactly once ---------------------
echo "2026-10-28T20:05:00.000000000Z 2026-10-28 20:05:00 [info]: New request" >> "$FAKE_DIR/$ID_A.log"
run_pass
run_pass
count=$(wc -l < "$SENT")
[ "$count" -eq 4 ] && pass "new line sent once across restarts" || fail "expected 4 lines total, got $count"
[ "$(grep -c 'New request' "$SENT")" -eq 1 ] || fail "new line sent more than once"

# --- 4. Same name, new container ID: a new stream, read from its start ------
echo "$ID_B" > "$FAKE_DIR/id"
date -u +%Y-%m-%dT%H:%M:%S.000000000Z > "$FAKE_DIR/created"
echo "2026-10-29T08:00:00.000000000Z recreated container first line" > "$FAKE_DIR/$ID_B.log"
run_pass
[ "$(grep -c 'recreated container first line' "$SENT")" -eq 1 ] \
    && pass "recreated container (new ID) read from the start" || fail "recreated container not read"
[ -s "$SHIPPER_STATE_DIR/docker-cursors/$ID_A" ] && [ -s "$SHIPPER_STATE_DIR/docker-cursors/$ID_B" ] \
    && pass "one cursor per container ID" || fail "cursor files missing"

# --- 5. A container older than the shipper's first run starts at the end ----
: > "$SENT"
ID_C=$(printf 'c%.0s' $(seq 1 64))
echo "$ID_C" > "$FAKE_DIR/id"
echo "2020-01-01T00:00:00.000000000Z" > "$FAKE_DIR/created"
echo "2026-10-01T00:00:00.000000000Z old history line" > "$FAKE_DIR/$ID_C.log"
run_pass
[ ! -s "$SENT" ] && pass "pre-existing container: history not replayed" || fail "pre-existing container replayed history"
[ -s "$SHIPPER_STATE_DIR/docker-cursors/$ID_C" ] \
    && pass "pre-existing container: cursor recorded at start" || fail "no cursor recorded for tail-0 start"

# --- 6. Shipper id: real hash of the decoded key, never e3b0c442 ------------
KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
expected=$(printf '%b' "$(printf '%s' "$KEY" | sed 's/../\\x&/g')" | sha256sum | cut -c1-8)
if command -v node >/dev/null 2>&1; then
    expected=$(node -e "console.log(require('crypto').createHash('sha256').update(Buffer.from('$KEY','hex')).digest('hex').slice(0,8))")
elif command -v python3 >/dev/null 2>&1; then
    expected=$(python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex('$KEY')).hexdigest()[:8])")
fi
got=$(generate_shipper_id "$KEY" 2>/dev/null)
[ "$got" = "$expected" ] && [ "$got" != "e3b0c442" ] \
    && pass "shipper id matches SHA-256 of the decoded key ($got)" || fail "shipper id: expected $expected, got '$got'"
generate_shipper_id "" >/dev/null 2>&1 && fail "empty key accepted" || pass "empty key refused"
generate_shipper_id "not-hex" >/dev/null 2>&1 && fail "non-hex key accepted" || pass "non-hex key refused"

# --- 7. Container exclusion (all-containers mode) --------------------------
container_excluded siembox-backend "" false && pass "siembox-backend skipped by default" || fail "siembox-backend not skipped"
container_excluded siembox-postgres "" false && pass "siembox-postgres skipped by default" || fail "siembox-postgres not skipped"
container_excluded siembox-backend "" true && fail "include_siembox_containers ignored" || pass "include_siembox_containers opts in"
container_excluded app "" false && fail "app excluded with an empty list" || pass "other containers tailed"
container_excluded redis-cache "nginx, redis-*" false && pass "glob exclude matches" || fail "glob exclude missed"
container_excluded nginx "nginx, redis-*" false && pass "name exclude matches" || fail "name exclude missed"
container_excluded nginx-proxy "nginx, redis-*" false && fail "exclude matched a prefix only" || pass "exclude matches whole names"
# The real all-containers path: the fake daemon lists siembox-backend and app.
printf 'siembox-backend\napp\n' > "$FAKE_DIR/name.all"
cp "$FAKE_DIR/name" "$FAKE_DIR/name.one"
cp "$FAKE_DIR/name.all" "$FAKE_DIR/name"
out=$(tail_docker_source "" docker local0 127.0.0.1 514 "" false 2>&1)
cp "$FAKE_DIR/name.one" "$FAKE_DIR/name"
for pid in "${TAILING_PIDS[@]}"; do kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; done
TAILING_PIDS=()
printf '%s' "$out" | grep -q "Skipping excluded container: siembox-backend" \
    && pass "all-containers mode skips siembox-backend" || fail "all-containers mode tailed siembox-backend"

# --- 8. Heartbeat fields do not count as a config change --------------------
if command -v jq >/dev/null 2>&1; then
    c1='{"id":7,"last_seen":"2026-10-29T20:08:00Z","updated_at":"x","siem_port":514,"sources":[{"id":1,"source_type":"docker","enabled":true,"container_name":"","tag":"docker","facility":"local0","updated_at":"a"}]}'
    c2='{"id":7,"last_seen":"2026-10-29T20:08:37Z","updated_at":"y","siem_port":514,"sources":[{"id":1,"source_type":"docker","enabled":true,"container_name":"","tag":"docker","facility":"local0","updated_at":"a"}]}'
    c3='{"id":7,"last_seen":"2026-10-29T20:09:14Z","siem_port":514,"sources":[{"id":1,"source_type":"docker","enabled":false,"container_name":"","tag":"docker","facility":"local0"}]}'
    set_current_config "$c1"
    config_changed "$c2" && fail "last_seen change treated as a config change" || pass "last_seen change ignored"
    config_changed "$c3" && pass "source change detected" || fail "source change missed"
else
    echo "SKIP: jq not installed (config fingerprint test)"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "All shipper cursor tests passed"
    exit 0
fi
echo "$FAILURES test(s) failed"
exit 1
