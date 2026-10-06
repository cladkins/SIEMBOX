#!/bin/bash
set -e

# SIEMBox Managed Log Shipper
# Automatically registers with SIEMBox and pulls configuration

# Configuration from environment variables
SIEMBOX_API_URL="${SIEMBOX_API_URL:-http://localhost:3001/api}"
SHIPPER_API_KEY="${SHIPPER_API_KEY}"
# Reported on register and shown in the UI. Bump this when the shipper gains a
# server-visible capability: SIEMBox uses it to tell "this shipper is too old to
# do X" apart from "this shipper is misconfigured".
#   1.1.0 — reports container inventory (incl. explicit docker-unavailable reports)
#   1.2.0 — runs nmap network scans SIEMBox dispatches to it (LAN-side scanning)
#   1.3.0 — also runs dispatched nuclei vulnerability scans (LAN-side)
#   1.4.0 — also runs dispatched log-discovery scans (bundled Node agent)
#   1.4.1 — nuclei: ensure templates before running, honor per-scan timeout,
#           surface the real nuclei error on failure
SHIPPER_VERSION="1.4.1"
CONFIG_POLL_INTERVAL="${CONFIG_POLL_INTERVAL:-30}" # seconds
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-60}" # seconds
# How often to report this host's container images to SIEMBox for vuln scanning.
# Set to 0 to disable. Containers change slowly, so the default is generous.
CONTAINER_REPORT_INTERVAL="${CONTAINER_REPORT_INTERVAL:-300}" # seconds
# Network scanning: how often to poll SIEMBox for nmap jobs assigned to this
# shipper (0 disables scanning entirely). These scans run from the shipper, out
# on the LAN, where the SIEMBox backend's own nmap can't reach from inside its
# Docker network. SCAN_TIMEOUT caps the wall-clock of a single nmap run.
SCAN_POLL_INTERVAL="${SCAN_POLL_INTERVAL:-30}" # seconds, 0 to disable
SCAN_TIMEOUT="${SCAN_TIMEOUT:-900}" # seconds (matches the backend's 15-min cap)
# For dispatched nuclei (vulnerability) scans the shipper uses its OWN nuclei
# template corpus. Set false to skip the one-time background template update at
# startup (e.g. air-gapped, or you mount a template volume yourself).
NUCLEI_UPDATE_TEMPLATES="${NUCLEI_UPDATE_TEMPLATES:-true}"
# Marker written once nuclei templates are confirmed present, so a dispatched
# vuln scan never runs before templates exist (which fails instantly with a bare
# "exit 1"). Set by the startup warm-up and by the first job's synchronous fetch.
NUCLEI_TEMPLATES_MARKER="${NUCLEI_TEMPLATES_MARKER:-/tmp/siembox-nuclei-templates.ready}"
# Bundled Node agent that runs dispatched log-discovery scans (baked into the
# image by the Dockerfile; see log-shipper/discovery-agent/).
DISCOVERY_AGENT="${DISCOVERY_AGENT:-/usr/local/lib/siembox/discovery-agent.js}"

# Color output for logs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" >&2
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" >&2
}

# Generate short shipper ID from API key (first 8 chars of SHA256)
# NOTE: API key is a 64-char hex string. We must decode it to binary before hashing
# to match the backend's computation: SHA256(decode(api_key, 'hex'))
generate_shipper_id() {
    local api_key="$1"
    echo -n "$api_key" | xxd -r -p | sha256sum 2>/dev/null | cut -c1-8 || echo -n "$api_key" | xxd -r -p | md5sum 2>/dev/null | cut -c1-8
}

# Save configuration to cache file
save_cached_config() {
    local config="$1"
    if [ -n "$config" ]; then
        echo "$config" > "$CACHED_CONFIG_FILE" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_debug "Configuration cached to $CACHED_CONFIG_FILE"
            return 0
        else
            log_warn "Failed to cache configuration"
            return 1
        fi
    fi
}

# Load configuration from cache file
load_cached_config() {
    if [ -f "$CACHED_CONFIG_FILE" ]; then
        local cached_config=$(cat "$CACHED_CONFIG_FILE" 2>/dev/null)
        if [ -n "$cached_config" ]; then
            log_info "Loaded cached configuration from $CACHED_CONFIG_FILE"
            echo "$cached_config"
            return 0
        fi
    fi
    log_debug "No cached configuration available"
    return 1
}

# Global variables
CURRENT_CONFIG=""
TAILING_PIDS=()
LAST_HEARTBEAT=0
LAST_CONTAINER_REPORT=0
LAST_SCAN_POLL=0
SHIPPER_ID="" # Short identifier derived from API key for log attribution
CACHED_CONFIG_FILE="/tmp/siembox-cached-config.json" # Fallback config cache

# Send log to SIEMBox via syslog
send_log() {
    local message="$1"
    local tag="${2:-log-shipper}"
    local facility="${3:-local0}"
    local severity="${4:-info}"
    local siem_host="${5:-localhost}"
    local siem_port="${6:-514}"

    # Syslog severity levels
    case $severity in
        emerg) sev=0 ;;
        alert) sev=1 ;;
        crit) sev=2 ;;
        err|error) sev=3 ;;
        warn|warning) sev=4 ;;
        notice) sev=5 ;;
        info) sev=6 ;;
        debug) sev=7 ;;
        *) sev=6 ;;
    esac

    # Facility codes
    case $facility in
        local0) fac=16 ;;
        local1) fac=17 ;;
        local2) fac=18 ;;
        local3) fac=19 ;;
        local4) fac=20 ;;
        local5) fac=21 ;;
        local6) fac=22 ;;
        local7) fac=23 ;;
        *) fac=16 ;;
    esac

    # Calculate priority
    pri=$((fac * 8 + sev))

    # RFC 3164 syslog format with shipper identification
    # Include SHIPPER_ID in the tag so we can trace logs back to their source
    timestamp=$(date '+%b %d %H:%M:%S')
    hostname=$(hostname)

    # If SHIPPER_ID is set, append it to the tag in brackets [SHIPPERID]
    if [ -n "$SHIPPER_ID" ]; then
        syslog_msg="<${pri}>${timestamp} ${hostname} ${tag}[${SHIPPER_ID}]: ${message}"
    else
        syslog_msg="<${pri}>${timestamp} ${hostname} ${tag}: ${message}"
    fi

    # Send via netcat
    echo "$syslog_msg" | nc -u -w1 ${siem_host} ${siem_port} 2>/dev/null || true
}

# Fetch configuration from SIEMBox
fetch_config() {
    local api_key="$1"

    log_debug "Fetching configuration from SIEMBox..."

    local config_file="/tmp/siembox-config-$$.json"

    local http_code=$(curl -s -w "%{http_code}" -o "$config_file" "${SIEMBOX_API_URL}/shippers/config/${api_key}" 2>/dev/null)

    if [ "$http_code" = "200" ]; then
        cat "$config_file"
        rm -f "$config_file"
        return 0
    else
        log_error "Failed to fetch config (HTTP $http_code)"
        rm -f "$config_file"
        return 1
    fi
}

# Register with SIEMBox
register_shipper() {
    local api_key="$1"

    log_info "Registering with SIEMBox..."

    local metadata=$(cat <<EOF
{
  "api_key": "$api_key",
  "version": "$SHIPPER_VERSION",
  "hostname": "$(hostname)",
  "metadata": {
    "os": "$(uname -s)",
    "arch": "$(uname -m)",
    "kernel": "$(uname -r)"
  }
}
EOF
)

    local response_file="/tmp/siembox-register-$$.json"

    local http_code=$(curl -s -w "%{http_code}" -o "$response_file" \
        -X POST "${SIEMBOX_API_URL}/shippers/register" \
        -H "Content-Type: application/json" \
        -d "$metadata" 2>/dev/null)

    if [ "$http_code" = "200" ]; then
        log_info "Successfully registered with SIEMBox"
        # Extract .config from response and write to stdout
        jq '.config' "$response_file" 2>/dev/null
        rm -f "$response_file"
        return 0
    else
        log_error "Failed to register (HTTP $http_code)"
        rm -f "$response_file"
        return 1
    fi
}

# Stop all tailing processes
stop_tailing() {
    if [ ${#TAILING_PIDS[@]} -gt 0 ]; then
        log_info "Stopping all tailing processes (${#TAILING_PIDS[@]} processes)..."
        for pid in "${TAILING_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                log_debug "Killing process $pid"
                # Kill process group to ensure all children are terminated
                kill -TERM -$pid 2>/dev/null || kill -TERM $pid 2>/dev/null || true
                # Give it a moment to terminate gracefully
                sleep 0.1
                # Force kill if still alive
                if kill -0 "$pid" 2>/dev/null; then
                    kill -KILL -$pid 2>/dev/null || kill -KILL $pid 2>/dev/null || true
                fi
            fi
        done
        TAILING_PIDS=()
        log_debug "All tailing processes stopped"
    fi
}

# Start tailing a file source
tail_file_source() {
    local pattern="$1"
    local tag="$2"
    local facility="$3"
    local siem_host="$4"
    local siem_port="$5"

    local matched_files=0

    # Expand glob pattern - disable pathname expansion temporarily to check if pattern contains wildcards
    shopt -s nullglob
    local expanded_files=($pattern)
    shopt -u nullglob

    # If no files matched the pattern, check if it's a literal path that doesn't exist
    if [ ${#expanded_files[@]} -eq 0 ]; then
        log_warn "No files found matching pattern: $pattern"
        return
    fi

    # Tail each file that matched the pattern
    for file_path in "${expanded_files[@]}"; do
        if [ ! -e "$file_path" ]; then
            log_warn "File not found: $file_path (is the host path mounted into the shipper?)"
            continue
        fi
        if [ ! -f "$file_path" ]; then
            log_warn "Skipping non-regular file: $file_path"
            continue
        fi

        matched_files=$((matched_files + 1))
        log_info "Tailing file: $file_path (tag: $tag, pattern: $pattern)"

        # Use named pipe to properly track tail process PID
        local pipe="/tmp/shipper-pipe-$$-$RANDOM"
        mkfifo "$pipe" 2>/dev/null || {
            log_error "Failed to create named pipe for $file_path"
            continue
        }

        # Start tail process, redirect to pipe, background it
        tail -F "$file_path" > "$pipe" 2>/dev/null &
        local tail_pid=$!
        TAILING_PIDS+=($tail_pid)
        log_debug "Started tail process $tail_pid for $file_path"

        # Start reader process in a new process group
        (
            # Create new process group
            set -m
            while IFS= read -r line; do
                send_log "$line" "$tag" "$facility" "info" "$siem_host" "$siem_port"
            done < "$pipe"
        ) &
        local reader_pid=$!
        TAILING_PIDS+=($reader_pid)
        log_debug "Started reader process $reader_pid for $file_path"

        # Cleanup pipe in background after a moment (both processes have it open)
        (sleep 1; rm -f "$pipe" 2>/dev/null) &
    done

    if [ $matched_files -gt 1 ]; then
        log_info "Started tailing $matched_files files matching pattern: $pattern"
    fi
}

# Tail a single running container's logs to SIEMBox.
tail_one_docker_container() {
    local container="$1"
    local tag="$2"
    local facility="$3"
    local siem_host="$4"
    local siem_port="$5"

    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
        log_warn "Container not found or not running: $container"
        return
    fi

    log_info "Tailing Docker container: $container (tag: $tag)"

    # Use named pipe to properly track docker logs process PID
    local pipe="/tmp/shipper-docker-pipe-$$-$RANDOM"
    mkfifo "$pipe" 2>/dev/null || {
        log_error "Failed to create named pipe for container $container"
        return
    }

    # Start docker logs process, redirect to pipe, background it
    docker logs -f "$container" > "$pipe" 2>&1 &
    local docker_pid=$!
    TAILING_PIDS+=($docker_pid)
    log_debug "Started docker logs process $docker_pid for $container"

    # Start reader process in a new process group
    (
        # Create new process group
        set -m
        while IFS= read -r line; do
            send_log "$line" "$tag" "$facility" "info" "$siem_host" "$siem_port"
        done < "$pipe"
    ) &
    local reader_pid=$!
    TAILING_PIDS+=($reader_pid)
    log_debug "Started reader process $reader_pid for $container"

    # Cleanup pipe in background after a moment (both processes have it open)
    (sleep 1; rm -f "$pipe" 2>/dev/null) &
}

# Tail one container, or every running container when the name is blank / "*" /
# "all" (each line tagged with its own container name).
tail_docker_source() {
    local container="$1"
    local tag="$2"
    local facility="$3"
    local siem_host="$4"
    local siem_port="$5"

    # Treat blank / "*" / "all" (and forgiving variants like "* / all") as
    # "every running container".
    local container_norm
    container_norm=$(printf '%s' "$container" | tr -d '[:space:]')
    if [ -z "$container_norm" ] || [ "$container_norm" = "null" ] || [ "$container_norm" = "*" ] || [ "$container_norm" = "all" ] || [ "$container_norm" = "*/all" ]; then
        local names
        names=$(docker ps --format '{{.Names}}' 2>/dev/null)
        if [ -z "$names" ]; then
            log_warn "No running containers found to tail"
            return
        fi
        log_info "Tailing all running containers (each tagged with its name)"
        while IFS= read -r c; do
            [ -n "$c" ] && tail_one_docker_container "$c" "$c" "$facility" "$siem_host" "$siem_port"
        done <<< "$names"
        return
    fi

    tail_one_docker_container "$container" "$tag" "$facility" "$siem_host" "$siem_port"
}

# Tail the host's systemd journal via journalctl. Requires journalctl in the
# image and the journal mounted (e.g. /var/log/journal). Only new entries are
# forwarded (-n 0); an optional unit filter narrows it to a single service.
tail_journal_source() {
    local unit="$1"
    local tag="$2"
    local facility="$3"
    local siem_host="$4"
    local siem_port="$5"

    if ! command -v journalctl >/dev/null 2>&1; then
        log_warn "journalctl not available in this image; cannot read the systemd journal"
        return
    fi

    local args=(-f -o cat --no-pager -n 0)
    if [ -d /var/log/journal ] && [ -n "$(ls -A /var/log/journal 2>/dev/null)" ]; then
        args+=(-D /var/log/journal)
    elif [ -d /run/log/journal ] && [ -n "$(ls -A /run/log/journal 2>/dev/null)" ]; then
        args+=(-D /run/log/journal)
    fi
    if [ -n "$unit" ] && [ "$unit" != "null" ]; then
        args+=(-u "$unit")
    fi

    log_info "Tailing systemd journal (unit: ${unit:-all}, tag: $tag)"

    local pipe="/tmp/shipper-journal-pipe-$$-$RANDOM"
    mkfifo "$pipe" 2>/dev/null || {
        log_error "Failed to create named pipe for journal"
        return
    }

    journalctl "${args[@]}" > "$pipe" 2>/dev/null &
    local journal_pid=$!
    TAILING_PIDS+=($journal_pid)
    log_debug "Started journalctl process $journal_pid"

    (
        set -m
        while IFS= read -r line; do
            send_log "$line" "$tag" "$facility" "info" "$siem_host" "$siem_port"
        done < "$pipe"
    ) &
    local reader_pid=$!
    TAILING_PIDS+=($reader_pid)

    (sleep 1; rm -f "$pipe" 2>/dev/null) &
}

# Apply configuration from SIEMBox
apply_config() {
    local config="$1"

    log_debug "apply_config called with $(echo "$config" | wc -c) bytes of data"
    log_debug "apply_config first 200 chars: $(echo "$config" | head -c 200)"
    log_debug "apply_config checking sources: $(echo "$config" | jq '.sources' 2>/dev/null || echo 'jq failed')"

    # Stop existing tailing processes
    stop_tailing

    # Extract SIEMBox connection info from config (at top level after Phase 1 backend changes)
    local siem_host=$(echo "$config" | jq -r '.siem_host // ""' 2>/dev/null)
    local siem_port=$(echo "$config" | jq -r '.siem_port // "514"' 2>/dev/null)

    # If not in config, extract from SIEMBOX_API_URL environment variable
    if [ "$siem_host" = "null" ] || [ -z "$siem_host" ] || [ "$siem_host" = "" ]; then
        # Extract just the host from SIEMBOX_API_URL, tolerating a missing
        # scheme (curl assumes http, so users sometimes omit it):
        #   http://192.168.1.76:8421/api  ->  192.168.1.76
        #   192.168.1.76:8421/api         ->  192.168.1.76
        siem_host=$(echo "$SIEMBOX_API_URL" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')
        log_debug "Extracted SIEM host from SIEMBOX_API_URL: $siem_host"
    fi

    # Final fallback
    if [ "$siem_host" = "null" ] || [ -z "$siem_host" ]; then
        siem_host="localhost"
        log_warn "Could not determine SIEM host, using localhost"
    fi

    if [ "$siem_port" = "null" ] || [ -z "$siem_port" ]; then
        siem_port="514"
    fi

    log_info "Applying configuration (SIEM: ${siem_host}:${siem_port})"

    # Get number of sources
    local source_count=$(echo "$config" | jq -r '.sources | length' 2>/dev/null)

    log_debug "source_count='$source_count'"

    if [ -z "$source_count" ] || [ "$source_count" = "null" ] || [ "$source_count" = "0" ]; then
        log_warn "No sources configured (count=$source_count)"
        return
    fi

    log_info "Found $source_count source(s)"

    # Process each source
    for i in $(seq 0 $((source_count - 1))); do
        local source=$(echo "$config" | jq ".sources[$i]" 2>/dev/null)
        local enabled=$(echo "$source" | jq -r '.enabled')

        if [ "$enabled" != "true" ]; then
            continue
        fi

        local source_type=$(echo "$source" | jq -r '.source_type')
        local tag=$(echo "$source" | jq -r '.tag')
        local facility=$(echo "$source" | jq -r '.facility // "local0"')

        case $source_type in
            file)
                local file_path=$(echo "$source" | jq -r '.file_path')
                tail_file_source "$file_path" "$tag" "$facility" "$siem_host" "$siem_port"
                ;;
            docker)
                local container_name=$(echo "$source" | jq -r '.container_name')
                tail_docker_source "$container_name" "$tag" "$facility" "$siem_host" "$siem_port"
                ;;
            journal)
                local journal_unit=$(echo "$source" | jq -r '.journal_unit // ""')
                tail_journal_source "$journal_unit" "$tag" "$facility" "$siem_host" "$siem_port"
                ;;
            *)
                log_warn "Unsupported source type: $source_type"
                ;;
        esac
    done
}

# Check if configuration has changed
config_changed() {
    local new_config="$1"

    if [ "$CURRENT_CONFIG" != "$new_config" ]; then
        return 0
    else
        return 1
    fi
}

# Send heartbeat
send_heartbeat() {
    local current_time=$(date +%s)

    if [ $((current_time - LAST_HEARTBEAT)) -ge $HEARTBEAT_INTERVAL ]; then
        log_debug "Sending heartbeat..."
        register_shipper "$SHIPPER_API_KEY" > /dev/null 2>&1 || true
        LAST_HEARTBEAT=$current_time
    fi
}

# POST one container-inventory report. $1 = JSON array of containers,
# $2 = "true"/"false" for whether Docker was reachable, $3 = reason when not.
# Returns non-zero if the POST didn't get a 2xx so the caller can retry sooner.
send_container_report() {
    local items="$1" available="$2" reason="$3"

    local body
    body=$(jq -n --arg key "$SHIPPER_API_KEY" --argjson containers "$items" \
        --argjson available "$available" --arg reason "$reason" \
        '{api_key: $key, containers: $containers, docker_available: $available, docker_reason: $reason}' 2>/dev/null)
    [ -z "$body" ] && return 1

    # --max-time so an unreachable SIEMBox can't wedge the poll loop.
    local code
    code=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
        -X POST "${SIEMBOX_API_URL}/shippers/containers" \
        -H 'Content-Type: application/json' -d "$body" 2>/dev/null)

    case "$code" in
        2*) log_debug "Reported containers to SIEMBox (HTTP $code)"; return 0 ;;
        *)  log_warn "Container report to SIEMBox failed (HTTP ${code:-000}) — Container Scanning will not list this host's images"
            return 1 ;;
    esac
}

# Report this host's container images to SIEMBox so they can be vuln-scanned
# (Trivy) alongside the SIEMBox host's own containers. Best-effort + throttled.
#
# Always reports, even when Docker isn't reachable: an empty report with
# docker_available=false tells the server "this host checked in and cannot see
# Docker", which the UI can explain. Staying silent produced an unexplained gap
# in Container Scanning that looked identical to a broken shipper.
report_containers() {
    [ "${CONTAINER_REPORT_INTERVAL:-0}" -gt 0 ] 2>/dev/null || return 0
    local current_time=$(date +%s)
    [ $((current_time - LAST_CONTAINER_REPORT)) -ge "$CONTAINER_REPORT_INTERVAL" ] || return 0

    # jq builds the payload — without it there's nothing to send at all.
    if ! command -v jq >/dev/null 2>&1; then
        log_warn "jq not available; cannot report container inventory"
        LAST_CONTAINER_REPORT=$current_time
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        send_container_report '[]' false 'docker CLI not available in the shipper container' \
            && LAST_CONTAINER_REPORT=$current_time
        return 0
    fi

    # Tab-delimited "image<TAB>name<TAB>state" per container -> JSON array.
    local raw
    if ! raw=$(docker ps -a --format '{{.Image}}\t{{.Names}}\t{{.State}}' 2>/dev/null); then
        # Socket not mounted, or mounted but not readable by this user.
        send_container_report '[]' false 'Docker socket not reachable — mount /var/run/docker.sock into the shipper container' \
            && LAST_CONTAINER_REPORT=$current_time
        return 0
    fi

    local items
    items=$(printf '%s\n' "$raw" \
        | jq -R -s 'split("\n") | map(select(length>0) | split("\t") | {image: .[0], name: .[1], running: (.[2] == "running")})' 2>/dev/null)
    [ -z "$items" ] && items='[]'

    # An empty list is still worth sending: it means "Docker is reachable and
    # this host currently runs nothing", which is a real answer.
    if send_container_report "$items" true ''; then
        LAST_CONTAINER_REPORT=$current_time
    fi
    # On failure LAST_CONTAINER_REPORT is left alone so the next poll retries
    # instead of waiting out a full interval.
    return 0
}

# ---------------------------------------------------------------------------
# NETWORK SCANNING (optional). SIEMBox can dispatch scans to this shipper so
# they run out on the LAN, where the SIEMBox backend's own nmap/nuclei can't
# reach from inside its Docker network. We poll for jobs assigned to us and run
# exactly the command the server hands us -- server-built flags, server-validated
# targets, chosen by neither us nor the client -- then post the raw output back
# for the backend to parse. Two job kinds, told apart by the job's `kind`:
#   kind=nmap   -> run `nmap <nmapArgs> <targets> -oX -`, post the XML
#   kind=nuclei -> run `nuclei <nucleiArgs> -target <t>...`, post the JSONL
# See backend/src/services/scanner/{nmapScanner,nucleiScanner}.ts and
# backend/src/routes/shippers.ts.
# ---------------------------------------------------------------------------

# POST a scan's raw output back to SIEMBox. $2 is the JSON field name the backend
# expects for this scan kind ("xml" for nmap, "jsonl" for nuclei).
post_scan_output() {
    local scan_id="$1" field="$2" output="$3"
    local body
    body=$(jq -n --arg key "$SHIPPER_API_KEY" --argjson sid "$scan_id" \
        --arg field "$field" --arg out "$output" \
        '{api_key:$key, scan_id:$sid} + {($field): $out}' 2>/dev/null) || true
    [ -z "$body" ] && { log_warn "Scan $scan_id: failed to build result body"; return; }

    local code
    code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
        -X POST "${SIEMBOX_API_URL}/shippers/scan-results" \
        -H 'Content-Type: application/json' -d "$body" 2>/dev/null) || true
    case "$code" in
        2*) log_info "Scan $scan_id results posted (HTTP $code)" ;;
        *)  log_warn "Scan $scan_id result POST failed (HTTP ${code:-000})" ;;
    esac
}

# Tell SIEMBox a scan could not be run (so it's marked failed, not stuck).
post_scan_error() {
    local scan_id="$1" message="$2"
    local body
    body=$(jq -n --arg key "$SHIPPER_API_KEY" --argjson sid "$scan_id" --arg err "$message" \
        '{api_key:$key, scan_id:$sid, error:$err}' 2>/dev/null) || true
    [ -z "$body" ] && return
    curl -s --max-time 20 -o /dev/null \
        -X POST "${SIEMBOX_API_URL}/shippers/scan-results" \
        -H 'Content-Type: application/json' -d "$body" 2>/dev/null || true
}

# Run an nmap (asset discovery) job: `nmap <nmapArgs> <targets> -oX -`, post XML.
# The server-built args and targets are read into bash ARRAYS so each token stays
# a single argv element -- never a shell-split string. This is what stops a
# target or flag from smuggling extra arguments into nmap (the backend also
# validates both, but the shipper must not re-introduce the hole by joining and
# re-splitting them through a shell).
run_nmap_job() {
    local scan_id="$1" job="$2"

    if ! command -v nmap >/dev/null 2>&1; then
        log_warn "Scan $scan_id: nmap not installed in this image"
        post_scan_error "$scan_id" "nmap not installed on the shipper"
        return
    fi

    local nmap_args=() targets=()
    mapfile -t nmap_args < <(printf '%s' "$job" | jq -r '.nmapArgs[]?' 2>/dev/null) || true
    mapfile -t targets  < <(printf '%s' "$job" | jq -r '.targets[]?'  2>/dev/null) || true

    if [ "${#targets[@]}" -eq 0 ]; then
        log_warn "Scan $scan_id has no targets; reporting failure"
        post_scan_error "$scan_id" "No targets in job"
        return
    fi

    log_info "Running scan $scan_id: nmap ${nmap_args[*]} ${targets[*]}"

    local xml rc=0
    # No eval, no joined string: the arrays expand to separate argv elements.
    xml=$(timeout "${SCAN_TIMEOUT}s" nmap "${nmap_args[@]}" "${targets[@]}" -oX - 2>/dev/null) || rc=$?

    if [ "$rc" -eq 124 ]; then
        log_warn "Scan $scan_id timed out after ${SCAN_TIMEOUT}s"
        post_scan_error "$scan_id" "Scan timed out after ${SCAN_TIMEOUT}s on the shipper"
    elif [ "$rc" -ne 0 ] || [ -z "$xml" ]; then
        log_warn "Scan $scan_id failed (nmap exit $rc)"
        post_scan_error "$scan_id" "nmap exited with code $rc on the shipper"
    else
        post_scan_output "$scan_id" xml "$xml"
    fi
}

# Run a nuclei (vulnerability) job: `nuclei <nucleiArgs> -target <t>...`, post the
# JSONL (one finding per line). Each target becomes its own `-target <t>` argv
# pair (same no-re-split guarantee as nmap). nuclei uses its OWN template corpus
# (see warm_nuclei_templates) -- the backend never hands it template file paths.
run_nuclei_job() {
    local scan_id="$1" job="$2"

    if ! command -v nuclei >/dev/null 2>&1; then
        log_warn "Scan $scan_id: nuclei not installed in this image"
        post_scan_error "$scan_id" "nuclei not installed on the shipper"
        return
    fi

    local nuclei_args=() targets=() target_args=()
    mapfile -t nuclei_args < <(printf '%s' "$job" | jq -r '.nucleiArgs[]?' 2>/dev/null) || true
    mapfile -t targets     < <(printf '%s' "$job" | jq -r '.targets[]?'     2>/dev/null) || true

    if [ "${#targets[@]}" -eq 0 ]; then
        log_warn "Scan $scan_id has no targets; reporting failure"
        post_scan_error "$scan_id" "No targets in job"
        return
    fi
    local t
    for t in "${targets[@]}"; do target_args+=(-target "$t"); done

    # Ensure templates exist first, so the scan doesn't fail with a bare "exit 1"
    # while the startup template update is still in flight (e.g. after a restart).
    if ! ensure_nuclei_templates "$scan_id"; then
        post_scan_error "$scan_id" "nuclei templates not available on the shipper — needs outbound internet for the first fetch, or set NUCLEI_UPDATE_TEMPLATES=false and mount a template volume"
        return
    fi

    # Honor the per-scan timeout the server set (it clamps/defaults it); fall back
    # to SCAN_TIMEOUT for older servers that don't send one.
    local timeout_s
    timeout_s=$(printf '%s' "$job" | jq -r '.timeoutSeconds // empty' 2>/dev/null) || true
    case "$timeout_s" in ''|*[!0-9]*) timeout_s="$SCAN_TIMEOUT" ;; esac

    log_info "Running scan $scan_id: nuclei ${nuclei_args[*]} ${target_args[*]} (timeout ${timeout_s}s)"

    local out rc=0 errfile
    errfile=$(mktemp 2>/dev/null || echo "/tmp/siembox-nuclei-err.$$")
    # Capture nuclei's stderr so a failure reports WHY (not just the exit code).
    out=$(timeout "${timeout_s}s" nuclei "${nuclei_args[@]}" "${target_args[@]}" 2>"$errfile") || rc=$?

    if [ "$rc" -eq 124 ]; then
        log_warn "Scan $scan_id timed out after ${timeout_s}s"
        post_scan_error "$scan_id" "Scan timed out after ${timeout_s}s on the shipper"
    elif [ "$rc" -ne 0 ]; then
        local reason
        reason=$(tr '\n' ' ' < "$errfile" 2>/dev/null | tail -c 300)
        log_warn "Scan $scan_id failed (nuclei exit $rc): ${reason}"
        post_scan_error "$scan_id" "nuclei exited with code $rc on the shipper: ${reason:-no error output}"
    else
        # Empty output just means no findings -- still a valid completed scan.
        post_scan_output "$scan_id" jsonl "$out"
    fi
    rm -f "$errfile"
}

# POST discovery signals (a JSON array the agent produced) back to SIEMBox.
post_discovery_results() {
    local scan_id="$1" signals="$2"
    local body
    body=$(jq -n --arg key "$SHIPPER_API_KEY" --argjson sid "$scan_id" --argjson signals "$signals" \
        '{api_key:$key, scan_id:$sid, signals:$signals}' 2>/dev/null) || true
    [ -z "$body" ] && { log_warn "Discovery scan $scan_id: failed to build result body"; return; }

    local code
    code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
        -X POST "${SIEMBOX_API_URL}/shippers/discovery-results" \
        -H 'Content-Type: application/json' -d "$body" 2>/dev/null) || true
    case "$code" in
        2*) log_info "Discovery scan $scan_id results posted (HTTP $code)" ;;
        *)  log_warn "Discovery scan $scan_id result POST failed (HTTP ${code:-000})" ;;
    esac
}

# Tell SIEMBox a discovery scan could not be run (so it's marked failed).
post_discovery_error() {
    local scan_id="$1" message="$2"
    local body
    body=$(jq -n --arg key "$SHIPPER_API_KEY" --argjson sid "$scan_id" --arg err "$message" \
        '{api_key:$key, scan_id:$sid, error:$err}' 2>/dev/null) || true
    [ -z "$body" ] && return
    curl -s --max-time 20 -o /dev/null \
        -X POST "${SIEMBOX_API_URL}/shippers/discovery-results" \
        -H 'Content-Type: application/json' -d "$body" 2>/dev/null || true
}

# Run a log-discovery job: feed the whole job (mode + cidrs + probePlan) to the
# bundled Node agent on stdin; it runs the same passive+active probe the backend
# would and prints observed signals (JSON array) on stdout, which we post back.
run_discovery_job() {
    local scan_id="$1" job="$2"

    if ! command -v node >/dev/null 2>&1; then
        log_warn "Scan $scan_id: node not installed in this image"
        post_discovery_error "$scan_id" "node runtime not available on the shipper"
        return
    fi
    if [ ! -f "$DISCOVERY_AGENT" ]; then
        log_warn "Scan $scan_id: discovery agent missing ($DISCOVERY_AGENT)"
        post_discovery_error "$scan_id" "discovery agent not present on the shipper"
        return
    fi

    log_info "Running discovery scan $scan_id"

    local signals rc=0
    signals=$(printf '%s' "$job" | timeout "${SCAN_TIMEOUT}s" node "$DISCOVERY_AGENT" 2>>/tmp/siembox-discovery-agent.log) || rc=$?

    if [ "$rc" -eq 124 ]; then
        log_warn "Discovery scan $scan_id timed out after ${SCAN_TIMEOUT}s"
        post_discovery_error "$scan_id" "Discovery scan timed out after ${SCAN_TIMEOUT}s on the shipper"
    elif [ "$rc" -ne 0 ] || [ -z "$signals" ]; then
        log_warn "Discovery scan $scan_id failed (agent exit $rc)"
        post_discovery_error "$scan_id" "discovery agent exited with code $rc on the shipper"
    else
        post_discovery_results "$scan_id" "$signals"
    fi
}

# Dispatch one scan job (a JSON object from the job-pull) by its `kind`. Runs in
# the background (see poll_and_run_scans) so a long scan doesn't stall heartbeats
# or config polling in the main loop.
run_scan_job() {
    local job="$1"

    local scan_id kind
    scan_id=$(printf '%s' "$job" | jq -r '.scanId // empty' 2>/dev/null) || true
    case "$scan_id" in
        ''|*[!0-9]*) log_warn "Scan job has no numeric scanId; skipping"; return ;;
    esac

    kind=$(printf '%s' "$job" | jq -r '.kind // "nmap"' 2>/dev/null) || true
    case "$kind" in
        nuclei)    run_nuclei_job    "$scan_id" "$job" ;;
        discovery) run_discovery_job "$scan_id" "$job" ;;
        nmap|*)    run_nmap_job      "$scan_id" "$job" ;;
    esac
}

# Poll for scan jobs assigned to this shipper and run them. Throttled by
# SCAN_POLL_INTERVAL (0 disables). The GET itself claims the jobs server-side
# (queued -> running), so each is handed out once.
poll_and_run_scans() {
    [ "${SCAN_POLL_INTERVAL:-0}" -gt 0 ] 2>/dev/null || return 0

    local current_time
    current_time=$(date +%s)
    [ $((current_time - LAST_SCAN_POLL)) -ge "$SCAN_POLL_INTERVAL" ] || return 0
    LAST_SCAN_POLL=$current_time

    command -v jq >/dev/null 2>&1 || return 0

    local resp
    resp=$(curl -s --max-time 20 "${SIEMBOX_API_URL}/shippers/scan-jobs/${SHIPPER_API_KEY}" 2>/dev/null) || true
    [ -z "$resp" ] && return 0

    local count
    count=$(printf '%s' "$resp" | jq -r '.jobs | length' 2>/dev/null) || true
    case "$count" in
        ''|*[!0-9]*) return 0 ;;
    esac
    [ "$count" -eq 0 ] && return 0

    log_info "Claimed $count scan job(s) from SIEMBox"
    local i job
    for i in $(seq 0 $((count - 1))); do
        job=$(printf '%s' "$resp" | jq -c ".jobs[$i]" 2>/dev/null) || true
        [ -z "$job" ] && continue
        run_scan_job "$job" &   # background so the main loop keeps heartbeating
    done
}

# Kick a one-time nuclei template update in the background at startup so templates
# are ready before the first dispatched vuln scan (nuclei would otherwise
# download them during the first scan and risk hitting SCAN_TIMEOUT). Non-fatal;
# skipped when scanning is disabled, nuclei isn't installed, or
# NUCLEI_UPDATE_TEMPLATES=false (air-gapped / self-managed templates).
warm_nuclei_templates() {
    [ "${SCAN_POLL_INTERVAL:-0}" -gt 0 ] 2>/dev/null || return 0
    [ "${NUCLEI_UPDATE_TEMPLATES:-true}" = "true" ] || return 0
    command -v nuclei >/dev/null 2>&1 || return 0
    log_info "Updating nuclei templates in the background (first run can take a minute)..."
    ( nuclei -update-templates >/dev/null 2>&1 && touch "$NUCLEI_TEMPLATES_MARKER" || true ) &
}

# Make sure nuclei has templates before running a dispatched scan. Returns 0 when
# templates are (now) present, 1 when they couldn't be fetched. Idempotent and
# cheap once the marker exists; only the first job after a restart pays the fetch.
ensure_nuclei_templates() {
    local scan_id="$1"
    [ -f "$NUCLEI_TEMPLATES_MARKER" ] && return 0
    # User manages templates themselves (auto-update off) -- trust nuclei to find them.
    [ "${NUCLEI_UPDATE_TEMPLATES:-true}" = "true" ] || return 0
    log_info "Scan $scan_id: fetching nuclei templates before first scan (one-time)..."
    if timeout 600 nuclei -update-templates >>/tmp/siembox-nuclei.log 2>&1; then
        touch "$NUCLEI_TEMPLATES_MARKER"
        return 0
    fi
    log_warn "Scan $scan_id: nuclei template update failed (see /tmp/siembox-nuclei.log)"
    return 1
}

# Main loop
main() {
    log_info "========================================="
    log_info "SIEMBox Managed Log Shipper Starting"
    log_info "========================================="
    log_info "Version: $SHIPPER_VERSION"
    log_info "API URL: $SIEMBOX_API_URL"
    log_info "Poll Interval: ${CONFIG_POLL_INTERVAL}s"
    log_info ""

    # Check for API key
    if [ -z "$SHIPPER_API_KEY" ]; then
        log_error "SHIPPER_API_KEY environment variable is required"
        exit 1
    fi

    # Generate shipper ID for log attribution
    SHIPPER_ID=$(generate_shipper_id "$SHIPPER_API_KEY")
    log_info "Shipper ID: $SHIPPER_ID"

    # Install required tools if not present
    if ! command -v nc &> /dev/null; then
        log_info "Installing netcat..."
        apk add --no-cache netcat-openbsd coreutils curl jq 2>/dev/null || \
            apt-get update && apt-get install -y netcat curl jq 2>/dev/null
    fi

    if ! command -v jq &> /dev/null; then
        log_info "Installing jq..."
        apk add --no-cache jq 2>/dev/null || \
            apt-get update && apt-get install -y jq 2>/dev/null
    fi

    # Initial registration
    log_info "Performing initial registration..."
    if config=$(register_shipper "$SHIPPER_API_KEY"); then
        log_debug "Registration returned $(echo "$config" | wc -c) bytes"
        log_debug "First 200 chars: $(echo "$config" | head -c 200)"
        log_debug "Config type check: $(echo "$config" | jq type 2>/dev/null || echo 'jq parse failed')"
        CURRENT_CONFIG="$config"
        save_cached_config "$config"
        apply_config "$config"
    else
        log_warn "Initial registration failed - checking for cached configuration..."
        if cached_config=$(load_cached_config); then
            log_info "Using cached configuration (API key may be invalid - creating ghost shipper)"
            CURRENT_CONFIG="$cached_config"
            apply_config "$cached_config"
        else
            log_error "No cached configuration available, retrying in ${CONFIG_POLL_INTERVAL}s..."
        fi
    fi

    # Report container inventory once at startup rather than waiting out the
    # first poll: a restart is how an operator checks whether reporting works,
    # so the answer should land in the logs immediately.
    report_containers

    # Pre-fetch nuclei templates (background) so the first dispatched vuln scan
    # doesn't have to download them mid-scan.
    warm_nuclei_templates

    log_info ""
    log_info "Log shipper running. Polling for configuration updates..."
    log_info ""

    # Main polling loop
    while true; do
        sleep $CONFIG_POLL_INTERVAL

        # Send heartbeat
        send_heartbeat

        # Report container inventory for vuln scanning (throttled inside)
        report_containers

        # Poll for and run any network-scan jobs assigned to this shipper
        poll_and_run_scans

        # Fetch latest config
        if new_config=$(fetch_config "$SHIPPER_API_KEY"); then
            # Successfully fetched config - save to cache for future fallback
            save_cached_config "$new_config"

            if config_changed "$new_config"; then
                log_info "Configuration changed, applying new configuration..."
                CURRENT_CONFIG="$new_config"
                apply_config "$new_config"
            fi
        else
            # Config fetch failed - continue with cached config if available
            if [ -z "$CURRENT_CONFIG" ]; then
                # No current config loaded, try to load from cache
                log_warn "Failed to fetch configuration - attempting to load cached config..."
                if cached_config=$(load_cached_config); then
                    log_info "Using cached configuration (API key may be invalid - creating ghost shipper)"
                    CURRENT_CONFIG="$cached_config"
                    apply_config "$cached_config"
                else
                    log_error "No cached configuration available, will retry on next poll..."
                fi
            else
                # Already running with a config (either current or cached), continue using it
                log_warn "Failed to fetch configuration - continuing with existing config (ghost shipper mode)"
            fi
        fi
    done
}

# Graceful shutdown
cleanup() {
    log_info ""
    log_info "Shutting down log shipper..."
    stop_tailing
    exit 0
}

trap cleanup SIGTERM SIGINT

main
