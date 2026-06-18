#!/bin/bash
set -e

# SIEMBox Managed Log Shipper
# Automatically registers with SIEMBox and pulls configuration

# Configuration from environment variables
SIEMBOX_API_URL="${SIEMBOX_API_URL:-http://localhost:3001/api}"
SHIPPER_API_KEY="${SHIPPER_API_KEY}"
SHIPPER_VERSION="1.0.0"
CONFIG_POLL_INTERVAL="${CONFIG_POLL_INTERVAL:-30}" # seconds
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-60}" # seconds

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

    if [ -z "$container" ] || [ "$container" = "null" ] || [ "$container" = "*" ] || [ "$container" = "all" ]; then
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
        # Extract host from SIEMBOX_API_URL (e.g., http://192.168.1.76:3001/api -> 192.168.1.76)
        siem_host=$(echo "$SIEMBOX_API_URL" | sed -E 's|^https?://([^:/]+).*|\1|')
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

    log_info ""
    log_info "Log shipper running. Polling for configuration updates..."
    log_info ""

    # Main polling loop
    while true; do
        sleep $CONFIG_POLL_INTERVAL

        # Send heartbeat
        send_heartbeat

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
