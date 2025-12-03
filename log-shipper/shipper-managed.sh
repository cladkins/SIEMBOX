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

# Global variables
CURRENT_CONFIG=""
TAILING_PIDS=()
LAST_HEARTBEAT=0

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

    # RFC 3164 syslog format
    timestamp=$(date '+%b %d %H:%M:%S')
    hostname=$(hostname)
    syslog_msg="<${pri}>${timestamp} ${hostname} ${tag}: ${message}"

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
        log_info "Stopping all tailing processes..."
        for pid in "${TAILING_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done
        TAILING_PIDS=()
    fi
}

# Start tailing a file source
tail_file_source() {
    local file_path="$1"
    local tag="$2"
    local facility="$3"
    local siem_host="$4"
    local siem_port="$5"

    if [ ! -f "$file_path" ]; then
        log_warn "File not found: $file_path"
        return
    fi

    log_info "Tailing file: $file_path (tag: $tag)"

    tail -F "$file_path" 2>/dev/null | while IFS= read -r line; do
        send_log "$line" "$tag" "$facility" "info" "$siem_host" "$siem_port"
    done &

    TAILING_PIDS+=($!)
}

# Start tailing a Docker container
tail_docker_source() {
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

    docker logs -f "$container" 2>&1 | while IFS= read -r line; do
        send_log "$line" "$tag" "$facility" "info" "$siem_host" "$siem_port"
    done &

    TAILING_PIDS+=($!)
}

# Apply configuration from SIEMBox
apply_config() {
    local config="$1"

    log_debug "apply_config called with $(echo "$config" | wc -c) bytes of data"
    log_debug "apply_config first 200 chars: $(echo "$config" | head -c 200)"
    log_debug "apply_config checking sources: $(echo "$config" | jq '.sources' 2>/dev/null || echo 'jq failed')"

    # Stop existing tailing processes
    stop_tailing

    # Extract SIEMBox connection info from config
    local siem_host=$(echo "$config" | jq -r '.config.siem_host // ""' 2>/dev/null)
    local siem_port=$(echo "$config" | jq -r '.config.siem_port // "514"' 2>/dev/null)

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
        apply_config "$config"
    else
        log_error "Initial registration failed, retrying in ${CONFIG_POLL_INTERVAL}s..."
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
            if config_changed "$new_config"; then
                log_info "Configuration changed, applying new configuration..."
                CURRENT_CONFIG="$new_config"
                apply_config "$new_config"
            fi
        else
            log_warn "Failed to fetch configuration, retrying..."
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
