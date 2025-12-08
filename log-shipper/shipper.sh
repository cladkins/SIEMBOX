#!/bin/bash
set -e

# SIEMBox Log Shipper
# Universal log forwarder for sending logs to SIEMBox via syslog

# Configuration from environment variables
SIEM_HOST="${SIEM_HOST:-localhost}"
SIEM_PORT="${SIEM_PORT:-514}"
SIEM_PROTOCOL="${SIEM_PROTOCOL:-udp}"  # udp or tcp
HOSTNAME="${SHIPPER_HOSTNAME:-$(hostname)}"
LOG_LEVEL="${LOG_LEVEL:-info}"

# Color output for logs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Send log to SIEMBox via syslog
send_log() {
    local message="$1"
    local tag="${2:-log-shipper}"
    local facility="${3:-local0}"
    local severity="${4:-info}"

    # Syslog severity levels: emerg=0, alert=1, crit=2, err=3, warning=4, notice=5, info=6, debug=7
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

    # Facility codes: local0=16, local1=17, local2=18, local3=19, local4=20, local5=21, local6=22, local7=23
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

    # Calculate priority: facility * 8 + severity
    pri=$((fac * 8 + sev))

    # RFC 3164 syslog format
    timestamp=$(date '+%b %d %H:%M:%S')
    syslog_msg="<${pri}>${timestamp} ${HOSTNAME} ${tag}: ${message}"

    # Send via netcat
    if [ "$SIEM_PROTOCOL" = "tcp" ]; then
        echo "$syslog_msg" | nc -w1 ${SIEM_HOST} ${SIEM_PORT}
    else
        echo "$syslog_msg" | nc -u -w1 ${SIEM_HOST} ${SIEM_PORT}
    fi
}

# Global variable for tracking background PIDs
TAILING_PIDS=()

# Tail a log file and forward it (supports glob patterns)
tail_file() {
    local pattern="$1"
    local tag="$2"
    local facility="${3:-local0}"

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
    for file in "${expanded_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_warn "Skipping non-regular file: $file"
            continue
        fi

        matched_files=$((matched_files + 1))
        log_info "Tailing file: $file (tag: $tag, pattern: $pattern)"

        # Use named pipe to properly track tail process PID
        local pipe="/tmp/shipper-pipe-$$-$RANDOM"
        mkfifo "$pipe" 2>/dev/null || {
            log_error "Failed to create named pipe for $file"
            continue
        }

        # Start tail process, redirect to pipe, background it
        tail -F "$file" > "$pipe" 2>/dev/null &
        local tail_pid=$!
        TAILING_PIDS+=($tail_pid)

        # Start reader process in a new process group
        (
            # Create new process group
            set -m
            while IFS= read -r line; do
                send_log "$line" "$tag" "$facility" "info"
            done < "$pipe"
        ) &
        local reader_pid=$!
        TAILING_PIDS+=($reader_pid)

        # Cleanup pipe in background after a moment (both processes have it open)
        (sleep 1; rm -f "$pipe" 2>/dev/null) &
    done

    if [ $matched_files -gt 1 ]; then
        log_info "Started tailing $matched_files files matching pattern: $pattern"
    fi
}

# Tail Docker container logs
tail_docker_container() {
    local container="$1"
    local tag="${2:-docker-${container}}"
    local facility="${3:-local1}"

    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
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

    # Start reader process in a new process group
    (
        # Create new process group
        set -m
        while IFS= read -r line; do
            send_log "$line" "$tag" "$facility" "info"
        done < "$pipe"
    ) &
    local reader_pid=$!
    TAILING_PIDS+=($reader_pid)

    # Cleanup pipe in background after a moment (both processes have it open)
    (sleep 1; rm -f "$pipe" 2>/dev/null) &
}

# Tail systemd journal
tail_journal() {
    local unit="$1"
    local tag="${2:-journal-${unit}}"
    local facility="${3:-local2}"

    log_info "Tailing systemd journal: $unit (tag: $tag)"

    # Use named pipe to properly track journalctl process PID
    local pipe="/tmp/shipper-journal-pipe-$$-$RANDOM"
    mkfifo "$pipe" 2>/dev/null || {
        log_error "Failed to create named pipe for journal unit $unit"
        return
    }

    # Start journalctl process, redirect to pipe, background it
    journalctl -u "$unit" -f -n 0 --no-pager > "$pipe" 2>/dev/null &
    local journal_pid=$!
    TAILING_PIDS+=($journal_pid)

    # Start reader process in a new process group
    (
        # Create new process group
        set -m
        while IFS= read -r line; do
            send_log "$line" "$tag" "$facility" "info"
        done < "$pipe"
    ) &
    local reader_pid=$!
    TAILING_PIDS+=($reader_pid)

    # Cleanup pipe in background after a moment (both processes have it open)
    (sleep 1; rm -f "$pipe" 2>/dev/null) &
}

# Parse configuration file if it exists
parse_config() {
    local config_file="${1:-/config/config.yml}"

    if [ ! -f "$config_file" ]; then
        log_warn "Config file not found: $config_file"
        return
    fi

    log_info "Parsing config file: $config_file"

    # Simple YAML parser for our specific format
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        # Parse file sources
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*path:[[:space:]]*(.+) ]]; then
            file_path="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*tag:[[:space:]]*(.+) ]]; then
            file_tag="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*facility:[[:space:]]*(.+) ]]; then
            file_facility="${BASH_REMATCH[1]}"
            # Start tailing when we have all info
            if [ -n "$file_path" ] && [ -n "$file_tag" ]; then
                tail_file "$file_path" "$file_tag" "${file_facility:-local0}"
                file_path=""
                file_tag=""
                file_facility=""
            fi
        fi

        # Parse Docker sources
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*container:[[:space:]]*(.+) ]]; then
            docker_container="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*tag:[[:space:]]*(.+) ]] && [ -n "$docker_container" ]; then
            docker_tag="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*facility:[[:space:]]*(.+) ]] && [ -n "$docker_container" ]; then
            docker_facility="${BASH_REMATCH[1]}"
            # Start tailing when we have all info
            if [ -n "$docker_container" ] && [ -n "$docker_tag" ]; then
                tail_docker_container "$docker_container" "$docker_tag" "${docker_facility:-local1}"
                docker_container=""
                docker_tag=""
                docker_facility=""
            fi
        fi
    done < "$config_file"
}

# Main
main() {
    log_info "========================================="
    log_info "SIEMBox Log Shipper Starting"
    log_info "========================================="
    log_info "SIEM Host: ${SIEM_HOST}:${SIEM_PORT} (${SIEM_PROTOCOL})"
    log_info "Hostname: ${HOSTNAME}"
    log_info ""

    # Install required tools if not present
    if ! command -v nc &> /dev/null; then
        log_info "Installing netcat..."
        apk add --no-cache netcat-openbsd coreutils 2>/dev/null || apt-get update && apt-get install -y netcat 2>/dev/null
    fi

    # Test connection to SIEM
    if nc -z -w2 ${SIEM_HOST} ${SIEM_PORT} 2>/dev/null; then
        log_info "Successfully connected to SIEMBox at ${SIEM_HOST}:${SIEM_PORT}"
        send_log "Log shipper started successfully" "log-shipper" "local0" "notice"
    else
        log_error "Cannot connect to SIEMBox at ${SIEM_HOST}:${SIEM_PORT}"
        log_warn "Will continue trying to send logs..."
    fi

    echo ""

    # Parse config file if provided
    if [ -f "/config/config.yml" ]; then
        parse_config "/config/config.yml"
    fi

    # Environment-based file sources (format: FILE_1=/path/to/file;tag;facility)
    for var in $(env | grep '^FILE_' | cut -d= -f1); do
        value="${!var}"
        IFS=';' read -r path tag facility <<< "$value"
        if [ -n "$path" ]; then
            tail_file "$path" "${tag:-file}" "${facility:-local0}"
        fi
    done

    # Environment-based Docker sources (format: DOCKER_1=container_name;tag;facility)
    if [ -S "/var/run/docker.sock" ]; then
        for var in $(env | grep '^DOCKER_' | cut -d= -f1); do
            value="${!var}"
            IFS=';' read -r container tag facility <<< "$value"
            if [ -n "$container" ]; then
                tail_docker_container "$container" "${tag:-docker}" "${facility:-local1}"
            fi
        done
    else
        log_warn "Docker socket not mounted - Docker container log forwarding disabled"
    fi

    # Environment-based systemd sources (format: JOURNAL_1=unit_name;tag;facility)
    if command -v journalctl &> /dev/null; then
        for var in $(env | grep '^JOURNAL_' | cut -d= -f1); do
            value="${!var}"
            IFS=';' read -r unit tag facility <<< "$value"
            if [ -n "$unit" ]; then
                tail_journal "$unit" "${tag:-journal}" "${facility:-local2}"
            fi
        done
    else
        log_warn "journalctl not available - systemd journal forwarding disabled"
    fi

    log_info ""
    log_info "Log shipper running. Press Ctrl+C to stop."
    log_info ""

    # Keep the container running
    wait
}

# Graceful shutdown
cleanup() {
    log_info ""
    log_info "Shutting down log shipper..."
    send_log "Log shipper stopping" "log-shipper" "local0" "notice"

    # Kill all tracked processes
    if [ ${#TAILING_PIDS[@]} -gt 0 ]; then
        log_info "Stopping all tailing processes (${#TAILING_PIDS[@]} processes)..."
        for pid in "${TAILING_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
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
    fi

    # Cleanup any remaining jobs
    kill $(jobs -p) 2>/dev/null || true

    # Clean up any stray named pipes
    rm -f /tmp/shipper-*pipe-$$ 2>/dev/null || true

    exit 0
}

trap cleanup SIGTERM SIGINT

main
