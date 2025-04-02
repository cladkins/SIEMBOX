#!/bin/bash

# Print each command before executing it
set -x
# Exit on any error
set -e

echo "Starting collector service..."

# Verify required directories exist and have correct permissions
echo "Verifying directories and permissions..."
ls -la /var/log/collector
ls -la /var/spool/rsyslog
ls -la /var/run/rsyslog
ls -la /var/log/collector/syslog.json
ls -la /var/log/collector/rsyslog-debug.log
ls -la /var/log/collector/rsyslog-gnutls.log

# Verify rsyslog configuration
echo "Checking rsyslog configuration..."
rsyslogd -N1 -f /etc/rsyslog.conf

# Make rsyslog executable
echo "Setting rsyslog permissions..."
chmod +x /usr/sbin/rsyslogd

echo "Starting rsyslog..."

# Start rsyslog in the foreground with debug output
/usr/sbin/rsyslogd -f /etc/rsyslog.conf -n -d &
RSYSLOG_PID=$!

echo "Waiting for rsyslog to initialize..."
sleep 5

# Check if rsyslog is running and listening
if ! kill -0 $RSYSLOG_PID 2>/dev/null; then
    echo "ERROR: rsyslog failed to start"
    echo "Checking rsyslog status..."
    ps aux | grep rsyslog
    echo "Checking rsyslog debug log..."
    cat /var/log/collector/rsyslog-debug.log
    exit 1
fi

# Verify port is listening with more detailed output
echo "Checking if rsyslog is listening on port 5514..."
for i in {1..5}; do
    echo "Attempt $i of 5..."
    netstat -tulpn | grep :5514 || true
    if netstat -tulpn | grep :5514 > /dev/null; then
        echo "rsyslog is listening on port 5514"
        break
    fi
    if [ $i -eq 5 ]; then
        echo "ERROR: rsyslog is not listening on port 5514"
        echo "Checking network status..."
        netstat -tulpn
        echo "Checking rsyslog process..."
        ps aux | grep rsyslog
        echo "Checking rsyslog logs..."
        cat /var/log/collector/rsyslog-debug.log
        exit 1
    fi
    sleep 2
done

echo "rsyslog started successfully with PID $RSYSLOG_PID"
echo "Current files in /var/log/collector:"
ls -la /var/log/collector

echo "Starting FastAPI application..."
# Start FastAPI in the background
uvicorn main:app --host 0.0.0.0 --port 8000 --log-level debug &
FASTAPI_PID=$!

# Wait for FastAPI to start
sleep 2

# Check if FastAPI is running
if ! kill -0 $FASTAPI_PID 2>/dev/null; then
    echo "ERROR: FastAPI failed to start"
    echo "Checking FastAPI status..."
    ps aux | grep uvicorn
    exit 1
fi

echo "FastAPI started successfully with PID $FASTAPI_PID"

# Keep the container running and monitor both processes
while true; do
    if ! kill -0 $RSYSLOG_PID 2>/dev/null; then
        echo "rsyslog process died"
        echo "Checking rsyslog debug log..."
        cat /var/log/collector/rsyslog-debug.log
        exit 1
    fi
    if ! kill -0 $FASTAPI_PID 2>/dev/null; then
        echo "FastAPI process died"
        exit 1
    fi
    sleep 1
done