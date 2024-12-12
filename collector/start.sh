#!/bin/bash

# Exit on any error
set -e

echo "Starting collector service..."

# Create required directories
mkdir -p /var/log/collector
mkdir -p /var/spool/rsyslog
mkdir -p /var/run/rsyslog

# Set permissions
chmod -R 755 /var/log/collector
chmod -R 755 /var/spool/rsyslog
chmod -R 755 /var/run/rsyslog

echo "Directories created and permissions set"

# Make rsyslog executable
chmod +x /usr/sbin/rsyslogd

echo "Starting rsyslog..."

# Start rsyslog in the foreground with debug output
/usr/sbin/rsyslogd -f /etc/rsyslog.conf -n -d &
RSYSLOG_PID=$!

echo "Waiting for rsyslog to initialize..."
sleep 2

# Check if rsyslog is running and listening
if ! kill -0 $RSYSLOG_PID 2>/dev/null; then
    echo "ERROR: rsyslog failed to start"
    cat /var/log/collector/rsyslog-debug.log
    exit 1
fi

# Verify port is listening
for i in {1..5}; do
    if netstat -tulpn | grep :5514 > /dev/null; then
        echo "rsyslog is listening on port 5514"
        break
    fi
    if [ $i -eq 5 ]; then
        echo "ERROR: rsyslog is not listening on port 5514"
        exit 1
    fi
    sleep 1
done

echo "rsyslog started successfully with PID $RSYSLOG_PID"
echo "Current files in /var/log/collector:"
ls -la /var/log/collector

echo "Starting FastAPI application..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --log-level debug