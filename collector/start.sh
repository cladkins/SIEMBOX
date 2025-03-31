#!/bin/bash

# Print each command before executing it
set -x
# Exit on any error
set -e

echo "Starting collector service..."

# Create required directories with verbose output
echo "Creating required directories..."
mkdir -p /var/log/collector
mkdir -p /var/spool/rsyslog
mkdir -p /var/run/rsyslog

# Set permissions with verbose output
echo "Setting directory permissions..."
chmod -R 777 /var/log/collector
chmod -R 777 /var/spool/rsyslog
chmod -R 777 /var/run/rsyslog

echo "Directory permissions set:"
ls -la /var/log/collector
ls -la /var/spool/rsyslog
ls -la /var/run/rsyslog

# Create and set permissions for syslog.json
echo "Creating syslog.json file..."
touch /var/log/collector/syslog.json
chmod 666 /var/log/collector/syslog.json

echo "syslog.json file status:"
ls -la /var/log/collector/syslog.json

# Make rsyslog executable
echo "Setting rsyslog permissions..."
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
    echo "Checking rsyslog status..."
    ps aux | grep rsyslog
    echo "Checking rsyslog debug log..."
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
        echo "Checking network status..."
        netstat -tulpn
        exit 1
    fi
    sleep 1
done

echo "rsyslog started successfully with PID $RSYSLOG_PID"
echo "Current files in /var/log/collector:"
ls -la /var/log/collector

echo "Starting FastAPI application..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --log-level debug