#!/bin/bash

# Start rsyslog (non-root method)
# This assumes rsyslog is configured to run without root privileges.
# You might need to adjust this based on your rsyslog configuration.
/usr/sbin/rsyslogd -n

# Start the FastAPI application
uvicorn main:app --host 0.0.0.0 --port 8000
