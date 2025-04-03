#!/bin/bash
set -e

echo "Changing ownership of /app/rules..."
# Change ownership to the user specified in docker-compose.yml (65534:65534)
# Use chown -R to ensure all subdirectories (like .git) are covered if they exist
chown -R 65534:65534 /app/rules || echo "Warning: Failed to chown /app/rules. Continuing..."

echo "Starting detection service..."
# Execute the original command
exec uvicorn main:app --host 0.0.0.0 --port 8000