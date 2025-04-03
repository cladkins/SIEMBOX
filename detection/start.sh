#!/bin/bash
set -e

echo "Starting detection service with local rules directory..."
# The rules directory is now mounted from the host, so we don't need to clone or update it

# Make sure the nobody user can read the rules
chmod -R a+r /app/rules || echo "Warning: Failed to chmod /app/rules. Continuing..."

# Execute the original command
exec uvicorn main:app --host 0.0.0.0 --port 8000