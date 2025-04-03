#!/bin/bash
set -e

echo "Setting up rules directory..."
mkdir -p /app/rules

# Skip Git security checks using environment variables
export GIT_ALLOW_PROTOCOL=file:https
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0

# Check if the rules directory is empty or doesn't contain the expected structure
if [ ! -d "/app/rules/rules" ]; then
    echo "Cloning Sigma rules repository..."
    # If the directory is not empty, clean it first
    if [ "$(ls -A /app/rules)" ]; then
        echo "Cleaning rules directory..."
        rm -rf /app/rules/*
    fi
    
    # Clone the Sigma rules repository with -c flag to set config inline
    git -c safe.directory=/app/rules clone --depth 1 https://github.com/SigmaHQ/sigma.git /app/rules
    echo "Sigma rules repository cloned successfully"
fi

# Make sure the nobody user can read the rules
chmod -R a+r /app/rules || echo "Warning: Failed to chmod /app/rules. Continuing..."

echo "Starting detection service..."
exec uvicorn main:app --host 0.0.0.0 --port 8000