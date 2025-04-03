#!/bin/bash
set -e

echo "Setting up rules directory..."
# Create rules directory if it doesn't exist
mkdir -p /app/rules

# Check if the rules directory is empty or doesn't contain a git repository
if [ ! -d "/app/rules/.git" ]; then
    echo "Cloning Sigma rules repository..."
    # If the directory is not empty, clean it first
    if [ "$(ls -A /app/rules)" ]; then
        echo "Cleaning rules directory..."
        rm -rf /app/rules/*
    fi
    
    # Clone the Sigma rules repository
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git /app/rules
    echo "Sigma rules repository cloned successfully"
else
    echo "Sigma rules repository already exists, updating..."
    cd /app/rules && git pull
fi

echo "Starting detection service..."
# Execute the original command
exec uvicorn main:app --host 0.0.0.0 --port 8000