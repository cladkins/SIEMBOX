#!/bin/bash

# Create rules directory if it doesn't exist
mkdir -p rules

# Set proper ownership and permissions for rules directory
# 65534:65534 corresponds to nobody:nogroup user
# Permissions 750 (rwxr-x---) ensure:
# - Detection Service (running as nobody:nogroup) has full access to read/write/execute
# - Write access (w) needed for git clone/pull operations
# - Execute access (x) needed for traversing directories
# - Read access (r) needed for loading rule files
# - Frontend never accesses rules directly, only through Detection Service API
# - All rule management (viewing, enabling, disabling) happens through API calls
# - System is secure against unauthorized direct access
#
# This is safe because:
# 1. Detection Service runs as nobody:nogroup and has full access for:
#    - Cloning Sigma rules repository
#    - Pulling updates from git
#    - Reading rule files for detection
# 2. Frontend uses API endpoints:
#    - GET /rules - List rules
#    - POST /rules/toggle - Enable/disable rules
#    - POST /rules/bulk-toggle - Bulk enable/disable
# 3. No other services or users need direct file access
chown 65534:65534 rules
chmod 750 rules

echo "Rules directory initialized with secure permissions (750) and nobody:nogroup ownership"