#!/bin/bash
# Diagnostic script to check what code is actually running in Docker

echo "=== Checking deployed backend code ==="
echo ""

echo "1. Checking git branch and commit:"
git branch --show-current
git log -1 --oneline

echo ""
echo "2. Checking if syslogServer.ts has the correct code:"
grep -n "raw_message:" backend/src/services/syslog/syslogServer.ts

echo ""
echo "3. Checking Docker container:"
docker ps | grep backend

echo ""
echo "4. Checking backend container code (if container is running):"
docker exec siembox-backend cat /app/dist/services/syslog/syslogServer.js 2>/dev/null | grep -A 2 "raw_message:" || echo "Container not running or file not found"

echo ""
echo "5. Recent backend logs:"
docker logs siembox-backend --tail 20 2>&1 | grep -E "(Starting|Error|syslog)" || echo "No relevant logs found"

echo ""
echo "=== Recommendation ==="
echo "If line 110 shows 'raw_message: parsed.message' but Docker shows different code,"
echo "then Docker needs to rebuild with --no-cache"
