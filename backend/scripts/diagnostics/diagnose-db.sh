#!/bin/bash
# SIEMBox Database Diagnostic Script
# Run this on the Docker host to diagnose database issues
# Usage: ./diagnose-db.sh > diagnostic-output.txt

set +e  # Don't exit on error - we want to capture all output

echo "=========================================="
echo "SIEMBox Database Diagnostic Report"
echo "=========================================="
echo "Date: $(date)"
echo "Host: $(hostname)"
echo ""

echo "=========================================="
echo "STEP 1: Container Status"
echo "=========================================="
docker ps --filter name=siembox --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""
echo "Exit codes (restart count):"
docker ps -a --filter name=siembox --format "{{.Names}}: Restarts={{.Status}}"
echo ""

echo "=========================================="
echo "STEP 2: Backend Container Logs (last 50)"
echo "=========================================="
docker logs siembox-backend --tail 50
echo ""

echo "=========================================="
echo "STEP 3: Database Container Logs (last 50)"
echo "=========================================="
docker logs siembox-database --tail 50
echo ""

echo "=========================================="
echo "STEP 4: Database Connectivity Test"
echo "=========================================="
docker exec siembox-backend node -e "
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'siembox',
  user: process.env.DB_USER || 'siembox',
  password: process.env.DB_PASSWORD || 'changeme'
});
pool.query('SELECT NOW() as current_time, current_database(), current_user')
  .then(r => {
    console.log('✓ DATABASE CONNECTION SUCCESSFUL');
    console.log(JSON.stringify(r.rows[0], null, 2));
    process.exit(0);
  })
  .catch(e => {
    console.error('✗ DATABASE CONNECTION FAILED');
    console.error('Message:', e.message);
    console.error('Code:', e.code);
    console.error('Detail:', e.detail);
    process.exit(1);
  });
" 2>&1 || echo "Connection test failed"
echo ""

echo "=========================================="
echo "STEP 5: List All Tables"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT
  table_name,
  (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = t.table_name) as column_count
FROM information_schema.tables t
WHERE table_schema = 'public'
  AND table_type = 'BASE TABLE'
ORDER BY table_name;
EOF
echo ""

echo "=========================================="
echo "STEP 6: Check raw_logs Schema"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
\d raw_logs
EOF
echo ""

echo "=========================================="
echo "STEP 7: Check parsed_logs Schema"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
\d parsed_logs
EOF
echo ""

echo "=========================================="
echo "STEP 8: Test Manual INSERT into raw_logs"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
INSERT INTO raw_logs (timestamp, raw_message, source_ip, facility, severity, hostname)
VALUES (NOW(), 'DIAGNOSTIC TEST MESSAGE', '192.168.1.1', 1, 6, 'test-host')
RETURNING id, timestamp, raw_message, source_ip;
EOF
echo ""

echo "=========================================="
echo "STEP 9: Data Counts"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT
  'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'parsers', COUNT(*) FROM parsers
UNION ALL
SELECT 'detection_rules', COUNT(*) FROM detection_rules
UNION ALL
SELECT 'raw_logs', COUNT(*) FROM raw_logs
UNION ALL
SELECT 'parsed_logs', COUNT(*) FROM parsed_logs
UNION ALL
SELECT 'alerts', COUNT(*) FROM alerts
ORDER BY table_name;
EOF
echo ""

echo "=========================================="
echo "STEP 10: List Parsers"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT
  id,
  name,
  parser_type,
  enabled,
  priority,
  LEFT(description, 50) as description_preview
FROM parsers
ORDER BY priority, name;
EOF
echo ""

echo "=========================================="
echo "STEP 11: List Detection Rules (first 20)"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT
  id,
  name,
  severity,
  enabled,
  tags
FROM detection_rules
ORDER BY severity DESC, name
LIMIT 20;
EOF
echo ""

echo "=========================================="
echo "STEP 12: Check Constraints on raw_logs/parsed_logs"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT
  conname AS constraint_name,
  conrelid::regclass AS table_name,
  contype AS constraint_type,
  pg_get_constraintdef(oid) AS constraint_definition
FROM pg_constraint
WHERE conrelid IN ('raw_logs'::regclass, 'parsed_logs'::regclass)
ORDER BY table_name, constraint_type;
EOF
echo ""

echo "=========================================="
echo "STEP 13: Recent raw_logs (last 10)"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT
  id,
  timestamp,
  LEFT(raw_message, 80) as message_preview,
  source_ip,
  facility,
  severity,
  hostname
FROM raw_logs
ORDER BY id DESC
LIMIT 10;
EOF
echo ""

echo "=========================================="
echo "STEP 14: Check for Migration Tracking"
echo "=========================================="
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
SELECT EXISTS (
  SELECT FROM information_schema.tables
  WHERE table_schema = 'public'
  AND table_name = 'schema_migrations'
) as migration_table_exists;
EOF
echo ""

echo "=========================================="
echo "STEP 15: Test Error Serialization"
echo "=========================================="
docker exec siembox-backend node -e "
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
});

// Try to insert with a deliberate error (non-existent column)
pool.query('INSERT INTO raw_logs (nonexistent_column) VALUES (\$1)', ['test'])
  .then(r => console.log('Unexpected success'))
  .catch(e => {
    console.log('=== ERROR OBJECT ANALYSIS ===');
    console.log('Type:', typeof e);
    console.log('Constructor:', e.constructor.name);
    console.log('Message:', e.message);
    console.log('Code:', e.code);
    console.log('Detail:', e.detail);
    console.log('Hint:', e.hint);
    console.log('Position:', e.position);
    console.log('');
    console.log('=== JSON.stringify(error) ===');
    console.log(JSON.stringify(e, null, 2));
  })
  .finally(() => process.exit());
" 2>&1
echo ""

echo "=========================================="
echo "DIAGNOSTIC COMPLETE"
echo "=========================================="
echo ""
echo "Summary:"
echo "- Save this output to a file"
echo "- Look for ERROR messages"
echo "- Check if tables exist"
echo "- Verify parser/rule counts"
echo "- Check if INSERT test succeeded"
echo ""
echo "Next steps based on findings:"
echo "1. If tables missing: Re-run migrations"
echo "2. If parsers=0: Check seed data migration"
echo "3. If INSERT fails: Check error details"
echo "4. If constraints fail: Review schema"
