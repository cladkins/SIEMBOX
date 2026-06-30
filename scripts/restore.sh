#!/usr/bin/env bash
# Restore a SIEMBox PostgreSQL dump produced by scripts/backup.sh.
# WARNING: this overwrites the current database contents.
#
# Usage:   ./scripts/restore.sh <backup.sql.gz>
# Env:     COMPOSE_FILE (default compose.prod.yaml), DB_USER / DB_NAME (default siembox)
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-compose.prod.yaml}"
DB_USER="${DB_USER:-siembox}"
DB_NAME="${DB_NAME:-siembox}"
FILE="${1:?usage: scripts/restore.sh <backup.sql.gz>}"

[ -f "$FILE" ] || { echo "No such file: $FILE" >&2; exit 1; }

echo "About to restore '$FILE' into the SIEMBox DB ($DB_NAME)."
echo "This OVERWRITES current data. Stop log ingestion first if you can."
read -r -p "Type 'yes' to continue: " ok
[ "$ok" = "yes" ] || { echo "Aborted."; exit 1; }

gunzip -c "$FILE" | docker compose -f "$COMPOSE_FILE" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME"

echo "Restore complete. Restart the backend so it re-reads state:"
echo "  docker compose -f $COMPOSE_FILE restart backend"
