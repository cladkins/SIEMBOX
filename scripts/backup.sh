#!/usr/bin/env bash
# Back up the SIEMBox PostgreSQL database to a timestamped, compressed dump.
# A DB dump is a complete backup of the instance (logs, parsers, detections,
# alerts, assets, settings, threat feeds, endpoint agents, users).
#
# Usage:   ./scripts/backup.sh
# Env:     COMPOSE_FILE (default compose.prod.yaml), OUT_DIR (default ./backups),
#          DB_USER / DB_NAME (default siembox)
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-compose.prod.yaml}"
OUT_DIR="${OUT_DIR:-./backups}"
DB_USER="${DB_USER:-siembox}"
DB_NAME="${DB_NAME:-siembox}"

mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/siembox-${TS}.sql.gz"

echo "Backing up SIEMBox DB ($DB_NAME) -> $OUT"
docker compose -f "$COMPOSE_FILE" exec -T postgres \
  pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$OUT"

echo "Done: $OUT ($(du -h "$OUT" | cut -f1))"
echo "Tip: copy backups off-box (another host / object storage) for real disaster recovery."
