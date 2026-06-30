# Backup & Restore

SIEMBox stores everything — logs, parsers, detections, alerts, assets, settings,
threat feeds, endpoint agents, and users — in a single PostgreSQL database, so a
database dump is a complete backup of the instance.

## Back up

From your SIEMBox host (where the compose file lives):

```bash
./scripts/backup.sh
# -> ./backups/siembox-YYYYMMDD-HHMMSS.sql.gz
```

It runs `pg_dump` inside the `postgres` container and writes a compressed,
timestamped dump to `./backups/`. Schedule it with cron (e.g. nightly at 02:30):

```cron
30 2 * * * cd /path/to/siembox && OUT_DIR=/srv/siembox-backups ./scripts/backup.sh >> /var/log/siembox-backup.log 2>&1
```

**Copy backups off-box** (another host / object storage) for real disaster recovery.

Overrides: `COMPOSE_FILE` (default `compose.prod.yaml`), `OUT_DIR` (default
`./backups`), `DB_USER` / `DB_NAME` (default `siembox`).

## Restore

> Restoring **overwrites** the current database. Stop ingestion first if you can.

```bash
./scripts/restore.sh ./backups/siembox-YYYYMMDD-HHMMSS.sql.gz
docker compose -f compose.prod.yaml restart backend
```

## Upgrades

Database migrations run automatically on backend startup and are idempotent, so
upgrades are non-destructive to your data. Still, **take a backup before upgrading**:

```bash
./scripts/backup.sh
docker compose -f compose.prod.yaml pull
docker compose -f compose.prod.yaml up -d
```

If the backend won't start after an upgrade, check its logs
(`docker compose -f compose.prod.yaml logs backend`). A failed migration is logged;
because migrations are idempotent, it's safe to restart once the cause is fixed.
