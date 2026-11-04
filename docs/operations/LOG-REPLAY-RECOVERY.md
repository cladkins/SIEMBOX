# Recovering from the Docker log replay loop (Oct 29 to Nov 3, 2026)

Shippers up to 1.4.2 re-read every Docker container log from the first line
about every 37 seconds, and all-containers sources shipped SIEMBox's own
logs. Root cause and fix: [TROUBLESHOOTING.md, "Docker logs replayed in a
loop"](./TROUBLESHOOTING.md#issue-docker-logs-replayed-in-a-loop).

## 1. Config changes on existing deployments

Do these in order. Nothing here touches stored logs.

1. **Backend and frontend.** Pull the new images and restart. Migrations 057
   and 058 add columns and a table; 007 no longer rewrites a parser. The
   `/config` change alone stops 1.4.2 shippers from replaying.
2. **Postgres.** Pull the new `compose.yaml` / `compose.prod.yaml` and run
   `docker compose up -d postgres`. It now starts with
   `max_wal_size=${POSTGRES_MAX_WAL_SIZE:-2GB}`.
3. **Every shipper (llm, streambox, komodo).** Pull
   `ghcr.io/cladkins/siembox-log-shipper` 1.5.0 and recreate the container.
   Keep the `shipper-cache:/tmp` volume: read positions live in
   `/tmp/siembox-state`. Check its log: `Shipper ID:` must not be `e3b0c442`.
   Containers that existed before the upgrade start at new lines, so the
   upgrade itself does not replay anything.
4. **Shipper 7 (llm) Docker source.** Leave *SIEMBox's own* off (the default).
   That stops it tailing `siembox-backend` and `siembox-postgres`. Add any
   other names to *Exclude*.
5. **Parsers.** *Parsers -> Browse Catalog*: reinstall `vaultwarden-access`,
   `plex` and `jellyfin`. The backend log then stops listing ids 122, 117 and
   105 as ReDoS-vulnerable at startup. Until you do, they run under the
   100 ms per-line budget in a worker.
6. **Direct syslog timezones.** UniFi APs, UCG-Max and Proxmox log
   America/Chicago time. Set it per source IP (or set the default):

   ```bash
   curl -X PUT http://<siembox>:8421/api/shippers/syslog-timezones/<device-ip> \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"timezone": "America/Chicago"}'
   ```

   Or switch the devices to log in UTC. Old rows keep their 6-hour offset.
7. **Monitoring.** `GET /health` now answers 503 when ingestion stalls while
   shippers are online. Point your uptime check at it. A critical
   "Log ingestion stalled" alert also appears after 10 minutes of zero ingest.

## 2. Count and delete replayed duplicates

Run in `psql` (`docker exec -it siembox-postgres psql -U siembox siembox`).
Take a backup first (`pg_dump`). Deleting a raw log also deletes its parsed
log (`ON DELETE CASCADE`); alerts survive with `parsed_log_id` set to NULL.

The replayed rows share `hostname`, `app_name` (container name) and
`raw_message` with the first copy, but not `timestamp` (1.4.2 stamped the
send time). The query keeps the earliest copy (lowest `id`) of each line and
marks the rest. The comparison set starts Oct 28, when the originals were
written. The last filter keeps only lines that carry their own timestamp
(`2026-10-28 20:03:31 ...`), so two identical lines written at different
times are never merged. Drop that filter only if you accept that risk.

### Count (read only)

```sql
WITH ranked AS (
  SELECT id, created_at, hostname, app_name,
         ROW_NUMBER() OVER (PARTITION BY hostname, app_name, md5(raw_message) ORDER BY id) AS copy
  FROM raw_logs
  WHERE created_at >= '2026-10-28'
    AND shipper_id = 'e3b0c442'
    AND raw_message ~ '^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
)
SELECT hostname, app_name, COUNT(*) AS duplicates
FROM ranked
WHERE copy > 1 AND created_at >= '2026-10-29'
GROUP BY hostname, app_name
ORDER BY duplicates DESC;
```

### Delete (optional)

Run the count first. Then, in one transaction, compare the number deleted
with the count before you commit:

```sql
BEGIN;

WITH ranked AS (
  SELECT id, created_at,
         ROW_NUMBER() OVER (PARTITION BY hostname, app_name, md5(raw_message) ORDER BY id) AS copy
  FROM raw_logs
  WHERE created_at >= '2026-10-28'
    AND shipper_id = 'e3b0c442'
    AND raw_message ~ '^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
)
DELETE FROM raw_logs r
USING ranked
WHERE r.id = ranked.id
  AND ranked.copy > 1
  AND ranked.created_at >= '2026-10-29';

-- Check the DELETE count matches, then:
COMMIT;   -- or ROLLBACK;
```

Afterwards, run `VACUUM (ANALYZE) raw_logs; VACUUM (ANALYZE) parsed_logs;`.
The per-minute ingest counters behind the Big Display (migration 041) are
not recounted, so they still show the replay spike.
