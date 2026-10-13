# SIEMBox Troubleshooting Guide

Comprehensive troubleshooting guide for diagnosing and resolving common issues in SIEMBox.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Deployment Issues](#deployment-issues)
- [Syslog & Log Ingestion](#syslog--log-ingestion)
- [Log Shipper Issues](#log-shipper-issues)
- [Log Discovery & API-Polled Sources](#log-discovery--api-polled-sources)
- [Parser Problems](#parser-problems)
- [Detection Rules](#detection-rules)
- [Database Issues](#database-issues)
- [Authentication Problems](#authentication-problems)
- [Performance Issues](#performance-issues)
- [Network & Connectivity](#network--connectivity)
- [Frontend Issues](#frontend-issues)
- [Container Issues](#container-issues)
- [Data Cleanup](#data-cleanup)
- [Advanced Diagnostics](#advanced-diagnostics)

---

## Quick Diagnostics

### Health Check Steps

Run these steps to identify which component is failing:

1. **Check container status** - Verify all containers are running (use your deployment platform)
2. **Review container logs** - Check logs for PostgreSQL, backend API, and frontend
3. **Test API health** - Try accessing: `http://your-siembox-ip:8421/api/health`
4. **Verify port access** - Ensure ports 8420, 8421, 514 are accessible from expected networks
5. **Check database connection** - Try connecting to PostgreSQL if accessible
6. **Verify syslog reception** - Send test syslog message and check for receipt

**For Docker deployments specifically:**
```bash
# Check container status
docker ps | grep siembox

# View logs
docker logs siembox-backend
docker logs siembox-postgres
docker logs siembox-frontend

# Test API endpoint
curl http://localhost:8421/api/health
```

### Common Error Patterns

| Error Message | Likely Cause | Quick Fix |
|---------------|--------------|-----------|
| `ECONNREFUSED` | Service not running | `docker-compose restart <service>` |
| `Error: connect ECONNREFUSED 127.0.0.1:5432` | `DB_HOST` is a loopback address, so the backend is dialing its own container (Postgres can be perfectly healthy) | Set `DB_HOST=postgres` and **redeploy** the stack — see [below](#issue-backend-cant-reach-postgres-on-127001) |
| `timeout exceeded when trying to connect` | The backend ran out of free database connections (a heavy query or scan was holding them) | See [Logs are dropped or ingestion is slow](#issue-logs-are-dropped-or-ingestion-is-slow) |
| `[DiscoveryApiPoller] source N (home-assistant) poll failed: ...` | An API-polled source can't be read: wrong port/endpoint, a non-admin token, or (before the Supervisor fallback) Home Assistant OS answering 404 for `/api/error_log` | See [An API-polled source keeps failing](#issue-an-api-polled-source-keeps-failing-home-assistant-http-404-from-error_log) |
| `401 Unauthorized` | Invalid/expired token | Login again |
| `Port 514: Permission denied` | Insufficient privileges | Run backend as root or use authbind |
| `FATAL: password authentication failed` | Wrong database password | Check .env DB_PASSWORD |
| `Module not found` | Missing dependencies | `docker-compose build --no-cache` |

---

## Deployment Issues

### Issue: Container Won't Start

**Symptoms:**
- Containers are in a failed state
- Service is unreachable or repeatedly restarting
- Logs show startup errors

**Common Causes and Solutions:**

**Port Already in Use**
- Check what's using ports 8420, 8421, or 514 on your system
- Either stop the conflicting service or change SIEMBox ports
- Verify port mappings in your deployment configuration

**Missing or Invalid Environment Variables**
- Verify `.env` file exists and is readable
- Check that all required variables are set:
  - `DB_PASSWORD` - Database password
  - `JWT_SECRET` - JWT signing key
  - `DEFAULT_ADMIN_PASSWORD` - Admin credentials
- Use `.env.example` as a template
- Invalid values (e.g., empty passwords) will cause startup failures

**Database Connection Issues**
- Ensure PostgreSQL container/service is healthy and responding
- Verify database name, user, and password in `.env` match your configuration
- Check network connectivity between backend and database
- For remote databases, verify firewall rules allow access on port 5432
- **Backend crash-loops on `connect ECONNREFUSED 127.0.0.1:5432` while Postgres
  shows healthy:** `DB_HOST` is set to a loopback address (`localhost` /
  `127.0.0.1`). Inside the backend container that is the container itself, not
  Postgres. See [Backend can't reach Postgres on 127.0.0.1](#issue-backend-cant-reach-postgres-on-127001) below.

**Insufficient System Resources**
- Check available disk space (logs grow quickly)
- Verify sufficient RAM (minimum 2GB recommended)
- Check system CPU isn't overloaded

**Permission Errors**
- Ensure the deployment user has proper permissions for volumes/directories
- Verify Docker/container engine has permission to access mounted paths
- Check file permissions on log directories

---

### Issue: Backend can't reach Postgres on 127.0.0.1

**Symptoms:**
- The backend log repeats `Migration failed: connect ECONNREFUSED 127.0.0.1:5432`
  every few seconds (the container exits and Docker restarts it with a growing
  delay), followed by a `Database unreachable --` line naming the likely cause
- `docker ps` shows `siembox-postgres` as `(healthy)`
- Nothing is ingested: the syslog listener on port 514 never starts

**Cause:** `DB_HOST` is `localhost` or `127.0.0.1`. Inside the backend container
that address is the container itself, not Postgres, so the connection is refused
even though the database is fine. Loopback is only correct with the optional
`network_mode: host` setup for Log Discovery (see [DEPLOYMENT.md](../../DEPLOYMENT.md)),
and setting `DB_HOST` without making the matching compose edits is the usual way
to end up here.

**Diagnose** (on the Docker host):

```bash
docker inspect siembox-backend --format '{{.HostConfig.NetworkMode}}'
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' siembox-backend | grep -E '^DB_(HOST|PORT)='
docker ps -a --filter name=siembox-postgres --format '{{.Status}}   {{.Ports}}'
```

**Fix:**
- **Network mode is the compose network (e.g. `siembox_siembox-network`) — the
  default.** Set `DB_HOST=postgres` (or delete the line; the compose default is
  `postgres`) wherever it is defined — the `.env` next to the compose file, or
  the stack's Environment in Komodo/Portainer — then **redeploy**
  (`docker compose -f compose.prod.yaml up -d`). A plain `docker restart` keeps
  the container's old environment, so it will not help.
- **Network mode is `host`.** Loopback is correct here, so the problem is
  Postgres itself: confirm the third command shows `127.0.0.1:5432->5432/tcp`
  (if not, redeploy so Postgres is recreated with the loopback publish), that
  nothing else holds the port (`ss -ltnp 'sport = :5432'`), and that Postgres is
  not crash-looping (`docker logs --tail 40 siembox-postgres`; check free disk
  space with `df -h`).

---

### Issue: Database Initialization Failures

**Symptoms:**
- Backend logs show migration or initialization errors
- Tables don't exist in database
- "Relation does not exist" errors in API responses
- Parsers or rules not loading

**Common Causes:**

1. **PostgreSQL not ready** - Database hasn't finished initializing
   - Solution: Wait 15-20 seconds and check if backend recovers

2. **Database connection issues** - Backend can't connect to database
   - Verify database is running and accessible
   - Check DB_HOST, DB_USER, DB_PASSWORD in .env
   - Verify network connectivity between containers/services

3. **Corrupted database state** - Previous failed migration left database in bad state
   - Solution: Back up data, then reset database and re-run migrations
   - Check database logs for corruption indicators

4. **Insufficient permissions** - Database user lacks required permissions
   - Verify database user has CREATE TABLE, INSERT, UPDATE permissions
   - May need to run migrations as database superuser

**How Initialization Works:**

On first start, the backend automatically:
1. Checks if database is ready
2. Runs all pending migrations (in order)
3. Imports seed data (parsers, rules)
4. Creates indexes and constraints

This should complete in 30-60 seconds. If not:
- Check backend container logs for specific error message
- Verify database container is healthy
- Ensure sufficient disk space
cd src/scripts
node migrate.js
```

**Database Not Ready:**
**Recovery Steps:**

1. Verify PostgreSQL is running and healthy
2. Wait 15-30 seconds for initialization
3. Check backend logs for initialization progress
4. If migrations are stuck, restart the backend service
5. As a last resort, reset database and re-run all migrations

**Important:** Database reset should only be done if:
- This is a test/development environment
- You have backed up all important data
- You understand the data will be permanently deleted

---

## Syslog & Log Ingestion

### Issue: No Logs Appearing in SIEMBox

**Diagnosis Checklist:**

1. **Verify syslog server is running** - Check backend logs for syslog initialization message
2. **Test network connectivity** - Verify you can reach port 514 from log source
3. **Send test log** - Manually send test syslog and check if received
4. **Check UI and database** - Verify log appears in SIEMBox

**Diagnostic Tests:**

**Test 1: Verify Backend Connectivity**
```bash
curl http://your-siembox-ip:8421/api/health
# Should return: {"status": "ok"}
```

**Test 2: Send Manual Syslog**
From any machine on your network:
```bash
# Method 1: Using logger (if available)
logger -n your-siembox-ip -P 514 "Test message"

# Method 2: Using netcat
echo "<134>$(date '+%b %d %H:%M:%S') testhost test: Test message" | nc -u your-siembox-ip 514
```

**Test 3: Check for Received Logs**
In SIEMBox UI:
- Go to Logs page
- Look for log with your test message
- If not visible, check filters/time range

**Common Causes and Solutions:**

**Firewall Blocking Port 514**
- Verify port 514 is open for UDP and TCP traffic
- Check firewall rules on both source and destination
- Test from local network first, then external

# Allow syslog from specific network
sudo ufw allow from 192.168.1.0/24 to any port 514

# Or allow all (less secure)
sudo ufw allow 514/udp
sudo ufw allow 514/tcp
```

**Backend Not Binding to Port 514:**
```bash
# Port 514 requires elevated privileges
# Check if backend is running as root in container

# View docker-compose settings
docker-compose config | grep -A5 backend

# Ensure backend has CAP_NET_BIND_SERVICE
# Add to docker-compose.yml if missing:
services:
  backend:
    cap_add:
      - NET_BIND_SERVICE
```

**Syslog Format Issues:**
```bash
# Backend expects RFC 3164 or RFC 5424 format
# Test with valid syslog message
echo "<14>Nov 30 12:00:00 server1 test[1234]: Test message" | nc -u <siembox-ip> 514

# Check backend logs for parsing errors
docker-compose logs backend | grep -i "error\|invalid"
```

---

### Issue: Logs Received But Not Parsed

**Symptoms:**
- Raw logs visible in SIEMBox UI
- No parsed fields extracted
- Parsed logs table is empty

**Root Cause:** No parser matches your log format

**Diagnosis:**

1. View a sample raw log in SIEMBox UI to see the format
2. Check Parsers page to see available parsers
3. Verify parser is enabled and has correct pattern
4. Test parser pattern against sample log

**Solutions:**

**Create New Parser:**

1. Go to Parsers page in SIEMBox UI
2. Click "Add Parser"
3. Choose parser type (regex/grok/JSON)
4. Enter pattern that matches your log format
5. Map extracted fields to field names
6. Test with sample log
7. Set appropriate priority (lower = matches first)
8. Save and enable

See [PARSERS.md](../../PARSERS.md) for detailed parser creation guide.

**Enable Existing Parser:**

1. Go to Parsers page
2. Find parser for your log type
3. Check "Enabled" checkbox
4. Save
5. New logs will be parsed on next ingestion

**Adjust Parser Priority:**

1. Go to Parsers page
2. Look at "Priority" column (lower number = higher priority)
3. If multiple parsers match, first one (lowest priority) wins
4. Adjust priorities to ensure correct parser matches
5. Save changes

**A generic parser is shadowing a specific one:** matching stops at the first
hit, so a broad parser with a low priority number claims logs a specific parser
was written for. The symptom is a log that *is* parsed but into the wrong
`event_type` with few fields (e.g. a UniFi IDS/IPS event landing as a bare
`cef_event`). Give the specific parser a lower priority number than the generic
one — `Logs → Parsed Logs → Parser` column shows which one actually claimed it.

---

### Issue: Long Logs Not Parsed (CEF, Windows Events, verbose JSON)

**Symptoms:**
- Short logs from the same device parse fine; long ones do not
- Raw Logs shows a message that looks cut off mid-field, or two messages joined
- Backend logs show `RFC 3164 match failed` with a `messageLength` well above
  your typical line

**Root Cause:** Syslog framing. Both transports are newline-delimited, and long
messages are the ones that expose framing bugs:

- **TCP is a byte stream.** A 1 KB+ line routinely arrives split across several
  socket reads. Each fragment must be reassembled before parsing — treated
  separately, one log becomes several corrupt records.
- **UDP datagrams can carry more than one line.** Senders and relays batch them.
  Stored as a single record, nothing anchored with `^…$` can match, because `.`
  does not cross a newline.

Both are handled from the release containing this note; earlier versions
mis-framed them. If you are on an older build, upgrade the backend image.

**Diagnosis:**

Run this against the database — it classifies each unparsed log by *why* it
looks wrong, which points at a different fix in each case:

Note `-T`: without it `docker compose exec` allocates a TTY and the heredoc is
swallowed. Paste the whole block, including the `SQL` terminator — not the bare
SELECT into a shell prompt.

```bash
docker compose exec -T postgres psql -U siembox -d siembox <<'SQL'
SELECT
  CASE
    WHEN rl.raw_message LIKE E'%\n%'         THEN 'packed datagram (several events in one record)'
    WHEN rl.raw_message ~ '^\w{3} +\d{1,2} ' THEN 'syslog header not stripped'
    ELSE                                          'unrecognised format (check lengths for truncation)'
  END                                        AS likely_cause,
  COUNT(*)                                   AS events,
  MIN(LENGTH(rl.raw_message))                AS min_len,
  MAX(LENGTH(rl.raw_message))                AS max_len,
  MODE() WITHIN GROUP (ORDER BY LENGTH(rl.raw_message)) AS most_common_len,
  COUNT(*) FILTER (WHERE LENGTH(rl.raw_message) BETWEEN 1000 AND 1024) AS at_1k_cap
FROM parsed_logs pl
JOIN raw_logs rl ON rl.id = pl.raw_log_id
WHERE pl.parser_id IS NULL
  AND pl.timestamp > NOW() - INTERVAL '24 hours'
GROUP BY 1
ORDER BY events DESC;
SQL
```

`max_len` well above 1024 rules out sender truncation. A large `at_1k_cap` with
`most_common_len` pinned just under 1024 is the signature of a device capping
its UDP datagrams — move that source to TCP.

Then drill into one format to see whether a specific parser is missing or a
present one is being defeated. Substitute your own marker for `CEF:`:

```bash
docker compose exec -T postgres psql -U siembox -d siembox <<'SQL'
SELECT COUNT(*)                                            AS unparsed,
       COUNT(*) FILTER (WHERE rl.raw_message LIKE E'%\n%') AS packed,
       MIN(LENGTH(rl.raw_message))                         AS min_len,
       MAX(LENGTH(rl.raw_message))                         AS max_len
FROM parsed_logs pl JOIN raw_logs rl ON rl.id = pl.raw_log_id
WHERE pl.parser_id IS NULL
  AND pl.timestamp > NOW() - INTERVAL '24 hours'
  AND rl.raw_message LIKE '%CEF:%';

-- a full sample with newlines marked, so a packed record is unmistakable
SELECT LENGTH(rl.raw_message) AS len,
       replace(rl.raw_message, E'\n', '[NL]') AS message
FROM parsed_logs pl JOIN raw_logs rl ON rl.id = pl.raw_log_id
WHERE pl.parser_id IS NULL
  AND pl.timestamp > NOW() - INTERVAL '24 hours'
  AND rl.raw_message LIKE '%CEF:%'
ORDER BY pl.id DESC LIMIT 2;
SQL
```

| Result | Meaning | Fix |
|--------|---------|-----|
| **packed datagram** | The sender put several events in one UDP datagram (or one TCP write). `.` never crosses a newline, so no `^…$` parser can match. | Fixed in the release containing this note — upgrade the backend image. |
| **syslog header not stripped** | The `<PRI>TIMESTAMP HOSTNAME` header parse failed, so the whole line was stored. | Check the sender's timestamp format against RFC 3164/5424. |
| **min_len 0** | Empty records from blank lines / keepalive newlines in a datagram. | Fixed in the release containing this note — blank frames are dropped on ingest. |
| **likely truncated by the sender** | The message ends mid key=value. Many devices cap UDP syslog at 1024 bytes. | Switch that source to TCP, which has no such cap. |
| **no parser matches** | Genuinely unrecognised format. | Install a parser from the catalog, or write one. |

Also useful:

```bash
# Fragmented or joined messages show up as unusual raw_message lengths
docker compose logs backend | grep "RFC 3164 match failed"
```

In the UI: **Logs → Parsed Logs → Parse Status: "Unparsed only"**, then compare
the raw message length against a working log from the same device. Note the Raw
Logs table renders a message on a single line, so a packed record with embedded
newlines looks deceptively like one normal event — the query above is the
reliable check.

**Also check:**

- **Sender-side truncation.** Many devices cap syslog at 1024 bytes. If the raw
  message ends mid-field, the sender truncated it — switch that source to TCP,
  which has no such limit.
- **`\r\n` line endings.** A stray trailing `\r` defeats a `$`-anchored parser.
  This is stripped on ingest now, but a custom parser that captures it will
  still fail.

---

### Issue: Logs are dropped or ingestion is slow

**Symptoms:**
- Admin dashboard → Recent Errors shows `timeout exceeded when trying to connect` (usually from `background:parser-engine`) or a `background:syslog-ingest` entry
- Backend log: `Ingestion is overloaded: dropped N UDP syslog message(s) in the last 10s ...`
- Backend log: `Ingest database connections failed N time(s) in the last 10s and were retried ...`
- Gaps in the Logs page that line up with a heavy page load, a scan, or database maintenance

**How ingestion copes with a busy database:**

Log ingestion (syslog, HTTP push, API polling) has its own database connection pool, separate from the one the web UI, API and background jobs use. In `pg_stat_activity` the two show up as `application_name = 'siembox-ingest'` and `'siembox-backend'`. A slow page or a running scan can no longer use up the connections that ingestion needs, and an ingestion burst can't freeze the UI.

Every syslog message goes through a bounded queue, and what happens when it fills depends on the transport:

| Source | When the database can't keep up |
|--------|---------------------------------|
| **TCP syslog** | The backend stops reading from the connection until there is room. The sender is slowed down by normal TCP flow control and **nothing is dropped** (the sender's own buffering decides how much it can absorb). |
| **UDP syslog** | UDP can't be slowed down, so once the queue is full the newest datagrams are **dropped and counted**. One summary line is logged every 10 seconds, and one entry per minute lands in Recent Errors. |
| **HTTP push** | The request waits for a connection. A batch that still can't reach the database stops early and reports the remaining entries as rejected with `database unavailable`; retry them (with `event_id` set, retries can't create duplicates). |

Connection failures on the ingest path (no free connection, connection refused, `too many clients`) are retried with backoff for up to 30 seconds before a message is given up on. Only failures where the statement cannot have run are retried, so a retry never stores a log twice. A message whose insert was already in flight when its connection was cut (for example `terminating connection due to administrator command`) is not retried, because it may already have been stored; each of those is logged as `Error processing syslog message`. On `docker stop` the backend stops listening, then waits up to 5 seconds for queued messages to be stored; anything still unprocessed after that is logged (`Shutdown: N syslog message(s) were still unprocessed ... and are lost`).

**Diagnosis:**
```bash
# Who holds connections, and what are they doing?
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT application_name, state, count(*)
   FROM pg_stat_activity WHERE datname = 'siembox'
   GROUP BY 1, 2 ORDER BY 1, 2;"

# Anything slow right now? (a long-running query is the usual culprit)
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pid, application_name, now() - query_start AS running, left(query, 100) AS query
   FROM pg_stat_activity
   WHERE state = 'active' AND datname = 'siembox'
   ORDER BY running DESC LIMIT 10;"

# Is something holding a lock that inserts are waiting on?
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pid, application_name, wait_event_type, wait_event, left(query, 80) AS query
   FROM pg_stat_activity WHERE wait_event_type = 'Lock';"
```

Look at what is slow rather than the symptom: a long `siembox-backend` query points at a UI page, scan or job; a lock wait on `raw_logs` points at maintenance (`VACUUM FULL`, `ALTER TABLE`); a saturated disk shows up as everything being slow at once.

**Solutions:**

- **Move must-not-lose sources off UDP.** TCP syslog and HTTP push degrade gracefully; UDP can only drop. rsyslog and syslog-ng can forward over TCP, and many appliances offer a TCP option — check the sender's remote-syslog settings.
- **Fix the cause** (the slow query, the lock, the disk) — the queue only buys time.
- **Tune the ingest path** if the load is simply high. In our testing (a 4-core machine running Postgres alongside the backend) the defaults sustained roughly 2,500 messages per second:

  | Variable | Default | Meaning |
  |----------|---------|---------|
  | `DB_INGEST_POOL_MAX` | `20` | Connections in the ingest pool. |
  | `INGEST_CONCURRENCY` | pool size − 2 | Messages processed at once; keep it at or below the pool size. |
  | `INGEST_QUEUE_MAX` | `20000` | Messages held in memory while all workers are busy; past this, UDP is dropped and TCP is slowed. |
  | `DB_INGEST_ACQUIRE_TIMEOUT_MS` | `10000` | How long one attempt waits for a free connection. |
  | `DB_INGEST_RETRY_MS` | `30000` | Total time spent retrying connection failures; `0` turns retrying off. |

  The backend's compose file passes through only the variables it lists, so add any of these to the `backend` service's `environment:` and redeploy. The backend now uses up to 40 database connections at most (20 main + 20 ingest); Postgres' default `max_connections = 100` covers that, but see [Too Many Connections](#issue-too-many-connections-error) if you run other clients.

---

## Log Shipper Issues

### Issue: Shipper Shows as "Offline" or "Unknown Source"

**Symptoms:**
- Shipper appears offline in SIEMBox UI
- Shipper shows as "Unknown Source" (ghost shipper)
- No logs being received from shipper

**Common Causes:**

1. **Invalid API Key** - Shipper API key is incorrect or expired
2. **Network Connectivity** - Shipper can't reach SIEMBox API
3. **Backend Down** - SIEMBox API is not responding
4. **Shipper Misconfiguration** - Log sources not configured

**Solutions:**

**Check Shipper Configuration:**
1. In SIEMBox UI, go to Shippers page
2. Find the offline shipper
3. Verify API key hasn't expired or been deleted
4. Verify log sources are configured and enabled
5. Note the Shipper ID (8-character hash)

**Verify Network Connectivity:**
1. From the shipper host, test:
   ```bash
   curl http://your-siembox-ip:8421/api/health
   ```
2. Should return `{"status": "ok"}`
3. If not reachable:
   - Check SIEMBox is running
   - Verify firewall allows port 8421
   - Check routing between networks

**Update Shipper API Key:**
1. In SIEMBox UI, open the shipper's details and copy its current API key (admins and operators can see it), or click **Regenerate** for a new one (admin only; an operator can delete the shipper and add it again instead)
2. Update shipper's SHIPPER_API_KEY environment variable
3. Restart shipper container
4. Wait 30-60 seconds for re-registration
5. Shipper should no longer show as offline

**Investigate Ghost Shipper:**

If shipper shows as "Unknown Source":
- Shipper is sending logs with invalid API key
- Logs continue due to cached configuration
- This is normal during API key rotation
- Once shipper is updated and restarted, it will re-register with correct key

See [SHIPPER-DIAGNOSTICS.md](./SHIPPER-DIAGNOSTICS.md) for detailed shipper troubleshooting.

# Check DNS resolution
docker exec siembox-log-shipper nslookup <siembox-hostname>

# Test syslog connectivity
docker exec siembox-log-shipper nc -zv <siembox-ip> 514
```

**Heartbeat Not Working:**
```bash
# Shipper sends heartbeat every 60 seconds
# Wait 2-3 minutes and check last_seen

# Check shipper script is running
docker exec siembox-log-shipper ps aux | grep shipper

# Check for errors in logs
docker logs siembox-log-shipper | grep -i error
```

---

### Issue: Logs Not Being Forwarded

**Symptoms:**
- Shipper shows online
- No logs appearing in SIEMBox
- Shipper logs show "File not found" warnings

**Diagnosis:**
```bash
# Check shipper logs for file access errors
docker logs siembox-log-shipper | grep -E "File not found|Permission denied"

# List shipper configuration
curl http://localhost:8421/api/shippers/<shipper-id> \
  -H "Authorization: Bearer $TOKEN" | jq '.sources, .volumes'

# Check if files exist on HOST
ls -la /var/log/nginx/access.log  # Example path
```

**Solutions:**

**Volume Not Mounted:**
```bash
# Problem: Shipper can't access log files because volume not mounted
# Check shipper's docker-compose.yml

# Add volume mount:
volumes:
  - /var/log/nginx:/var/log/nginx:ro  # HOST:CONTAINER:MODE

# Restart shipper
docker-compose down
docker-compose up -d

# Verify mount
docker inspect siembox-log-shipper | jq '.[0].Mounts'
```

**File Path Mismatch:**
```bash
# Source path in UI must match CONTAINER path, not HOST path

# Example:
# HOST path: /var/log/nginx/access.log
# Volume mount: /var/log/nginx:/logs:ro
# Source path in UI: /logs/access.log  (NOT /var/log/nginx/access.log)

# Update source path in UI or API:
curl -X PUT http://localhost:8421/api/shippers/sources/<source-id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/logs/access.log"}'
```

**Permission Denied:**
```bash
# Check file permissions on HOST
ls -la /var/log/nginx/access.log

# If not readable, add shipper user to group
# Or make file readable
sudo chmod +r /var/log/nginx/access.log
```

**Source Disabled:**
```bash
# Check if source is enabled
curl http://localhost:8421/api/shippers/<shipper-id>/sources \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {id, enabled, tag}'

# Enable source
curl -X PUT http://localhost:8421/api/shippers/sources/<source-id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

---

## Log Discovery & API-Polled Sources

### Issue: An API-polled source keeps failing (Home Assistant: HTTP 404 from error_log)

**Symptoms:**
- Backend log: `[DiscoveryApiPoller] source 94 (home-assistant) poll failed: ...`. Before Home Assistant's Supervisor fallback existed the message was `HTTP 404 from Home Assistant error_log`, and there was no way to change the port, endpoint or address of a polled source.
- No events arrive from the source; its row shows an error.

**Where to look:** every API-polled source shows the URL being polled (never the token) and its last error, in Log Discovery and under Log Shippers → API-Polled Sources. The same from the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8421/api/log-discovery/sources/94/poller \
  | jq '{last_status, last_error, url: .target.effective_url}'
```

**Why Home Assistant answers 404:** where Home Assistant serves its log depends on how it is installed.

| Install type | `/api/error_log` | `/api/hassio/core/logs` |
|--------------|------------------|-------------------------|
| Container or Core | the log file (`home-assistant.log`) | does not exist (404) |
| Container or Core with `HA_DISABLE_LOG_FILE=true` | 404 (no log file) | does not exist (404) |
| Home Assistant OS or Supervised | 404: no log file, unless `HA_DUPLICATE_LOG_FILE` is set | the Core log, from the Supervisor's journal |

Home Assistant registers `/api/error_log` only while it writes a log file. Home Assistant OS and Supervised installs log to the systemd journal and skip the file, so there the route doesn't exist and the answer is 404; the same log is available through the Supervisor at `/api/hassio/core/logs`.

**What SIEMBox does about it:** it asks `/api/error_log` first and, on a 404, reads `/api/hassio/core/logs?no_colors` (the latest journal entries; lines are stored in Home Assistant's own format, so the catalog parser still matches). It remembers which endpoint works for each source, so a Home Assistant OS install doesn't get a doomed request every poll, and tries `/api/error_log` again every 6 hours and whenever the remembered endpoint fails. The source's URL then ends in `/api/hassio/core/logs`. A standard install on port 8123 needs nothing configured.

**How much of the log is read:** only its end. From `/api/error_log` SIEMBox asks for the last 5 MB of the file plus the last record it already has, to find its place (`Range: bytes=-5242880` on a first poll, a little more after), so a `home-assistant.log` that has grown past 5 MB since Home Assistant last started keeps being collected, and up to 5 MB logged between two polls is collected whole. If more than 5 MB was logged since the last poll (a login brute force, debug logging, a long poll interval), every new line of those last 5 MB is collected and the lines before them are not. (Just over 5 MB can leave the read beginning inside the last record collected, so that nothing was missed; when SIEMBox can't tell that from a larger burst, the warning's message says lines "may not have been collected" rather than "were not collected".) From the Supervisor it asks for 500 new journal entries (plus the last record it already has, to find its place), and when more lines than that arrived since the last poll (a login brute force can do it), for 5000; if even those don't reach back to the last poll, the latest 5000 lines are collected. In both cases a warning, "Some Home Assistant log lines may not have been collected", is written to the error log on the dashboard: shorten that source's poll interval. Each poll resumes after the last record it collected, so an error that Home Assistant logs again and again, traceback and all, is collected once per time it is logged (for records of up to 2000 lines).

**Change the port, HTTPS, endpoint or address** (admin): Log Discovery → **Edit** on the source, or Log Shippers → API-Polled Sources → **Edit**, then **Save and poll now** to see the result straight away. Leave **Endpoint** empty for the automatic choice above. Set it to use only that path, for example behind a reverse proxy that serves Home Assistant under a prefix (`/homeassistant/api/error_log`). The same through the API:

```bash
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://localhost:8421/api/log-discovery/sources/94 \
  -d '{"port": 8123, "tls": false, "endpoint": "/api/hassio/core/logs"}'

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8421/api/log-discovery/sources/94/poller/run-now | jq .
```

Only a manually added source's address can be changed; a scan-discovered source is polled where the scan found it (add the other address as a manual source instead). A new endpoint or address makes the next poll start again from the source's recent lines, so up to 200 Home Assistant lines that were already stored can be stored a second time. Changing a manual source's address while it has a saved token needs the token again (the Edit dialog asks for it, or send `credential` with the PATCH); a saved token is never sent to a new address. Port, HTTPS and endpoint changes keep the saved token. If someone else moved the source to another address while your Edit dialog was open, or after you typed a token in the Onboard dialog (a token is kept for the address shown when you typed it, even if the dialog shows the new address since), saving a setting or a token answers `409` and changes nothing, so a token typed for the old address never reaches the new one: close the dialog, open it again and check the address (the Onboard dialog clears the token and shows the new address for you). A save that runs at the same moment as another admin's save of this source's address, port, HTTPS or endpoint also answers `409` and changes nothing, rather than undoing the other change, and so does a move without a token that runs at the same moment as a token save. A token saved for the source's current address and a change that keeps the address don't conflict: both apply. Changes to fields you did not touch are not detected: the dialog sends only what you changed, so another admin's earlier change of another field stays.

**The token must belong to an administrator.** Both log endpoints are admin-only. In Home Assistant, sign in as an administrator, open your profile → **Security** → **Long-lived access tokens** → **Create token**, and paste the token in the source's **Edit** dialog. A token of a user who is not an administrator gets 401 from both endpoints.

**What the errors mean:**

| `last_error` starts with | Cause | Fix |
|--------------------------|-------|-----|
| `Home Assistant rejected the token (HTTP 401 ...)` | The token is invalid or revoked, or its user is not an administrator | Create a long-lived token as an administrator and paste it in **Edit** |
| `Home Assistant refused the request (HTTP 403 ...)` | Home Assistant banned SIEMBox's address after failed logins (`ip_ban_enabled`), or a reverse proxy refuses it | Remove the address from `ip_bans.yaml` in Home Assistant's config folder, restart Home Assistant, check the token |
| `Home Assistant at http://... answered 404 for both log endpoints` | Neither endpoint exists there: `HA_DISABLE_LOG_FILE=true` on a Container/Core install, the wrong port (something else answers), or a reverse-proxy path | Check the port (8123 by default) and HTTPS; behind a reverse proxy set the endpoint with its prefix; on Container/Core, remove `HA_DISABLE_LOG_FILE` |
| `Home Assistant answered 404 for the configured endpoint ...` | The endpoint set in **Edit** doesn't exist on this install | Correct it, or clear it for the automatic choice |
| `Home Assistant could not get its log from the Supervisor (HTTP 502 ...)` | The Supervisor or its journal service isn't answering | Check Settings → System → Repairs and the Supervisor log on the Home Assistant host; the next poll retries |
| `... returned a web page, not Home Assistant's log` | The port or endpoint reaches another app or a proxy's page | Correct the port or endpoint |
| `Couldn't connect to http://...: connection refused` (or `TLS handshake failed`, `connection reset`) | Wrong address or port, the device is down, or the HTTPS switch doesn't match the port | Fix the address, port or HTTPS in **Edit** |

---

## Parser Problems

### Issue: "Invalid regular expression: Invalid group" Error

**Symptoms:**
- Backend logs show repeated errors: `Regex parser <name> error: Invalid regular expression: Invalid group`
- Parser appears in database but fails at runtime
- Error mentions `(?P` in the pattern

**Root Cause:**
Parser contains Python-style regex syntax `(?P<name>...)` instead of JavaScript syntax `(?<name>...)`. JavaScript's RegExp doesn't support Python's named group syntax.

**Example Error:**
```
Regex parser vaultwarden-access error: Invalid regular expression: /^\[(?P\d{4}-\d{2}-\d{2}...: Invalid group
```

**Diagnosis:**
```bash
# Check for Python-style regex in database
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT id, name, substring(pattern, 1, 100) as pattern_preview
   FROM parsers
   WHERE pattern LIKE '%(?P<%'
   ORDER BY priority;"

# Run comprehensive validation
npx ts-node backend/scripts/validate-parsers.ts
```

**Solution:**

**Option 1: SQL Fix Script (Recommended for existing databases)**
```bash
# Fix vaultwarden parser specifically
docker exec -i siembox-postgres psql -U siembox -d siembox < backend/scripts/fix_vaultwarden_parser.sql

# Or connect interactively
docker exec -it siembox-postgres psql -U siembox -d siembox

# Then update the parser
UPDATE parsers
SET pattern = '<corrected-javascript-pattern>',
    updated_at = NOW()
WHERE name = 'vaultwarden-access';
```

**Option 2: Fix Migration (For fresh deployments)**
If you haven't deployed yet, fix the migration file:
- Edit `backend/migrations/005_add_vaultwarden_parser.sql`
- Replace all `(?P<name>` with `(?<name>`
- Ensure pattern uses negative lookahead instead of non-greedy quantifiers for complex extractions

**Option 3: Validation & Batch Fix**
```bash
# Validate all parsers and get detailed report
cd backend
npx ts-node scripts/validate-parsers.ts

# View SQL validation report
docker exec -i siembox-postgres psql -U siembox -d siembox \
  < scripts/validate_all_parsers_and_rules.sql
```

**Prevention:**
- Always use JavaScript regex syntax: `(?<name>...)` not `(?P<name>...)`
- Test regex patterns at https://regex101.com with flavor "ECMAScript (JavaScript)"
- Run `npx ts-node backend/scripts/validate-parsers.ts` before deployment
- Include parser validation in your CI/CD pipeline

**Related Files:**
- `backend/scripts/fix_vaultwarden_parser.sql` - Fix script for vaultwarden parser
- `backend/scripts/validate-parsers.ts` - Comprehensive parser validation
- `backend/scripts/validate_all_parsers_and_rules.sql` - SQL-based validation report
- `backend/scripts/README.md` - Documentation for all validation scripts

---

### Issue: Parser Not Matching Logs

**Diagnosis:**
```bash
# Test parser with sample log
curl -X POST http://localhost:8421/api/parsers/<parser-id>/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sample": "your actual log message here"}'

# Check response:
# {"matched": true, "fields": {...}}  = Success
# {"matched": false, "fields": null}  = No match
```

**Common Issues:**

**Regex Syntax Error:**
```bash
# Test regex pattern separately
# Use https://regex101.com with flavor "ECMAScript (JavaScript)"

# Common mistakes:
# ❌ Single backslash: \d+
# ✅ Double backslash: \\d+

# ❌ Named groups with brackets: (?<name>[A-Z]+)
# ✅ Escaped backslashes: (?<name>[A-Z]+)
```

**Field Mapping Wrong:**
```json
// For regex parsers, map capture group NUMBER to field name
{
  "1": "timestamp",
  "2": "hostname",
  "3": "message"
}

// NOT:
{
  "timestamp": "timestamp"  // ❌ Wrong
}
```

**Grok Pattern Issues:**
```bash
# SIEMBox uses node-grok library
# Built-in patterns: https://github.com/Beh01der/node-grok/tree/master/patterns

# Example grok pattern:
%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}

# Field mappings for grok:
{
  "timestamp": "timestamp",
  "level": "level",
  "message": "message"
}
```

---

### Issue: Parser Matches Wrong Logs

**Symptoms:**
- Parser designed for SSH logs matches Apache logs
- Multiple parsers matching same log

**Diagnosis:**
```bash
# Check parser priorities
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT id, name, priority, enabled FROM parsers ORDER BY priority;"

# View which parser matched a log
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pl.id, pl.parser_id, p.name, pl.parsed_data
   FROM parsed_logs pl
   JOIN parsers p ON pl.parser_id = p.id
   ORDER BY pl.timestamp DESC LIMIT 10;"
```

**Solution:**
```bash
# Make parser pattern more specific
# Add additional constraints to regex

# Before (too generic):
# (?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<message>.+)

# After (specific to SSH):
# (?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+sshd\\[(?<pid>\\d+)\\]:

# Update parser priority (lower = higher precedence)
# Specific parsers: 1-50
# Application-specific: 51-100
# Generic parsers: 100-500
# Fallback parser: 1000
```

---

## Detection Rules

### Issue: Rule Not Triggering Alerts

**Check parse coverage FIRST.** Detection rules are only evaluated on logs
that a parser matched — logs that fall through to the unparsed fallback are
stored and searchable but **never run through the rules engine**. If most of
your stream is unparsed, no amount of rule tuning will produce alerts. The
Dashboard shows **Detection Coverage (24h)** (and warns below 50%), and the
Parsers page shows per-parser **Matches (24h)**; or query directly:

```bash
curl http://localhost:8421/api/logs/parse-coverage \
  -H "Authorization: Bearer $TOKEN"

# Or in the database: share of logs invisible to detection
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT (parser_id IS NULL) AS unparsed, COUNT(*)
   FROM parsed_logs WHERE timestamp >= NOW() - INTERVAL '24 hours' GROUP BY 1;"
```

If coverage is low, fix parsing first. The **Recommended for your logs** panel
at the top of the Parsers page dry-runs every not-installed catalog parser
against a sample of your recent unparsed logs and ranks them by coverage
gained (weighting warning-or-worse traffic higher) — install from there, and
use its "no catalog match" list to seed the AI builder for sources the catalog
doesn't cover. See [Parser Problems](#parser-problems) for why a parser that
passes its self-tests can still miss your live logs.

**Aggregation rules and clock skew.** Threshold rules (`aggregation:`) count
matching logs inside a time window measured against the **server's** clock,
but `parsed_logs.timestamp` comes from the sender. A device with a wrong
timezone or clock puts its logs outside the window, so counts never reach the
threshold and the rule stays silent even though its conditions match. Compare
sender vs. ingest time per source:

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT COALESCE(p.name,'(fallback)') AS parser,
          percentile_cont(0.5) WITHIN GROUP (ORDER BY pl.created_at - pl.timestamp) AS median_skew
   FROM parsed_logs pl LEFT JOIN parsers p ON pl.parser_id = p.id
   WHERE pl.created_at > NOW() - INTERVAL '24 hours' GROUP BY 1;"
```

Median skew should be near zero; minutes-to-hours means a sender clock or
timezone problem.

**Diagnosis:**
```bash
# Check if rule is enabled
curl http://localhost:8421/api/rules \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {id, name, enabled}'

# Check parsed logs match rule conditions
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT parsed_data FROM parsed_logs
   WHERE parsed_data->>'event' = 'Failed password'
   ORDER BY timestamp DESC LIMIT 5;"

# Check backend logs for rule evaluation
docker-compose logs backend | grep -i "rule\|alert"
```

**Common Issues:**

**Field Name Mismatch:**
```yaml
# Rule looks for 'source_ip' but parser extracts 'src_ip'
conditions:
  - field: source_ip  # ❌ Field doesn't exist in parsed data
    operator: equals
    value: "192.168.1.100"

# Fix: Use correct field name from parser
conditions:
  - field: src_ip  # ✅ Matches parser output
    operator: equals
    value: "192.168.1.100"
```

**Threshold Not Met:**
```yaml
# Rule requires 5 events but only 3 occurred
aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5  # Needs 5 events

# Solution: Lower threshold or extend timeframe
aggregation:
  field: source_ip
  timeframe: 10m  # Longer window
  threshold: 3    # Lower threshold
```

**Condition Operator:**
```yaml
# Using wrong operator
conditions:
  - field: status_code
    operator: equals  # ❌ Expects exact string match
    value: "404"

# For numeric comparisons:
conditions:
  - field: status_code
    operator: equals  # ✅ Works if status_code is string "404"
    value: "404"
```

---

### Issue: Too Many False Positive Alerts

**Solution:**
```yaml
# Add more specific conditions
conditions:
  - field: event
    operator: equals
    value: "Failed password"
  - field: user
    operator: not_contains  # ✅ Exclude test accounts
    value: "test"

# Increase threshold
aggregation:
  threshold: 10  # Up from 5

# Extend timeframe
aggregation:
  timeframe: 10m  # Up from 5m

# Add exclusion conditions
conditions:
  - field: source_ip
    operator: not_contains
    value: "10.0.0"  # Exclude internal network
```

---

## Database Issues

### Issue: "Too Many Connections" Error

**Symptoms:**
```
FATAL: sorry, too many clients already
Error: connect ETIMEDOUT
```

**Diagnosis:**
```bash
# Check current connections
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT COUNT(*) as connection_count FROM pg_stat_activity;"

# Check max connections setting
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SHOW max_connections;"

# View active connections
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pid, usename, application_name, client_addr, state
   FROM pg_stat_activity WHERE state != 'idle';"
```

**Solutions:**

**Increase Max Connections:**
```bash
# Edit docker-compose.yml
services:
  postgres:
    command:
      - "postgres"
      - "-c"
      - "max_connections=200"  # Increased from 100

# Restart
docker-compose restart postgres
```

**Fix Connection Leaks:**
```bash
# Kill idle connections
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state = 'idle' AND state_change < NOW() - INTERVAL '10 minutes';"

# Restart backend to reset connection pool
docker-compose restart backend
```

---

### Issue: Database Disk Space Full

**Symptoms:**
```
ERROR: could not extend file: No space left on device
database disk quota exceeded
```

**Diagnosis:**
```bash
# Check disk usage
df -h /var/lib/docker/volumes/

# Check database size
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pg_size_pretty(pg_database_size('siembox'));"

# Check table sizes
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
   FROM pg_tables
   WHERE schemaname = 'public'
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"
```

**Solutions:**

**Emergency Cleanup:**
```bash
# Delete old logs manually
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "DELETE FROM raw_logs WHERE timestamp < NOW() - INTERVAL '7 days';"

docker exec siembox-postgres psql -U siembox -d siembox -c \
  "DELETE FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '7 days';"

# Vacuum to reclaim space
docker exec siembox-postgres psql -U siembox -d siembox -c "VACUUM FULL;"
```

**Configure Retention:**
```bash
# Set retention policies via API
curl -X PUT http://localhost:8421/api/settings/retention \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs_days": 14,
    "parsed_logs_days": 30,
    "alerts_days": 90,
    "auto_cleanup_enabled": true
  }'

# Trigger manual cleanup
curl -X POST http://localhost:8421/api/settings/retention/cleanup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs_days": 7,
    "parsed_logs_days": 14,
    "alerts_days": 30
  }'
```

---

## Authentication Problems

### Issue: Unable to Login

**Symptoms:**
- "Invalid username or password" error
- Login form doesn't respond

**Diagnosis:**
```bash
# Check if backend is running
docker-compose ps backend

# Check backend logs for auth errors
docker-compose logs backend | grep -i "auth\|login"

# Verify user exists
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT id, username, email, enabled FROM users;"
```

**Solutions:**

**Wrong Password:**
```bash
# Reset admin password (requires database access)
docker exec siembox-postgres psql -U siembox -d siembox

# Generate new password hash (use bcrypt online tool or Node.js)
# Then update:
UPDATE users SET password_hash = '$2b$10$NEW_HASH_HERE' WHERE username = 'admin';
```

**Account Disabled:**
```bash
# Enable account
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "UPDATE users SET enabled = true WHERE username = 'admin';"
```

**CORS Error:**
```bash
# Check browser console for CORS errors
# Update backend .env:
CORS_ORIGIN=http://your-frontend-domain.com

# Restart backend
docker-compose restart backend
```

---

### Issue: Session Expired Immediately

**Symptoms:**
- Login successful but redirected back to login
- Token expires within seconds

**Diagnosis:**
```bash
# Check system time synchronization
docker exec siembox-backend date
docker exec siembox-postgres date
date  # Host system time

# Check session expiration
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT user_id, created_at, expires_at, NOW()
   FROM sessions ORDER BY created_at DESC LIMIT 5;"
```

**Solution:**
```bash
# Synchronize system clocks
sudo ntpdate -s time.nist.gov

# Or install NTP daemon
sudo apt install ntp
sudo systemctl enable ntp
sudo systemctl start ntp
```

---

### Issue: 401 or 403 from Shipper, Asset, Vulnerability or Scan Endpoints After Upgrading

**Symptoms:**
- A script or integration that reads `/api/assets`, `/api/vulnerabilities` or manages `/api/shippers` now gets `401 Authentication required`
- An analyst or viewer gets `403` when changing a shipper, its sources or volumes
- An operator gets `403` when regenerating a shipper's key, or generating or revoking its HTTP push key
- A viewer gets `403` when adding, editing or deleting an asset or starting an asset scan; an analyst or viewer gets `403` when starting or cancelling a vulnerability, log-discovery or container scan, changing or running a scheduled scan, changing a vulnerability's status or downloading Nuclei templates
- Straight after the upgrade, Asset Inventory shows "Session expired. Please login again." and logs you out, and it happens again after you log back in

**Cause:** these routes now require a login, and each write requires a role. Earlier versions answered them without a login, or let any logged-in role make the call.
- Shippers: regenerating a shipper's key (`POST /api/shippers/:id/regenerate-key`) and the HTTP push-key routes (`POST` and `DELETE /api/shippers/:id/http-push-key`) need an admin. Every other change to a shipper, its sources or its volumes needs an admin or operator.
- Scans and assets: a write needs the roles that can open the page that makes it. That is admin, analyst or operator for Asset Inventory and Templates, and admin or operator for Vulnerability Scanning, Vulnerability Management, Scheduled Scans, Log Discovery and Container Scanning. See [Roles for scan and asset writes](../reference/API.md#roles-for-scan-and-asset-writes).
- The shipper agent's own endpoints (`/register`, `/config/:api_key`, `/scan-jobs/:api_key` and the rest) are unaffected: they still authenticate with the shipper's key.

The "Session expired" loop comes from a browser tab that was open during the upgrade. That tab still runs the previous UI, which requested `/assets/scans*` without the session token. The API now answers those requests with `401`, and the UI treats any `401` as an expired session. Logging in again in the same tab does not help, because the tab keeps the old UI loaded.

**Solution:**
```bash
# Log in once and send the token on each request
TOKEN=$(curl -s -X POST http://localhost:8421/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "..."}' | jq -r '.token')

curl http://localhost:8421/api/assets -H "Authorization: Bearer $TOKEN"
```

For the "Session expired" loop, reload the page (Ctrl+Shift+R, or Cmd+Shift+R on macOS) so the tab loads the new UI, then log in if asked. Other open tabs need the same reload.

For a `403`, use an account with the role listed under **Cause**: an admin to regenerate a shipper's key or manage its HTTP push key, an admin or operator for other shipper, source and volume changes. An operator who needs a new shipper key can delete the shipper and add it again; its sources and volumes then have to be added again. Analysts and viewers can still list shippers, but the list omits each shipper's `api_key`.

---

### Issue: 403 When Changing Parsers, Rules or Alerts, or Using the AI Analyst

**Symptoms:**
- A script or integration using a viewer's token gets `403 Access denied. Required role: analyst or higher. Your role: viewer` when it creates, changes, deletes, imports or installs parsers or detection rules (including `/catalog/install`, `/catalog/install-all` and `/catalog/refresh`), calls `POST /api/parsers/validate` or `POST /api/parsers/test`, updates an alert (`PUT /api/alerts/:id`), or uses the AI Analyst (`POST /api/ai/chat`, renaming or deleting a chat thread)
- An analyst or operator gets `403 Access denied. Required role: admin or higher` from `DELETE /api/alerts/:id`
- A viewer no longer sees Add, Import, Delete or Install on the Parsers and Detection Rules pages (Edit is now View), Refresh in the catalog dialogs, the Update buttons on Alerts, or the AI triage panel's Analyze now, Re-run, Ask the analyst and Use suggested status buttons
- A viewer's `GET /api/parsers/catalog?refresh=true` or `GET /api/rules/catalog?refresh=true` returns the cached catalog instead of fetching it again from GitHub

**Cause:** viewers are read-only. Changing parsers and detection rules, re-fetching their catalogs from GitHub (each fetch uses the GitHub API's 60-requests-an-hour allowance), triaging alerts and the AI Analyst need analyst or higher, and deleting an alert needs an admin. Earlier versions let any logged-in role make these calls, deleting alerts included. See [Roles](../reference/API.md#roles).

**Solution:** use an analyst, operator or admin account for those calls, and an admin to delete an alert (or close it as `closed` or `false_positive`, which needs only an analyst). A browser tab that was open during the upgrade still shows the old controls: reload it. Each refusal is written to the audit log, which shows which accounts still make these calls:
```sql
SELECT a.created_at, u.username, a.resource_type, a.details->>'method' AS method, a.details->>'path' AS path
  FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
 WHERE a.action = 'access.denied' AND a.resource_type IN ('parser', 'detection_rule', 'alert', 'ai_chat')
 ORDER BY a.created_at DESC LIMIT 50;
```
`path` is relative to the route family (`resource_type`), for example `/12` for `PUT /api/parsers/12`.

---

## Performance Issues

### Issue: Slow Query Response

**Diagnosis:**
```bash
# Check database load
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pid, query, state, query_start
   FROM pg_stat_activity
   WHERE state != 'idle'
   ORDER BY query_start;"

# Check slow queries (if enabled)
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT query, mean_exec_time, calls
   FROM pg_stat_statements
   ORDER BY mean_exec_time DESC LIMIT 10;"

# Check index usage
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT schemaname, tablename, indexname, idx_scan
   FROM pg_stat_user_indexes
   ORDER BY idx_scan ASC;"
```

**Solutions:**

**Missing Indexes:**
```sql
-- Add index on frequently queried fields
CREATE INDEX idx_parsed_logs_timestamp ON parsed_logs(timestamp);
CREATE INDEX idx_parsed_logs_source_ip ON parsed_logs((parsed_data->>'source_ip'));
CREATE INDEX idx_raw_logs_source_ip ON raw_logs(source_ip);
```

**Increase Resources:**
```yaml
# docker-compose.yml
services:
  postgres:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
    shm_size: 512MB
```

**Optimize Queries:**
```bash
# Use pagination (limit/offset)
curl "http://localhost:8421/api/logs/parsed?limit=50&offset=0"

# Use specific time ranges
curl "http://localhost:8421/api/logs/parsed?start_date=2025-11-30T00:00:00Z&end_date=2025-11-30T23:59:59Z"
```

---

### Issue: High Memory Usage

**Diagnosis:**
```bash
# Check container memory
docker stats --no-stream

# Check PostgreSQL memory
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pg_size_pretty(pg_total_relation_size('parsed_logs'));"
```

**Solutions:**
```yaml
# Tune PostgreSQL memory settings
services:
  postgres:
    command:
      - "postgres"
      - "-c"
      - "shared_buffers=512MB"
      - "-c"
      - "effective_cache_size=2GB"
      - "-c"
      - "work_mem=8MB"
```

---

## Network & Connectivity

### Issue: Can't Access Web UI

**Diagnosis:**
```bash
# Check if frontend is running
docker-compose ps frontend

# Check frontend logs
docker-compose logs frontend

# Test locally
curl -I http://localhost:8420

# Test from remote
curl -I http://<server-ip>:8420
```

**Solutions:**

**Firewall Blocking:**
```bash
sudo ufw allow 8420/tcp
```

**Wrong Port:**
```bash
# Check docker-compose.yml ports mapping
docker-compose config | grep -A2 "frontend:" | grep ports

# Access on correct port
```

**Reverse Proxy Configuration:**
```bash
# If using nginx, check config
sudo nginx -t
sudo systemctl status nginx

# Check nginx logs
sudo tail -f /var/log/nginx/error.log
```

### Issue: Digital Risk domain monitoring shows errors (or never finds anything)

The domain monitor (`domain-monitor` job) needs outbound HTTPS to `crt.sh`,
`data.iana.org` and the registries' RDAP servers, plus working DNS. Each
watched domain records the outcome of its last run per collector:

```bash
# Per-collector status, notes and errors of every watched domain
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8421/api/exposure/domains \
  | jq '.[] | {domain, last_status, last_error, collectors: .last_summary.collectors}'

# Run one domain now and read the result directly (allow a few minutes)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8421/api/exposure/domains/1/run-now | jq .
```

**What the statuses mean:**
- `baseline` on the first run is normal: existing certificates, lookalikes,
  registration data and DNS records are recorded silently, and only later
  changes alert (expiry warnings and certificates from a CA outside
  `expected_cas` are the exceptions).
- `ct: crt.sh is temporarily unavailable (HTTP 502)` / `did not answer in time`:
  crt.sh is a free, often overloaded service. These are transient — the failed
  collectors are retried after 60 minutes (backing off), the others keep their
  regular schedule, and nothing is lost: a newly registered lookalike crt.sh
  failed on is checked first next time, and still counts as new.
- `ct: could not connect to crt.sh within 45 s (is outbound HTTPS blocked?)` (or
  the same for an RDAP server) — no connection was ever made (TCP or the TLS
  handshake never completed): an egress firewall, proxy or SNI filter is
  dropping outbound HTTPS from the backend. The `domain-monitor` job itself
  shows `failed` only when nothing worked for any domain (e.g. no network or
  DNS at all); otherwise the failing collectors show in each domain's
  `last_error`.
- `ct` warning `<name>: crt.sh returned only part of the certificates for
  <name> ... too many to monitor reliably` (or `returned more than 10 MB`; also
  `details.own_domain_error`) — crt.sh stops at 10,000 matching names per
  query, picked in no particular order, so the domain's own certificates can't
  be monitored; the certificates of its registered lookalikes still are. To
  monitor your own certificates, watch a narrower name (e.g. a subdomain).
  Turning `ct` off for the domain would stop the lookalike certificate checks
  too.
- `ct: crt.sh answered HTTP 403` (or another 4xx) — crt.sh, or more often an
  egress proxy or TLS-inspecting filter in between, refused the request (for
  the domain itself or for one of its lookalikes; brand domains query only
  lookalikes). It is not retried early, and no lookalike check is put off
  because of it: allow outbound HTTPS to `crt.sh` and the next regular run
  picks it up.
- `rdap: unsupported` — the TLD publishes no RDAP service, or only a plain-HTTP
  one (refused on purpose); registration changes can't be monitored there.
- `rdap: refused to contact ...` — the RDAP server named by IANA's bootstrap
  resolved to a private or otherwise non-public address, which is refused as
  an SSRF guard. Check the backend's DNS for split-horizon or filtering setups.
- `dns` warning `the resolver returned no NS records for a delegated domain` — a
  filtering or broken resolver; NS changes can't be judged until it answers
  NS queries (the old baseline is kept, nothing is reported as removed). Its
  other empty answers in that run are not trusted either (warnings `<type>: no
  records, from a resolver that also returned no NS records; not trusted`), so
  it can't record or report MX, TXT or DMARC records as removed — or as added
  once it is fixed. Optionally set `exposure_dns_secondary_resolver` to a
  resolver you trust.
- `dns: every DNS lookup for <name> failed (NS: <name> does not resolve
  (NXDOMAIN); ...)` — the watched name doesn't exist right now: a registry or
  registrar hold (check the `rdap` status), a lapsed registration, or a
  resolver that blocks it. Nothing is reported as removed meanwhile.
- `dns` warning `<type>: <resolver> failed (...); the system resolver's answer
  was used alone` — the second resolver didn't answer, so that record set was
  not cross-checked; findings say so in `detail.resolvers`.
- `lookalike: DNS lookups failed for every lookalike candidate` — DNS from the
  backend is down or blocked; retried automatically.

### Issue: Everyone shows the same IP address

**Symptoms:**
- Audit rows, the Admin dashboard's error list and shipper records show one
  address (a `172.x` Docker address, your reverse proxy's, or `127.0.0.1`) for
  every user.
- Users who aren't doing much get `429 Too Many Requests` together: they all
  share one budget of `API_RATE_LIMIT_MAX` (default 1000) requests per 15
  minutes, and one budget of 100 failed sign-ins (each account still has its
  own 10).
- The backend log has hourly `Ignored X-Forwarded-For from <address> ...`
  warnings: a proxy in front of the web UI, or a caller of port 8421, whose
  `X-Forwarded-For` has been ignored for more than 45 s. Only proxies on
  private, carrier-grade NAT, loopback, ULA or link-local addresses are logged:
  one on a public address (Cloudflare's proxy, a VPS proxying over the
  internet) is not, so its absence proves nothing. Check `you.address` below.

**Diagnosis:** as an admin, open `GET /api/admin/client-address` through the
web UI's address and read `you` and `warnings`:
```bash
curl -s -H "Authorization: Bearer $TOKEN" http://<host>:8420/api/admin/client-address
docker logs siembox-backend 2>&1 | grep -E "Client addresses|Proxy socket|X-Forwarded-For|TRUSTED_PROXIES"
```

**Causes and fixes** (DEPLOYMENT.md, "Client addresses and reverse proxies",
has the full table):
- **`proxySocket.state` is `no-volume`:** the compose file predates the
  `api-socket` volume. In bridge mode the `frontend` name still keeps addresses
  correct; with host networking everyone shares the frontend container's
  address. Pull the current compose file and redeploy.
- **A reverse proxy in front of SIEMBox:** add it to `TRUSTED_PROXIES`, keeping
  `frontend` (`TRUSTED_PROXIES=frontend,192.168.1.20`), and redeploy with
  `docker compose up -d` (a plain restart keeps the old environment). A proxy
  container on `siembox-network` can be listed by service name; one on the
  Docker host must proxy to the host's LAN address, not `127.0.0.1`. A proxy
  on a public address shows up in `ignoredForwardedFor.peers` with
  `local: false`, and in `warnings` only when your own request came through
  it.
- **`proxySocket.state` is `listening`, yet the frontend's address is reported
  as ignored:** the frontend isn't reaching the socket. Check that the
  frontend container runs the current image and mounts `api-socket` at
  `/run/siembox`, and that `SIEMBOX_PROXY_SOCKET` is unset (the bundled nginx
  only connects to `/run/siembox/api.sock`).
- **`you.address` is the Docker gateway (`172.x.0.1`):** you are reaching a
  published port over IPv6 or from the Docker host itself, which Docker's
  userland proxy rewrites to the gateway. Use the host's IPv4 LAN address.
- **A `TRUSTED_PROXIES` entry doesn't take effect:** `warnings` says why (a
  rejected value such as `*` or `uniquelocal`, a name that doesn't resolve on
  the backend's network, a name in host networking mode, where only IP
  addresses work). A name whose answers are listed under `ignoredAnswers` got
  them from a DNS server other than Docker's (a LAN DNS server, typical on a
  macvlan or ipvlan network): list the proxy's IP address instead.
- **With host networking, the frontend's `172.x` address shows up in
  `ignoredForwardedFor.peers` right after a backend restart:** expected. nginx
  uses its TCP fallback for up to 30 s after the socket failed (a restart, or a
  request that timed out), and that address can't be trusted by name here.
  Each such window counts on its own once the socket serves requests again;
  only one that goes on for more than 45 s is reported in `warnings`.

### Issue: Frontend log shows `connect() to unix:/run/siembox/api.sock failed`

**Symptoms:** the frontend container logs
`connect() to unix:/run/siembox/api.sock failed (2: No such file or directory)`
(or `(111: Connection refused)`), each followed by
`upstream server temporarily disabled`, about every 30 seconds, while the web
UI works.

**Cause:** nginx proxies `/api` to the backend's unix socket on the
`api-socket` volume and falls back to `BACKEND_UPSTREAM` over TCP when it can't
connect, retrying the socket every 30 s. The socket is missing when:
- the compose file predates the volume (images updated, compose file not);
- the backend image is older than the frontend image;
- the backend logged `Proxy socket not started: ...` (its reason follows), or
  runs with `SIEMBOX_PROXY_SOCKET=off` or with it set to another path (the
  bundled nginx only connects to `/run/siembox/api.sock`);
- the backend is restarting (a few lines then are normal; nginx stays on the
  TCP fallback for up to 30 s after the backend is back, then returns to the
  socket).

A request on the socket that times out (`upstream timed out`) also makes that
nginx worker use the fallback for 30 s, followed by the same
`upstream server temporarily disabled` line.

**Solution:** pull the current compose file (it mounts `api-socket` at
`/run/siembox` on the backend and read-only on the frontend) and redeploy with
`docker compose up -d`. Then check `GET /api/admin/client-address`:
`proxySocket.state` should be `listening` and `you.via` `proxy-socket`.

### Issue: `429 Too Many Requests` or "Too many failed sign-in attempts ..."

**Cause:** a rate limit (DEPLOYMENT.md and API.md, "Rate Limiting"): more than
`API_RATE_LIMIT_MAX` (default 1000) API requests in 15 minutes from one
address; 10 failed sign-ins in 15 minutes for one account from one address
("... for this account from your address"); or, after 100 failed sign-ins
from one address, another try for an account that already failed from it in
its own 15-minute window ("... from your address"). The message says how long
to wait; the counters are kept in memory.

**Solution:**
- Wait for the time in the message, or restart the backend to clear every
  counter at once.
- If many people share one address (an office NAT, a reverse proxy SIEMBox
  doesn't trust), see "Everyone shows the same IP address" above, or raise
  `API_RATE_LIMIT_MAX`.
- Shippers and endpoint agents have their own limits (`SHIPPER_LOG_PUSH_MAX`,
  `EDR_AGENT_RATE_MAX`); EDR enrollment counts toward the general limit.

---

## Frontend Issues

### Issue: Blank Page or JavaScript Errors

**Diagnosis:**
```bash
# Check browser console (F12)
# Look for errors

# Check if API is accessible
curl http://localhost:8421/api/auth/me \
  -H "Authorization: Bearer $TOKEN"

# Check frontend build
docker-compose logs frontend | grep -i error
```

**Solutions:**

**Rebuild Frontend:**
```bash
docker-compose down
docker-compose build --no-cache frontend
docker-compose up -d frontend
```

**API URL Misconfigured:**
```bash
# Check VITE_API_URL in .env
grep VITE_API_URL .env

# Should be:
VITE_API_URL=/api  # If using same domain
# Or:
VITE_API_URL=http://backend-server:8421/api  # If separate
```

---

## Container Issues

### Issue: Container Keeps Restarting

**Diagnosis:**
```bash
# Check restart count
docker ps -a | grep siembox

# View last crash logs
docker-compose logs --tail=100 <service-name>

# Check exit code
docker inspect <container-id> | jq '.[0].State'
```

**Solutions:**

**Out of Memory:**
```bash
# Increase memory limit
# docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 2G
```

**Dependency Not Ready:**
```bash
# Ensure proper depends_on with healthcheck
services:
  backend:
    depends_on:
      postgres:
        condition: service_healthy
```

---

## Data Cleanup

### Issue: Cleanup Service Not Running

**Diagnosis:**
```bash
# Check if cleanup is enabled
curl http://localhost:8421/api/settings/retention \
  -H "Authorization: Bearer $TOKEN"

# Check backend logs for cleanup
docker-compose logs backend | grep -i cleanup
```

**Solution:**
```bash
# Enable auto cleanup
curl -X PUT http://localhost:8421/api/settings/retention \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auto_cleanup_enabled": true,
    "raw_logs_days": 30,
    "parsed_logs_days": 90,
    "alerts_days": 365
  }'

# Restart backend
docker-compose restart backend
```

---

## Advanced Diagnostics

### Full System Health Check Script

```bash
#!/bin/bash
echo "=== SIEMBox Health Check ==="
echo ""

echo "1. Container Status:"
docker-compose ps
echo ""

echo "2. Port Listening:"
netstat -tuln | grep -E "514|8420|8421|5432"
echo ""

echo "3. Database Connectivity:"
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT 1;"
echo ""

echo "4. Log Counts:"
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT
    (SELECT COUNT(*) FROM raw_logs) as raw_logs,
    (SELECT COUNT(*) FROM parsed_logs) as parsed_logs,
    (SELECT COUNT(*) FROM alerts) as alerts;"
echo ""

echo "5. Disk Usage:"
df -h /var/lib/docker/volumes/ | grep siembox
echo ""

echo "6. Recent Errors:"
docker-compose logs --tail=50 | grep -i error
echo ""

echo "Health check complete!"
```

---

## Getting Help

If you've tried everything and still have issues:

1. **Gather Information:**
```bash
# Collect logs
docker-compose logs > siembox-logs-$(date +%Y%m%d).txt

# System info
docker version > system-info.txt
docker-compose version >> system-info.txt
uname -a >> system-info.txt
```

2. **Check Documentation:**
- [README.md](./README.md)
- [DEPLOYMENT.md](./DEPLOYMENT.md)
- [API.md](./API.md)

3. **Search Existing Issues:**
https://github.com/cladkins/SIEMBOX/issues

4. **Open New Issue:**
https://github.com/cladkins/SIEMBOX/issues/new

Include:
- System information
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs
- Configuration (sanitized)

---

**Last Updated:** 2025-12-02
