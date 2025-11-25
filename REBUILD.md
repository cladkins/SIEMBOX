# SIEM BOX - Minimal Rebuild

**Goal:** Strip everything back to basics. Just receive syslog and display it.

## Phase 1: Database - Just Logs

### What We Need
- Single table: `logs`
- Columns: id, timestamp, hostname, source_ip, message, raw_syslog

### SQL Schema
```sql
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    hostname VARCHAR(255),
    source_ip VARCHAR(45),
    message TEXT,
    raw_syslog TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX idx_logs_source_ip ON logs(source_ip);
```

---

## Phase 2: Syslog Listener

### What It Does
1. Listen on UDP 514
2. Parse basic syslog format
3. Store in database
4. Log success/errors

### Syslog Format (RFC 3164)
```
<PRI>TIMESTAMP HOSTNAME MESSAGE
```

Example:
```
<134>Nov 24 12:34:56 firewall kernel: DROP IN=eth0 SRC=1.2.3.4
```

### Code Flow
```
UDP 514 → Parse → Insert DB → Done
```

---

## Phase 3: Simple API

### Endpoints
1. `GET /logs` - Get recent logs
2. `GET /logs/count` - Total log count
3. `GET /health` - Is it alive?

That's it. No auth, no pagination (yet), no filters.

---

## Phase 4: Basic Frontend

### Single Page
- Table showing last 50 logs
- Columns: Timestamp, Hostname, Source IP, Message
- Auto-refresh every 5 seconds
- No charts, no graphs, just logs

---

## Testing Checklist

- [ ] Database table created
- [ ] Can insert test log manually
- [ ] Syslog listener starts without errors
- [ ] Send test syslog via netcat
- [ ] Log appears in database
- [ ] API returns logs
- [ ] Frontend displays logs
- [ ] Real firewall syslog appears

---

## Success Criteria

```bash
# Send syslog
echo "<134>Nov 24 12:34:56 test-host test message" | nc -u -w1 localhost 514

# Check it's stored
curl http://localhost:8000/logs

# See it in browser
open http://localhost:3000
```

If all three work → we have a SIEM.

Then we can add features one by one.
