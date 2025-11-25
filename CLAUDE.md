# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

SIEM BOX is a **lightweight, self-hosted SIEM solution** designed for homelab environments. The architecture has been simplified to focus on the core functionality: **syslog ingestion, log storage, and web-based viewing**.

## Simplified Architecture

### Core Components

**Backend: `simple-backend.py` (~350 lines)**
- FastAPI application with integrated syslog server
- UDP 514 syslog receiver (RFC 3164 parsing)
- PostgreSQL storage via asyncpg
- JWT authentication
- REST API for log retrieval

**Database: PostgreSQL**
- Single `logs` table with indexes
- Schema defined in `init-minimal-db.sql`
- Stores parsed syslog messages

**Frontend: React Dashboard**
- Located in `frontend/`
- Nginx-served static build
- Connects to backend API
- JWT token-based authentication

### Log Flow

```
Firewall/Router → UDP 514 → simple-backend.py → PostgreSQL → React UI
    (Syslog)                   (Parse + Store)     (logs)      (View)
```

1. Device sends syslog to UDP 514
2. `simple-backend.py` parses syslog (RFC 3164 format)
3. Extracts: timestamp, hostname, source_ip, message
4. Stores in `logs` table
5. Frontend queries via `/api/v1/logs` endpoint

## File Structure

```
/
├── simple-backend.py          # Main backend (syslog + API)
├── init-minimal-db.sql        # Database schema
├── compose.yaml               # Docker deployment
├── frontend/                  # React UI
│   ├── Dockerfile
│   └── (React app)
├── backend-old-backup/        # Archived complex backend (not used)
└── compose-old-backup.yaml    # Archived complex compose (not used)
```

## Development Commands

### Docker Deployment (Primary Method)

```bash
# Start all services
docker compose up -d

# Watch logs
docker compose logs -f

# Stop services
docker compose down

# View specific service logs
docker logs siembox-backend
docker logs siembox-postgres
docker logs siembox-frontend
```

### Testing Syslog Ingestion

```bash
# Send test syslog
echo "<134>Nov 24 12:34:56 test-host Test message" | nc -u localhost 514

# Check backend received it
docker logs siembox-backend | grep SYSLOG

# Check database
docker exec siembox-postgres psql -U siembox -d siembox \
  -c "SELECT * FROM logs ORDER BY id DESC LIMIT 5;"
```

### API Testing

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Get logs (with auth token)
TOKEN="<your-token-here>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/logs

# Dashboard stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/dashboard/stats
```

## Important Implementation Details

### Backend: simple-backend.py

**Key Classes:**
- `SyslogServer` - Handles UDP 514 syslog ingestion
- `SyslogProtocol` - asyncio DatagramProtocol for receiving UDP packets

**Key Functions:**
- `parse_syslog()` - Parses RFC 3164 format: `<PRI>TIMESTAMP HOSTNAME MESSAGE`
- `handle_syslog()` - Receives UDP packet, parses, stores in DB
- `store_log()` - Inserts into PostgreSQL `logs` table

**API Endpoints:**
- `POST /api/v1/auth/login` - Returns JWT token (hardcoded admin/admin123)
- `GET /api/v1/logs` - Returns paginated logs (requires auth)
- `GET /api/v1/dashboard/stats` - Returns log counts (requires auth)

**Authentication:**
- Hardcoded credentials: `admin` / `admin123`
- JWT tokens with 24-hour expiration
- Bearer token authentication on protected endpoints

### Database Schema

**Table: logs**
```sql
CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,        -- Parsed from syslog
    hostname VARCHAR(255),               -- Parsed from syslog
    source_ip VARCHAR(45) NOT NULL,      -- UDP source address
    message TEXT,                        -- Parsed message content
    raw_syslog TEXT NOT NULL,            -- Original syslog string
    created_at TIMESTAMP DEFAULT NOW()   -- Insertion timestamp
);
```

**Indexes:**
- `idx_logs_timestamp` - Fast time-based queries
- `idx_logs_source_ip` - Filter by source
- `idx_logs_hostname` - Filter by host

### Frontend

**Build System:** Vite
**Framework:** React 18
**Deployment:** Nginx container serves static build

**Key Pages:**
- Login page (`/login`)
- Dashboard (`/`)
- Logs page (`/logs`)

**API Integration:**
- Uses `fetch()` with JWT tokens
- Base URL configured in Vite proxy
- Nginx proxies `/api/*` to backend

### Docker Compose Structure

```yaml
services:
  postgres:          # PostgreSQL database
  backend:           # simple-backend.py
  frontend:          # React + Nginx
```

**Ports:**
- `514/udp` - Syslog ingestion
- `3000` - Frontend web UI
- `8000` - Backend API
- `5432` - PostgreSQL (internal)

## Configuration

### Environment Variables (Backend)

Set in `compose.yaml` under backend service:

```yaml
environment:
  DB_HOST: postgres
  DB_PORT: 5432
  DB_NAME: siembox
  DB_USER: siembox
  DB_PASS: siembox
  SECRET_KEY: change-me-in-production
```

### Syslog Configuration

Devices should send syslog to:
- **Host:** SIEM BOX IP address
- **Port:** 514
- **Protocol:** UDP
- **Format:** Any (will be parsed as RFC 3164)

## Troubleshooting

### No logs appearing in UI

1. **Check backend is receiving syslogs:**
   ```bash
   docker logs siembox-backend | grep SYSLOG
   ```
   Should see: `[SYSLOG] ✅ hostname from source_ip`

2. **Verify database has logs:**
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox \
     -c "SELECT COUNT(*) FROM logs;"
   ```

3. **Test API returns logs:**
   ```bash
   # Login and get token
   TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}' | \
     python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

   # Get logs
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/logs
   ```

4. **Check frontend can reach backend:**
   - Open browser console (F12)
   - Look for API errors
   - Verify requests to `/api/v1/*` are going through

### Port 514 permission errors

Port 514 requires privileged access. If you see permission errors:

```bash
docker logs siembox-backend | grep -i permission
```

Add to `compose.yaml` under backend service:
```yaml
backend:
  privileged: true
```

### Frontend build fails

```bash
# Check frontend logs
docker logs siembox-frontend

# Rebuild
docker compose up -d --build frontend
```

## What This System Does

✅ **Working Features:**
- Syslog ingestion (UDP 514)
- Log storage in PostgreSQL
- REST API with authentication
- React dashboard for viewing logs
- Basic statistics (total logs, 24h logs)

❌ **Not Implemented:**
- Detection rules
- Alerts
- Notifications
- Vulnerability scanning
- User management (beyond hardcoded admin)
- Log filtering/search in UI (backend supports it)
- Advanced analytics

## Development Philosophy

This is a **simplified, focused SIEM** that does ONE thing well: **collect and display syslogs**.

**Design Principles:**
1. Simple is better than complex
2. Self-contained (no external dependencies)
3. Easy to understand (~350 lines of backend code)
4. Easy to deploy (one docker compose command)
5. Foundation for future features

## Next Steps for Enhancement

When basic functionality is proven working:

1. **Add log filtering** in frontend (backend already supports `limit`, `skip`)
2. **Add basic detection rules** (e.g., failed SSH attempts)
3. **Add simple alerting** (e.g., Discord webhook)
4. **Add log search** (by hostname, IP, message content)
5. **Add user management** (proper user database)

But first: **verify basic syslog → storage → display works perfectly**.

## Testing Checklist

Before considering enhancements:

- [ ] Can receive syslog from firewall/router
- [ ] Logs appear in database
- [ ] React UI displays logs
- [ ] Dashboard shows correct stats
- [ ] Authentication works
- [ ] Can view logs from last 24 hours
- [ ] System stable for 24+ hours
- [ ] No memory leaks
- [ ] No database performance issues

## Support & Documentation

- **[README.md](README.md)** - Main documentation
- **[SIMPLE-DEPLOY.md](SIMPLE-DEPLOY.md)** - Deployment guide
- **[TESTING.md](TESTING.md)** - Testing procedures
- **API Docs**: http://localhost:8000/docs (FastAPI auto-generated)

## Common Issues

**Issue:** "Can't login to UI"
**Solution:** Credentials are hardcoded: `admin` / `admin123`

**Issue:** "No logs showing in UI"
**Solution:** Check all 3 layers (syslog reception, database storage, API response)

**Issue:** "Port 514 already in use"
**Solution:** Another syslog daemon might be running (rsyslog, syslog-ng)

---

**Remember:** This is a SIMPLE system. Don't add complexity unless absolutely necessary. The goal is a working foundation, not a feature-complete enterprise SIEM.
