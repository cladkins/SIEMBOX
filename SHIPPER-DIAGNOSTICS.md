# Log Shipper Diagnostic Guide

This guide helps diagnose issues with the SIEMBox managed log shipper when logs aren't being forwarded.

## Architecture Overview

The managed log shipper uses this workflow:

```
Container Start
    ↓
Register with Backend API (/api/shippers/register)
    ↓
Receive Configuration (sources, volumes, siem_host, siem_port)
    ↓
Apply Configuration (start tailing files/containers)
    ↓
Poll for Updates (every CONFIG_POLL_INTERVAL seconds)
    ↓
Send Heartbeat (every HEARTBEAT_INTERVAL seconds)
```

## Your Configuration

Based on your docker-compose.yml:

- **API Key**: `f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031`
- **Backend URL**: `http://192.168.1.76:3001/api`
- **Config Poll**: Every 30 seconds
- **Heartbeat**: Every 60 seconds
- **Network**: Host mode

**Volume Mounts**:
- `/etc/komodo/stacks/npm/data/logs` → `/etc/komodo/stacks/npm/data/logs` (ro)
- `/var/run/docker.sock` → `/var/run/docker.sock` (ro)

**UI Configuration** (from screenshot):
- **Log Source**: file type
- **Path**: `/etc/komodo/stacks/npm/data/logs/*.log`
- **Tag**: `NGINX`
- **Facility**: `local0`

## Common Issues & Solutions

### Issue 1: Configuration Not Being Returned

**Symptom**: Shipper logs show "No sources configured" or "source_count=0"

**Diagnosis**:
1. Run the API test script:
   ```bash
   ./test-shipper-config-api.sh
   ```

2. Expected response should include:
   ```json
   {
     "sources": [
       {
         "source_type": "file",
         "file_path": "/etc/komodo/stacks/npm/data/logs/*.log",
         "tag": "NGINX",
         "facility": "local0",
         "enabled": true
       }
     ],
     "siem_host": "192.168.1.76",
     "siem_port": 514
   }
   ```

**Possible Causes**:
- Database doesn't have the source record
- API endpoint isn't querying sources correctly
- Source is disabled (`enabled = false`)

**Solution**:
Check the database directly:
```sql
-- Find your shipper ID
SELECT id, name, api_key FROM log_shippers
WHERE api_key = 'f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031';

-- Check sources (replace {shipper_id} with the ID from above)
SELECT * FROM shipper_sources WHERE shipper_id = {shipper_id};
```

### Issue 2: Files Not Found in Container

**Symptom**: Shipper logs show "No files found matching pattern"

**Diagnosis**:
Check if files exist inside the container:
```bash
docker exec siembox-log-shipper ls -la /etc/komodo/stacks/npm/data/logs/
```

**Possible Causes**:
- Volume mount is incorrect
- Path doesn't exist on host
- No log files match the glob pattern `*.log`

**Solution**:
1. Verify files exist on host:
   ```bash
   ls -la /etc/komodo/stacks/npm/data/logs/
   ```

2. Check volume mounts are active:
   ```bash
   docker inspect siembox-log-shipper | jq '.[0].Mounts'
   ```

3. Test glob pattern expansion:
   ```bash
   docker exec siembox-log-shipper sh -c 'ls -la /etc/komodo/stacks/npm/data/logs/*.log'
   ```

### Issue 3: File Permissions

**Symptom**: Shipper can see files but can't read them

**Diagnosis**:
Check file permissions inside container:
```bash
docker exec siembox-log-shipper sh -c 'ls -la /etc/komodo/stacks/npm/data/logs/ && id'
```

**Solution**:
Files must be readable by the user running the shipper (typically root in Alpine).

### Issue 4: Shipper Not Fetching Configuration

**Symptom**: Shipper logs show connection errors or HTTP failures

**Diagnosis**:
Test connectivity from inside the container:
```bash
docker exec siembox-log-shipper curl -v http://192.168.1.76:3001/api/shippers/config/f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031
```

**Possible Causes**:
- Network connectivity issue
- Backend not running
- Firewall blocking
- Using host network mode but backend is in bridge network

**Solution**:
Since you're using `network_mode: host`, the container should have full host network access. Verify:
1. Backend is accessible from host: `curl http://192.168.1.76:3001/api/health`
2. No firewall rules blocking localhost

### Issue 5: Configuration Format Error

**Symptom**: Shipper receives config but doesn't apply it

**Check shipper logs for**:
- "jq failed" - JSON parsing issue
- "Unsupported source type" - source_type field is wrong
- Debug logs showing config structure

**Solution**:
The shipper expects this exact structure:
```json
{
  "sources": [
    {
      "source_type": "file",
      "file_path": "/path/to/files/*.log",
      "tag": "TAG_NAME",
      "facility": "local0",
      "enabled": true
    }
  ],
  "siem_host": "192.168.1.76",
  "siem_port": 514
}
```

## Diagnostic Procedure

Follow these steps in order:

### Step 1: Check Shipper Container Logs

```bash
docker logs -f siembox-log-shipper
```

**Look for**:
- `[INFO] SIEMBox Managed Log Shipper Starting` - Container started
- `[INFO] Successfully registered with SIEMBox` - Initial registration worked
- `[DEBUG] Registration returned X bytes` - Config was received
- `[INFO] Found N source(s)` - Sources were parsed
- `[INFO] Tailing file: /path/to/file` - File tailing started
- `[WARN] No files found matching pattern` - Glob expansion failed
- `[ERROR] Failed to fetch config` - API call failed

### Step 2: Test API Endpoint

```bash
./test-shipper-config-api.sh
```

This script will:
- Call the configuration API endpoint
- Display the HTTP status code
- Pretty-print the JSON response
- Show number of sources
- Display SIEM connection info

### Step 3: Verify File Access

```bash
# On the host
ls -la /etc/komodo/stacks/npm/data/logs/

# Inside container
docker exec siembox-log-shipper ls -la /etc/komodo/stacks/npm/data/logs/

# Test glob pattern
docker exec siembox-log-shipper sh -c 'ls -la /etc/komodo/stacks/npm/data/logs/*.log'
```

### Step 4: Check Database State

```bash
# Connect to PostgreSQL
docker exec -it siembox-postgres psql -U siembox -d siembox

# Check shipper
SELECT id, name, api_key, status, last_seen FROM log_shippers;

# Check sources (use the shipper ID from above)
SELECT * FROM shipper_sources WHERE shipper_id = {your_shipper_id};

# Check volumes
SELECT * FROM shipper_volumes WHERE shipper_id = {your_shipper_id};
```

### Step 5: Manual Configuration Test

If the API isn't returning configuration, you can test the shipper manually:

1. Create a test config file:
   ```yaml
   # /tmp/test-config.json
   {
     "sources": [
       {
         "source_type": "file",
         "file_path": "/etc/komodo/stacks/npm/data/logs/*.log",
         "tag": "NGINX",
         "facility": "local0",
         "enabled": true
       }
     ],
     "siem_host": "192.168.1.76",
     "siem_port": 514
   }
   ```

2. Inject it into the container to test:
   ```bash
   docker exec siembox-log-shipper sh -c 'cat > /tmp/test-config.json' < /tmp/test-config.json
   ```

## Debug Mode

The managed shipper has extensive debug logging. Check logs for these patterns:

```bash
# Filter for configuration-related logs
docker logs siembox-log-shipper 2>&1 | grep -E "(DEBUG|apply_config|source)"

# Filter for file tailing
docker logs siembox-log-shipper 2>&1 | grep -E "(Tailing|tail_file|No files)"

# Filter for API calls
docker logs siembox-log-shipper 2>&1 | grep -E "(Fetching|register|HTTP)"
```

## Key Log Messages

| Message | Meaning | Action |
|---------|---------|--------|
| `No sources configured (count=0)` | Backend returned empty sources array | Check database sources table |
| `No files found matching pattern: X` | Glob expansion found no files | Verify files exist and are accessible |
| `Tailing file: /path/to/file` | ✓ Successfully started tailing | Working correctly! |
| `Failed to fetch config (HTTP 404)` | Invalid API key | Check API key in docker-compose.yml |
| `Failed to register (HTTP 500)` | Backend error | Check backend logs |
| `jq failed` | JSON parsing error | Check API response format |

## Expected Working Output

When everything is working, you should see:

```
[INFO] 2025-12-10 16:30:00 =========================================
[INFO] 2025-12-10 16:30:00 SIEMBox Managed Log Shipper Starting
[INFO] 2025-12-10 16:30:00 =========================================
[INFO] 2025-12-10 16:30:00 Version: 1.0.0
[INFO] 2025-12-10 16:30:00 API URL: http://192.168.1.76:3001/api
[INFO] 2025-12-10 16:30:00 Poll Interval: 30s
[INFO] 2025-12-10 16:30:00
[INFO] 2025-12-10 16:30:00 Performing initial registration...
[INFO] 2025-12-10 16:30:01 Successfully registered with SIEMBox
[INFO] 2025-12-10 16:30:01 Applying configuration (SIEM: 192.168.1.76:514)
[INFO] 2025-12-10 16:30:01 Found 1 source(s)
[INFO] 2025-12-10 16:30:01 Tailing file: /etc/komodo/stacks/npm/data/logs/nginx.log (tag: NGINX, pattern: /etc/komodo/stacks/npm/data/logs/*.log)
[INFO] 2025-12-10 16:30:01
[INFO] 2025-12-10 16:30:01 Log shipper running. Polling for configuration updates...
```

## Next Steps

After running through this diagnostic guide, you should have identified one of these scenarios:

1. **Configuration not in database** → Add source via UI or API
2. **Files don't exist** → Fix volume mount or verify host path
3. **API not returning config** → Check backend logs and database queries
4. **Files found but not parsing** → Check syslog format and parser configuration
5. **Everything looks good** → Check if logs are arriving at backend (check `raw_logs` table)

## Contact

If you're still stuck after following this guide, gather:
- Output from `./test-shipper-config-api.sh`
- Shipper container logs (`docker logs siembox-log-shipper`)
- Backend logs showing the API request
- Database query results for shipper_sources table

This information will help diagnose the exact issue.
