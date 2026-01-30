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

## Shipper Configuration

When you set up a log shipper, you configure:

- **API Key**: Unique identifier for shipper authentication
- **Backend URL**: SIEMBox API endpoint (typically http://siembox-server:3001/api)
- **Config Poll**: How often shipper checks for config updates (default 30 seconds)
- **Heartbeat**: How often shipper reports status to backend (default 60 seconds)

**Log Sources** configured via the SIEMBox UI:
- **Source Type**: file, journald, or docker
- **Source Path**: Location of logs to collect (e.g., `/var/log/nginx/*.log`)
- **Tag**: Label for logs (e.g., `NGINX`)
- **Facility**: Syslog facility level (default `local0`)

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
1. In SIEMBox UI, go to Shippers page
2. Find your shipper
3. Verify sources are configured and enabled
4. If not, create a new source with correct path
5. Shipper will fetch new config on next poll (within 30 seconds)

### Issue 2: Files Not Found in Container

**Symptom**: Shipper logs show "No files found matching pattern"

**Possible Causes**:
- Volume mount is incorrect or missing
- Source path doesn't exist on the system
- No log files match the glob pattern
- File permissions prevent reading

**Solution**:
1. Verify the source path exists on your system and contains log files
2. Check that the path is correctly configured in SIEMBox UI
3. Verify the shipper container has access to the directory (via volume mount)
4. Check file permissions allow reading by the shipper process
5. For Docker container logs, ensure `/var/run/docker.sock` is mounted

### Issue 3: File Permissions

**Symptom**: Shipper can see files but can't read them

**Diagnosis**:
Verify the source path has readable permissions for the shipper process.

**Solution**:
Files must be readable by the shipper user (typically root in the container). Ensure:
- Source files have world-readable permissions (or user-readable)
- Parent directories are traversable (executable)
- Volume mounts preserve permissions

### Issue 4: Shipper Not Fetching Configuration

**Symptom**: Shipper logs show connection errors or HTTP failures

**Possible Causes**:
- Network connectivity issue between shipper and SIEMBox
- Backend API is not running
- Firewall blocking the connection
- Incorrect backend URL in shipper configuration

**Solution**:
1. Verify backend API is accessible from the network where shipper runs
2. Test with: `curl http://your-siembox-ip:3001/api/health`
3. Check firewall rules allow port 3001
4. Verify shipper environment variables point to correct backend URL
5. Check SIEMBox logs for connection errors

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

### Step 1: Verify Configuration

In the SIEMBox UI:
1. Navigate to Shippers page
2. Find your shipper
3. Verify sources are configured with:
   - Correct source path
   - Proper file pattern (e.g., `*.log`)
   - Correct tag and facility
   - Source is enabled (not disabled)

### Step 2: Check Backend Connectivity

From a machine on your network, verify SIEMBox is accessible:
```bash
curl http://your-siembox-ip:3001/api/health
```

Expected response:
```json
{"status": "ok"}
```

### Step 3: Verify Shipper Container

Through your deployment platform's logs/shell:
- Check shipper container is running
- Review startup logs for errors
- Verify environment variables (SHIPPER_API_KEY, SIEM_HOST, SIEM_PORT)

### Step 4: Test Source Paths

Verify the source paths exist and are accessible:
- For file sources: Ensure files exist at the configured path
- For Docker sources: Ensure Docker socket is mounted
- For journald sources: Ensure journal is accessible

### Step 5: Monitor Log Flow

Once configured:
1. Send test log to source (e.g., write to monitored file)
2. Check SIEMBox UI for received logs
3. Monitor shipper for errors
```

### Step 4: Check Configuration Delivery

Once sources are configured in the SIEMBox UI, verify they are being delivered to the shipper:

1. The shipper polls for configuration every 30 seconds
2. After configuring sources, wait 30-60 seconds
3. Check shipper logs for "Applying configuration" message
4. Look for "Found N source(s)" in logs
5. Verify "Tailing file:" messages appear

## Log Analysis

Review shipper logs for key messages indicating status:

**Looking for in logs:**
- `Performing initial registration...` - Shipper starting up
- `Successfully registered with SIEMBox` - API key valid and registration worked
- `Applying configuration` - Configuration received from backend
- `Found N source(s)` - Sources parsed successfully
- `Tailing file:` - File monitoring active
- `No files found matching pattern` - Path issue
- `Failed to fetch config` - Connection or API key error
- `Successfully sent N logs` - Logs being forwarded

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

When everything is working correctly, you should see these key messages in shipper logs:

```
[INFO] SIEMBox Managed Log Shipper Starting
[INFO] Performing initial registration...
[INFO] Successfully registered with SIEMBox
[INFO] Applying configuration (SIEM: your-siembox-ip:514)
[INFO] Found N source(s)
[INFO] Tailing file: /path/to/logs (tag: TAGNAME)
[INFO] Log shipper running. Polling for configuration updates...
[INFO] Successfully sent N logs to SIEM
```

Once you see these messages:
1. Logs should start appearing in SIEMBox UI
2. Check raw log viewer to confirm logs are being received
3. Verify parser tags match your configured tags
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
