# Source Identification Feature - Implementation Summary

## Overview

Added the ability to identify log sources in the parsed logs UI by storing and displaying the syslog TAG field (app_name). This solves the problem where logs from multiple sources (different Docker containers, file sources) arriving from the same IP address could not be distinguished.

## Problem Statement

**Before this change:**
- All logs from source IP 192.168.1.194 looked identical
- No way to tell if a log came from:
  - NGINX file logs
  - Docker container logs (backend, postgres, etc.)
  - Different shipper sources
- Analysts had to manually correlate logs with external information

**Screenshot showing the problem:**
- Only "Source IP" and "Event Type" columns visible
- All logs from 192.168.1.194 appear identical
- No indication of which container or file generated each log

## Solution

Added the `app_name` field (syslog TAG) throughout the system:

### Database Changes (`backend/migrations/001_initial_schema.sql`)
```sql
-- Added to raw_logs table:
app_name VARCHAR(255), -- Syslog TAG field (e.g., NGINX, docker-backend)

-- Added index for filtering:
CREATE INDEX IF NOT EXISTS idx_raw_logs_app_name ON raw_logs(app_name);
```

### Backend Changes

**1. RawLog Model** (`backend/src/models/RawLog.ts`)
- Added `app_name` to `RawLog` interface
- Added `app_name` to `CreateRawLogParams` interface
- Updated `create()` method to insert app_name

**2. Syslog Server** (`backend/src/services/syslog/syslogServer.ts`)
- Modified `processSyslogMessage()` to pass `parsed.appName` to `RawLogModel.create()`
- The syslog parser already extracts the TAG field as `appName`

**3. ParsedLog Model** (`backend/src/models/ParsedLog.ts`)
- Added `app_name` to `ParsedLog` interface (optional field from join)
- Modified `findAll()` to join with raw_logs table:
  ```sql
  SELECT pl.*, rl.app_name
  FROM parsed_logs pl
  LEFT JOIN raw_logs rl ON pl.raw_log_id = rl.id
  ```
- Added `appName` filter parameter support
- Updated all WHERE clauses to use table prefixes (pl., rl.)

**4. Logs API** (`backend/src/routes/logs.ts`)
- Added `app_name` query parameter to parsed logs endpoint
- Passed through to `ParsedLogModel.findAll()`

### Frontend Changes (`frontend/src/views/Logs.vue`)

**1. New Filter Input**
```html
<el-form-item label="Source">
  <el-input
    v-model="filters.app_name"
    placeholder="e.g., NGINX"
    clearable
    style="width: 180px"
  />
</el-form-item>
```

**2. New Source Column**
```html
<el-table-column prop="app_name" label="Source" width="150">
  <template #default="{ row }">
    <el-tag v-if="row.app_name" type="success" size="small">
      {{ row.app_name }}
    </el-tag>
    <el-text v-else type="info" size="small">N/A</el-text>
  </template>
</el-table-column>
```

**3. Filter State and Query Building**
- Added `app_name` to filters reactive object
- Added `app_name` to `buildQueryParams()` function

## Data Flow

```
Syslog Message Arrives
  ↓
RFC 3164 Parsing (extracts TAG → appName)
  ↓
Store in raw_logs (includes app_name) ✓
  ↓
Parser Engine processes message
  ↓
Store in parsed_logs
  ↓
API Query (JOIN raw_logs to get app_name)
  ↓
Frontend displays Source column with app_name
```

## Example Usage

### Log Shipper Configuration

When you configure sources in the log shipper UI:

**File Source:**
- Path: `/etc/komodo/stacks/npm/data/logs/*.log`
- Tag: `NGINX`
- Result: Logs appear with `app_name = "NGINX"`

**Docker Source:**
- Container: `siembox-backend`
- Tag: `BACKEND`
- Result: Logs appear with `app_name = "BACKEND"`

### Syslog Format

The shipper sends logs in RFC 3164 format:
```
<PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
```

Example:
```
<134>Dec 10 20:36:20 komodo NGINX: [10/Dec/2025:20:35:53 +0000] - 200 GET
```

The TAG field (`NGINX` in this example) is extracted and stored as `app_name`.

### UI Display

**Parsed Logs Table:**
```
Timestamp           | Source IP      | Source  | Event Type    | Parsed Data
--------------------|----------------|---------|---------------|-------------
Dec 10, 2025 16:55  | 192.168.1.194  | NGINX   | http_request  | View Data
Dec 10, 2025 16:55  | 192.168.1.194  | BACKEND | http_request  | View Data
Dec 10, 2025 16:54  | 192.168.1.194  | NGINX   | http_request  | View Data
```

**Filtering:**
- Filter by Source: Enter "NGINX" to see only NGINX logs
- Filter by Source IP + Source: Combine filters for precise analysis
- All filters work together (AND logic)

## Migration Notes

### For Existing Deployments

**1. Database Schema Update**

After pulling this code, the database will automatically create the `app_name` column when migrations run on startup.

**For manual migration:**
```sql
ALTER TABLE raw_logs ADD COLUMN app_name VARCHAR(255);
CREATE INDEX idx_raw_logs_app_name ON raw_logs(app_name);
```

**2. Existing Logs**

- Old logs in `raw_logs` will have `app_name = NULL`
- The UI handles this gracefully (shows "N/A")
- New logs will have the app_name field populated

**3. No Downtime Required**

- The column addition is non-breaking
- NULL values are handled throughout the stack
- Frontend displays "N/A" for logs without app_name

## Testing Recommendations

### Backend Testing
```bash
# 1. Check raw_logs table has app_name column
docker exec -it siembox-postgres psql -U siembox -d siembox \
  -c "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'raw_logs';"

# 2. Verify new logs have app_name
docker exec -it siembox-postgres psql -U siembox -d siembox \
  -c "SELECT id, app_name, LEFT(raw_message, 50) FROM raw_logs ORDER BY id DESC LIMIT 5;"

# 3. Test API endpoint with app_name filter
curl "http://localhost:3001/api/logs/parsed?app_name=NGINX" | jq '.logs[0]'
```

### Frontend Testing

1. Navigate to Logs page
2. Verify "Source" column appears between "Source IP" and "Event Type"
3. Verify source tags are displayed (green badges)
4. Test source filter:
   - Enter "NGINX" in Source filter
   - Click Search
   - Verify only NGINX logs appear
5. Test combined filters:
   - Source IP: 192.168.1.194
   - Source: BACKEND
   - Verify only backend logs from that IP appear

### Integration Testing

1. **Configure Docker source in shipper UI:**
   - Type: docker
   - Container: siembox-backend
   - Tag: BACKEND
   - Verify logs appear with Source = "BACKEND"

2. **Configure file source in shipper UI:**
   - Type: file
   - Path: /var/log/nginx/*.log
   - Tag: NGINX
   - Verify logs appear with Source = "NGINX"

3. **Test filtering:**
   - Multiple sources from same IP
   - Filter by each source individually
   - Verify correct logs displayed

## Performance Impact

### Database
- **Index added**: `idx_raw_logs_app_name` for fast filtering
- **JOIN added**: `LEFT JOIN raw_logs` in parsed logs query
  - Expected impact: < 50ms for typical queries
  - Mitigated by existing indexes on `raw_log_id`

### API
- No breaking changes to existing endpoints
- New optional parameter: `app_name`
- Backward compatible (old clients work unchanged)

### Frontend
- One additional column in table (minimal render cost)
- One additional filter input
- No impact on initial page load

## Known Limitations

1. **Old logs**: Logs created before this deployment will have `app_name = NULL`
   - Displayed as "N/A" in UI
   - Cannot be filtered by source

2. **Non-standard syslog**: If logs don't follow RFC 3164 format with TAG field:
   - `app_name` may be NULL
   - Parser will still extract what it can

3. **TAG field length**: Limited to 255 characters (PostgreSQL VARCHAR limit)
   - Should be sufficient for all practical use cases
   - Syslog TAG is typically short (< 32 chars)

## Future Enhancements

Potential improvements for future releases:

1. **Source autocomplete**: Populate source filter with existing app_name values
2. **Source icons**: Display icons for known sources (Docker, file, journal)
3. **Source details**: Hover tooltip showing full source configuration
4. **Quick filters**: One-click buttons for common sources
5. **Source grouping**: Group logs by source in UI
6. **Color coding**: Different colors for different source types
7. **Export includes source**: CSV export with source column

## Documentation Updates

This feature is now documented in:
- `API.md` - Updated GET /logs/parsed endpoint with app_name parameter
- This changelog (CHANGELOG-SOURCE-IDENTIFICATION.md)
- Code comments in modified files

## Related Issues

This implementation addresses the user's issue where logs from multiple sources at the same IP (192.168.1.194) were indistinguishable in the UI.

## Commit

```
commit 68fe361
Author: Claude Sonnet 4.5 (via Claude Code)
Date: Dec 10, 2025

feat(logs): add source identification with app_name field

Add app_name (syslog TAG) field to raw_logs table to enable source
identification in parsed logs UI.
```

## Support

For issues or questions about this feature:
- Check the log shipper configuration (ensure TAG is set correctly)
- Verify raw_logs.app_name is being populated for new logs
- Check API response includes app_name field
- Review frontend console for any errors
