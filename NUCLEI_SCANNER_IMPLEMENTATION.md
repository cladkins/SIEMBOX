# Nuclei Vulnerability Scanner Implementation

This document describes the Nuclei vulnerability scanner integration for SIEMBox.

## Overview

The Nuclei scanner service provides automated vulnerability scanning capabilities using the [Nuclei vulnerability scanner](https://github.com/projectdiscovery/nuclei). It follows the same architectural pattern as the existing NMAP scanner and integrates seamlessly with the SIEMBox asset and vulnerability management system.

## Files Created

### Type Definitions

**`backend/src/types/nucleiTypes.ts`**
- Complete TypeScript type definitions for Nuclei scanner
- Interfaces for scan configuration, results, templates, and errors
- Based on Nuclei JSON output format
- Includes processed vulnerability types for database storage

Key types:
- `NucleiScanConfig`: Configuration for initiating scans
- `NucleiResult`: Raw JSON output from Nuclei
- `NucleiTemplateInfo`: Template metadata (CVE, CVSS, severity)
- `ProcessedNucleiVulnerability`: Normalized vulnerability data
- `NucleiScanSummary`: High-level scan results

### Scanner Service

**`backend/src/services/scanner/nucleiScanner.ts`**
- Main scanner implementation following NMAP scanner pattern
- Uses `child_process.spawn()` to execute Nuclei CLI
- Parses JSON output line-by-line in real-time
- Supports scan cancellation via SIGTERM
- Implements timeout handling (default: 30 minutes)
- Stores results in database via VulnerabilityProcessor

Key methods:
- `scan(options)`: Initiate a new vulnerability scan
- `getScanStatus(scanId)`: Get current scan status
- `getRecentScans(limit)`: Get scan history
- `cancelScan(scanId)`: Cancel a running scan

### Vulnerability Processor

**`backend/src/services/scanner/vulnerabilityProcessor.ts`**
- Processes scan results and stores in database
- Handles CVE-based deduplication (upsert logic)
- Links vulnerabilities to assets
- Calculates risk scores automatically
- Provides statistics and reporting

Key methods:
- `processNucleiResults(scanId, results)`: Process scan results
- `getVulnerabilityStats()`: Get dashboard statistics
- `getAssetVulnerabilities(assetId, filters)`: Get asset vulnerabilities
- `refreshDashboardSummary()`: Refresh materialized view

### API Integration

**`backend/src/routes/vulnerabilities.ts` (Updated)**
- Integrated Nuclei scanner into existing vulnerability routes
- Removed TODO placeholders and connected to real scanner
- Added support for template selection and severity filtering

Updated endpoints:
- `POST /api/vulnerabilities/scans` - Trigger vulnerability scan
- `GET /api/vulnerabilities/scans` - List all scans
- `GET /api/vulnerabilities/scans/:scanId` - Get scan details
- `GET /api/vulnerabilities/scans/:scanId/status` - Poll scan status
- `POST /api/vulnerabilities/scans/:scanId/cancel` - Cancel scan
- `GET /api/vulnerabilities/summary` - Get vulnerability statistics
- `GET /api/vulnerabilities/asset/:assetId` - Get asset vulnerabilities

### Documentation

**`backend/src/services/scanner/README.md`**
- Comprehensive documentation for all scanner services
- Usage examples for NMAP and Nuclei scanners
- Architecture overview and database schema
- Error handling and troubleshooting guide
- Performance optimization tips
- Security considerations

**`backend/test-nuclei-scanner.js`**
- Test script for Nuclei scanner integration
- Validates Nuclei installation
- Tests result parsing logic
- Demonstrates command building
- Includes sample Nuclei output

## Prerequisites

### Install Nuclei

```bash
# Install via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add to PATH
export PATH=$PATH:~/go/bin

# Verify installation
nuclei -version

# Update templates
nuclei -update-templates
```

### Docker Installation (Alternative)

If running in Docker, add Nuclei to the backend Dockerfile:

```dockerfile
# Install Go
RUN apt-get update && apt-get install -y golang-go

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ENV PATH="${PATH}:/root/go/bin"

# Update templates on container build
RUN nuclei -update-templates
```

## Usage Examples

### Basic CVE Scan

```bash
curl -X POST http://localhost:3001/api/vulnerabilities/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "templates": "cves",
    "severity": ["critical", "high"],
    "description": "Critical CVE scan for web server"
  }'
```

Response:
```json
{
  "message": "Vulnerability scan initiated",
  "scanId": 42,
  "status": "queued",
  "target": "192.168.1.100",
  "templateSelection": {
    "cves": true,
    "severities": ["critical", "high"]
  }
}
```

### Scan with Specific Templates

```bash
curl -X POST http://localhost:3001/api/vulnerabilities/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "templates": ["apache", "nginx", "wordpress"],
    "description": "Web application scan"
  }'
```

### Scan All Templates

```bash
curl -X POST http://localhost:3001/api/vulnerabilities/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.50",
    "templates": "all",
    "rateLimit": 150,
    "timeout": 3600000,
    "description": "Comprehensive vulnerability scan"
  }'
```

### Check Scan Status

```bash
curl http://localhost:3001/api/vulnerabilities/scans/42/status
```

Response:
```json
{
  "id": 42,
  "status": "running",
  "progress": 50,
  "vulnerabilities_found": 5,
  "started_at": "2024-01-15T10:30:00Z"
}
```

### Get Scan Results

```bash
curl http://localhost:3001/api/vulnerabilities/scans/42
```

Response:
```json
{
  "id": 42,
  "scan_type": "vulnerability",
  "target": "192.168.1.100",
  "status": "completed",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:45:00Z",
  "duration_seconds": 900,
  "vulnerabilities_found": 8,
  "results_summary": {
    "vulnerabilitiesFound": 8,
    "severityCounts": {
      "critical": 2,
      "high": 3,
      "medium": 2,
      "low": 1,
      "info": 0
    }
  }
}
```

### Cancel a Running Scan

```bash
curl -X POST http://localhost:3001/api/vulnerabilities/scans/42/cancel \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Get Vulnerability Summary

```bash
curl http://localhost:3001/api/vulnerabilities/summary
```

Response:
```json
{
  "critical_open": 5,
  "high_open": 12,
  "medium_open": 28,
  "low_open": 45,
  "info_open": 103,
  "affected_assets": 24,
  "unique_cves": 67
}
```

### Get Asset Vulnerabilities

```bash
curl http://localhost:3001/api/vulnerabilities/asset/123?status=open&severity=critical
```

Response:
```json
{
  "asset_id": 123,
  "vulnerabilities": [
    {
      "id": 1,
      "cve_id": "CVE-2021-44228",
      "title": "Apache Log4j RCE",
      "severity": "critical",
      "cvss_score": 10.0,
      "status": "open",
      "first_detected": "2024-01-15T10:30:00Z",
      "evidence": "Template: CVE-2021-44228\nMatched at: http://192.168.1.100:8080/api/login"
    }
  ],
  "total": 1
}
```

## Template Selection Options

### Predefined Template Sets

- `"cves"` or `"default"`: Use CVE templates only
- `"all"`: Use all available templates (can be very slow)

### Custom Template Selection

```json
{
  "templates": ["apache", "nginx", "wordpress"]
}
```

This will use templates tagged with these names.

### Severity Filtering

```json
{
  "severity": ["critical", "high"]
}
```

Available severities: `critical`, `high`, `medium`, `low`, `info`

### Exclusions

```json
{
  "templateSelection": {
    "all": true,
    "exclude": ["fuzzing/", "dos/"],
    "excludeTags": ["intrusive"]
  }
}
```

## Database Schema

### Scan Tracking

```sql
-- vulnerability_scans table
id SERIAL PRIMARY KEY
scan_type VARCHAR(50) -- 'vulnerability'
target VARCHAR(255)
status VARCHAR(20) -- 'queued', 'running', 'completed', 'failed', 'cancelled'
started_at TIMESTAMPTZ
completed_at TIMESTAMPTZ
duration_seconds INTEGER
vulnerabilities_found INTEGER
initiated_by INTEGER REFERENCES users(id)
scan_options JSONB
error_message TEXT
results_summary JSONB
```

### Vulnerability Storage

```sql
-- vulnerabilities table
id SERIAL PRIMARY KEY
cve_id VARCHAR(20) UNIQUE NOT NULL
cvss_score NUMERIC(3,1)
cvss_vector VARCHAR(100)
severity VARCHAR(20)
title VARCHAR(500)
description TEXT
remediation TEXT
references TEXT[]
cwe_id VARCHAR(20)
metadata JSONB
```

### Asset-Vulnerability Mapping

```sql
-- asset_vulnerabilities table
id SERIAL PRIMARY KEY
asset_id INTEGER REFERENCES assets(id)
vulnerability_id INTEGER REFERENCES vulnerabilities(id)
status VARCHAR(20) DEFAULT 'open' -- 'open', 'investigating', 'patched', 'mitigated', 'accepted', 'false_positive'
evidence TEXT
risk_score NUMERIC(3,1) -- Auto-calculated: asset_criticality × cvss_score
first_detected TIMESTAMPTZ
last_detected TIMESTAMPTZ
patched_at TIMESTAMPTZ
patched_by INTEGER REFERENCES users(id)
notes TEXT
```

## Architecture

### Scan Flow

1. **API Request**: User triggers scan via POST `/api/vulnerabilities/scans`
2. **Database Record**: Scan record created with status `queued`
3. **Process Spawn**: Nuclei CLI spawned as child process
4. **Status Update**: Scan status changes to `running`
5. **JSON Streaming**: Results parsed line-by-line from stdout
6. **Result Processing**: Each vulnerability upserted to database
7. **Completion**: Scan status changes to `completed` or `failed`
8. **Audit Log**: All operations logged for compliance

### Result Processing Pipeline

```
Nuclei CLI → JSON Lines → NucleiResult → ProcessedNucleiVulnerability
                                                    ↓
                                        VulnerabilityProcessor
                                                    ↓
                                    ┌───────────────┴───────────────┐
                                    ↓                               ↓
                          vulnerabilities table          asset_vulnerabilities table
                          (CVE definitions)               (asset-vuln mappings)
```

### Deduplication Strategy

1. **CVE-based**: Vulnerabilities with same CVE ID are merged
2. **Asset-based**: Same CVE on same asset updates `last_detected`
3. **Upsert Logic**: `ON CONFLICT (cve_id) DO UPDATE`
4. **Evidence Tracking**: Each detection adds to evidence field

## Error Handling

### Common Errors

**`NUCLEI_NOT_FOUND`**
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**`TEMPLATE_NOT_FOUND`**
```bash
# Update templates
nuclei -update-templates
```

**`TIMEOUT`**
- Default timeout: 30 minutes
- Increase via `timeout` parameter (milliseconds)

**`NETWORK_ERROR`**
- Check target accessibility
- Verify firewall rules
- Check rate limiting

### Error Logging

All errors are:
1. Logged to console with `[Nuclei]` prefix
2. Stored in `vulnerability_scans.error_message`
3. Returned in API response

## Security Considerations

1. **Authentication Required**: Scan initiation requires valid JWT token
2. **Audit Logging**: All scans logged to `audit_logs` table
3. **Rate Limiting**: Configurable to prevent DoS on targets
4. **Process Isolation**: Nuclei runs as child process with limited privileges
5. **Input Validation**: Target URLs/IPs validated before scanning
6. **Scan Cancellation**: Users can cancel runaway scans

## Performance Optimization

### For Quick Scans

```json
{
  "templates": "cves",
  "severity": ["critical"],
  "rateLimit": 200
}
```

### For Comprehensive Scans

```json
{
  "templates": "all",
  "rateLimit": 150,
  "timeout": 7200000
}
```

### Best Practices

1. Use severity filters to reduce scope
2. Exclude DOS/fuzzing templates in production
3. Set appropriate rate limits for target capacity
4. Schedule large scans during off-peak hours
5. Use specific tags instead of `all` templates
6. Monitor database size (vulnerabilities table can grow large)

## Testing

### Run Test Script

```bash
cd backend
node test-nuclei-scanner.js
```

This will:
1. Check if Nuclei is installed
2. Get Nuclei version
3. Test result parsing with sample data
4. Test command builder
5. Verify JSON line parsing

### Manual Testing

```bash
# Test Nuclei directly
nuclei -target https://example.com -t cves/ -json -silent

# Test with specific CVE
nuclei -target 192.168.1.100 -t cves/2021/CVE-2021-44228.yaml -json -silent
```

## Troubleshooting

### Nuclei Not Found

**Symptom**: Error "Nuclei is not installed or not accessible"

**Solution**:
```bash
which nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:~/go/bin
```

### Templates Not Found

**Symptom**: No vulnerabilities found, "template not found" errors

**Solution**:
```bash
nuclei -update-templates
nuclei -tl  # List available templates
```

### Scan Hangs/Times Out

**Symptom**: Scan never completes

**Solution**:
- Reduce scope (use severity filter)
- Increase timeout parameter
- Check target accessibility
- Review rate limiting

### Duplicate Vulnerabilities

**Symptom**: Same CVE appears multiple times

**Solution**:
- Check `vulnerabilities.cve_id` unique constraint
- Verify upsert logic in `vulnerabilityProcessor.ts`
- Check if CVE ID extraction is working correctly

### Database Performance Issues

**Symptom**: Slow vulnerability queries

**Solution**:
```sql
-- Refresh materialized view
REFRESH MATERIALIZED VIEW dashboard_vulnerability_summary;

-- Check indexes
\d asset_vulnerabilities
\d vulnerabilities

-- Vacuum and analyze
VACUUM ANALYZE vulnerabilities;
VACUUM ANALYZE asset_vulnerabilities;
```

## Future Enhancements

- [ ] Scheduled/recurring scans
- [ ] Custom Nuclei template support
- [ ] Authenticated scanning (with credentials)
- [ ] Real-time progress updates via WebSocket
- [ ] Scan result export (PDF/CSV)
- [ ] Integration with ticketing systems
- [ ] Automatic remediation workflows
- [ ] Vulnerability trending and analytics
- [ ] Template management UI
- [ ] Scan profiles (pre-configured template sets)

## References

- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/)
- [SIEMBox API Documentation](docs/reference/API.md)

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review the [Scanner README](backend/src/services/scanner/README.md)
3. Check Nuclei documentation
4. Open a GitHub issue

---

**Implementation Date**: 2024-01-15
**Status**: Ready for testing
**Version**: 1.0.0
