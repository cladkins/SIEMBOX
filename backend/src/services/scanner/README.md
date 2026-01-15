# SIEMBox Scanner Services

This directory contains the vulnerability and asset discovery scanner services for SIEMBox.

## Scanner Services

### NMAP Scanner (`nmapScanner.ts`)

**Purpose**: Network asset discovery and service detection.

**Features**:
- Host discovery (ping scans)
- Port scanning (TCP/UDP)
- Service version detection
- OS fingerprinting
- Stores discovered assets and services in the database

**Usage**:
```typescript
import { NmapScanner } from './nmapScanner';

// Initiate an asset discovery scan
const scanId = await NmapScanner.scan({
  targets: ['192.168.1.0/24', '10.0.0.1'],
  scanType: 'service', // 'ping', 'port', 'service', 'os'
  userId: 1,
  description: 'Weekly network scan'
});

// Check scan status
const status = await NmapScanner.getScanStatus(scanId);

// Get recent scans
const recentScans = await NmapScanner.getRecentScans(20);
```

**Scan Types**:
- `ping`: Host discovery only (no port scan)
- `port`: TCP connect scan on top 1000 ports
- `service`: Service version detection on top 1000 ports
- `os`: OS detection with service version detection

**Database Tables**:
- `vulnerability_scans`: Scan metadata and status
- `assets`: Discovered network assets
- `asset_services`: Services running on assets

---

### Nuclei Scanner (`nucleiScanner.ts`)

**Purpose**: Vulnerability scanning using Nuclei templates.

**Features**:
- CVE detection using community templates
- Misconfiguration detection
- Security issue identification
- CVSS scoring and severity classification
- Evidence collection and reporting
- Real-time JSON parsing of scan results

**Usage**:
```typescript
import { NucleiScanner } from './nucleiScanner';

// Scan for all CVEs
const scanId = await NucleiScanner.scan({
  target: '192.168.1.100',
  templateSelection: {
    cves: true,
    severities: ['critical', 'high']
  },
  userId: 1,
  description: 'Critical CVE scan for web server'
});

// Scan with specific templates
const scanId2 = await NucleiScanner.scan({
  target: 'https://example.com',
  templateSelection: {
    templates: ['cves/2021/CVE-2021-44228.yaml'],
    tags: ['log4j', 'rce']
  },
  userId: 1,
  timeout: 60 * 60 * 1000 // 1 hour
});

// Scan with all templates (use with caution)
const scanId3 = await NucleiScanner.scan({
  target: '10.0.0.50',
  templateSelection: {
    all: true,
    exclude: ['fuzzing/', 'dos/']
  },
  userId: 1,
  rateLimit: 150 // requests per second
});

// Cancel a running scan
await NucleiScanner.cancelScan(scanId);

// Check scan status
const status = await NucleiScanner.getScanStatus(scanId);

// Get recent vulnerability scans
const recentScans = await NucleiScanner.getRecentScans(20);
```

**Template Selection Options**:
- `all`: Use all available templates (can be slow)
- `cves`: Use CVE templates only
- `templates`: Array of specific template paths
- `tags`: Filter templates by tags (e.g., ['apache', 'nginx', 'wordpress'])
- `severities`: Filter by severity levels
- `exclude`: Exclude specific templates or directories
- `excludeTags`: Exclude templates with certain tags

**Common Tag Categories**:
- **Platforms**: `apache`, `nginx`, `wordpress`, `jenkins`, `jira`, `confluence`
- **Vulnerability Types**: `rce`, `sqli`, `xss`, `lfi`, `ssrf`, `xxe`
- **Protocols**: `http`, `dns`, `tcp`, `ssl`, `network`
- **Severity**: `critical`, `high`, `medium`, `low`, `info`

**Database Tables**:
- `vulnerability_scans`: Scan metadata and status
- `vulnerabilities`: CVE/vulnerability definitions
- `assets`: Affected assets (IP addresses)
- `asset_vulnerabilities`: Links vulnerabilities to assets with evidence

**Nuclei CLI Requirements**:
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify installation
nuclei -version

# Update templates
nuclei -update-templates

# List available templates
nuclei -tl
```

**Scan Configuration**:
- Default timeout: 30 minutes (configurable)
- Automatic template updates on scan start
- JSON output parsing (one result per line)
- Process isolation (spawn child process)
- Cancellation support (SIGTERM)

---

### Vulnerability Processor (`vulnerabilityProcessor.ts`)

**Purpose**: Processes and stores vulnerability scan results in the database.

**Features**:
- Vulnerability upsert (CVE-based deduplication)
- Asset discovery and linking
- Risk score calculation
- Evidence tracking
- Statistics and reporting

**Usage**:
```typescript
import { VulnerabilityProcessor } from './vulnerabilityProcessor';

// Process Nuclei results (done automatically by NucleiScanner)
const summary = await VulnerabilityProcessor.processNucleiResults(
  scanId,
  processedVulnerabilities
);

// Get vulnerability statistics
const stats = await VulnerabilityProcessor.getVulnerabilityStats();
// Returns: { critical_open, high_open, medium_open, low_open, info_open, affected_assets, unique_cves }

// Get vulnerabilities for a specific asset
const assetVulns = await VulnerabilityProcessor.getAssetVulnerabilities(
  assetId,
  {
    status: 'open',
    severity: 'critical',
    limit: 50,
    offset: 0
  }
);

// Refresh dashboard materialized view
await VulnerabilityProcessor.refreshDashboardSummary();
```

**Vulnerability Data Structure**:
```typescript
interface VulnerabilityData {
  cveId?: string;              // CVE identifier (e.g., "CVE-2021-44228")
  title: string;               // Vulnerability name
  description?: string;        // Detailed description
  severity: string;            // 'critical', 'high', 'medium', 'low', 'info'
  cvssScore?: number;          // CVSS score (0.0-10.0)
  cvssVector?: string;         // CVSS vector string
  cweId?: string;              // CWE identifier
  remediation?: string;        // Remediation guidance
  references?: string[];       // External references
  metadata?: object;           // Additional data
}
```

---

## Architecture

### Scan Flow

1. **Initiation**: User creates scan via API
2. **Database Record**: Scan record created with status `queued`
3. **Execution**: Scanner spawns child process
4. **Status Update**: Scan status changes to `running`
5. **Result Processing**: Results parsed and stored
6. **Completion**: Scan status changes to `completed` or `failed`
7. **Audit Log**: All scan operations logged for compliance

### Database Schema

```sql
-- Scan tracking
vulnerability_scans (id, scan_type, target, status, vulnerabilities_found, ...)

-- Vulnerability definitions
vulnerabilities (id, cve_id UNIQUE, severity, cvss_score, title, description, ...)

-- Discovered assets
assets (id, ip_address UNIQUE, hostname, os_type, ...)

-- Asset-vulnerability mappings
asset_vulnerabilities (asset_id, vulnerability_id, status, evidence, risk_score, ...)
```

### Scanner Interface

All scanners implement a common pattern:
- `scan(options)`: Initiate a scan, returns scan ID
- `getScanStatus(scanId)`: Get current scan status
- `getRecentScans(limit)`: Get recent scan history
- `cancelScan(scanId)`: Cancel a running scan (if supported)

---

## Type Definitions

### NMAP Types (`types/nmapTypes.ts`)
- `NmapScanConfig`: Scan configuration
- `NmapScanResult`: Parsed scan results
- `NmapHost`: Discovered host information
- `NmapPort`: Port and service details
- `NmapOS`: OS detection results

### Nuclei Types (`types/nucleiTypes.ts`)
- `NucleiScanConfig`: Scan configuration
- `NucleiResult`: Raw Nuclei JSON output
- `NucleiTemplateInfo`: Template metadata
- `ProcessedNucleiVulnerability`: Normalized vulnerability data
- `NucleiScanSummary`: Scan results summary

### Service Types (`types/serviceTypes.ts`)
- `Scanner<TConfig, TResult>`: Generic scanner interface
- `ScanResultProcessor`: Result processing interface
- `DiscoveredVulnerability`: Common vulnerability structure

---

## Error Handling

### NMAP Scanner Errors
- `NMAP_NOT_FOUND`: Nmap binary not installed
- `TARGET_NOT_FOUND`: Target unreachable
- `INVALID_TARGET`: Invalid IP/CIDR specification
- `TIMEOUT`: Scan exceeded timeout (default: 15 minutes)
- `PERMISSION_DENIED`: Insufficient privileges

### Nuclei Scanner Errors
- `NUCLEI_NOT_FOUND`: Nuclei binary not installed
- `TEMPLATE_NOT_FOUND`: Specified template doesn't exist
- `INVALID_TARGET`: Invalid target URL/IP
- `TIMEOUT`: Scan exceeded timeout (default: 30 minutes)
- `NETWORK_ERROR`: Network connectivity issues

All errors are logged to console and stored in `vulnerability_scans.error_message`.

---

## Performance Considerations

### NMAP Scanner
- Default timeout: 15 minutes
- Scans run asynchronously (non-blocking)
- Results processed in batches
- Upserts prevent duplicate assets

### Nuclei Scanner
- Default timeout: 30 minutes (vuln scans take longer)
- JSON streaming (line-by-line parsing)
- Rate limiting configurable (`-rate-limit` flag)
- Template caching via Nuclei's built-in cache
- Automatic template updates on scan start

### Optimization Tips
1. Use `severity` filters to reduce scan scope
2. Exclude unnecessary templates (`exclude` option)
3. Set appropriate `rateLimit` for target capacity
4. Schedule large scans during off-peak hours
5. Use specific `tags` instead of `all` templates

---

## Security Considerations

1. **Scan Authorization**: All scans require authenticated user with appropriate role
2. **Audit Logging**: All scan operations logged to `audit_logs` table
3. **Rate Limiting**: Prevent DoS on target systems
4. **Network Isolation**: Consider running scanners in isolated network segments
5. **Credential Management**: Use `scan_credentials` table for authenticated scans
6. **Process Isolation**: Scanners run as child processes with limited privileges

---

## Future Enhancements

### Planned Features
- [ ] Scheduled/recurring scans
- [ ] Authenticated Nuclei scans (with credentials)
- [ ] Custom Nuclei template support
- [ ] OpenVAS integration
- [ ] Nessus integration
- [ ] Real-time scan progress WebSocket updates
- [ ] Scan result export (PDF/CSV/JSON)
- [ ] Vulnerability trend analysis
- [ ] Auto-remediation workflows
- [ ] Integration with ticketing systems (Jira, ServiceNow)

### Scanner Registry (Future)
Implement `ScannerFactory` pattern to dynamically register scanners:
```typescript
const factory = new ScannerFactory();
factory.registerScanner(new NmapScanner());
factory.registerScanner(new NucleiScanner());
factory.registerScanner(new OpenVASScanner());

const scanner = factory.getScannerForType('vulnerability');
```

---

## Testing

### Manual Testing

**Test NMAP Scanner**:
```bash
# From backend directory
node -e "
const { NmapScanner } = require('./dist/services/scanner/nmapScanner');
NmapScanner.scan({
  targets: ['127.0.0.1'],
  scanType: 'port',
  userId: 1
}).then(id => console.log('Scan ID:', id));
"
```

**Test Nuclei Scanner**:
```bash
# From backend directory
node -e "
const { NucleiScanner } = require('./dist/services/scanner/nucleiScanner');
NucleiScanner.scan({
  target: 'https://example.com',
  templateSelection: { cves: true },
  userId: 1
}).then(id => console.log('Scan ID:', id));
"
```

### Integration Testing
- Create test fixtures with known vulnerabilities
- Verify scan results match expected findings
- Test error handling (invalid targets, timeouts)
- Validate database state after scans

---

## Troubleshooting

### NMAP Issues

**Problem**: "NMAP not found"
```bash
# Install NMAP
apt-get install nmap  # Debian/Ubuntu
yum install nmap      # RHEL/CentOS
brew install nmap     # macOS
```

**Problem**: Scan times out
- Reduce target scope (fewer IPs)
- Increase timeout in scan options
- Use faster scan type ('ping' instead of 'service')

### Nuclei Issues

**Problem**: "Nuclei not found"
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add to PATH
export PATH=$PATH:~/go/bin
```

**Problem**: "Templates not found"
```bash
# Update Nuclei templates
nuclei -update-templates
```

**Problem**: Scan runs forever
- Set explicit timeout in scan options
- Use `severities` filter to reduce scope
- Exclude heavy template directories (`exclude: ['fuzzing/', 'dos/']`)

**Problem**: Rate limiting / target blocking
- Reduce `rateLimit` parameter
- Add delays between requests
- Use proxy rotation (future feature)

### Database Issues

**Problem**: Duplicate vulnerabilities
- CVE-based deduplication should prevent this
- Check `vulnerabilities.cve_id` unique constraint
- Verify upsert logic in `vulnerabilityProcessor.ts`

**Problem**: Slow dashboard queries
```sql
-- Refresh materialized view
REFRESH MATERIALIZED VIEW dashboard_vulnerability_summary;

-- Check indexes
\d asset_vulnerabilities
\d vulnerabilities
```

---

## Contributing

When adding new scanner integrations:

1. Create type definitions in `backend/src/types/`
2. Implement scanner class in `backend/src/services/scanner/`
3. Follow existing patterns (NMAP/Nuclei as reference)
4. Add comprehensive error handling
5. Implement audit logging
6. Update this README
7. Add API endpoints in `backend/src/routes/`
8. Update API documentation (`docs/reference/API.md`)

---

## References

- [NMAP Reference Guide](https://nmap.org/book/man.html)
- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/)
- [CWE Database](https://cwe.mitre.org/)
