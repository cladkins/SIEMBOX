# SIEMBox UI Features - Testing Guide

## Overview

This guide covers testing for the 4 new features added to SIEMBox:
1. API Key Regeneration
2. Syslog Configuration with Verification
3. Shipper Activity Log
4. IP Whitelist Management

**Test Environment**: Remote Docker deployment
**Branch**: `develop`
**Commits**: `2594e89` to `e7f8f32` (4 commits)

---

## Prerequisites

Before testing, ensure:
- [ ] Code deployed to remote Docker server
- [ ] Docker containers running: `docker ps`
- [ ] Backend accessible: `curl http://localhost:5000/health`
- [ ] Frontend accessible: Navigate to `http://localhost:3000`
- [ ] Logged in as admin user (required for all features)

---

## Feature 1: API Key Regeneration

**Location**: Shippers page → View shipper → API Key section

### Test Steps

1. **Navigate to Shippers Page**
   - Go to `/shippers`
   - Click "View" button on any shipper

2. **Locate Regenerate Button**
   - [ ] Verify "Regenerate" button appears next to "Copy" button
   - [ ] Button should have warning color (yellow/orange)
   - [ ] Refresh icon should be visible

3. **Test Regeneration Flow**
   - [ ] Click "Regenerate" button
   - [ ] Confirmation dialog appears with warning message
   - [ ] Dialog mentions shipper name
   - [ ] Dialog warns about immediate invalidation

4. **Confirm Regeneration**
   - [ ] Click "Regenerate Key" button
   - [ ] Loading spinner appears on button
   - [ ] Success message displays: "API key regenerated successfully..."
   - [ ] New key appears in input field (64-char hex string)
   - [ ] New key automatically copied to clipboard (paste to verify)

5. **Verify Key Change**
   - [ ] Copy new key from input field
   - [ ] Compare with previous key (should be different)
   - [ ] Close and reopen dialog - new key persists

6. **Test Cancel**
   - [ ] Click "Regenerate" again
   - [ ] Click "Cancel" in dialog
   - [ ] No changes occur, no API call made

### Expected Behavior

- ✅ Old API key immediately becomes invalid
- ✅ Shipper with old key becomes "ghost shipper" (continues sending logs but can't fetch config)
- ✅ New key must be updated in shipper container environment variable

### Error Cases to Test

1. **Non-admin User** (if available):
   - [ ] Should not see Regenerate button, or
   - [ ] Should receive 403 error if attempting

2. **Network Error**:
   - [ ] Disconnect network, try regenerating
   - [ ] Should show error message
   - [ ] Button should exit loading state

---

## Feature 2: Syslog Configuration with Verification

**Location**: Settings page → Syslog Server Configuration card & System Information card

### Test Steps

#### Part A: Syslog Configuration Form

1. **Navigate to Settings Page**
   - Go to `/settings`
   - Locate "Syslog Server Configuration" card (left column)

2. **Review Current Configuration**
   - [ ] Host field displays current value (e.g., "localhost" or "0.0.0.0")
   - [ ] Port field displays current value (default: 514)
   - [ ] Info alert explains restart requirement

3. **Test Form Validation**
   - [ ] Try saving with empty host → Should show warning
   - [ ] Try port 0 → Should not allow (min: 1)
   - [ ] Try port 99999 → Should not allow (max: 65535)
   - [ ] Enter valid host and port → Should accept

4. **Test Save**
   - [ ] Change host to "0.0.0.0"
   - [ ] Change port to 5514
   - [ ] Click "Save Settings"
   - [ ] Success message appears
   - [ ] Reload page - values persist

5. **Test Reset**
   - [ ] Change values
   - [ ] Click "Reset" button
   - [ ] Values revert to saved state

#### Part B: System Information Card (Syslog Status)

1. **Locate Syslog Status Section**
   - Go to Settings page
   - Right column → "System Information" card (renamed from "Database Statistics")
   - Top section shows Syslog Status

2. **Review Status Display**
   - [ ] "Syslog Receiver" row shows status badge
   - [ ] Badge color: Green (healthy), Yellow (warning), or Red (error)
   - [ ] Status message displays (e.g., "Syslog receiver is active and receiving logs")
   - [ ] Listening port shown (e.g., "Port 514")

3. **Review Last Log Received**
   - [ ] Timestamp displays (e.g., "Dec 15, 2025 14:30")
   - [ ] Shows "Never" if no logs received
   - [ ] Logs count displays (e.g., "142 logs in last 5 min")

4. **Test Port Mismatch Warning**
   - [ ] If configured port ≠ listening port, warning alert appears
   - [ ] Alert shows both ports (configured vs listening)
   - [ ] Alert color is warning (yellow)

5. **Test Refresh**
   - [ ] Click refresh button (circular arrow icon)
   - [ ] Syslog status updates
   - [ ] Database statistics also refresh

### Expected Behavior

**Healthy Status**: Green badge, recent logs, ports match
**Warning Status**: Yellow badge, no recent logs OR port mismatch
**Error Status**: Red badge, port mismatch AND no logs

### Configuration Testing

1. **Port Mismatch Scenario**:
   - Database configured port: 5514
   - Environment variable `SYSLOG_PORT`: 514
   - Result: Warning alert appears

2. **Correct Configuration**:
   - Database and environment match (both 514)
   - Logs flowing in
   - Result: Healthy status (green)

---

## Feature 3: Shipper Activity Log

**Location**: Shippers page → View shipper → Activity Log section (bottom)

### Test Steps

1. **Navigate to Shipper Details**
   - Go to `/shippers`
   - Click "View" on any shipper
   - Scroll to bottom of dialog

2. **Locate Activity Log Section**
   - [ ] Section header: "Activity Log"
   - [ ] Subtitle: "Configuration change history"
   - [ ] Table with 3 columns: Timestamp, Action, Description

3. **Review Activity Records**
   - [ ] Table loads automatically when dialog opens
   - [ ] Loading spinner appears briefly
   - [ ] Records display in reverse chronological order (newest first)
   - [ ] Limited to 50 most recent records

4. **Verify Activity Types**
   - [ ] "Created" - Green tag, shown when shipper first created
   - [ ] "Config Updated" - Blue tag, when shipper details changed
   - [ ] "Source Added" - Green tag, when log source added
   - [ ] "Source Updated" - Yellow tag, when log source modified
   - [ ] "Source Deleted" - Red tag, when log source removed
   - [ ] "Volume Added" - Green tag, when volume mount added
   - [ ] "Volume Deleted" - Red tag, when volume mount removed
   - [ ] "Key Regenerated" - Yellow tag, when API key regenerated

5. **Test New Shipper**
   - [ ] Create a new shipper
   - [ ] View its details immediately
   - [ ] Activity log should show "Created" entry

6. **Generate Activity Records**
   - [ ] Add a log source → Should create "Source Added" activity
   - [ ] Edit the source → Should create "Source Updated" activity
   - [ ] Add volume mount → Should create "Volume Added" activity
   - [ ] Regenerate API key → Should create "Key Regenerated" activity
   - [ ] Close and reopen dialog
   - [ ] All activities should be visible in chronological order

7. **Test Empty State**
   - [ ] View a shipper with no activity (if possible)
   - [ ] Should show "No activity recorded yet"

### Expected Behavior

- ✅ Activity records created automatically by backend
- ✅ Each CRUD operation logs an activity
- ✅ Activities include human-readable descriptions
- ✅ Timestamps formatted consistently (e.g., "Dec 15, 2025 14:30")
- ✅ Color-coded tags improve scannability

### Accessibility Testing

- [ ] Tab navigation works (Tab key moves through table rows)
- [ ] Arrow keys navigate table cells
- [ ] Screen reader announces table structure properly
- [ ] High contrast mode maintains readability

---

## Feature 4: IP Whitelist Management

**Location**: Settings page → IP Whitelist Management card (left column)

### Test Steps

#### Part A: View IP Whitelist

1. **Navigate to Settings Page**
   - Go to `/settings`
   - Locate "IP Whitelist Management" card (after Manual Cleanup)

2. **Review Initial State**
   - [ ] Info alert explains CIDR support and "empty = allow all" behavior
   - [ ] Table shows existing whitelist entries (may be empty)
   - [ ] Columns: IP Address/CIDR, Description, Linked Rule, Added, Actions

3. **Review Empty State**
   - [ ] If table is empty, appropriate message displays
   - [ ] "Add IP" button is functional

#### Part B: Add IP Address

1. **Open Add Dialog**
   - [ ] Click "Add IP" button (top right)
   - [ ] Dialog opens: "Add IP to Whitelist"

2. **Test Single IP**
   - [ ] Enter: `192.168.1.100`
   - [ ] Description: "Test server"
   - [ ] Leave rule_id empty
   - [ ] Click "Add"
   - [ ] Success message appears
   - [ ] Table refreshes with new entry
   - [ ] IP shown as blue tag

3. **Test CIDR Range**
   - [ ] Click "Add IP" again
   - [ ] Enter: `10.0.0.0/8`
   - [ ] Description: "Internal network"
   - [ ] Click "Add"
   - [ ] Success message appears
   - [ ] Both entries visible in table

4. **Test with Rule Link**
   - [ ] Click "Add IP"
   - [ ] Enter: `172.16.0.0/12`
   - [ ] Description: "Production servers"
   - [ ] Rule ID: `5` (use an existing rule ID)
   - [ ] Click "Add"
   - [ ] Success message
   - [ ] Linked Rule column shows "#5"

#### Part C: Validation Testing

1. **Test Duplicate IP**
   - [ ] Try adding `192.168.1.100` again
   - [ ] Should fail with error: "This IP address already exists in the whitelist"
   - [ ] Status: 409 Conflict

2. **Test Invalid CIDR**
   - [ ] Enter: `999.999.999.999`
   - [ ] Click "Add"
   - [ ] Should fail with error: "Invalid IP address or CIDR format"
   - [ ] Status: 400 Bad Request

3. **Test Invalid CIDR Range**
   - [ ] Enter: `192.168.1.0/99`
   - [ ] Should fail with invalid format error

4. **Test Empty Input**
   - [ ] Leave IP field blank
   - [ ] Click "Add"
   - [ ] Should show warning: "Please enter an IP address or CIDR"

#### Part D: Edit IP Entry

1. **Open Edit Dialog**
   - [ ] Click "Edit" button on any entry
   - [ ] Dialog opens: "Edit IP Whitelist Entry"

2. **Verify IP is Immutable**
   - [ ] IP Address field is disabled (grayed out)
   - [ ] Cannot change IP address

3. **Test Edit**
   - [ ] Change description to "Updated description"
   - [ ] Change rule_id to different value
   - [ ] Click "Update"
   - [ ] Success message appears
   - [ ] Table refreshes
   - [ ] Changes are visible
   - [ ] IP address remains unchanged

#### Part E: Delete IP Entry

1. **Open Delete Confirmation**
   - [ ] Click "Delete" button (red) on any entry
   - [ ] Confirmation dialog appears
   - [ ] Dialog shows IP address being deleted

2. **Confirm Deletion**
   - [ ] Click "Delete"
   - [ ] Success message: "IP address removed from whitelist"
   - [ ] Table refreshes
   - [ ] Entry is gone

3. **Test Cancel**
   - [ ] Click "Delete" on another entry
   - [ ] Click "Cancel" in confirmation
   - [ ] Entry remains in table

### Expected Behavior

**CIDR Validation**:
- ✅ PostgreSQL validates CIDR format
- ✅ Accepts: 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/12
- ✅ Accepts single IPs: 192.168.1.100 (treated as /32)
- ✅ Rejects: 999.999.999.999, invalid CIDR ranges

**Empty Whitelist**:
- ✅ If whitelist is empty, ALL IPs can send logs
- ✅ Info alert explicitly states this behavior

**Rule Linking**:
- ✅ If rule_id is set, whitelist only applies to that rule
- ✅ If rule_id is null, whitelist applies to all rules

---

## Integration Testing

### Cross-Feature Tests

1. **API Key Regeneration → Activity Log**
   - [ ] Regenerate a shipper's API key
   - [ ] Open Activity Log for that shipper
   - [ ] Verify "Key Regenerated" activity appears

2. **Syslog Config → Shipper Registration**
   - [ ] Change syslog port in database (e.g., to 5514)
   - [ ] Register a new shipper (call `/api/shippers/register`)
   - [ ] Verify shipper receives port 5514 in config response
   - [ ] Check for port mismatch warning in System Information

3. **IP Whitelist → Log Ingestion**
   - [ ] Add a whitelist entry for your test IP
   - [ ] Send logs from that IP
   - [ ] Verify logs are received
   - [ ] Add whitelist entry for different IP
   - [ ] Try sending from non-whitelisted IP (if enforced)

---

## Performance Testing

### Load Testing

1. **Activity Log with 50+ Records**
   - [ ] Create shipper with many operations (add/edit/delete sources repeatedly)
   - [ ] Verify activity log loads in <200ms
   - [ ] Verify only 50 most recent records shown

2. **IP Whitelist with 100+ Entries**
   - [ ] Add 100 CIDR ranges
   - [ ] Verify table renders in <500ms
   - [ ] Test scrolling performance

3. **Syslog Status with High Traffic**
   - [ ] Generate 1000+ logs per minute
   - [ ] Verify status updates correctly
   - [ ] Check "logs in last 5 min" counter accuracy

### Browser Testing

Test on multiple browsers:
- [ ] Chrome/Edge (Chromium)
- [ ] Firefox
- [ ] Safari (macOS)
- [ ] Mobile Safari (iOS)
- [ ] Mobile Chrome (Android)

---

## Security Testing

### Authorization Testing

1. **Admin-Only Endpoints**
   - [ ] Log out admin user
   - [ ] Log in as non-admin (Analyst or Viewer role)
   - [ ] Attempt to access Settings page
   - [ ] Should not see IP Whitelist Management
   - [ ] Should not see Syslog Configuration
   - [ ] Or should receive 403 Forbidden errors

2. **API Direct Access**
   - [ ] Use browser dev tools → Network tab
   - [ ] Copy an admin API request (e.g., POST /api/settings/ip-whitelist)
   - [ ] Change auth token to non-admin user
   - [ ] Replay request
   - [ ] Should receive 403 Forbidden

### Data Validation

1. **SQL Injection Attempts**
   - [ ] Try adding IP: `'; DROP TABLE ip_whitelist; --`
   - [ ] Should be safely escaped, no SQL execution

2. **XSS Attempts**
   - [ ] Add IP description: `<script>alert('XSS')</script>`
   - [ ] Should be displayed as text, not executed

---

## Regression Testing

Ensure existing features still work:

1. **Parsers**
   - [ ] Create, edit, delete parsers
   - [ ] Test parser with logs

2. **Rules**
   - [ ] Create, edit, delete rules
   - [ ] Verify rule triggers alerts

3. **Alerts**
   - [ ] View, acknowledge, dismiss alerts

4. **Logs**
   - [ ] Search and filter logs
   - [ ] Export logs to CSV

5. **Shippers (existing features)**
   - [ ] Create, edit, delete shippers
   - [ ] Add/edit/delete sources
   - [ ] Add/delete volumes

---

## Known Issues / Limitations

1. **Syslog Port Change**
   - Changing port in database doesn't restart syslog server
   - Requires Docker container restart to take effect
   - Port mismatch warning alerts user to this

2. **Activity Log Pagination**
   - Limited to 50 records
   - No pagination controls yet
   - Can be added in future release

3. **IP Whitelist Enforcement**
   - Backend may need additional logic to actually enforce whitelist
   - Current implementation stores whitelist but may not block non-whitelisted IPs
   - Verify with backend implementation

---

## Troubleshooting

### Common Issues

**Issue**: API Key regenerate button not appearing
**Solution**:
- Verify logged in as admin
- Check browser console for errors
- Verify backend endpoint exists: `curl -X POST http://localhost:5000/api/shippers/1/regenerate-key`

**Issue**: Syslog status shows "error" or "warning"
**Solution**:
- Check `SYSLOG_PORT` environment variable matches database config
- Verify syslog server is running: `docker logs siembox-backend | grep syslog`
- Send test log to verify receiving

**Issue**: Activity log empty or not loading
**Solution**:
- Check backend logs: `docker logs siembox-backend`
- Verify `shipper_activity` table exists
- Check database for activity records: `SELECT * FROM shipper_activity LIMIT 10;`

**Issue**: IP Whitelist validation errors
**Solution**:
- Verify CIDR format: Use online CIDR calculator
- Check PostgreSQL `inet` type support
- Review backend logs for actual error

---

## Test Results Template

Use this template to record test results:

```
## Test Session: [Date]
**Tester**: [Name]
**Environment**: [Local/Remote Docker]
**Browser**: [Chrome/Firefox/Safari]

### Feature 1: API Key Regeneration
- [ ] All tests passed
- [ ] Issues found: [List]

### Feature 2: Syslog Configuration
- [ ] All tests passed
- [ ] Issues found: [List]

### Feature 3: Shipper Activity Log
- [ ] All tests passed
- [ ] Issues found: [List]

### Feature 4: IP Whitelist Management
- [ ] All tests passed
- [ ] Issues found: [List]

### Overall Assessment
- [ ] Ready for production
- [ ] Needs fixes before production
- [ ] Critical issues: [List]
```

---

## Next Steps After Testing

1. **Document Issues**: Open GitHub issues for any bugs found
2. **Update Documentation**: Add user guide sections to existing docs
3. **Deploy to Production**: Follow deployment checklist
4. **Monitor**: Track usage and errors in production logs
5. **Gather Feedback**: Ask users for feedback after 1 week

---

## Contact

For questions or issues during testing:
- GitHub Issues: https://github.com/cladkins/SIEMBOX/issues
- Tag with `[Testing]` and specific feature name
