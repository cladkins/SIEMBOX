# SIEM BOX - User Guide

This comprehensive user guide covers how to use the SIEM BOX web interface for security monitoring, log analysis, alert management, vulnerability scanning, and system administration.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Log Management](#log-management)
4. [Alert Management](#alert-management)
5. [Detection Rules](#detection-rules)
6. [Vulnerability Management](#vulnerability-management)
7. [System Settings](#system-settings)
8. [User Management](#user-management)
9. [Search and Filtering](#search-and-filtering)
10. [Reports and Analytics](#reports-and-analytics)
11. [Mobile Interface](#mobile-interface)
12. [Keyboard Shortcuts](#keyboard-shortcuts)
13. [Troubleshooting](#troubleshooting)

## Getting Started

### Accessing SIEM BOX

1. **Open your web browser** and navigate to your SIEM BOX instance:
   - Default URL: `http://localhost:3000` (development)
   - Production URL: `https://siembox.yourdomain.com`

2. **Login** with your credentials:
   - Default admin username: `admin`
   - Default admin password: `admin` (change immediately)

3. **First-time setup**:
   - Change default password
   - Configure notification settings
   - Set up log sources
   - Review detection rules

### Interface Overview

The SIEM BOX interface consists of several main areas:

- **Navigation Bar**: Access to main sections (Dashboard, Logs, Alerts, Rules, Vulnerabilities, Settings)
- **Main Content Area**: Primary workspace for each section
- **Status Bar**: System status and notifications
- **User Menu**: Profile settings and logout

### Navigation

| Section | Purpose | Key Features |
|---------|---------|--------------|
| **Dashboard** | Overview and metrics | Real-time statistics, charts, recent alerts |
| **Logs** | Log analysis and search | Log viewer, filtering, export |
| **Alerts** | Alert management | Alert list, investigation, resolution |
| **Rules** | Detection rule management | Rule editor, testing, deployment |
| **Vulnerabilities** | Security assessment | Network scanning, vulnerability reports, asset discovery |
| **Settings** | System configuration | User management, notifications, system settings |

## Dashboard Overview

The dashboard provides a real-time overview of your security posture and system health.

### Key Metrics

#### Security Overview
- **Active Alerts**: Current open security alerts
- **Alert Trend**: 24-hour alert volume trend
- **Top Alert Categories**: Most common alert types
- **Severity Distribution**: Breakdown by alert severity

#### System Health
- **Log Ingestion Rate**: Logs processed per minute
- **System Status**: Service health indicators
- **Storage Usage**: Database and disk utilization
- **Processing Performance**: System performance metrics

#### Recent Activity
- **Latest Alerts**: Most recent security alerts
- **Recent Logs**: Latest log entries
- **System Events**: Recent system activities

### Dashboard Widgets

#### Alert Summary Widget
- **Purpose**: Quick overview of alert status
- **Features**:
  - Total alert count
  - Alerts by severity (Critical, High, Medium, Low)
  - Alert trend graph
  - Quick action buttons

#### Log Volume Widget
- **Purpose**: Monitor log ingestion health
- **Features**:
  - Real-time log count
  - Ingestion rate graph
  - Source breakdown
  - Processing status

#### Top Sources Widget
- **Purpose**: Identify most active log sources
- **Features**:
  - Source ranking by volume
  - Source health status
  - Quick navigation to source logs

#### System Status Widget
- **Purpose**: Monitor system health
- **Features**:
  - Service status indicators
  - Resource utilization
  - Performance metrics
  - Health alerts

### Customizing the Dashboard

1. **Widget Configuration**:
   - Click the gear icon on any widget
   - Adjust time ranges and display options
   - Enable/disable specific metrics

2. **Layout Customization**:
   - Drag and drop widgets to rearrange
   - Resize widgets by dragging corners
   - Add/remove widgets from the widget menu

3. **Refresh Settings**:
   - Set auto-refresh intervals
   - Manual refresh button
   - Real-time updates toggle

## Log Management

The Logs section provides comprehensive log analysis and search capabilities.

### Log Viewer

#### Main Features
- **Real-time log streaming**: Live log updates
- **Advanced filtering**: Multi-field search and filtering
- **Export capabilities**: Download logs in various formats
- **Detailed view**: Expandable log entries with full details

#### Log Entry Information
Each log entry displays:
- **Timestamp**: When the log was generated
- **Source**: Log source (hostname, application)
- **Severity**: Log severity level
- **Message**: Log content
- **Parsed Fields**: Extracted structured data

### Search and Filtering

#### Quick Search
- **Text Search**: Search across all log fields
- **Field Search**: Search specific fields (e.g., `src_ip:192.168.1.100`)
- **Regex Search**: Use regular expressions for complex patterns

#### Advanced Filters

##### Time Range Filtering
- **Preset Ranges**: Last hour, 24 hours, 7 days, 30 days
- **Custom Range**: Specify exact start and end times
- **Relative Time**: "Last 2 hours", "Since yesterday"

##### Field-Based Filtering
- **Source IP**: Filter by source IP address
- **Hostname**: Filter by source hostname
- **Application**: Filter by application/service name
- **Severity**: Filter by log severity level
- **Log Type**: Filter by parsed log type

##### Advanced Query Syntax
```
# Basic field search
hostname:server01

# Multiple values
severity:(error OR critical)

# Range queries
timestamp:[2024-01-01 TO 2024-01-31]

# Wildcard search
message:*failed*

# Boolean operators
src_ip:192.168.1.* AND severity:error

# Negation
NOT hostname:test-server
```

### Log Export

#### Export Options
- **CSV**: Comma-separated values for spreadsheet analysis
- **JSON**: Structured data for programmatic processing
- **PDF**: Formatted report for documentation
- **Raw**: Original log format

#### Export Process
1. Apply desired filters to narrow down logs
2. Click the "Export" button
3. Select export format
4. Choose fields to include
5. Download the generated file

### Log Analysis Tools

#### Pattern Recognition
- **Automatic pattern detection**: Identify common log patterns
- **Pattern highlighting**: Visual indicators for recognized patterns
- **Pattern statistics**: Frequency and trend analysis

#### Field Analysis
- **Field statistics**: Value distribution and frequency
- **Unique value counts**: Distinct values per field
- **Field correlation**: Relationships between fields

#### Timeline Analysis
- **Event timeline**: Chronological view of events
- **Volume analysis**: Log volume over time
- **Anomaly detection**: Unusual patterns or spikes

## Alert Management

The Alerts section provides comprehensive alert investigation and management capabilities.

### Alert List View

#### Alert Information
Each alert displays:
- **Title**: Alert description
- **Severity**: Critical, High, Medium, Low
- **Category**: Security category (brute force, web attack, etc.)
- **Status**: Open, Investigating, Resolved, False Positive
- **Triggered Time**: When the alert was generated
- **Source Information**: Related IP addresses, hostnames

#### Alert Status Management
- **Open**: New, unacknowledged alerts
- **Investigating**: Alerts being actively investigated
- **Resolved**: Alerts that have been addressed
- **False Positive**: Alerts marked as false positives

### Alert Investigation

#### Alert Details View
Click on any alert to view detailed information:

##### Basic Information
- **Alert ID**: Unique identifier
- **Detection Rule**: Rule that triggered the alert
- **Triggered Time**: Exact timestamp
- **Severity and Category**: Classification information

##### Context Information
- **Related Logs**: Log entries that triggered the alert
- **Source Details**: IP addresses, hostnames, users involved
- **Timeline**: Sequence of events leading to the alert

##### Investigation Tools
- **Related Alerts**: Other alerts from the same source
- **Historical Data**: Previous similar alerts
- **Threat Intelligence**: External threat information (if configured)

#### Alert Actions

##### Individual Alert Actions
- **Acknowledge**: Mark alert as being investigated
- **Resolve**: Mark alert as resolved
- **False Positive**: Mark alert as false positive
- **Add Notes**: Add investigation notes
- **Assign**: Assign to team member

##### Bulk Actions
- **Bulk Acknowledge**: Acknowledge multiple alerts
- **Bulk Resolve**: Resolve multiple alerts
- **Bulk Status Change**: Change status of multiple alerts
- **Bulk Export**: Export multiple alerts

### Alert Workflows

#### Investigation Workflow
1. **Initial Triage**: Review alert details and severity
2. **Context Gathering**: Examine related logs and alerts
3. **Impact Assessment**: Determine scope and impact
4. **Response Planning**: Plan remediation actions
5. **Resolution**: Implement fixes and mark resolved

#### Escalation Process
- **Automatic Escalation**: Based on time and severity
- **Manual Escalation**: Escalate to senior team members
- **Notification Escalation**: Additional notification channels

### Alert Filtering and Search

#### Quick Filters
- **By Severity**: Filter by alert severity level
- **By Status**: Filter by alert status
- **By Category**: Filter by security category
- **By Time Range**: Filter by time period

#### Advanced Search
- **Field-based search**: Search specific alert fields
- **Boolean operators**: Complex search queries
- **Saved searches**: Save frequently used searches

## Detection Rules

The Rules section allows management of detection rules that identify security threats.

### Rule Management

#### Rule List View
- **Rule Name**: Human-readable rule identifier
- **Type**: Rule type (threshold, pattern, correlation, etc.)
- **Severity**: Alert severity for matches
- **Category**: Security category
- **Status**: Enabled/Disabled
- **Last Modified**: When the rule was last updated

#### Rule Actions
- **Enable/Disable**: Toggle rule activation
- **Edit**: Modify rule configuration
- **Test**: Test rule against sample data
- **Clone**: Create copy of existing rule
- **Delete**: Remove rule (with confirmation)

### Rule Creation and Editing

#### Rule Configuration Form

##### Basic Information
- **Name**: Unique rule identifier
- **Description**: Detailed explanation of what the rule detects
- **Severity**: Alert severity (Low, Medium, High, Critical)
- **Category**: Security category classification

##### Rule Logic
- **Rule Type**: Select detection method
  - Threshold: Count-based detection
  - Pattern: Signature-based detection
  - Correlation: Multi-event analysis
  - Anomaly: Baseline deviation

##### Conditions
- **Log Type**: Type of logs to analyze
- **Field Conditions**: Specific field criteria
- **Time Windows**: Time-based constraints
- **Thresholds**: Numeric limits

#### Rule Testing

##### Test Interface
- **Sample Data**: Upload or select test logs
- **Test Execution**: Run rule against test data
- **Results Display**: Show matches and non-matches
- **Performance Metrics**: Execution time and resource usage

##### Validation Process
1. **Syntax Check**: Verify rule syntax is correct
2. **Logic Validation**: Ensure rule logic is sound
3. **Performance Test**: Check rule performance impact
4. **False Positive Check**: Test against known good data

### Rule Templates

#### Pre-built Templates
- **Brute Force Detection**: Multiple failed login attempts
- **Web Attack Patterns**: SQL injection, XSS, etc.
- **Network Scanning**: Port scanning detection
- **Privilege Escalation**: Unauthorized privilege elevation

#### Custom Templates
- **Save as Template**: Convert custom rules to templates
- **Template Library**: Manage custom templates
- **Template Sharing**: Export/import templates

## Vulnerability Management

The Vulnerability Management section provides comprehensive security assessment capabilities for your network infrastructure and containerized environments.

### Asset Discovery

#### Network Discovery
- **Automatic Network Scanning**: Discover devices on your network automatically
- **IP Range Configuration**: Define specific IP ranges to scan
- **Service Detection**: Identify running services and open ports
- **Operating System Fingerprinting**: Detect OS versions and types

#### Asset Inventory
- **Device List**: Comprehensive inventory of discovered assets
- **Asset Details**: Detailed information for each discovered device
  - IP addresses and hostnames
  - Operating system information
  - Open ports and services
  - Last seen timestamps
- **Asset Categorization**: Organize assets by type, criticality, or location
- **Asset Tracking**: Monitor changes in your asset inventory over time

### Vulnerability Scanning

#### Scan Configuration
- **Scan Types**: Choose from different scanning methodologies
  - **Quick Scan**: Fast port scan for basic service discovery
  - **Comprehensive Scan**: Detailed vulnerability assessment
  - **Custom Scan**: User-defined scan parameters
- **Target Selection**: Define scan targets
  - Individual IP addresses
  - IP ranges (CIDR notation)
  - Hostname lists
  - Asset groups

#### Scan Management
- **Schedule Scans**: Automate vulnerability assessments
  - One-time scans
  - Recurring schedules (daily, weekly, monthly)
  - Custom cron expressions
- **Scan History**: Track all previous scans
  - Scan results and timestamps
  - Performance metrics
  - Comparison between scans
- **Real-time Monitoring**: Monitor scan progress in real-time

### Vulnerability Reports

#### Vulnerability Dashboard
- **Risk Overview**: High-level security posture summary
  - Total vulnerabilities by severity
  - Risk score trends
  - Most vulnerable assets
- **Recent Findings**: Latest discovered vulnerabilities
- **Remediation Progress**: Track vulnerability resolution

#### Detailed Vulnerability Information
Each vulnerability entry provides:
- **CVE Information**: Common Vulnerabilities and Exposures details
- **CVSS Scores**: Common Vulnerability Scoring System ratings
- **Severity Classification**: Critical, High, Medium, Low
- **Affected Assets**: List of vulnerable systems
- **Description**: Detailed vulnerability explanation
- **Remediation Guidance**: Steps to fix the vulnerability
- **References**: Links to additional information

#### Vulnerability Filtering and Search
- **Severity Filters**: Filter by vulnerability severity
- **Asset Filters**: Filter by affected assets
- **CVE Search**: Search by specific CVE identifiers
- **Date Ranges**: Filter by discovery date
- **Status Filters**: Filter by remediation status

### Container Security

#### Container Scanning
- **Image Vulnerability Assessment**: Scan container images for known vulnerabilities
- **Runtime Security**: Monitor running containers for security issues
- **Registry Integration**: Integrate with container registries for automated scanning
- **Compliance Checking**: Verify containers meet security standards

#### Container Inventory
- **Running Containers**: List of active containers
- **Image Information**: Details about container images
- **Security Policies**: Define and enforce container security policies
- **Compliance Reports**: Container security compliance status

### Remediation Management

#### Vulnerability Tracking
- **Status Management**: Track vulnerability remediation status
  - Open: Newly discovered vulnerabilities
  - In Progress: Vulnerabilities being addressed
  - Resolved: Fixed vulnerabilities
  - Accepted Risk: Acknowledged but not fixed
- **Assignment**: Assign vulnerabilities to team members
- **Due Dates**: Set remediation deadlines
- **Notes and Comments**: Add remediation notes and progress updates

#### Remediation Workflows
- **Prioritization**: Automatically prioritize based on risk scores
- **Escalation**: Escalate overdue vulnerabilities
- **Notifications**: Alert teams about new vulnerabilities and deadlines
- **Integration**: Connect with ticketing systems for workflow management

### Risk Assessment

#### Risk Scoring
- **Automated Risk Calculation**: Calculate risk scores based on:
  - CVSS scores
  - Asset criticality
  - Exposure level
  - Exploitability
- **Custom Risk Models**: Define organization-specific risk calculations
- **Risk Trends**: Track risk changes over time

#### Compliance Reporting
- **Regulatory Compliance**: Generate reports for compliance frameworks
- **Executive Dashboards**: High-level risk summaries for management
- **Detailed Reports**: Comprehensive vulnerability and remediation reports
- **Export Options**: Export reports in PDF, CSV, and JSON formats

### Integration Features

#### API Integration
- **REST API**: Programmatic access to vulnerability data
- **Webhook Notifications**: Real-time vulnerability alerts
- **Third-party Integration**: Connect with external security tools
- **Data Export**: Export vulnerability data for external analysis

#### Notification Integration
- **Email Alerts**: Automated vulnerability notifications
- **Discord/Slack**: Team collaboration notifications
- **Custom Webhooks**: Integration with custom notification systems
- **SMS Alerts**: Critical vulnerability notifications

## System Settings

The Settings section provides system configuration and administration capabilities.

### General Settings

#### System Information
- **Version Information**: SIEM BOX version and build
- **System Status**: Overall system health
- **License Information**: License details and expiration
- **Support Information**: Contact and support details

#### Basic Configuration
- **System Name**: Custom name for your SIEM BOX instance
- **Time Zone**: System time zone setting
- **Language**: Interface language selection
- **Theme**: Light/dark theme selection

### Notification Settings

#### Email Configuration
- **SMTP Settings**: Mail server configuration
- **Email Templates**: Customize email formats
- **Recipient Lists**: Manage email distribution lists
- **Test Email**: Send test notifications

#### Integration Settings
- **Discord**: Webhook configuration for Discord notifications
- **Slack**: Webhook configuration for Slack notifications
- **Webhooks**: Custom webhook endpoints
- **SMS**: SMS provider configuration

### Data Management

#### Log Retention
- **Retention Policies**: Configure how long to keep logs
- **Archive Settings**: Long-term storage configuration
- **Cleanup Schedules**: Automated data cleanup
- **Storage Monitoring**: Track storage usage

#### Backup and Restore
- **Backup Configuration**: Automated backup settings
- **Manual Backup**: Create immediate backups
- **Restore Options**: Restore from backup files
- **Export/Import**: Configuration export and import

### Security Settings

#### Authentication
- **Password Policies**: Password complexity requirements
- **Session Management**: Session timeout and security
- **Two-Factor Authentication**: 2FA configuration
- **API Security**: API key management

#### Access Control
- **User Roles**: Define user permission levels
- **IP Restrictions**: Limit access by IP address
- **Audit Logging**: Track user activities
- **Security Policies**: System security configurations

## User Management

### User Administration

#### User List
- **Username**: User login identifier
- **Full Name**: User's display name
- **Email**: Contact email address
- **Role**: User permission level
- **Status**: Active/Inactive
- **Last Login**: Most recent login time

#### User Actions
- **Add User**: Create new user account
- **Edit User**: Modify user information
- **Reset Password**: Force password reset
- **Disable User**: Temporarily disable account
- **Delete User**: Permanently remove user

### Role Management

#### Built-in Roles
- **Administrator**: Full system access
- **Security Analyst**: Alert and log management
- **Viewer**: Read-only access
- **Operator**: Limited operational access

#### Custom Roles
- **Create Role**: Define custom permission sets
- **Permission Matrix**: Granular permission control
- **Role Assignment**: Assign roles to users

### User Profile

#### Profile Settings
- **Personal Information**: Name, email, contact details
- **Password Change**: Update login password
- **Notification Preferences**: Personal notification settings
- **Interface Preferences**: Theme, language, dashboard layout

#### Activity History
- **Login History**: Recent login activities
- **Action Log**: User actions and changes
- **Session Information**: Current and recent sessions

## Search and Filtering

### Global Search

#### Search Capabilities
- **Cross-section Search**: Search across logs, alerts, and rules
- **Intelligent Suggestions**: Auto-complete and suggestions
- **Search History**: Recent search queries
- **Saved Searches**: Bookmark frequently used searches

#### Search Syntax
```
# Basic text search
failed login

# Field-specific search
src_ip:192.168.1.100

# Time range search
timestamp:[2024-01-01 TO 2024-01-31]

# Boolean operators
(failed OR error) AND src_ip:192.168.*

# Wildcard search
hostname:web*

# Phrase search
"authentication failed"
```

### Advanced Filtering

#### Filter Types
- **Text Filters**: String matching and patterns
- **Numeric Filters**: Range and comparison operators
- **Date Filters**: Time range and relative dates
- **Boolean Filters**: True/false values
- **List Filters**: Multiple value selection

#### Filter Combinations
- **AND Logic**: All conditions must match
- **OR Logic**: Any condition can match
- **NOT Logic**: Exclude matching items
- **Nested Logic**: Complex condition combinations

### Search Performance

#### Optimization Tips
- **Use Specific Fields**: Search specific fields rather than all fields
- **Limit Time Ranges**: Use narrow time ranges for better performance
- **Index Awareness**: Understand which fields are indexed
- **Query Complexity**: Keep queries as simple as possible

## Reports and Analytics

### Built-in Reports

#### Security Reports
- **Alert Summary**: Alert statistics and trends
- **Threat Analysis**: Threat pattern analysis
- **Incident Reports**: Detailed incident documentation
- **Compliance Reports**: Regulatory compliance status

#### Operational Reports
- **System Health**: System performance and status
- **Log Statistics**: Log volume and source analysis
- **User Activity**: User access and activity reports
- **Performance Metrics**: System performance analysis

### Custom Reports

#### Report Builder
- **Data Sources**: Select logs, alerts, or system data
- **Filters**: Apply filters to narrow data scope
- **Visualizations**: Choose charts, tables, or graphs
- **Scheduling**: Automate report generation

#### Report Formats
- **PDF**: Formatted documents for sharing
- **CSV**: Data export for analysis
- **HTML**: Web-based reports
- **JSON**: Structured data export

### Analytics Dashboard

#### Metrics and KPIs
- **Security Metrics**: Alert rates, response times, resolution rates
- **Operational Metrics**: System uptime, performance, capacity
- **Trend Analysis**: Historical trends and patterns
- **Comparative Analysis**: Period-over-period comparisons

## Mobile Interface

### Mobile Access

#### Responsive Design
- **Adaptive Layout**: Optimized for mobile screens
- **Touch Interface**: Touch-friendly controls
- **Offline Capability**: Limited offline functionality
- **Push Notifications**: Mobile alert notifications

#### Mobile Features
- **Alert Management**: View and manage alerts on mobile
- **Quick Actions**: Acknowledge, resolve, escalate alerts
- **Dashboard View**: Mobile-optimized dashboard
- **Search**: Basic search and filtering capabilities

### Mobile App (Future)
- **Native Apps**: iOS and Android applications
- **Enhanced Features**: Full mobile functionality
- **Offline Mode**: Extended offline capabilities
- **Biometric Authentication**: Fingerprint/face recognition

## Keyboard Shortcuts

### Global Shortcuts
- **Ctrl+/** (Cmd+/): Show help and shortcuts
- **Ctrl+K** (Cmd+K): Global search
- **Ctrl+Shift+D** (Cmd+Shift+D): Go to Dashboard
- **Ctrl+Shift+L** (Cmd+Shift+L): Go to Logs
- **Ctrl+Shift+A** (Cmd+Shift+A): Go to Alerts
- **Ctrl+Shift+R** (Cmd+Shift+R): Go to Rules
- **Ctrl+Shift+V** (Cmd+Shift+V): Go to Vulnerabilities
- **Ctrl+Shift+S** (Cmd+Shift+S): Go to Settings

### Section-Specific Shortcuts

#### Logs Section
- **F5**: Refresh log view
- **Ctrl+F** (Cmd+F): Focus search box
- **Ctrl+E** (Cmd+E): Export logs
- **Space**: Pause/resume live updates

#### Alerts Section
- **A**: Acknowledge selected alert
- **R**: Resolve selected alert
- **F**: Mark as false positive
- **E**: Edit alert
- **Ctrl+A** (Cmd+A): Select all alerts

#### Rules Section
- **N**: Create new rule
- **E**: Edit selected rule
- **T**: Test selected rule
- **D**: Disable/enable selected rule

#### Vulnerabilities Section
- **S**: Start new scan
- **R**: Refresh vulnerability list
- **F**: Filter vulnerabilities
- **E**: Export vulnerability report
- **A**: Acknowledge selected vulnerability

## Troubleshooting

### Common Issues

#### Login Problems
**Issue**: Cannot log in to SIEM BOX
**Solutions**:
- Verify username and password
- Check if account is active
- Clear browser cache and cookies
- Try incognito/private browsing mode
- Contact administrator for password reset

#### Performance Issues
**Issue**: Interface is slow or unresponsive
**Solutions**:
- Check network connectivity
- Clear browser cache
- Disable browser extensions
- Try different browser
- Check system resources

#### Data Not Loading
**Issue**: Logs or alerts not displaying
**Solutions**:
- Check time range filters
- Verify data sources are active
- Check system status
- Refresh the page
- Contact administrator

#### Search Not Working
**Issue**: Search returns no results
**Solutions**:
- Check search syntax
- Verify time range
- Clear search filters
- Try simpler search terms
- Check data availability

### Browser Compatibility

#### Supported Browsers
- **Chrome**: Version 90+
- **Firefox**: Version 88+
- **Safari**: Version 14+
- **Edge**: Version 90+

#### Browser Settings
- **JavaScript**: Must be enabled
- **Cookies**: Must be enabled
- **Local Storage**: Must be enabled
- **WebSockets**: Must be supported

### Getting Help

#### Built-in Help
- **Help Menu**: Access help documentation
- **Tooltips**: Hover over elements for help
- **Guided Tours**: Interactive feature tours
- **Keyboard Shortcuts**: Press Ctrl+/ for shortcuts

#### Support Resources
- **Documentation**: Comprehensive user guides
- **Community Forum**: User community support
- **Support Tickets**: Professional support
- **Training Materials**: Video tutorials and guides

This user guide provides comprehensive coverage of the SIEM BOX web interface. For additional help or specific questions, consult the built-in help system or contact your system administrator.