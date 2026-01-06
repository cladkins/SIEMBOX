# SIEM BOX - Alert Configuration Guide

This guide covers how to configure alert notifications in SIEM BOX using the web interface, including email, Discord, webhooks, SMS, and other notification channels.

## Table of Contents

1. [Overview](#overview)
2. [Web Interface Configuration](#web-interface-configuration)
3. [Notification Channels](#notification-channels)
4. [Email Configuration](#email-configuration)
5. [Discord Configuration](#discord-configuration)
6. [Webhook Configuration](#webhook-configuration)
7. [SMS Configuration](#sms-configuration)
8. [Alert Management](#alert-management)
9. [Global Settings](#global-settings)
10. [Alert Filtering](#alert-filtering)
11. [Testing Notifications](#testing-notifications)
12. [API Usage](#api-usage)
13. [Troubleshooting](#troubleshooting)
14. [Best Practices](#best-practices)

## Overview

SIEM BOX's notification system ensures that security alerts reach the right people through the right channels at the right time. All notification configuration is managed through the intuitive web interface, with support for multiple notification channels, sophisticated filtering, rate limiting, and escalation capabilities.

### Key Features

- **Multiple Channels**: Email, Discord, Slack, webhooks, SMS
- **Smart Filtering**: Route alerts based on severity, category, and content
- **Rate Limiting**: Prevent notification flooding
- **Escalation**: Automatic escalation for unacknowledged alerts
- **Deduplication**: Reduce duplicate notifications
- **Grouping**: Combine related alerts
- **Templates**: Customizable notification formats

### Notification Flow

1. **Alert Generation**: Detection rules create alerts
2. **Filtering**: Alerts are filtered based on configured criteria
3. **Channel Selection**: Appropriate notification channels are selected
4. **Rate Limiting**: Notifications are throttled if necessary
5. **Delivery**: Notifications are sent via configured channels
6. **Tracking**: Delivery status is tracked and logged
7. **Escalation**: Unacknowledged alerts may be escalated

## Web Interface Configuration

All notification settings are configured through the SIEM BOX web interface, providing an intuitive and user-friendly experience for managing alert notifications.

### Accessing Notification Settings

1. **Navigate to Settings**: Click on "Settings" in the main navigation
2. **Select Notifications Tab**: Choose the "Notifications" tab from the settings menu
3. **Configure Channels**: Set up individual notification channels using the web forms

### Settings Page Overview

The Settings page provides comprehensive notification management through several sections:

#### Notification Channels Section
- **Email Settings**: SMTP configuration and recipient management
- **Discord Integration**: Webhook setup and message formatting
- **Webhook Configuration**: Custom webhook endpoints and payload formats
- **SMS Settings**: Provider configuration and recipient phone numbers

#### Global Configuration Section
- **Rate Limiting**: Prevent notification flooding with configurable thresholds
- **Alert Filtering**: Define which alerts trigger notifications
- **Quiet Hours**: Suppress non-critical notifications during specified times
- **Deduplication**: Reduce duplicate notifications with smart grouping

#### Testing and Validation Section
- **Test Notifications**: Send test messages to verify configuration
- **Delivery Status**: Monitor notification delivery success rates
- **Configuration Validation**: Real-time validation of settings

### Configuration Workflow

1. **Initial Setup**: Configure basic notification channels (typically email first)
2. **Test Configuration**: Use built-in testing tools to verify setup
3. **Refine Settings**: Adjust filtering and rate limiting based on alert volume
4. **Add Additional Channels**: Integrate Discord, webhooks, or SMS as needed
5. **Monitor Performance**: Use the dashboard to track notification effectiveness

### Real-Time Configuration

- **Immediate Application**: Changes take effect immediately without restart
- **Live Validation**: Settings are validated in real-time as you type
- **Preview Mode**: See how notifications will look before saving
- **Rollback Support**: Easily revert to previous configurations

## Notification Channels

SIEM BOX supports multiple notification channels, each with specific configuration options and use cases.

### Supported Channels

| Channel | Use Case | Response Time | Cost |
|---------|----------|---------------|------|
| **Email** | Detailed alerts, documentation | Medium | Low |
| **Discord** | Team collaboration, real-time alerts | Fast | Free |
| **Slack** | Business communication, workflows | Fast | Varies |
| **Webhook** | Integration with other systems | Fast | Varies |
| **SMS** | Critical alerts, out-of-band | Immediate | High |

### Channel Selection Strategy

- **Critical Alerts**: SMS + Email + Discord/Slack
- **High Severity**: Email + Discord/Slack
- **Medium Severity**: Email or Discord/Slack
- **Low Severity**: Email only (optional)

## Email Configuration

Email notifications provide detailed alert information and are suitable for documentation and follow-up. All email settings are configured through the web interface.

### Configuring Email via Web Interface

1. **Navigate to Settings → Notifications → Email**
2. **Enable Email Notifications**: Toggle the "Enable Email" switch
3. **Configure SMTP Settings**: Fill in the SMTP server details
4. **Add Recipients**: Specify email addresses for notifications
5. **Test Configuration**: Use the "Send Test Email" button to verify setup

### Email Configuration Form Fields

The web interface provides the following configuration options:

| Field | Description | Example |
|-------|-------------|---------|
| **Enable Email** | Toggle to enable/disable email notifications | ✓ Enabled |
| **SMTP Server** | Mail server hostname | `smtp.gmail.com` |
| **SMTP Port** | Mail server port | `587` |
| **Use TLS** | Enable TLS encryption | ✓ Enabled |
| **Use SSL** | Enable SSL encryption (alternative to TLS) | ☐ Disabled |
| **Username** | SMTP authentication username | `alerts@yourdomain.com` |
| **Password** | SMTP authentication password | `••••••••••••` |
| **From Email** | Sender email address | `siembox@yourdomain.com` |
| **Recipients** | Email addresses for notifications | `admin@yourdomain.com` |

### Web Interface Features

#### Real-Time Validation
- **SMTP Connection Testing**: Automatically tests SMTP connectivity
- **Email Format Validation**: Validates email address formats
- **Credential Verification**: Tests authentication credentials
- **Port Accessibility**: Checks if SMTP ports are accessible

#### Recipient Management
- **Add Multiple Recipients**: Easily add multiple email addresses
- **Recipient Groups**: Organize recipients by role or department
- **Individual Testing**: Send test emails to specific recipients
- **Bulk Operations**: Add/remove multiple recipients at once

### Email Templates

Customize email appearance and content:

```yaml
email:
  templates:
    subject: "[SIEM BOX] {severity} Alert - {title}"
    include_logo: true
    custom_footer: "This alert was generated by SIEM BOX."
    
    # HTML template (optional)
    html_template: |
      <html>
        <body>
          <h2 style="color: {severity_color};">{title}</h2>
          <p><strong>Severity:</strong> {severity}</p>
          <p><strong>Category:</strong> {category}</p>
          <p><strong>Time:</strong> {triggered_at}</p>
          <p><strong>Description:</strong> {description}</p>
          <hr>
          <p>{custom_footer}</p>
        </body>
      </html>
```

### Email Provider Examples

#### Gmail Configuration

```yaml
email:
  enabled: true
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "your-email@gmail.com"
  password: "your-app-password"  # Generate in Google Account settings
```

#### Outlook/Office 365

```yaml
email:
  enabled: true
  smtp_server: "smtp-mail.outlook.com"
  smtp_port: 587
  use_tls: true
  username: "your-email@outlook.com"
  password: "your-password"
```

#### Custom SMTP Server

```yaml
email:
  enabled: true
  smtp_server: "mail.yourdomain.com"
  smtp_port: 25
  use_tls: false
  username: "siembox@yourdomain.com"
  password: "your-password"
```

## Discord Configuration

Discord notifications provide real-time alerts with rich formatting and team collaboration features.

### Basic Discord Setup

```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
    username: "SIEM BOX"
    avatar_url: "https://your-domain.com/siembox-logo.png"
```

### Discord Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `enabled` | boolean | Enable/disable Discord notifications |
| `webhook_url` | string | Discord webhook URL |
| `username` | string | Bot username for notifications |
| `avatar_url` | string | Bot avatar image URL |
| `mention_roles` | object | Role mentions by severity |

### Role Mentions

Configure role mentions for different severity levels:

```yaml
discord:
  mention_roles:
    critical: "@security-team"
    high: "@security-team"
    medium: "@on-call"
    low: ""
```

### Creating Discord Webhook

1. Go to your Discord server settings
2. Navigate to "Integrations" → "Webhooks"
3. Click "Create Webhook"
4. Configure the webhook:
   - Name: "SIEM BOX Alerts"
   - Channel: Select your alerts channel
   - Copy the webhook URL
5. Use the URL in your configuration

### Discord Message Format

Discord messages include:
- **Severity-based colors**
- **Rich embeds** with alert details
- **Timestamp** information
- **Quick action buttons** (if configured)

## Slack Configuration

Slack notifications integrate with business workflows and provide team collaboration features.

### Basic Slack Setup

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    channel: "#security-alerts"
    username: "SIEM BOX"
    icon_emoji: ":warning:"
```

### Slack Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `enabled` | boolean | Enable/disable Slack notifications |
| `webhook_url` | string | Slack webhook URL |
| `channel` | string | Target Slack channel |
| `username` | string | Bot username |
| `icon_emoji` | string | Bot icon emoji |
| `icon_url` | string | Bot icon image URL |

### Advanced Slack Features

```yaml
slack:
  format:
    use_blocks: true              # Use Slack Block Kit
    include_actions: true         # Add action buttons
    thread_related_alerts: true   # Thread related alerts
  
  # Custom fields in messages
  custom_fields:
    - title: "Source IP"
      value: "{src_ip}"
      short: true
    - title: "Detection Rule"
      value: "{rule_name}"
      short: true
```

### Creating Slack Webhook

1. Go to your Slack workspace
2. Navigate to "Apps" → "Incoming Webhooks"
3. Click "Add to Slack"
4. Select the channel for notifications
5. Copy the webhook URL
6. Use the URL in your configuration

### Slack Action Buttons

Configure interactive buttons for alert management:

```yaml
slack:
  format:
    include_actions: true
    actions:
      - name: "acknowledge"
        text: "Acknowledge"
        style: "primary"
        url: "https://siembox.yourdomain.com/alerts/{alert_id}/acknowledge"
      - name: "resolve"
        text: "Resolve"
        style: "danger"
        url: "https://siembox.yourdomain.com/alerts/{alert_id}/resolve"
```

## Webhook Configuration

Webhooks enable integration with external systems, SOAR platforms, and custom applications.

### Basic Webhook Setup

```yaml
notifications:
  webhook:
    enabled: true
    webhook_url: "https://your-system.com/webhook"
    method: "POST"
    headers:
      Content-Type: "application/json"
      Authorization: "Bearer YOUR_API_TOKEN"
      X-SIEM-Source: "SIEM-BOX"
```

### Webhook Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `enabled` | boolean | Enable/disable webhook notifications |
| `webhook_url` | string | Target webhook URL |
| `method` | string | HTTP method (POST, PUT) |
| `headers` | object | Custom HTTP headers |
| `payload_format` | string | Payload format (json, xml, custom) |
| `timeout` | integer | Request timeout in seconds |

### Retry Configuration

Configure retry behavior for failed webhook deliveries:

```yaml
webhook:
  retry:
    max_attempts: 3
    backoff_factor: 2
    timeout: 30
    retry_codes: [500, 502, 503, 504]
```

### Custom Payload Format

Customize the webhook payload structure:

```yaml
webhook:
  payload_format: "custom"
  custom_payload:
    event_type: "security_alert"
    timestamp: "{triggered_at}"
    severity: "{severity}"
    alert:
      id: "{alert_id}"
      title: "{title}"
      description: "{description}"
      category: "{category}"
    source:
      ip: "{src_ip}"
      hostname: "{hostname}"
    metadata:
      rule_id: "{rule_id}"
      rule_name: "{rule_name}"
```

### Integration Examples

#### Splunk Integration

```yaml
webhook:
  webhook_url: "https://splunk.yourdomain.com:8088/services/collector"
  headers:
    Authorization: "Splunk YOUR_HEC_TOKEN"
    Content-Type: "application/json"
  custom_payload:
    sourcetype: "siembox:alert"
    event: "{alert_data}"
```

#### PagerDuty Integration

```yaml
webhook:
  webhook_url: "https://events.pagerduty.com/v2/enqueue"
  headers:
    Content-Type: "application/json"
  custom_payload:
    routing_key: "YOUR_INTEGRATION_KEY"
    event_action: "trigger"
    payload:
      summary: "{title}"
      severity: "{severity}"
      source: "SIEM BOX"
```

## SMS Configuration

SMS notifications provide immediate alerts for critical security events.

### Basic SMS Setup (Twilio)

```yaml
notifications:
  sms:
    enabled: true
    provider: "twilio"
    twilio:
      account_sid: "YOUR_TWILIO_ACCOUNT_SID"
      auth_token: "YOUR_TWILIO_AUTH_TOKEN"
      from_number: "+1234567890"
      to_numbers:
        - "+1987654321"
        - "+1555123456"
```

### SMS Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `enabled` | boolean | Enable/disable SMS notifications |
| `provider` | string | SMS provider (twilio, aws_sns) |
| `from_number` | string | Sender phone number |
| `to_numbers` | array | Recipient phone numbers |

### AWS SNS Configuration

```yaml
sms:
  enabled: true
  provider: "aws_sns"
  aws_sns:
    region: "us-east-1"
    access_key_id: "YOUR_ACCESS_KEY"
    secret_access_key: "YOUR_SECRET_KEY"
    topic_arn: "arn:aws:sns:us-east-1:123456789:siembox-alerts"
```

### SMS Message Format

SMS messages are automatically truncated and formatted:

```
[SIEM BOX] HIGH: SSH Brute Force Attack
Source: 192.168.1.100
Time: 2024-01-15 14:30:25
View: https://siembox.yourdomain.com/alerts/123
```

## Alert Management

The SIEM BOX web interface provides comprehensive alert management capabilities, allowing users to investigate, respond to, and track security alerts through an intuitive dashboard.

### Alert Dashboard

#### Real-Time Alert Monitoring
- **Live Alert Feed**: Real-time updates of new security alerts
- **Alert Statistics**: Summary of alert counts by severity and status
- **Trend Analysis**: Visual charts showing alert patterns over time
- **Quick Filters**: Instant filtering by severity, category, or time range

#### Alert List View
The main alert interface displays:
- **Alert Title**: Descriptive name of the security event
- **Severity Level**: Critical, High, Medium, Low with color coding
- **Category**: Type of security threat (brute force, web attack, etc.)
- **Status**: Open, Investigating, Resolved, False Positive
- **Timestamp**: When the alert was triggered
- **Source Information**: IP addresses, hostnames, and affected systems

### Alert Investigation Workflow

#### Individual Alert Management
1. **Alert Selection**: Click on any alert to view detailed information
2. **Context Analysis**: Review related logs and system information
3. **Status Updates**: Change alert status through dropdown menus
4. **Note Addition**: Add investigation notes and findings
5. **Assignment**: Assign alerts to specific team members
6. **Resolution**: Mark alerts as resolved with resolution details

#### Bulk Alert Operations
- **Multi-Select**: Select multiple alerts using checkboxes
- **Bulk Status Change**: Update status for multiple alerts simultaneously
- **Bulk Assignment**: Assign multiple alerts to team members
- **Bulk Export**: Export selected alerts for external analysis
- **Bulk Acknowledgment**: Acknowledge multiple alerts at once

### Alert Details and Context

#### Comprehensive Alert Information
Each alert provides detailed context including:
- **Detection Rule**: Which rule triggered the alert
- **Raw Log Data**: Original log entries that caused the alert
- **Parsed Fields**: Structured data extracted from logs
- **Timeline**: Sequence of events leading to the alert
- **Related Alerts**: Other alerts from the same source or timeframe

#### Investigation Tools
- **Log Correlation**: View related log entries around the alert time
- **Source Analysis**: Detailed information about source IPs and systems
- **Historical Context**: Previous alerts from the same source
- **Threat Intelligence**: External threat information (if configured)

### Alert Response Actions

#### Available Actions
- **Acknowledge**: Mark alert as being investigated
- **Resolve**: Mark alert as resolved with resolution notes
- **False Positive**: Mark alert as false positive to improve detection
- **Escalate**: Escalate to senior team members or management
- **Create Ticket**: Generate tickets in external systems (if integrated)

#### Response Tracking
- **Action History**: Complete audit trail of all actions taken
- **Response Times**: Track time from alert to acknowledgment/resolution
- **Team Collaboration**: Multiple team members can work on the same alert
- **Status Notifications**: Automatic notifications when alert status changes

### Alert Filtering and Search

#### Advanced Filtering Options
- **Severity Filters**: Filter by Critical, High, Medium, Low severity
- **Status Filters**: Filter by Open, Investigating, Resolved, False Positive
- **Category Filters**: Filter by security category (brute force, web attack, etc.)
- **Time Range Filters**: Custom date/time ranges or preset periods
- **Source Filters**: Filter by source IP, hostname, or system

#### Search Capabilities
- **Full-Text Search**: Search across all alert fields and descriptions
- **Field-Specific Search**: Search specific fields like source IP or rule name
- **Boolean Operators**: Use AND, OR, NOT for complex searches
- **Saved Searches**: Save frequently used search queries
- **Search History**: Access previous search queries

### Alert Metrics and Reporting

#### Performance Metrics
- **Mean Time to Acknowledge (MTTA)**: Average time to acknowledge alerts
- **Mean Time to Resolve (MTTR)**: Average time to resolve alerts
- **Alert Volume Trends**: Historical alert volume analysis
- **False Positive Rates**: Track and reduce false positive alerts

#### Reporting Features
- **Executive Dashboards**: High-level security metrics for management
- **Detailed Reports**: Comprehensive alert analysis and trends
- **Custom Reports**: Build custom reports based on specific criteria
- **Scheduled Reports**: Automatically generate and distribute reports

## Global Settings

Global settings apply to all notification channels and control overall behavior.

### Rate Limiting

Prevent notification flooding:

```yaml
global_settings:
  rate_limiting:
    enabled: true
    max_alerts_per_minute: 10
    max_alerts_per_hour: 100
    burst_threshold: 5
    
    # Per-channel limits
    channel_limits:
      email: 50      # per hour
      discord: 100   # per hour
      slack: 100     # per hour
      sms: 10        # per hour
```

### Deduplication

Reduce duplicate notifications:

```yaml
global_settings:
  deduplication:
    enabled: true
    time_window: 300  # 5 minutes
    fields: ["title", "category", "src_ip"]
    
    # Deduplication strategies
    strategy: "exact_match"  # or "fuzzy_match"
    similarity_threshold: 0.8  # for fuzzy matching
```

### Alert Grouping

Combine related alerts:

```yaml
global_settings:
  grouping:
    enabled: true
    time_window: 600  # 10 minutes
    max_group_size: 10
    group_by: ["category", "src_ip"]
    
    # Group notification template
    group_template:
      subject: "[SIEM BOX] {count} {category} alerts from {src_ip}"
      summary: "Multiple alerts detected from the same source"
```

### Quiet Hours

Suppress non-critical notifications during specified hours:

```yaml
global_settings:
  quiet_hours:
    enabled: true
    start_time: "22:00"
    end_time: "08:00"
    timezone: "UTC"
    
    # Emergency override
    emergency_override:
      severity: ["critical"]
      categories: ["malware", "privilege_escalation"]
```

## Alert Filtering

Configure which alerts trigger notifications for each channel.

### Severity-Based Filtering

```yaml
email:
  filters:
    min_severity: "medium"  # Only medium, high, critical
    max_severity: "high"    # Up to high (exclude critical)

discord:
  filters:
    min_severity: "high"    # Only high and critical

sms:
  filters:
    min_severity: "critical"  # Only critical alerts
```

### Category-Based Filtering

```yaml
email:
  filters:
    categories:
      - "brute_force"
      - "web_attack"
      - "privilege_escalation"
      - "malware"
    
    exclude_categories:
      - "low_priority"
      - "informational"
```

### Field-Based Filtering

```yaml
discord:
  filters:
    field_conditions:
      src_ip: "!192.168.1.0/24"  # Exclude internal IPs
      username: "!service_account"  # Exclude service accounts
    
    pattern_filters:
      title: "(?i)(test|demo)"  # Exclude test alerts
```

### Time-Based Filtering

```yaml
slack:
  filters:
    business_hours_only: true
    timezone: "America/New_York"
    business_hours:
      start: "09:00"
      end: "17:00"
    business_days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
```

## Escalation Rules

Automatically escalate unacknowledged alerts to ensure response.

### Basic Escalation

```yaml
global_settings:
  escalation:
    enabled: true
    rules:
      - condition:
          severity: "critical"
          unacknowledged_time: 900  # 15 minutes
        action:
          notification_types: ["email", "sms"]
          escalate_to: ["manager@yourdomain.com"]
          
      - condition:
          severity: "high"
          unacknowledged_time: 1800  # 30 minutes
        action:
          notification_types: ["email"]
          escalate_to: ["security-lead@yourdomain.com"]
```

### Advanced Escalation

```yaml
escalation:
  rules:
    - name: "Critical Alert Escalation"
      condition:
        severity: ["critical"]
        categories: ["malware", "privilege_escalation"]
        unacknowledged_time: 600
      action:
        notification_types: ["email", "sms", "discord"]
        escalate_to: ["ciso@yourdomain.com"]
        message_template: "URGENT: Critical security alert requires immediate attention"
        
    - name: "Business Hours Escalation"
      condition:
        severity: ["high", "critical"]
        business_hours: true
        unacknowledged_time: 1200
      action:
        notification_types: ["email", "slack"]
        escalate_to: ["security-team@yourdomain.com"]
```

## Testing Notifications

### Test Mode

Enable test mode to verify notification configuration:

```yaml
testing:
  test_mode: true
  test_recipients:
    email: ["test@yourdomain.com"]
    discord: true
    slack: true
    webhook: true
  
  # Scheduled testing
  schedule:
    enabled: true
    frequency: "weekly"
    day_of_week: "monday"
    time: "09:00"
```

### Manual Testing

Test individual notification channels:

```bash
# Test email notifications
curl -X POST "http://localhost:8000/api/v1/alerts/test/email" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "test@yourdomain.com",
    "test_alert": {
      "title": "Test Alert",
      "severity": "medium",
      "category": "test"
    }
  }'

# Test Discord notifications
curl -X POST "http://localhost:8000/api/v1/alerts/test/discord" \
  -d '{"test_alert": {"title": "Test Alert", "severity": "high"}}'

# Test all channels
curl -X POST "http://localhost:8000/api/v1/alerts/test/all"
```

### Validation Checklist

- [ ] Notifications are delivered to correct recipients
- [ ] Message formatting is correct and readable
- [ ] Severity-based filtering works as expected
- [ ] Rate limiting prevents flooding
- [ ] Escalation rules trigger appropriately
- [ ] All channels are properly configured

## API Usage

### Send Notifications

```bash
# Send notifications for specific alerts
curl -X POST "http://localhost:8000/api/v1/alerts/notify" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_ids": ["alert-uuid-1", "alert-uuid-2"],
    "notification_types": ["email", "discord"]
  }'
```

### Get Notification Status

```bash
# Check notification delivery status
curl "http://localhost:8000/api/v1/alerts/{alert_id}/notifications"
```

Response:
```json
{
  "alert_id": "alert-uuid-1",
  "notifications_sent": {
    "email": {
      "status": "delivered",
      "timestamp": "2024-01-15T14:30:25Z",
      "recipient": "admin@yourdomain.com"
    },
    "discord": {
      "status": "delivered",
      "timestamp": "2024-01-15T14:30:26Z",
      "webhook_url": "https://discord.com/api/webhooks/..."
    }
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Email Not Delivered

**Symptoms**: Email notifications not received

**Solutions**:
- Check SMTP server settings
- Verify authentication credentials
- Check spam/junk folders
- Test SMTP connectivity
- Review email server logs

#### 2. Discord/Slack Webhook Failures

**Symptoms**: Webhook notifications failing

**Solutions**:
- Verify webhook URL is correct
- Check webhook permissions
- Test webhook manually with curl
- Review webhook rate limits
- Check network connectivity

#### 3. SMS Not Delivered

**Symptoms**: SMS notifications not received

**Solutions**:
- Verify Twilio/AWS credentials
- Check phone number format
- Review SMS provider logs
- Check account balance/limits
- Test with different phone numbers

#### 4. Rate Limiting Issues

**Symptoms**: Notifications being dropped

**Solutions**:
- Review rate limiting settings
- Adjust thresholds based on alert volume
- Implement alert grouping
- Use severity-based filtering
- Monitor notification queues

### Debug Mode

Enable debug logging for notification troubleshooting:

```bash
# Set environment variable
export NOTIFICATION_DEBUG=true

# Check notification logs
docker logs siembox-backend | grep notification
```

### Health Monitoring

Monitor notification system health:

```yaml
health_monitoring:
  enabled: true
  check_interval: 300
  
  thresholds:
    email_failure_rate: 0.1
    webhook_failure_rate: 0.05
    consecutive_failures: 5
  
  self_alerts:
    enabled: true
    notification_types: ["email"]
    severity: "medium"
```

## Best Practices

### Channel Strategy

1. **Layer Notifications**: Use multiple channels for critical alerts
2. **Match Urgency**: Align notification speed with alert severity
3. **Consider Cost**: Balance notification coverage with costs
4. **Test Regularly**: Verify all channels work correctly
5. **Monitor Delivery**: Track notification success rates

### Alert Quality

1. **Meaningful Subjects**: Use descriptive alert titles
2. **Rich Context**: Include relevant details in notifications
3. **Actionable Information**: Provide clear next steps
4. **Consistent Formatting**: Use templates for consistency
5. **Appropriate Severity**: Match notification urgency to actual risk

### Performance

1. **Efficient Filtering**: Use specific filters to reduce processing
2. **Batch Processing**: Group related notifications when possible
3. **Async Delivery**: Use background tasks for notification sending
4. **Monitor Resources**: Track notification system performance
5. **Optimize Templates**: Keep message templates efficient

### Security

1. **Secure Credentials**: Protect API keys and passwords
2. **Encrypt Communications**: Use TLS for all channels
3. **Access Control**: Limit notification configuration access
4. **Audit Logs**: Track notification configuration changes
5. **Data Privacy**: Avoid including sensitive data in notifications

### Maintenance

1. **Regular Testing**: Test all notification channels monthly
2. **Update Credentials**: Rotate API keys and passwords regularly
3. **Monitor Quotas**: Track usage against provider limits
4. **Review Filters**: Adjust filtering based on alert patterns
5. **Document Changes**: Keep configuration changes documented

This comprehensive guide provides everything needed to configure effective alert notifications in SIEM BOX. Start with basic email notifications, then gradually add other channels based on your team's needs and preferences.