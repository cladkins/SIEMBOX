# SIEM BOX - Notification Service Documentation

## Overview

The SIEM BOX Notification Service provides comprehensive alerting capabilities across multiple communication channels. When security events are detected, the system can automatically notify administrators through Email, Discord, Slack, SMS, and custom webhooks.

## Features

### Supported Notification Channels

1. **Email (SMTP)**
   - HTML formatted alerts
   - Multiple recipients
   - TLS/SSL support
   - Customizable templates

2. **Discord**
   - Rich embed messages
   - Webhook integration
   - Color-coded severity levels
   - Custom bot appearance

3. **Slack**
   - Rich attachment formatting
   - Channel-specific routing
   - Custom bot integration
   - Interactive elements

4. **SMS (Twilio)**
   - Concise alert messages
   - Multiple recipients
   - International support
   - Delivery confirmation

5. **Custom Webhooks**
   - JSON payload delivery
   - Configurable HTTP methods
   - Custom headers
   - Retry logic

### Key Capabilities

- **Multi-Channel Delivery**: Send alerts to multiple channels simultaneously
- **Template System**: Customizable message templates for each channel
- **Rate Limiting**: Prevent notification spam with configurable limits
- **Channel Management**: Enable/disable channels dynamically
- **History Tracking**: Complete audit trail of all notifications
- **Test Functionality**: Verify channel configurations
- **Severity Filtering**: Route alerts based on severity levels
- **Category Filtering**: Include/exclude specific alert categories

## API Endpoints

### Channel Management

#### Get All Channels
```http
GET /api/v1/notifications/channels
```

Query Parameters:
- `enabled_only` (boolean): Filter to enabled channels only
- `channel_type` (string): Filter by channel type

#### Create Channel
```http
POST /api/v1/notifications/channels
```

Request Body:
```json
{
  "name": "Security Team Email",
  "type": "email",
  "config": {
    "enabled": true,
    "smtp_server": "smtp.company.com",
    "smtp_port": 587,
    "username": "alerts@company.com",
    "password": "secure_password",
    "from_email": "siembox@company.com",
    "to_emails": ["security@company.com", "admin@company.com"],
    "use_tls": true
  },
  "min_severity": "medium",
  "categories": ["brute_force", "malware", "intrusion"],
  "rate_limit_per_hour": 50
}
```

#### Update Channel
```http
PUT /api/v1/notifications/channels/{channel_id}
```

#### Delete Channel
```http
DELETE /api/v1/notifications/channels/{channel_id}
```

### Notification Operations

#### Send Notifications
```http
POST /api/v1/notifications/send
```

Request Body:
```json
{
  "alert_ids": ["uuid1", "uuid2"],
  "channel_ids": ["channel_uuid1", "channel_uuid2"],
  "force_send": false
}
```

#### Test Channel
```http
POST /api/v1/notifications/test
```

Request Body:
```json
{
  "channel_id": "channel_uuid"
}
```

### History and Statistics

#### Get Notification History
```http
GET /api/v1/notifications/history
```

Query Parameters:
- `alert_id` (string): Filter by alert ID
- `channel_id` (string): Filter by channel ID
- `status` (string): Filter by status (sent, failed, pending)
- `hours` (integer): Time window in hours (default: 24)
- `limit` (integer): Maximum results (default: 100)
- `offset` (integer): Pagination offset

#### Get Statistics
```http
GET /api/v1/notifications/stats
```

Response:
```json
{
  "total_sent": 1250,
  "total_failed": 23,
  "success_rate": 98.2,
  "channels": {
    "channel_id": {
      "name": "Security Email",
      "type": "email",
      "enabled": true,
      "sent": 800,
      "failed": 5,
      "success_rate": 99.4
    }
  },
  "recent_activity": [
    {
      "id": "notification_id",
      "alert_id": "alert_id",
      "channel_type": "email",
      "status": "sent",
      "created_at": "2025-01-07T10:30:00Z"
    }
  ]
}
```

## Configuration

### Environment Variables

```bash
# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
EMAIL_FROM=siembox@yourdomain.com

# Discord Configuration
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-url

# Slack Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your-webhook-url
SLACK_TOKEN=xoxb-your-slack-bot-token

# SMS Configuration (Twilio)
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_FROM_NUMBER=+1234567890

# Webhook Configuration
WEBHOOK_TIMEOUT=30
WEBHOOK_RETRY_ATTEMPTS=3

# Rate Limiting
NOTIFICATION_RATE_LIMIT_PER_HOUR=100
NOTIFICATION_BATCH_SIZE=10
```

### Channel Configuration Examples

#### Email Channel
```json
{
  "enabled": true,
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "username": "alerts@company.com",
  "password": "app_password",
  "from_email": "siembox@company.com",
  "to_emails": ["security@company.com"],
  "use_tls": true
}
```

#### Discord Channel
```json
{
  "enabled": true,
  "webhook_url": "https://discord.com/api/webhooks/123/abc",
  "username": "SIEM BOX",
  "avatar_url": "https://company.com/logo.png"
}
```

#### Slack Channel
```json
{
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/T00/B00/XXX",
  "channel": "#security-alerts",
  "username": "SIEM BOX",
  "icon_emoji": ":warning:"
}
```

#### SMS Channel
```json
{
  "enabled": true,
  "provider": "twilio",
  "twilio": {
    "account_sid": "AC123...",
    "auth_token": "auth_token",
    "from_number": "+1234567890",
    "to_numbers": ["+0987654321", "+1122334455"]
  }
}
```

#### Webhook Channel
```json
{
  "enabled": true,
  "webhook_url": "https://api.company.com/alerts",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token123"
  },
  "timeout": 30
}
```

## Message Templates

### Template Variables

The following variables are available in all templates:

- `{{alert.id}}` - Alert unique identifier
- `{{alert.title}}` - Alert title
- `{{alert.description}}` - Alert description
- `{{alert.severity}}` - Alert severity (low, medium, high, critical)
- `{{alert.category}}` - Alert category
- `{{alert.timestamp}}` - Alert timestamp
- `{{alert.source_ip}}` - Source IP address
- `{{alert.destination_ip}}` - Destination IP address
- `{{alert.hostname}}` - Source hostname
- `{{alert.rule_name}}` - Detection rule name
- `{{alert.raw_log}}` - Original log entry

### Default Templates

#### Email Template
```html
<h2>🚨 SIEM BOX Security Alert</h2>
<table>
  <tr><td><strong>Severity:</strong></td><td>{{alert.severity}}</td></tr>
  <tr><td><strong>Title:</strong></td><td>{{alert.title}}</td></tr>
  <tr><td><strong>Description:</strong></td><td>{{alert.description}}</td></tr>
  <tr><td><strong>Time:</strong></td><td>{{alert.timestamp}}</td></tr>
  <tr><td><strong>Source:</strong></td><td>{{alert.source_ip}}</td></tr>
  <tr><td><strong>Rule:</strong></td><td>{{alert.rule_name}}</td></tr>
</table>
<hr>
<p><strong>Raw Log:</strong></p>
<pre>{{alert.raw_log}}</pre>
```

#### Discord Template
```markdown
🚨 **SIEM Alert**
**Severity:** {{alert.severity}}
**Title:** {{alert.title}}
**Description:** {{alert.description}}
**Time:** {{alert.timestamp}}
**Source:** {{alert.source_ip}}
**Rule:** {{alert.rule_name}}
```

## Database Schema

### notification_channels
```sql
CREATE TABLE notification_channels (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB NOT NULL,
    min_severity VARCHAR(20) DEFAULT 'low',
    categories TEXT[],
    exclude_categories TEXT[],
    rate_limit_per_hour INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### notification_history
```sql
CREATE TABLE notification_history (
    id UUID PRIMARY KEY,
    alert_id UUID NOT NULL,
    channel_id UUID,
    channel_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    message TEXT,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE SET NULL
);
```

### notification_templates
```sql
CREATE TABLE notification_templates (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(50) NOT NULL,
    subject_template TEXT,
    body_template TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, channel_type)
);
```

## Integration

### Automatic Notifications

The notification service is automatically integrated with the detection engine. When new alerts are created:

1. The detection service creates alert records
2. Background task initiates notification sending
3. Notifications are sent to all enabled channels
4. Delivery status is tracked in notification_history
5. Failed notifications are logged for retry

### Manual Notifications

Administrators can manually trigger notifications through:

1. **API Endpoints**: Send notifications for specific alerts
2. **Admin Interface**: Web-based notification management
3. **CLI Tools**: Command-line notification utilities

## Monitoring and Troubleshooting

### Health Checks

Monitor notification service health through:

```http
GET /api/v1/notifications/config
```

This endpoint returns:
- Channel configuration status
- Recent notification statistics
- Service health indicators

### Common Issues

#### Email Notifications Not Working
1. Verify SMTP credentials
2. Check firewall/network connectivity
3. Ensure TLS/SSL settings match server requirements
4. Test with notification test endpoint

#### Discord/Slack Webhooks Failing
1. Verify webhook URL is correct
2. Check webhook permissions
3. Ensure JSON payload format is valid
4. Monitor rate limits

#### SMS Notifications Not Sending
1. Verify Twilio credentials
2. Check phone number formats
3. Ensure sufficient Twilio balance
4. Verify sender number is registered

### Logging

Notification service logs are available at:
- Application logs: `/var/log/siembox/notifications.log`
- Error logs: `/var/log/siembox/notification-errors.log`

Log levels:
- `INFO`: Successful notifications
- `WARNING`: Rate limiting, retries
- `ERROR`: Failed notifications, configuration issues

## Security Considerations

### Credential Management
- Store sensitive credentials in environment variables
- Use application-specific passwords for email
- Rotate API tokens regularly
- Implement least-privilege access

### Data Protection
- Notification content may contain sensitive information
- Ensure secure transmission (TLS/HTTPS)
- Consider data retention policies
- Implement access controls

### Rate Limiting
- Configure appropriate rate limits
- Monitor for notification abuse
- Implement circuit breakers for failing channels
- Use exponential backoff for retries

## Performance Optimization

### Batch Processing
- Group notifications by channel type
- Process notifications asynchronously
- Implement queue-based delivery
- Use connection pooling

### Caching
- Cache channel configurations
- Reuse SMTP connections
- Cache template compilations
- Implement configuration hot-reloading

### Monitoring
- Track notification delivery times
- Monitor channel success rates
- Alert on high failure rates
- Implement performance metrics

## Future Enhancements

### Planned Features
- Microsoft Teams integration
- PagerDuty integration
- Custom notification plugins
- Advanced template engine
- Notification scheduling
- Escalation policies
- Mobile push notifications
- Voice call notifications

### API Improvements
- GraphQL support
- Webhook subscriptions
- Real-time notification status
- Bulk operations
- Advanced filtering