"""
SIEM BOX - Alert Notification Service
"""
import smtplib
import json
import asyncio
import aiohttp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.logs import Alert
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class EmailNotifier:
    """
    Email notification handler
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.smtp_server = config.get("smtp_server", "localhost")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.from_email = config.get("from_email", "siembox@localhost")
        self.to_emails = config.get("to_emails", [])
        self.use_tls = config.get("use_tls", True)
        self.enabled = config.get("enabled", False)
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert notification via email"""
        
        if not self.enabled or not self.to_emails:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ", ".join(self.to_emails)
            msg['Subject'] = f"[SIEM BOX] {alert.severity.upper()} - {alert.title}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                server.send_message(msg)
            
            logger.info(f"Email notification sent for alert {alert.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification for alert {alert.id}: {e}")
            return False
    
    def _create_email_body(self, alert: Alert) -> str:
        """Create HTML email body for alert"""
        
        severity_colors = {
            "low": "#28a745",
            "medium": "#ffc107", 
            "high": "#fd7e14",
            "critical": "#dc3545"
        }
        
        color = severity_colors.get(alert.severity, "#6c757d")
        
        # Extract key information from alert data
        alert_data = alert.alert_data or {}
        source_info = alert_data.get("source_info", {})
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .content {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #333; }}
                .value {{ color: #666; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #999; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚨 SIEM BOX Security Alert</h2>
                <p><strong>Severity:</strong> {alert.severity.upper()}</p>
            </div>
            
            <div class="content">
                <div class="field">
                    <span class="label">Alert Title:</span>
                    <span class="value">{alert.title}</span>
                </div>
                
                <div class="field">
                    <span class="label">Description:</span>
                    <span class="value">{alert.description or 'No description provided'}</span>
                </div>
                
                <div class="field">
                    <span class="label">Category:</span>
                    <span class="value">{alert.category}</span>
                </div>
                
                <div class="field">
                    <span class="label">Triggered At:</span>
                    <span class="value">{alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                </div>
                
                <div class="field">
                    <span class="label">Source Hostname:</span>
                    <span class="value">{source_info.get('hostname', 'Unknown')}</span>
                </div>
                
                <div class="field">
                    <span class="label">Source IP:</span>
                    <span class="value">{source_info.get('src_ip', 'Unknown')}</span>
                </div>
                
                <div class="field">
                    <span class="label">Application:</span>
                    <span class="value">{source_info.get('app_name', 'Unknown')}</span>
                </div>
                
                <div class="field">
                    <span class="label">Alert ID:</span>
                    <span class="value">{alert.id}</span>
                </div>
            </div>
            
            <div class="footer">
                <p>This alert was generated by SIEM BOX. Please investigate and take appropriate action.</p>
                <p>To manage this alert, access your SIEM BOX dashboard.</p>
            </div>
        </body>
        </html>
        """
        
        return html_body


class DiscordNotifier:
    """
    Discord webhook notification handler
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url = config.get("webhook_url", "")
        self.username = config.get("username", "SIEM BOX")
        self.avatar_url = config.get("avatar_url", "")
        self.enabled = config.get("enabled", False)
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert notification via Discord webhook"""
        
        if not self.enabled or not self.webhook_url:
            return False
        
        try:
            # Create Discord embed
            embed = self._create_discord_embed(alert)
            
            payload = {
                "username": self.username,
                "embeds": [embed]
            }
            
            if self.avatar_url:
                payload["avatar_url"] = self.avatar_url
            
            # Send webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 204:
                        logger.info(f"Discord notification sent for alert {alert.id}")
                        return True
                    else:
                        logger.error(f"Discord webhook failed with status {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to send Discord notification for alert {alert.id}: {e}")
            return False
    
    def _create_discord_embed(self, alert: Alert) -> Dict[str, Any]:
        """Create Discord embed for alert"""
        
        severity_colors = {
            "low": 0x28a745,
            "medium": 0xffc107,
            "high": 0xfd7e14, 
            "critical": 0xdc3545
        }
        
        color = severity_colors.get(alert.severity, 0x6c757d)
        
        # Extract key information
        alert_data = alert.alert_data or {}
        source_info = alert_data.get("source_info", {})
        
        embed = {
            "title": f"🚨 {alert.title}",
            "description": alert.description or "Security alert triggered",
            "color": color,
            "timestamp": alert.triggered_at.isoformat(),
            "fields": [
                {
                    "name": "Severity",
                    "value": alert.severity.upper(),
                    "inline": True
                },
                {
                    "name": "Category", 
                    "value": alert.category,
                    "inline": True
                },
                {
                    "name": "Source IP",
                    "value": source_info.get("src_ip", "Unknown"),
                    "inline": True
                },
                {
                    "name": "Hostname",
                    "value": source_info.get("hostname", "Unknown"),
                    "inline": True
                },
                {
                    "name": "Application",
                    "value": source_info.get("app_name", "Unknown"),
                    "inline": True
                },
                {
                    "name": "Alert ID",
                    "value": str(alert.id),
                    "inline": True
                }
            ],
            "footer": {
                "text": "SIEM BOX Security Monitoring"
            }
        }
        
        return embed


class WebhookNotifier:
    """
    Generic webhook notification handler
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url = config.get("webhook_url", "")
        self.headers = config.get("headers", {})
        self.method = config.get("method", "POST")
        self.enabled = config.get("enabled", False)
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert notification via generic webhook"""
        
        if not self.enabled or not self.webhook_url:
            return False
        
        try:
            # Create payload
            payload = {
                "alert_id": str(alert.id),
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "category": alert.category,
                "status": alert.status,
                "triggered_at": alert.triggered_at.isoformat(),
                "alert_data": alert.alert_data
            }
            
            # Send webhook
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    self.method,
                    self.webhook_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if 200 <= response.status < 300:
                        logger.info(f"Webhook notification sent for alert {alert.id}")
                        return True
                    else:
                        logger.error(f"Webhook failed with status {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to send webhook notification for alert {alert.id}: {e}")
            return False


class SlackNotifier:
    """
    Slack webhook notification handler
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url = config.get("webhook_url", "")
        self.channel = config.get("channel", "#security-alerts")
        self.username = config.get("username", "SIEM BOX")
        self.icon_emoji = config.get("icon_emoji", ":warning:")
        self.enabled = config.get("enabled", False)
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert notification via Slack webhook"""
        
        if not self.enabled or not self.webhook_url:
            return False
        
        try:
            # Create Slack message
            payload = self._create_slack_payload(alert)
            
            # Send webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Slack notification sent for alert {alert.id}")
                        return True
                    else:
                        logger.error(f"Slack webhook failed with status {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to send Slack notification for alert {alert.id}: {e}")
            return False
    
    def _create_slack_payload(self, alert: Alert) -> Dict[str, Any]:
        """Create Slack message payload for alert"""
        
        severity_colors = {
            "low": "#28a745",
            "medium": "#ffc107",
            "high": "#fd7e14",
            "critical": "#dc3545"
        }
        
        color = severity_colors.get(alert.severity, "#6c757d")
        
        # Extract key information
        alert_data = alert.alert_data or {}
        source_info = alert_data.get("source_info", {})
        
        # Create attachment
        attachment = {
            "color": color,
            "title": f"🚨 {alert.title}",
            "text": alert.description or "Security alert triggered",
            "fields": [
                {
                    "title": "Severity",
                    "value": alert.severity.upper(),
                    "short": True
                },
                {
                    "title": "Category",
                    "value": alert.category,
                    "short": True
                },
                {
                    "title": "Source IP",
                    "value": source_info.get("src_ip", "Unknown"),
                    "short": True
                },
                {
                    "title": "Hostname",
                    "value": source_info.get("hostname", "Unknown"),
                    "short": True
                },
                {
                    "title": "Application",
                    "value": source_info.get("app_name", "Unknown"),
                    "short": True
                },
                {
                    "title": "Alert ID",
                    "value": str(alert.id),
                    "short": True
                }
            ],
            "footer": "SIEM BOX Security Monitoring",
            "ts": int(alert.triggered_at.timestamp())
        }
        
        payload = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [attachment]
        }
        
        return payload


class SMSNotifier:
    """
    SMS notification handler using Twilio
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", False)
        self.provider = config.get("provider", "twilio")
        
        # Twilio configuration
        twilio_config = config.get("twilio", {})
        self.account_sid = twilio_config.get("account_sid", "")
        self.auth_token = twilio_config.get("auth_token", "")
        self.from_number = twilio_config.get("from_number", "")
        self.to_numbers = twilio_config.get("to_numbers", [])
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert notification via SMS"""
        
        if not self.enabled or not self.to_numbers:
            return False
        
        if self.provider == "twilio":
            return await self._send_twilio_sms(alert)
        else:
            logger.error(f"Unsupported SMS provider: {self.provider}")
            return False
    
    async def _send_twilio_sms(self, alert: Alert) -> bool:
        """Send SMS via Twilio"""
        
        try:
            # Import Twilio client
            from twilio.rest import Client
            
            client = Client(self.account_sid, self.auth_token)
            
            # Create SMS message
            message_body = self._create_sms_message(alert)
            
            # Send to all recipients
            success_count = 0
            for to_number in self.to_numbers:
                try:
                    message = client.messages.create(
                        body=message_body,
                        from_=self.from_number,
                        to=to_number
                    )
                    logger.info(f"SMS sent to {to_number} for alert {alert.id}: {message.sid}")
                    success_count += 1
                except Exception as e:
                    logger.error(f"Failed to send SMS to {to_number}: {e}")
            
            return success_count > 0
            
        except ImportError:
            logger.error("Twilio library not installed. Install with: pip install twilio")
            return False
        except Exception as e:
            logger.error(f"Failed to send SMS notification for alert {alert.id}: {e}")
            return False
    
    def _create_sms_message(self, alert: Alert) -> str:
        """Create SMS message for alert"""
        
        # Extract key information
        alert_data = alert.alert_data or {}
        source_info = alert_data.get("source_info", {})
        src_ip = source_info.get("src_ip", "Unknown")
        
        # Create concise message (SMS has character limits)
        message = f"🚨 SIEM BOX Alert\n"
        message += f"Severity: {alert.severity.upper()}\n"
        message += f"Title: {alert.title}\n"
        message += f"Source: {src_ip}\n"
        message += f"Time: {alert.triggered_at.strftime('%H:%M:%S')}\n"
        message += f"ID: {str(alert.id)[:8]}"
        
        return message


class NotificationService:
    """
    Main notification service that manages all notification types
    """
    
    def __init__(self):
        self.notifiers = {}
        self.load_default_config()
    
    def load_default_config(self):
        """Load notification configuration from centralized settings"""
        
        # Email configuration from settings
        email_config = {
            "enabled": bool(settings.smtp_server and settings.smtp_username and settings.email_from),
            "smtp_server": settings.smtp_server or "",
            "smtp_port": settings.smtp_port,
            "username": settings.smtp_username or "",
            "password": settings.smtp_password or "",
            "from_email": settings.email_from or "",
            "to_emails": [],  # This should be configured per alert or via additional settings
            "use_tls": settings.smtp_use_tls
        }
        
        # Discord configuration from settings
        discord_config = {
            "enabled": bool(settings.discord_webhook_url),
            "webhook_url": settings.discord_webhook_url or "",
            "username": "SIEM BOX",
            "avatar_url": ""
        }
        
        # Slack configuration from settings
        slack_config = {
            "enabled": bool(settings.slack_webhook_url),
            "webhook_url": settings.slack_webhook_url or "",
            "channel": "#security-alerts",
            "username": "SIEM BOX",
            "icon_emoji": ":warning:"
        }
        
        # Webhook configuration
        webhook_config = {
            "enabled": False,  # No specific webhook settings in config yet
            "webhook_url": "",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json"
            }
        }
        
        # SMS configuration from settings
        sms_config = {
            "enabled": bool(settings.twilio_account_sid and settings.twilio_auth_token),
            "provider": "twilio",
            "twilio": {
                "account_sid": settings.twilio_account_sid or "",
                "auth_token": settings.twilio_auth_token or "",
                "from_number": settings.twilio_from_number or "",
                "to_numbers": []  # This should be configured per alert or via additional settings
            }
        }
        
        self.notifiers = {
            "email": EmailNotifier(email_config),
            "discord": DiscordNotifier(discord_config),
            "slack": SlackNotifier(slack_config),
            "webhook": WebhookNotifier(webhook_config),
            "sms": SMSNotifier(sms_config)
        }
    
    def update_config(self, notification_type: str, config: Dict[str, Any]):
        """Update configuration for a specific notification type"""
        
        if notification_type == "email":
            self.notifiers["email"] = EmailNotifier(config)
        elif notification_type == "discord":
            self.notifiers["discord"] = DiscordNotifier(config)
        elif notification_type == "slack":
            self.notifiers["slack"] = SlackNotifier(config)
        elif notification_type == "webhook":
            self.notifiers["webhook"] = WebhookNotifier(config)
        elif notification_type == "sms":
            self.notifiers["sms"] = SMSNotifier(config)
        else:
            raise ValueError(f"Unknown notification type: {notification_type}")
    
    async def send_alert_notification(self, db: AsyncSession, alert_id: str) -> bool:
        """Send notification for a single alert"""
        try:
            result = await db.execute(select(Alert).filter(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            
            if not alert:
                logger.error(f"Alert {alert_id} not found for notification")
                return False
            
            # Send to all enabled notification types
            sent_count, failed_count, errors = await self.send_notifications(db, [alert_id])
            
            return sent_count > 0
            
        except Exception as e:
            logger.error(f"Error sending alert notification: {e}")
            return False
    
    async def send_notifications(self, db: AsyncSession, alert_ids: List[str],
                               notification_types: Optional[List[str]] = None) -> Tuple[int, int, List[str]]:
        """
        Send notifications for multiple alerts
        
        Returns:
            Tuple of (sent_count, failed_count, errors)
        """
        sent_count = 0
        failed_count = 0
        errors = []
        
        # Get alerts
        query = select(Alert).filter(Alert.id.in_(alert_ids))
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        # Determine which notification types to use
        if notification_types is None:
            notification_types = ["email", "discord", "slack", "webhook", "sms"]
        
        for alert in alerts:
            alert_sent = False
            
            for notif_type in notification_types:
                if notif_type not in self.notifiers:
                    continue
                
                notifier = self.notifiers[notif_type]
                
                try:
                    if notif_type == "email":
                        success = notifier.send_alert(alert)
                    else:
                        success = await notifier.send_alert(alert)
                    
                    if success:
                        alert_sent = True
                        # Update notification tracking
                        if not alert.notifications_sent:
                            alert.notifications_sent = {}
                        alert.notifications_sent[notif_type] = {
                            "sent_at": datetime.utcnow().isoformat(),
                            "status": "success"
                        }
                    else:
                        if not alert.notifications_sent:
                            alert.notifications_sent = {}
                        alert.notifications_sent[notif_type] = {
                            "sent_at": datetime.utcnow().isoformat(),
                            "status": "failed"
                        }
                        
                except Exception as e:
                    logger.error(f"Error sending {notif_type} notification for alert {alert.id}: {e}")
                    errors.append(f"Alert {alert.id} - {notif_type}: {str(e)}")
            
            if alert_sent:
                sent_count += 1
            else:
                failed_count += 1
        
        # Update database
        try:
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"Database error updating notification status: {e}")
            errors.append(f"Database error: {str(e)}")
        
        return sent_count, failed_count, errors
    
    async def get_notification_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get notification statistics"""
        
        # Count alerts with notifications sent
        query = select(func.count(Alert.id)).filter(
            Alert.notifications_sent.isnot(None)
        )
        result = await db.execute(query)
        alerts_with_notifications = result.scalar()
        
        query = select(func.count(Alert.id))
        result = await db.execute(query)
        total_alerts = result.scalar()
        
        # Count by notification type
        notification_counts = {}
        for notif_type in ["email", "discord", "webhook"]:
            query = select(func.count(Alert.id)).filter(
                Alert.notifications_sent[notif_type].isnot(None)
            )
            result = await db.execute(query)
            count = result.scalar()
            notification_counts[notif_type] = count
        
        # Get configuration status
        config_status = {}
        for notif_type, notifier in self.notifiers.items():
            config_status[notif_type] = {
                "enabled": notifier.enabled,
                "configured": self._is_notifier_configured(notifier)
            }
        
        return {
            "total_alerts": total_alerts,
            "alerts_with_notifications": alerts_with_notifications,
            "notification_rate": (alerts_with_notifications / total_alerts * 100) if total_alerts > 0 else 0,
            "notification_counts": notification_counts,
            "configuration_status": config_status
        }
    
    def _is_notifier_configured(self, notifier) -> bool:
        """Check if a notifier is properly configured"""
        
        if isinstance(notifier, EmailNotifier):
            return bool(notifier.smtp_server and notifier.from_email and notifier.to_emails)
        elif isinstance(notifier, DiscordNotifier):
            return bool(notifier.webhook_url)
        elif isinstance(notifier, WebhookNotifier):
            return bool(notifier.webhook_url)
        
        return False
    
    def test_notification(self, notification_type: str) -> bool:
        """Send a test notification"""
        
        if notification_type not in self.notifiers:
            return False
        
        # Create a test alert
        test_alert = Alert(
            id="test-alert-id",
            title="SIEM BOX Test Alert",
            description="This is a test notification to verify your configuration.",
            severity="low",
            category="test",
            status="open",
            triggered_at=datetime.utcnow(),
            alert_data={
                "source_info": {
                    "hostname": "test-host",
                    "src_ip": "192.168.1.100",
                    "app_name": "test-app"
                }
            }
        )
        
        notifier = self.notifiers[notification_type]
        
        try:
            if notification_type == "email":
                return notifier.send_alert(test_alert)
            else:
                # For async notifiers, use asyncio.run for proper async handling
                return asyncio.run(notifier.send_alert(test_alert))
        except Exception as e:
            logger.error(f"Test notification failed for {notification_type}: {e}")
            return False


# Global notification service instance
notification_service = NotificationService()