"""
SIEM BOX - Notification Schemas
"""
from pydantic import BaseModel, Field, ConfigDict, validator
from typing import Optional, Dict, Any, List, Union
from datetime import datetime
from uuid import UUID
from enum import Enum


class NotificationChannelType(str, Enum):
    """Supported notification channel types"""
    EMAIL = "email"
    DISCORD = "discord"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"


class NotificationStatus(str, Enum):
    """Notification delivery status"""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    RETRYING = "retrying"


class SeverityLevel(str, Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Configuration Schemas
class EmailConfig(BaseModel):
    """Email notification configuration"""
    enabled: bool = Field(default=False, description="Enable email notifications")
    smtp_server: str = Field(..., description="SMTP server hostname")
    smtp_port: int = Field(default=587, description="SMTP server port")
    use_tls: bool = Field(default=True, description="Use TLS encryption")
    username: str = Field(..., description="SMTP username")
    password: str = Field(..., description="SMTP password")
    from_email: str = Field(..., description="From email address")
    to_emails: List[str] = Field(..., description="List of recipient email addresses")
    
    @validator('smtp_port')
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v
    
    @validator('to_emails')
    def validate_emails(cls, v):
        if not v:
            raise ValueError('At least one recipient email is required')
        return v


class DiscordConfig(BaseModel):
    """Discord notification configuration"""
    enabled: bool = Field(default=False, description="Enable Discord notifications")
    webhook_url: str = Field(..., description="Discord webhook URL")
    username: str = Field(default="SIEM BOX", description="Bot username")
    avatar_url: Optional[str] = Field(None, description="Bot avatar URL")
    mention_roles: Dict[str, str] = Field(default_factory=dict, description="Role mentions by severity")


class SlackConfig(BaseModel):
    """Slack notification configuration"""
    enabled: bool = Field(default=False, description="Enable Slack notifications")
    webhook_url: str = Field(..., description="Slack webhook URL")
    channel: str = Field(..., description="Slack channel")
    username: str = Field(default="SIEM BOX", description="Bot username")
    icon_emoji: str = Field(default=":warning:", description="Bot icon emoji")


class WebhookConfig(BaseModel):
    """Generic webhook notification configuration"""
    enabled: bool = Field(default=False, description="Enable webhook notifications")
    webhook_url: str = Field(..., description="Webhook URL")
    method: str = Field(default="POST", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")


class SMSConfig(BaseModel):
    """SMS notification configuration"""
    enabled: bool = Field(default=False, description="Enable SMS notifications")
    provider: str = Field(default="twilio", description="SMS provider")
    account_sid: str = Field(..., description="Twilio Account SID")
    auth_token: str = Field(..., description="Twilio Auth Token")
    from_number: str = Field(..., description="From phone number")
    to_numbers: List[str] = Field(..., description="List of recipient phone numbers")


class NotificationChannelConfig(BaseModel):
    """Unified notification channel configuration"""
    type: NotificationChannelType = Field(..., description="Notification channel type")
    name: str = Field(..., description="Configuration name")
    email: Optional[EmailConfig] = None
    discord: Optional[DiscordConfig] = None
    slack: Optional[SlackConfig] = None
    webhook: Optional[WebhookConfig] = None
    sms: Optional[SMSConfig] = None
    
    # Filtering options
    min_severity: SeverityLevel = Field(default=SeverityLevel.LOW, description="Minimum severity level")
    categories: List[str] = Field(default_factory=list, description="Alert categories to include")
    exclude_categories: List[str] = Field(default_factory=list, description="Alert categories to exclude")
    rate_limit_per_hour: Optional[int] = Field(None, description="Maximum notifications per hour")


# Request/Response Schemas
class NotificationChannelCreate(BaseModel):
    """Schema for creating notification channels"""
    type: NotificationChannelType
    name: str
    config: Dict[str, Any]
    min_severity: SeverityLevel = SeverityLevel.LOW
    categories: List[str] = Field(default_factory=list)
    exclude_categories: List[str] = Field(default_factory=list)
    rate_limit_per_hour: Optional[int] = None


class NotificationChannelUpdate(BaseModel):
    """Schema for updating notification channels"""
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    min_severity: Optional[SeverityLevel] = None
    categories: Optional[List[str]] = None
    exclude_categories: Optional[List[str]] = None
    rate_limit_per_hour: Optional[int] = None
    enabled: Optional[bool] = None


class NotificationChannelResponse(BaseModel):
    """Schema for notification channel responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    type: NotificationChannelType
    name: str
    enabled: bool
    config: Dict[str, Any]
    min_severity: SeverityLevel
    categories: List[str]
    exclude_categories: List[str]
    rate_limit_per_hour: Optional[int]
    created_at: datetime
    updated_at: datetime


class NotificationHistoryResponse(BaseModel):
    """Schema for notification history responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    alert_id: UUID
    channel_id: UUID
    channel_type: NotificationChannelType
    status: NotificationStatus
    sent_at: Optional[datetime]
    error_message: Optional[str]
    retry_count: int
    created_at: datetime


class SendNotificationRequest(BaseModel):
    """Schema for sending notifications"""
    alert_ids: List[UUID] = Field(..., description="List of alert IDs")
    channel_ids: Optional[List[UUID]] = Field(None, description="Specific channels to use")
    force_send: bool = Field(default=False, description="Bypass rate limiting and filters")


class SendNotificationResponse(BaseModel):
    """Schema for send notification responses"""
    success: bool
    sent_count: int
    failed_count: int
    skipped_count: int
    errors: List[str] = Field(default_factory=list)
    notification_ids: List[UUID] = Field(default_factory=list)


class TestNotificationRequest(BaseModel):
    """Schema for testing notifications"""
    channel_id: UUID = Field(..., description="Channel to test")
    test_message: Optional[str] = Field(None, description="Custom test message")


class TestNotificationResponse(BaseModel):
    """Schema for test notification responses"""
    success: bool
    message: str
    error: Optional[str] = None
    sent_at: Optional[datetime] = None


class NotificationStatsResponse(BaseModel):
    """Schema for notification statistics"""
    total_sent: int
    total_failed: int
    success_rate: float
    channels: Dict[str, Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]
    rate_limits: Dict[str, Dict[str, Any]]


class NotificationConfigResponse(BaseModel):
    """Schema for notification configuration responses"""
    channels: List[NotificationChannelResponse]
    global_settings: Dict[str, Any]
    health_status: Dict[str, Any]


# Bulk Operations
class BulkNotificationRequest(BaseModel):
    """Schema for bulk notification operations"""
    operation: str = Field(..., description="Operation type: send, test, enable, disable")
    channel_ids: List[UUID] = Field(..., description="Channel IDs to operate on")
    alert_ids: Optional[List[UUID]] = Field(None, description="Alert IDs for send operation")


class BulkNotificationResponse(BaseModel):
    """Schema for bulk notification responses"""
    success: bool
    processed_count: int
    failed_count: int
    results: List[Dict[str, Any]]
    errors: List[str] = Field(default_factory=list)


# Template Schemas
class NotificationTemplate(BaseModel):
    """Schema for notification templates"""
    name: str
    channel_type: NotificationChannelType
    subject_template: Optional[str] = None
    body_template: str
    variables: List[str] = Field(default_factory=list)


class NotificationTemplateCreate(BaseModel):
    """Schema for creating notification templates"""
    name: str
    channel_type: NotificationChannelType
    subject_template: Optional[str] = None
    body_template: str


class NotificationTemplateResponse(NotificationTemplate):
    """Schema for notification template responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    created_at: datetime
    updated_at: datetime