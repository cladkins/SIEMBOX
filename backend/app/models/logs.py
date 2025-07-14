"""
SIEM BOX - Log Database Models
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, text, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID, INET, JSONB
from sqlalchemy import TIMESTAMP, TypeDecorator, String as SQLString
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.database import Base
import uuid


class UUID(TypeDecorator):
    """Platform-independent UUID type.
    Uses PostgreSQL's UUID type when available, otherwise uses String.
    """
    impl = SQLString
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PostgresUUID(as_uuid=True))
        else:
            return dialect.type_descriptor(SQLString(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return uuid.UUID(value)


class INET_TYPE(TypeDecorator):
    """Platform-independent INET type.
    Uses PostgreSQL's INET type when available, otherwise uses String.
    """
    impl = SQLString
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(INET)
        else:
            return dialect.type_descriptor(SQLString(45))  # IPv6 max length


class JSON_TYPE(TypeDecorator):
    """Platform-independent JSON type.
    Uses PostgreSQL's JSONB when available, otherwise uses Text.
    """
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB)
        else:
            return dialect.type_descriptor(Text)


# RawLog model removed - log data now stored in Cribl
# This model is no longer needed in Pattern B architecture


class ParsedLog(Base):
    """
    Parsed log entries with structured data extracted from raw logs
    NOTE: In Pattern B architecture, this model is deprecated as parsing is handled by Cribl
    """
    __tablename__ = "parsed_logs"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # DEPRECATED: Foreign key to raw log (no longer used in Pattern B)
    raw_log_id = Column(UUID(), nullable=True, index=True,
                       comment="DEPRECATED: Raw log ID reference, no longer used in Pattern B architecture")
    
    # Timestamps
    parsed_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True,
                      comment="When the log was parsed")
    
    # Log classification
    log_type = Column(String(50), nullable=True, index=True,
                     comment="Type of log (firewall, auth, web, etc.)")
    severity = Column(String(20), nullable=True, index=True,
                     comment="Log severity level")
    category = Column(String(50), nullable=True, index=True,
                     comment="Log category (security, system, network, etc.)")
    
    # Parsed fields
    parsed_fields = Column(JSON_TYPE(), nullable=True,
                          comment="Structured data extracted from the log")
    
    # Parser information
    parser_name = Column(String(100), nullable=True,
                        comment="Name of the parser used")
    parser_version = Column(String(20), nullable=True,
                           comment="Version of the parser used")
    
    # Relationships
    # raw_log relationship removed - no longer applicable in Pattern B
    alerts = relationship("Alert", back_populates="parsed_log")

    def __repr__(self):
        return f"<ParsedLog(id={self.id}, log_type={self.log_type}, severity={self.severity})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "raw_log_id": str(self.raw_log_id) if self.raw_log_id else None,
            "parsed_at": self.parsed_at.isoformat() if self.parsed_at else None,
            "log_type": self.log_type,
            "severity": self.severity,
            "category": self.category,
            "parsed_fields": self.parsed_fields,
            "parser_name": self.parser_name,
            "parser_version": self.parser_version
        }


class DetectionRule(Base):
    """
    Detection rules for identifying security events and anomalies
    """
    __tablename__ = "detection_rules"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Rule metadata
    name = Column(String(255), nullable=False, index=True,
                 comment="Human-readable rule name")
    description = Column(Text, nullable=True,
                        comment="Detailed description of what the rule detects")
    
    # Rule configuration
    rule_type = Column(String(50), nullable=False, index=True,
                      comment="Type of rule (threshold, pattern, correlation)")
    severity = Column(String(20), nullable=False, index=True,
                     comment="Alert severity for matches")
    category = Column(String(50), nullable=False, index=True,
                     comment="Security category (intrusion, malware, etc.)")
    
    # Rule logic
    conditions = Column(JSON_TYPE(), nullable=False,
                       comment="Rule conditions and logic")
    
    # Rule status
    is_enabled = Column(Boolean, default=True, index=True,
                       comment="Whether the rule is active")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    alerts = relationship("Alert", back_populates="detection_rule")

    def __repr__(self):
        return f"<DetectionRule(id={self.id}, name={self.name}, severity={self.severity})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "category": self.category,
            "conditions": self.conditions,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Alert(Base):
    """
    Security alerts generated by detection rules
    """
    __tablename__ = "alerts"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    parsed_log_id = Column(UUID(), ForeignKey("parsed_logs.id"), nullable=False, index=True)
    detection_rule_id = Column(UUID(), ForeignKey("detection_rules.id"), nullable=False, index=True)
    
    # Alert metadata
    title = Column(String(255), nullable=False,
                  comment="Alert title/summary")
    description = Column(Text, nullable=True,
                        comment="Detailed alert description")
    
    # Alert classification
    severity = Column(String(20), nullable=False, index=True,
                     comment="Alert severity level")
    category = Column(String(50), nullable=False, index=True,
                     comment="Security category")
    
    # Alert status
    status = Column(String(20), nullable=False, default="open", index=True,
                   comment="Alert status (open, investigating, resolved, false_positive)")
    
    # Alert data
    alert_data = Column(JSON_TYPE(), nullable=True,
                       comment="Additional alert context and data")
    
    # Timestamps
    triggered_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True,
                         comment="When the alert was triggered")
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    resolved_at = Column(TIMESTAMP(timezone=True), nullable=True,
                        comment="When the alert was resolved")
    
    # Notification tracking
    notifications_sent = Column(JSON_TYPE(), nullable=True,
                               comment="Track which notifications have been sent")
    
    # Relationships
    parsed_log = relationship("ParsedLog", back_populates="alerts")
    detection_rule = relationship("DetectionRule", back_populates="alerts")

    def __repr__(self):
        return f"<Alert(id={self.id}, title={self.title}, severity={self.severity}, status={self.status})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "parsed_log_id": str(self.parsed_log_id),
            "detection_rule_id": str(self.detection_rule_id),
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "status": self.status,
            "alert_data": self.alert_data,
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notifications_sent": self.notifications_sent
        }


class NotificationChannel(Base):
    """
    Notification channels configuration
    """
    __tablename__ = "notification_channels"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Channel metadata
    name = Column(String(255), nullable=False, index=True,
                 comment="Human-readable channel name")
    type = Column(String(50), nullable=False, index=True,
                 comment="Channel type (email, discord, slack, webhook, sms)")
    enabled = Column(Boolean, default=True, index=True,
                    comment="Whether the channel is active")
    
    # Configuration
    config = Column(JSON_TYPE(), nullable=False,
                   comment="Channel-specific configuration")
    
    # Filtering options
    min_severity = Column(String(20), nullable=False, default="low",
                         comment="Minimum severity level to send")
    categories = Column(JSON_TYPE(), nullable=True,
                       comment="Alert categories to include")
    exclude_categories = Column(JSON_TYPE(), nullable=True,
                               comment="Alert categories to exclude")
    rate_limit_per_hour = Column(Integer, nullable=True,
                                comment="Maximum notifications per hour")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    notification_history = relationship("NotificationHistory", back_populates="channel")

    def __repr__(self):
        return f"<NotificationChannel(id={self.id}, name={self.name}, type={self.type})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "name": self.name,
            "type": self.type,
            "enabled": self.enabled,
            "config": self.config,
            "min_severity": self.min_severity,
            "categories": self.categories,
            "exclude_categories": self.exclude_categories,
            "rate_limit_per_hour": self.rate_limit_per_hour,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class NotificationHistory(Base):
    """
    Notification delivery history and tracking
    """
    __tablename__ = "notification_history"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    alert_id = Column(UUID(), ForeignKey("alerts.id"), nullable=False, index=True)
    channel_id = Column(UUID(), ForeignKey("notification_channels.id"), nullable=False, index=True)
    
    # Notification metadata
    channel_type = Column(String(50), nullable=False, index=True,
                         comment="Type of notification channel")
    status = Column(String(20), nullable=False, default="pending", index=True,
                   comment="Delivery status (pending, sent, failed, retrying)")
    
    # Delivery tracking
    sent_at = Column(TIMESTAMP(timezone=True), nullable=True,
                    comment="When the notification was successfully sent")
    error_message = Column(Text, nullable=True,
                          comment="Error message if delivery failed")
    retry_count = Column(Integer, default=0,
                        comment="Number of retry attempts")
    
    # Notification content
    subject = Column(String(500), nullable=True,
                    comment="Notification subject/title")
    content = Column(Text, nullable=True,
                    comment="Notification content/body")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    alert = relationship("Alert")
    channel = relationship("NotificationChannel", back_populates="notification_history")

    def __repr__(self):
        return f"<NotificationHistory(id={self.id}, alert_id={self.alert_id}, status={self.status})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "alert_id": str(self.alert_id),
            "channel_id": str(self.channel_id),
            "channel_type": self.channel_type,
            "status": self.status,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "subject": self.subject,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class NotificationTemplate(Base):
    """
    Notification templates for different channels and alert types
    """
    __tablename__ = "notification_templates"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Template metadata
    name = Column(String(255), nullable=False, index=True,
                 comment="Template name")
    channel_type = Column(String(50), nullable=False, index=True,
                         comment="Channel type this template is for")
    
    # Template content
    subject_template = Column(Text, nullable=True,
                             comment="Subject/title template with variables")
    body_template = Column(Text, nullable=False,
                          comment="Body template with variables")
    variables = Column(JSON_TYPE(), nullable=True,
                      comment="Available template variables")
    
    # Template settings
    is_default = Column(Boolean, default=False,
                       comment="Whether this is the default template for the channel type")
    enabled = Column(Boolean, default=True,
                    comment="Whether the template is active")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<NotificationTemplate(id={self.id}, name={self.name}, channel_type={self.channel_type})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "name": self.name,
            "channel_type": self.channel_type,
            "subject_template": self.subject_template,
            "body_template": self.body_template,
            "variables": self.variables,
            "is_default": self.is_default,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }