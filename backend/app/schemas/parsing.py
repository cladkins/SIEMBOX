"""
SIEM BOX - Parsing and Detection Schemas
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime
from uuid import UUID


# Parsed Log Schemas
class ParsedLogBase(BaseModel):
    """Base schema for parsed logs"""
    log_type: Optional[str] = Field(None, description="Type of log (firewall, auth, web, etc.)")
    severity: Optional[str] = Field(None, description="Log severity level")
    category: Optional[str] = Field(None, description="Log category (security, system, network, etc.)")
    parsed_fields: Optional[Dict[str, Any]] = Field(None, description="Structured data extracted from the log")
    parser_name: Optional[str] = Field(None, description="Name of the parser used")
    parser_version: Optional[str] = Field(None, description="Version of the parser used")


class ParsedLogCreate(ParsedLogBase):
    """Schema for creating parsed logs"""
    raw_log_id: UUID = Field(..., description="ID of the associated raw log")


class ParsedLogResponse(ParsedLogBase):
    """Schema for parsed log responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    raw_log_id: UUID
    parsed_at: datetime


# Detection Rule Schemas
class DetectionRuleBase(BaseModel):
    """Base schema for detection rules"""
    name: str = Field(..., description="Human-readable rule name")
    description: Optional[str] = Field(None, description="Detailed description of what the rule detects")
    rule_type: str = Field(..., description="Type of rule (threshold, pattern, correlation)")
    severity: str = Field(..., description="Alert severity for matches")
    category: str = Field(..., description="Security category (intrusion, malware, etc.)")
    conditions: Dict[str, Any] = Field(..., description="Rule conditions and logic")
    is_enabled: bool = Field(True, description="Whether the rule is active")


class DetectionRuleCreate(DetectionRuleBase):
    """Schema for creating detection rules"""
    pass


class DetectionRuleUpdate(BaseModel):
    """Schema for updating detection rules"""
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class DetectionRuleResponse(DetectionRuleBase):
    """Schema for detection rule responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    created_at: datetime
    updated_at: datetime


# Alert Schemas
class AlertBase(BaseModel):
    """Base schema for alerts"""
    title: str = Field(..., description="Alert title/summary")
    description: Optional[str] = Field(None, description="Detailed alert description")
    severity: str = Field(..., description="Alert severity level")
    category: str = Field(..., description="Security category")
    status: str = Field("open", description="Alert status")
    alert_data: Optional[Dict[str, Any]] = Field(None, description="Additional alert context and data")


class AlertCreate(AlertBase):
    """Schema for creating alerts"""
    parsed_log_id: UUID = Field(..., description="ID of the associated parsed log")
    detection_rule_id: UUID = Field(..., description="ID of the detection rule that triggered this alert")


class AlertUpdate(BaseModel):
    """Schema for updating alerts"""
    status: Optional[str] = None
    description: Optional[str] = None
    alert_data: Optional[Dict[str, Any]] = None


class AlertResponse(AlertBase):
    """Schema for alert responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    parsed_log_id: UUID
    detection_rule_id: UUID
    triggered_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    notifications_sent: Optional[Dict[str, Any]] = None


# Parser Configuration Schemas
class ParserConfig(BaseModel):
    """Schema for parser configuration"""
    name: str = Field(..., description="Parser name")
    version: str = Field(..., description="Parser version")
    log_type: str = Field(..., description="Type of logs this parser handles")
    patterns: List[Dict[str, Any]] = Field(..., description="Regex patterns and field mappings")
    severity_mapping: Optional[Dict[str, str]] = Field(None, description="Mapping of log levels to severity")
    category: str = Field(..., description="Log category")
    enabled: bool = Field(True, description="Whether the parser is enabled")


class ParseRequest(BaseModel):
    """Schema for parsing requests"""
    raw_log_ids: List[UUID] = Field(..., description="List of raw log IDs to parse")
    parser_name: Optional[str] = Field(None, description="Specific parser to use (optional)")


class ParseResponse(BaseModel):
    """Schema for parsing responses"""
    success: bool = Field(..., description="Whether parsing was successful")
    parsed_count: int = Field(..., description="Number of logs successfully parsed")
    failed_count: int = Field(..., description="Number of logs that failed to parse")
    errors: List[str] = Field(default_factory=list, description="List of parsing errors")


# Detection Engine Schemas
class DetectionRequest(BaseModel):
    """Schema for detection requests"""
    parsed_log_ids: List[UUID] = Field(..., description="List of parsed log IDs to analyze")
    rule_ids: Optional[List[UUID]] = Field(None, description="Specific rules to apply (optional)")


class DetectionResponse(BaseModel):
    """Schema for detection responses"""
    success: bool = Field(..., description="Whether detection was successful")
    alerts_generated: int = Field(..., description="Number of alerts generated")
    rules_applied: int = Field(..., description="Number of rules applied")
    errors: List[str] = Field(default_factory=list, description="List of detection errors")


# Notification Schemas
class NotificationConfig(BaseModel):
    """Schema for notification configuration"""
    type: str = Field(..., description="Notification type (email, discord, webhook)")
    enabled: bool = Field(True, description="Whether notifications are enabled")
    config: Dict[str, Any] = Field(..., description="Notification-specific configuration")


class NotificationRequest(BaseModel):
    """Schema for notification requests"""
    alert_ids: List[UUID] = Field(..., description="List of alert IDs to send notifications for")
    notification_types: Optional[List[str]] = Field(None, description="Specific notification types to send")


class NotificationResponse(BaseModel):
    """Schema for notification responses"""
    success: bool = Field(..., description="Whether notifications were sent successfully")
    sent_count: int = Field(..., description="Number of notifications sent")
    failed_count: int = Field(..., description="Number of notifications that failed")
    errors: List[str] = Field(default_factory=list, description="List of notification errors")