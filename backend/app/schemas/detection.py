"""
SIEM BOX - Detection Pydantic Schemas for API Validation
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Alert severity levels"""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RuleType(str, Enum):
    """Detection rule types"""
    threshold = "threshold"
    pattern = "pattern"
    correlation = "correlation"
    anomaly = "anomaly"


class AlertStatus(str, Enum):
    """Alert status values"""
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


class DetectionRuleBase(BaseModel):
    """Base schema for detection rules"""
    name: str = Field(..., min_length=1, max_length=255, description="Rule name")
    description: Optional[str] = Field(None, max_length=1000, description="Rule description")
    rule_type: RuleType = Field(..., description="Type of detection rule")
    severity: SeverityLevel = Field(..., description="Alert severity level")
    category: str = Field(..., min_length=1, max_length=100, description="Rule category")
    conditions: Dict[str, Any] = Field(..., description="Rule conditions and parameters")
    is_enabled: bool = Field(True, description="Whether the rule is enabled")


class DetectionRuleCreate(DetectionRuleBase):
    """Schema for creating detection rules"""
    pass


class DetectionRuleUpdate(BaseModel):
    """Schema for updating detection rules"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    rule_type: Optional[RuleType] = None
    severity: Optional[SeverityLevel] = None
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    conditions: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class DetectionRuleResponse(DetectionRuleBase):
    """Schema for detection rule responses"""
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class AlertBase(BaseModel):
    """Base schema for alerts"""
    title: str = Field(..., min_length=1, max_length=255, description="Alert title")
    description: str = Field(..., min_length=1, max_length=1000, description="Alert description")
    severity: SeverityLevel = Field(..., description="Alert severity level")
    category: str = Field(..., min_length=1, max_length=100, description="Alert category")
    status: AlertStatus = Field(AlertStatus.open, description="Alert status")
    alert_data: Dict[str, Any] = Field(default_factory=dict, description="Additional alert data")


class AlertCreate(AlertBase):
    """Schema for creating alerts"""
    parsed_log_id: str = Field(..., description="ID of the parsed log that triggered the alert")
    detection_rule_id: str = Field(..., description="ID of the detection rule that created the alert")


class AlertUpdate(BaseModel):
    """Schema for updating alerts"""
    status: Optional[AlertStatus] = None
    notes: Optional[str] = Field(None, max_length=1000, description="Alert notes")


class AlertResponse(AlertBase):
    """Schema for alert responses"""
    id: str
    parsed_log_id: str
    detection_rule_id: str
    triggered_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    notes: Optional[str] = None
    
    class Config:
        from_attributes = True


class DetectionRequest(BaseModel):
    """Schema for detection execution requests"""
    parsed_log_ids: List[str] = Field(..., min_items=1, description="List of parsed log IDs to analyze")
    rule_ids: Optional[List[str]] = Field(None, description="Optional list of specific rule IDs to apply")


class DetectionResponse(BaseModel):
    """Schema for detection execution responses"""
    success: bool = Field(..., description="Whether detection completed successfully")
    alerts_generated: int = Field(..., ge=0, description="Number of alerts generated")
    rules_applied: int = Field(..., ge=0, description="Number of rules applied")
    errors: List[str] = Field(default_factory=list, description="List of errors encountered")


class DetectionStatsResponse(BaseModel):
    """Schema for detection statistics"""
    rules: Dict[str, int] = Field(..., description="Rule statistics")
    alerts: Dict[str, int] = Field(..., description="Alert statistics")
    severity_distribution: Dict[str, int] = Field(..., description="Alert severity distribution")
    category_distribution: Dict[str, int] = Field(..., description="Alert category distribution")


class AlertQueryParams(BaseModel):
    """Schema for alert query parameters"""
    status: Optional[AlertStatus] = None
    severity: Optional[SeverityLevel] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of results")
    offset: int = Field(0, ge=0, description="Number of results to skip")


class RuleQueryParams(BaseModel):
    """Schema for rule query parameters"""
    enabled_only: bool = Field(False, description="Only return enabled rules")
    rule_type: Optional[RuleType] = None
    severity: Optional[SeverityLevel] = None
    category: Optional[str] = None