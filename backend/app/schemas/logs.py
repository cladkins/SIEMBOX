"""
SIEM BOX - Log Pydantic Schemas for API Validation
"""
from pydantic import BaseModel, Field, field_validator, validator
from typing import Optional, Dict, Any
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
import uuid
from typing import List, TypeVar, Generic

T = TypeVar('T')

class PaginatedResponse(BaseModel, Generic[T]):
    """
    Generic paginated response schema
    """
    items: List[T]
    total: int
    page: int
    size: int
    pages: int


class LogIngestRequest(BaseModel):
    """
    Schema for log ingestion API requests
    """
    timestamp: datetime = Field(..., description="Original timestamp from the log source")
    source_ip: Optional[str] = Field(None, description="IP address of the log source")
    source_port: Optional[int] = Field(None, ge=1, le=65535, description="Port number of the log source")
    protocol: Optional[str] = Field(None, max_length=10, description="Protocol used (TCP, UDP, etc.)")
    hostname: Optional[str] = Field(None, max_length=255, description="Hostname of the log source")
    app_name: Optional[str] = Field(None, max_length=100, description="Application or service name")
    log_type: Optional[str] = Field(None, max_length=50, description="Type/category of log (auth, firewall, etc.)")
    severity: Optional[str] = Field(None, max_length=20, description="Log severity (info, warn, error, etc.)")
    category: Optional[str] = Field(None, max_length=50, description="High-level category (security, system, etc.)")
    fields: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional structured fields already parsed from the log"
    )
    raw_message: str = Field(..., min_length=1, description="Complete raw log message")
    
    @validator('source_ip')
    def validate_ip_address(cls, v):
        """Validate IP address format"""
        if v is not None:
            try:
                # Try to parse as IPv4 or IPv6
                IPv4Address(v)
            except:
                try:
                    IPv6Address(v)
                except:
                    raise ValueError('Invalid IP address format')
        return v
    
    @validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol format"""
        if v is not None:
            return v.upper()
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T12:00:00Z",
                "source_ip": "192.168.1.100",
                "source_port": 514,
                "protocol": "UDP",
                "hostname": "firewall.local",
                "app_name": "unifi",
                "log_type": "firewall",
                "severity": "medium",
                "category": "network",
                "fields": {
                    "action": "BLOCK",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "192.168.1.100",
                    "rule": "Default deny"
                },
                "raw_message": "Jan 01 12:00:00 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.1 DST=192.168.1.100"
            }
        }


class LogRecordBase(BaseModel):
   """
   Base schema for log records
   """
   timestamp: datetime = Field(..., description="Original timestamp from the log source")
   source_ip: Optional[str] = Field(None, description="IP address of the log source")
   hostname: Optional[str] = Field(None, max_length=255, description="Hostname of the log source")
   raw_message: str = Field(..., min_length=1, description="Complete raw log message")


class LogIngestResponse(BaseModel):
    """
    Schema for log ingestion API responses
    """
    success: bool = Field(..., description="Whether the log was successfully ingested")
    log_id: str = Field(..., description="Unique identifier for the ingested log")
    message: str = Field(..., description="Response message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "log_id": "123e4567-e89b-12d3-a456-426614174000",
                "message": "Log successfully ingested"
            }
        }


class LogResponse(BaseModel):
    """
    Schema for log retrieval API responses (Raw Logs)
    """
    id: str
    timestamp: datetime
    source_ip: Optional[str]
    hostname: Optional[str]
    source_type: Optional[str]  # Derived from app_name or hostname
    raw_message: str
    created_at: datetime  # Maps to received_at

    @field_validator('source_ip', mode='before')
    @classmethod
    def validate_ip_address(cls, v):
        if isinstance(v, (IPv4Address, IPv6Address)):
            return str(v)
        return v
    
    class Config:
        from_attributes = True

class ParsedLogResponse(BaseModel):
    """
    Schema for parsed log responses
    """
    id: str
    raw_log_id: str
    timestamp: datetime
    source_ip: Optional[str]
    source_type: Optional[str]
    log_level: str
    message: str
    parsed_fields: dict
    created_at: datetime
    
    @field_validator('source_ip', mode='before')
    @classmethod
    def validate_ip_address(cls, v):
        if isinstance(v, (IPv4Address, IPv6Address)):
            return str(v)
        return v
    
    class Config:
        from_attributes = True


class HealthCheckResponse(BaseModel):
    """
    Schema for health check responses
    """
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Current timestamp")
    version: str = Field(..., description="Application version")
    database: str = Field(..., description="Database connection status")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-01T12:00:00Z",
                "version": "1.0.0",
                "database": "connected"
            }
        }
