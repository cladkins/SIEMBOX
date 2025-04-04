from datetime import datetime
import os
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field
import json
from ocsf import schema

# Generate a key if not provided
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"Generated new encryption key: {ENCRYPTION_KEY.decode()}")

# Ensure the key is bytes
if isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

class Setting(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    last_used_at = Column(DateTime, nullable=True)

    def set_value(self, value: str):
        if value:
            self.value = fernet.encrypt(value.encode()).decode()

    def get_value(self) -> Optional[str]:
        if self.value:
            return fernet.decrypt(self.value.encode()).decode()
        return None

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String)
    level = Column(String)
    message = Column(Text)
    processed = Column(Boolean, default=False)
    log_metadata = Column(JSON, default={})
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    alert = relationship("Alert", back_populates="logs")

class InternalLog(Base):  # Renamed from AppLog to InternalLog
    __tablename__ = "internal_logs"  # Changed from app_logs to internal_logs
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    service = Column(String, nullable=False)
    level = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    log_metadata = Column(JSON, default={})
    component = Column(String)
    trace_id = Column(String)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    rule_name = Column(String)
    severity = Column(String)
    description = Column(Text)
    logs = relationship("Log", back_populates="alert")
    ocsf_logs = relationship("OCSFLog", back_populates="alert")

# New request model for creating internal logs
class CreateInternalLogRequest(BaseModel):
    service: str
    level: str
    message: str
    log_metadata: Dict[str, Any] = Field(default_factory=dict)
    component: Optional[str] = None
    trace_id: Optional[str] = None

# Pydantic models for API responses
class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    level: str
    message: str
    processed: bool
    log_metadata: Dict[str, Any] = Field(default_factory=dict)
    alert_id: Optional[int] = None

    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class InternalLogResponse(BaseModel):  # Renamed from AppLogResponse to InternalLogResponse
    id: int
    timestamp: datetime
    service: str
    level: str
    message: str
    log_metadata: Dict[str, Any] = Field(default_factory=dict)
    component: Optional[str] = None
    trace_id: Optional[str] = None

    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class PaginatedLogsResponse(BaseModel):
    logs: List[LogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class PaginatedInternalLogsResponse(BaseModel):  # Renamed from PaginatedAppLogsResponse
    logs: List[InternalLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class OCSFLog(Base):
    __tablename__ = "ocsf_logs"
    id = Column(Integer, primary_key=True)
    
    # OCSF Core Fields (v1.0.0)
    activity_id = Column(Integer)
    activity_name = Column(String)
    category_uid = Column(Integer)
    category_name = Column(String)
    class_uid = Column(Integer)
    class_name = Column(String)
    time = Column(DateTime)
    severity = Column(String)
    severity_id = Column(Integer)
    status = Column(String)
    status_id = Column(Integer)
    message = Column(Text)
    
    # OCSF Observables
    src_endpoint = Column(JSON)  # Source endpoint details
    dst_endpoint = Column(JSON)  # Destination endpoint details
    device = Column(JSON)        # Device information
    
    # Original data
    raw_event = Column(JSON)
    
    # Relationships
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    alert = relationship("Alert", back_populates="ocsf_logs")
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)

class OCSFLogResponse(BaseModel):
    id: int
    time: datetime
    category_name: str
    activity_name: str
    severity: str
    message: str
    src_endpoint: Optional[Dict[str, Any]] = None
    dst_endpoint: Optional[Dict[str, Any]] = None
    raw_event: Dict[str, Any]
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class PaginatedOCSFLogsResponse(BaseModel):
    logs: List[OCSFLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

class Rule(BaseModel):
    id: str
    title: str
    description: str
    level: str
    detection: Dict[str, Any]
    logsource: Dict[str, str]
    enabled: bool = False
    category: str = ""

    class Config:
        orm_mode = True

class RuleResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: str
    enabled: bool
    category: Optional[str] = None

    class Config:
        orm_mode = True

class RulesListResponse(BaseModel):
    rules: List[RuleResponse]
    total: int

class APIKeys(BaseModel):
    IPAPI_KEY: Optional[str] = None
    CROWDSEC_API_KEY: Optional[str] = None

class APIKeyResponse(BaseModel):
    IPAPI_KEY: Optional[str] = None
    CROWDSEC_API_KEY: Optional[str] = None
    crowdsec_validation: Optional[Dict[str, Any]] = None

    @classmethod
    def from_settings(cls, settings: List[Setting]) -> 'APIKeyResponse':
        response = cls()
        for setting in settings:
            if setting.key == "IPAPI_KEY":
                response.IPAPI_KEY = "********" if setting.value else None
            elif setting.key == "CROWDSEC_API_KEY":
                response.CROWDSEC_API_KEY = "********" if setting.value else None
        return response