from datetime import datetime
import os
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base
from cryptography.fernet import Fernet
from pydantic import BaseModel

# Generate a key if not provided
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"Generated new encryption key: {ENCRYPTION_KEY.decode()}")

# Ensure the key is bytes
if isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

class Settings(Base):
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

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    rule_name = Column(String)
    severity = Column(String)
    description = Column(Text)
    logs = relationship("Log", back_populates="alert")

# Pydantic models for API responses
class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    level: str
    message: str
    processed: bool
    log_metadata: Dict[str, Any] = {}
    alert_id: Optional[int] = None

    class Config:
        orm_mode = True

class PaginatedLogsResponse(BaseModel):
    logs: List[LogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool

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
    def from_settings(cls, settings: List[Settings]) -> 'APIKeyResponse':
        response = cls()
        for setting in settings:
            if setting.key == "IPAPI_KEY":
                response.IPAPI_KEY = "********" if setting.value else None
            elif setting.key == "CROWDSEC_API_KEY":
                response.CROWDSEC_API_KEY = "********" if setting.value else None
        return response