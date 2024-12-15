from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean
from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional, Dict, Any
from database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    message = Column(String)
    level = Column(String, index=True)
    log_metadata = Column(JSON, default=dict)

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    message: str
    level: str
    log_metadata: dict = Field(default_factory=dict)

    class Config:
        from_attributes = True

class PaginatedLogsResponse(BaseModel):
    logs: List[LogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool

    class Config:
        from_attributes = True

class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)  # Changed from name to title
    description = Column(String)
    category = Column(String, index=True)
    enabled = Column(Boolean, default=False)
    severity = Column(String)
    rule_content = Column(JSON)

class RuleResponse(BaseModel):
    id: int
    title: str  # Changed from name to title
    description: str
    category: str
    enabled: bool
    severity: str
    rule_content: Dict

    class Config:
        from_attributes = True

class RulesListResponse(BaseModel):
    rules: List[RuleResponse]
    total: int

class APIKeys(BaseModel):
    IPAPI_KEY: str = ""
    CROWDSEC_API_KEY: str = ""

class APIKeyResponse(BaseModel):
    IPAPI_KEY: str
    CROWDSEC_API_KEY: str
    crowdsec_validation: Optional[Dict[str, Any]] = None