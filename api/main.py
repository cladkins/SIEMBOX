from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from typing import Dict, List
from datetime import datetime
import aiohttp
from fastapi.responses import JSONResponse

app = FastAPI(title="SIEMBox API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
SQLALCHEMY_DATABASE_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@db/siembox"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class APIKey(Base):
    __tablename__ = "api_keys"

    key_name = Column(String, primary_key=True)
    key_value = Column(String)

class Log(Base):
    __tablename__ = "logs"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String)
    type = Column(String)
    message = Column(Text)
    raw_data = Column(JSON)

class Detection(Base):
    __tablename__ = "detections"

    id = Column(String, primary_key=True)
    rule_id = Column(String)
    rule_name = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_source = Column(String)
    severity = Column(String)
    matched_log = Column(JSON)

# Create tables
Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Schemas
class APIKeys(BaseModel):
    IPAPI_KEY: str
    CROWDSEC_API_KEY: str

class LogBase(BaseModel):
    source: str
    type: str
    message: str
    raw_data: Dict

class LogCreate(LogBase):
    pass

class LogResponse(LogBase):
    id: str
    timestamp: datetime

    class Config:
        from_attributes = True

class DetectionBase(BaseModel):
    rule_id: str
    rule_name: str
    log_source: str
    severity: str
    matched_log: Dict

class DetectionCreate(DetectionBase):
    pass

class DetectionResponse(DetectionBase):
    id: str
    timestamp: datetime

    class Config:
        from_attributes = True

class RuleState(BaseModel):
    rule_id: str
    enabled: bool
    category: str = ""

# Routes for rule management
@app.get("/api/rules")
async def get_rules(page: int = 1, page_size: int = 100):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://detection:8000/rules?page={page}&page_size={page_size}') as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise HTTPException(
                        status_code=response.status,
                        detail=f"Failed to fetch rules from detection service: {response.status}"
                    )
    except aiohttp.ClientError as e:
        raise HTTPException(status_code=500, detail=f"Error connecting to detection service: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching rules: {e}")

@app.post("/api/rules/toggle")
async def toggle_rule(rule_state: RuleState):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post('http://detection:8000/rules/toggle', json=rule_state.dict()) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise HTTPException(
                        status_code=response.status,
                        detail="Failed to toggle rule in detection service"
                    )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Routes
@app.get("/api/settings/api-keys")
async def get_api_keys(db: Session = Depends(get_db)):
    """Get stored API keys"""
    try:
        keys = {}
        for key in db.query(APIKey).all():
            keys[key.key_name] = key.key_value
        return {
            "IPAPI_KEY": keys.get("IPAPI_KEY", ""),
            "CROWDSEC_API_KEY": keys.get("CROWDSEC_API_KEY", "")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/settings/api-keys")
async def update_api_keys(api_keys: APIKeys, db: Session = Depends(get_db)):
    """Update API keys"""
    try:
        # Update IPAPI key
        ipapi_key = db.query(APIKey).filter(APIKey.key_name == "IPAPI_KEY").first()
        if ipapi_key:
            ipapi_key.key_value = api_keys.IPAPI_KEY
        else:
            db.add(APIKey(key_name="IPAPI_KEY", key_value=api_keys.IPAPI_KEY))

        # Update CrowdSec key
        crowdsec_key = db.query(APIKey).filter(APIKey.key_name == "CROWDSEC_API_KEY").first()
        if crowdsec_key:
            crowdsec_key.key_value = api_keys.CROWDSEC_API_KEY
        else:
            db.add(APIKey(key_name="CROWDSEC_API_KEY", key_value=api_keys.CROWDSEC_API_KEY))

        db.commit()
        return {"message": "API keys updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs", response_model=List[LogResponse])
async def get_logs(db: Session = Depends(get_db)):
    """Get all logs"""
    try:
        logs = db.query(Log).order_by(Log.timestamp.desc()).limit(1000).all()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logs", response_model=LogResponse)
async def create_log(log: LogCreate, db: Session = Depends(get_db)):
    """Create a new log entry"""
    try:
        from uuid import uuid4
        db_log = Log(
            id=str(uuid4()),
            source=log.source,
            type=log.type,
            message=log.message,
            raw_data=log.raw_data
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/detections", response_model=List[DetectionResponse])
async def get_detections(db: Session = Depends(get_db)):
    """Get all detections"""
    try:
        detections = db.query(Detection).order_by(Detection.timestamp.desc()).limit(1000).all()
        return detections
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detections", response_model=DetectionResponse)
async def create_detection(detection: DetectionCreate, db: Session = Depends(get_db)):
    """Create a new detection"""
    try:
        from uuid import uuid4
        db_detection = Detection(
            id=str(uuid4()),
            rule_id=detection.rule_id,
            rule_name=detection.rule_name,
            log_source=detection.log_source,
            severity=detection.severity,
            matched_log=detection.matched_log
        )
        db.add(db_detection)
        db.commit()
        db.refresh(db_detection)
        return db_detection
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
