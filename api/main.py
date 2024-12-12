from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, JSON, Text, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from typing import Dict, List, Optional
from datetime import datetime
import aiohttp
from fastapi.responses import JSONResponse
import logging
import time
import psutil
from tenacity import retry, stop_after_attempt, wait_exponential
import asyncio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="SIEMBox API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "http://collector:8000",
        "http://192.168.1.45:3000",
        "http://192.168.1.45:8000",
        "http://192.168.1.45:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Default stats for services when they're unavailable
default_collector_stats = {
    "total_logs": 0,
    "logs_per_minute": 0,
    "active_connections": 0,
    "last_log_received": None,
    "status": "degraded"
}

default_detection_stats = {
    "enabled_rules": 0,
    "total_rules": 0,
    "alerts_last_24h": 0,
    "processing_rate": 0,
    "status": "degraded"
}

default_iplookup_stats = {
    "lookup_count": 0,
    "cache_hit_rate": 0,
    "threat_detections": 0,
    "api_quota_remaining": 0,
    "status": "degraded"
}

# Global stats tracking
stats = {
    "start_time": time.time(),
    "status": "operational",
    "services": {
        "collector": {"status": "unknown", "last_check": None},
        "detection": {"status": "unknown", "last_check": None},
        "iplookup": {"status": "unknown", "last_check": None},
        "database": {"status": "unknown", "last_check": None}
    }
}

# Database configuration with retry logic
def create_db_engine(max_retries=5, retry_interval=5):
    """Create database engine with retry logic"""
    for attempt in range(max_retries):
        try:
            SQLALCHEMY_DATABASE_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@db/siembox"
            engine = create_engine(
                SQLALCHEMY_DATABASE_URL,
                pool_pre_ping=True,  # Enable connection health checks
                pool_recycle=300     # Recycle connections every 5 minutes
            )
            # Test the connection
            with engine.connect() as conn:
                conn.execute(select(1))
            stats["services"]["database"]["status"] = "operational"
            stats["services"]["database"]["last_check"] = datetime.now().isoformat()
            return engine
        except Exception as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")
                stats["services"]["database"]["status"] = "error"
                stats["services"]["database"]["last_check"] = datetime.now().isoformat()
                raise
            logger.warning(f"Database connection attempt {attempt + 1} failed, retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)

engine = create_db_engine()
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

# Create tables with retry logic
@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=4, max=10))
def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

# Dependency with connection management
def get_db():
    db = SessionLocal()
    try:
        # Test the connection
        db.execute(select(1))
        stats["services"]["database"]["status"] = "operational"
        stats["services"]["database"]["last_check"] = datetime.now().isoformat()
        yield db
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        stats["services"]["database"]["status"] = "error"
        stats["services"]["database"]["last_check"] = datetime.now().isoformat()
        raise HTTPException(status_code=500, detail="Database connection error")
    finally:
        db.close()

async def get_crowdsec_key(db: Session = Depends(get_db)) -> str:
    """Get CrowdSec API key from database."""
    try:
        key = db.query(APIKey).filter(APIKey.key_name == "CROWDSEC_API_KEY").first()
        return key.key_value if key else None
    except Exception as e:
        logger.error(f"Error retrieving CrowdSec API key: {e}")
        return None

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

class BulkRuleState(BaseModel):
    enabled: bool
    category: str = ""

async def check_service_health(service_name: str, url: str):
    """Check health of a service."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    stats["services"][service_name]["status"] = "operational"
                else:
                    stats["services"][service_name]["status"] = "degraded"
                stats["services"][service_name]["last_check"] = datetime.now().isoformat()
                return await response.json()
    except Exception as e:
        logger.error(f"Error checking {service_name} health: {e}")
        stats["services"][service_name]["status"] = "error"
        stats["services"][service_name]["last_check"] = datetime.now().isoformat()
        return None

async def get_system_metrics():
    """Get system metrics."""
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "cpu_usage": cpu_usage,
            "memory_usage": memory.percent,
            "disk_usage": disk.percent,
            "memory_available": memory.available,
            "disk_available": disk.free
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return None

# Service Stats Routes
@app.get("/api/collector/stats")
async def get_collector_stats():
    """Get collector service statistics"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://collector:8000/stats') as response:
                if response.status == 200:
                    data = await response.json()
                    stats["services"]["collector"]["status"] = "operational"
                    return data
                else:
                    stats["services"]["collector"]["status"] = "degraded"
                    return default_collector_stats
    except Exception as e:
        logger.error(f"Failed to fetch collector stats: {e}")
        stats["services"]["collector"]["status"] = "degraded"
        return default_collector_stats

@app.get("/api/detection/stats")
async def get_detection_stats():
    """Get detection service statistics"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://detection:8000/stats') as response:
                if response.status == 200:
                    data = await response.json()
                    stats["services"]["detection"]["status"] = "operational"
                    return data
                else:
                    stats["services"]["detection"]["status"] = "degraded"
                    return default_detection_stats
    except Exception as e:
        logger.error(f"Failed to fetch detection stats: {e}")
        stats["services"]["detection"]["status"] = "degraded"
        return default_detection_stats

@app.get("/api/iplookup/stats")
async def get_iplookup_stats(db: Session = Depends(get_db)):
    """Get IP lookup service statistics"""
    try:
        # Get CrowdSec API key from database
        api_key = await get_crowdsec_key(db)
        headers = {"x-api-key": api_key} if api_key else {}
        
        async with aiohttp.ClientSession() as session:
            async with session.get('http://iplookup:8000/stats', headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats["services"]["iplookup"]["status"] = "operational"
                    return data
                else:
                    stats["services"]["iplookup"]["status"] = "degraded"
                    return default_iplookup_stats
    except Exception as e:
        logger.error(f"Failed to fetch IP lookup stats: {e}")
        stats["services"]["iplookup"]["status"] = "degraded"
        return default_iplookup_stats

# IP Lookup Service Proxy Routes
@app.get("/iplookup/validate/crowdsec")
async def proxy_validate_crowdsec(db: Session = Depends(get_db)):
    """Proxy validation request to IP lookup service"""
    try:
        # Get API key from database
        api_key = await get_crowdsec_key(db)
        if not api_key:
            return JSONResponse(
                status_code=200,
                content={"valid": False, "message": "No API key provided"}
            )

        headers = {"x-api-key": api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get('http://iplookup:8000/validate/crowdsec', headers=headers) as response:
                return JSONResponse(
                    status_code=response.status,
                    content=await response.json()
                )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/iplookup/api/status")
async def proxy_iplookup_status(db: Session = Depends(get_db)):
    """Proxy status request to IP lookup service"""
    try:
        # Get API key from database
        api_key = await get_crowdsec_key(db)
        headers = {"x-api-key": api_key} if api_key else {}

        async with aiohttp.ClientSession() as session:
            async with session.get('http://iplookup:8000/api/status', headers=headers) as response:
                return JSONResponse(
                    status_code=response.status,
                    content=await response.json()
                )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/iplookup/lookup/{ip}")
async def proxy_ip_lookup(ip: str, db: Session = Depends(get_db)):
    """Proxy IP lookup request to IP lookup service"""
    try:
        # Get API key from database
        api_key = await get_crowdsec_key(db)
        headers = {"x-api-key": api_key} if api_key else {}

        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://iplookup:8000/lookup/{ip}', headers=headers) as response:
                return JSONResponse(
                    status_code=response.status,
                    content=await response.json()
                )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

@app.post("/api/rules/bulk-toggle")
async def bulk_toggle_rules(state: BulkRuleState):
    """Proxy bulk toggle request to detection service"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post('http://detection:8000/rules/bulk-toggle', json=state.dict()) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise HTTPException(
                        status_code=response.status,
                        detail="Failed to bulk toggle rules in detection service"
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

        # Save to database first
        db.commit()

        # Attempt validation but don't fail if it doesn't work
        validation_result = {"valid": False, "message": "Validation skipped"}
        try:
            # Pass the API key in the x-api-key header
            headers = {"x-api-key": api_keys.CROWDSEC_API_KEY}
            async with aiohttp.ClientSession() as session:
                async with session.get('http://iplookup:8000/validate/crowdsec', headers=headers) as response:
                    if response.status == 200:
                        validation_result = await response.json()
                    else:
                        logger.error(f"Validation failed with status {response.status}")
                        validation_result = {"valid": False, "message": "Validation failed"}
        except Exception as e:
            logger.warning(f"CrowdSec validation failed but keys were saved: {str(e)}")

        return {
            "message": "API keys updated successfully",
            "crowdsec_validation": validation_result
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Error saving API keys: {str(e)}")
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

@app.get("/api/system/health")
async def get_system_health():
    """Get system-wide health information"""
    try:
        # Check all services health
        service_checks = await asyncio.gather(
            check_service_health("collector", "http://collector:8000/health"),
            check_service_health("detection", "http://detection:8000/health"),
            check_service_health("iplookup", "http://iplookup:8000/health")
        )
        
        # Get system metrics
        metrics = await get_system_metrics()
        
        # Calculate overall status
        service_statuses = [stats["services"][service]["status"] for service in stats["services"]]
        if "error" in service_statuses:
            overall_status = "error"
        elif "degraded" in service_statuses:
            overall_status = "degraded"
        else:
            overall_status = "operational"
        
        stats["status"] = overall_status
        
        return {
            "status": overall_status,
            "uptime": int(time.time() - stats["start_time"]),
            "services": stats["services"],
            "system_metrics": metrics
        }
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return {
            "status": "degraded",
            "uptime": int(time.time() - stats["start_time"]),
            "services": stats["services"],
            "system_metrics": None
        }

@app.get("/health")
async def health_check():
    """Basic health check endpoint"""
    try:
        # Quick DB check
        db = SessionLocal()
        db.execute(select(1))
        db.close()
        
        return {
            "status": stats["status"],
            "timestamp": datetime.now().isoformat(),
            "uptime": int(time.time() - stats["start_time"])
        }
    except Exception as e:
        stats["status"] = "error"
        logger.error(f"Health check failed: {e}")
        return {
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "uptime": int(time.time() - stats["start_time"])
        }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the application"""
    logger.info("Starting API service...")
    try:
        # Initialize database
        init_db()
        logger.info("Database initialized successfully")
        
        # Initial health check of all services
        await get_system_health()
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)