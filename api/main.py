#!/usr/bin/env python3
from fastapi import FastAPI, Depends, Query, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, update, and_, not_
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import traceback
import psutil
import os
import json
import httpx
import asyncio
from database import get_db, Base, engine
from models import (
    Log, LogResponse, PaginatedLogsResponse,
    InternalLog, InternalLogResponse, PaginatedInternalLogsResponse,
    Rule, RuleResponse, RulesListResponse,
    APIKeys, APIKeyResponse, Setting, CreateInternalLogRequest,
    Alert
)
from pydantic import BaseModel
from typing import Dict, Any, Optional

class CreateLogRequest(BaseModel):
    source: str
    message: str
    level: str = "INFO"
    log_metadata: Dict[str, Any] = {}
from app_logger import setup_logging

# Set up logging with the new handler
logger = setup_logging("api", get_db)

# Initialize FastAPI app
app = FastAPI(title="SIEM Box API", version="1.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Internal services list
INTERNAL_SERVICES = {'api', 'collector', 'detection', 'iplookup', 'frontend', 'detections_page'}

@app.post("/api/app-logs", response_model=InternalLogResponse)
async def create_internal_log(
    log_data: CreateInternalLogRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new internal application log entry"""
    try:
        new_log = InternalLog(
            service=log_data.service,
            message=log_data.message,
            level=log_data.level,
            log_metadata=log_data.log_metadata,
            component=log_data.component,
            trace_id=log_data.trace_id,
            timestamp=datetime.utcnow()
        )

        db.add(new_log)
        await db.commit()
        await db.refresh(new_log)

        logger.info(f"Successfully created internal log entry with id: {new_log.id}")
        return new_log
    except SQLAlchemyError as e:
        logger.error(f"Database error in create_internal_log: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in create_internal_log: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/api/app-logs", response_model=PaginatedInternalLogsResponse)
async def get_internal_logs(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=100),
    service: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
):
    """Get paginated internal application logs"""
    try:
        # Calculate offset
        offset = (page - 1) * page_size

        # Build query
        query = select(InternalLog).order_by(desc(InternalLog.timestamp))

        # Apply filters
        if service:
            query = query.where(InternalLog.service == service)
        if level:
            query = query.where(InternalLog.level == level)
        if start_time:
            query = query.where(InternalLog.timestamp >= start_time)
        if end_time:
            query = query.where(InternalLog.timestamp <= end_time)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_count = await db.scalar(count_query)

        # Get paginated logs
        result = await db.execute(
            query.offset(offset).limit(page_size)
        )
        logs = result.scalars().all()

        total_pages = (total_count + page_size - 1) // page_size if total_count else 1
        has_more = page < total_pages

        return PaginatedInternalLogsResponse(
            logs=logs,
            total=total_count or 0,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_more=has_more
        )
    except Exception as e:
        logger.error(f"Error getting internal logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def forward_to_detection(log_data: dict):
    """Forward log to detection service for analysis."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://detection:8000/analyze",
                json=log_data,
                timeout=10.0
            )
            if response.status_code == 200:
                result = response.json()
                alerts = result.get("alerts", [])
                if alerts:
                    logger.info(f"Detection service found {len(alerts)} alerts")
                    logger.info(f"Alert details: {json.dumps(alerts)}")
                return result
            else:
                logger.error(f"Detection service returned status {response.status_code}")
    except Exception as e:
        logger.error(f"Error forwarding to detection service: {str(e)}")
    return None

@app.post("/api/logs", response_model=LogResponse)
async def create_log(
    log_data: CreateLogRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new log entry and forward to detection service"""
    try:
        # Create new log entry
        new_log = Log(
            source=log_data.source,
            message=log_data.message,
            level=log_data.level,
            log_metadata=log_data.log_metadata,
            timestamp=datetime.utcnow()
        )

        db.add(new_log)
        await db.commit()
        await db.refresh(new_log)

        # Forward to detection service
        log_dict = {
            "id": new_log.id,
            "source": new_log.source,
            "message": new_log.message,
            "level": new_log.level,
            "metadata": new_log.log_metadata,
            "timestamp": new_log.timestamp.isoformat()
        }
        
        # Forward to detection service and wait for response
        detection_result = await forward_to_detection(log_dict)
        
        if detection_result and detection_result.get("alerts"):
            alerts = detection_result["alerts"]
            logger.info(f"Processing {len(alerts)} alerts for log {new_log.id}")
            # Create alert record for the matched rule
            if alerts:
                alert = Alert(
                    rule_name=alerts[0]["rule_name"],
                    severity=alerts[0]["severity"],
                    description=alerts[0]["rule_name"],
                    timestamp=datetime.utcnow()
                )
                db.add(alert)
                await db.flush()
                
                # Update existing log entry with alert_id
                new_log.alert_id = alert.id
                await db.commit()
                logger.info(f"Created alert {alert.id} for log {new_log.id}")
            logger.info(f"Created alert {alert.id} for log {new_log.id}")
        
        logger.info(f"Successfully created log entry with id: {new_log.id}")
        return new_log

    except SQLAlchemyError as e:
        logger.error(f"Database error in create_log: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in create_log: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/api/logs", response_model=PaginatedLogsResponse)
async def get_logs(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=100),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    has_alert: Optional[bool] = Query(None)
):
    """Get paginated logs with enhanced error handling and performance optimizations"""
    try:
        logger.info(f"Starting get_logs request: page={page}, page_size={page_size}")

        # Calculate offset
        offset = (page - 1) * page_size

        # Build query with time range filter and exclude internal sources
        query = select(Log).where(
            not_(Log.source.in_(INTERNAL_SERVICES))
        ).order_by(desc(Log.timestamp))

        # Add alert filter if specified
        if has_alert is not None:
            if has_alert:
                query = query.where(Log.alert_id.isnot(None))
            else:
                query = query.where(Log.alert_id.is_(None))

        if start_time:
            query = query.where(Log.timestamp >= start_time)
        if end_time:
            query = query.where(Log.timestamp <= end_time)

        try:
            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await db.scalar(count_query)

            # Get paginated logs
            result = await db.execute(
                query.offset(offset).limit(page_size)
            )
            logs = result.scalars().all()

            total_pages = (total_count + page_size - 1) // page_size if total_count else 1
            has_more = page < total_pages

            response = PaginatedLogsResponse(
                logs=logs,
                total=total_count or 0,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                has_more=has_more
            )
            return response
        except SQLAlchemyError as e:
            logger.error(f"Database error in get_logs query execution: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in get_logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/api/settings/api-keys", response_model=APIKeyResponse)
async def get_api_keys(db: AsyncSession = Depends(get_db)):
    """Get API keys with masked values"""
    try:
        result = await db.execute(select(Setting).where(Setting.key.in_(["IPAPI_KEY", "CROWDSEC_API_KEY"])))
        settings = result.scalars().all()
        return APIKeyResponse.from_settings(settings)
    except Exception as e:
        logger.error(f"Error getting API keys: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/settings/api-keys", response_model=APIKeyResponse)
async def update_api_keys(api_keys: APIKeys, db: AsyncSession = Depends(get_db)):
    """Update API keys"""
    try:
        # Update IPAPI_KEY
        if api_keys.IPAPI_KEY is not None:
            ipapi_setting = await db.execute(
                select(Setting).where(Setting.key == "IPAPI_KEY")
            )
            ipapi_setting = ipapi_setting.scalar_one_or_none()
            
            if ipapi_setting:
                ipapi_setting.set_value(api_keys.IPAPI_KEY)
            else:
                ipapi_setting = Setting(key="IPAPI_KEY")
                ipapi_setting.set_value(api_keys.IPAPI_KEY)
                db.add(ipapi_setting)

        # Update CROWDSEC_API_KEY
        if api_keys.CROWDSEC_API_KEY is not None:
            crowdsec_setting = await db.execute(
                select(Setting).where(Setting.key == "CROWDSEC_API_KEY")
            )
            crowdsec_setting = crowdsec_setting.scalar_one_or_none()
            
            if crowdsec_setting:
                crowdsec_setting.set_value(api_keys.CROWDSEC_API_KEY)
            else:
                crowdsec_setting = Setting(key="CROWDSEC_API_KEY")
                crowdsec_setting.set_value(api_keys.CROWDSEC_API_KEY)
                db.add(crowdsec_setting)

        await db.commit()

        # Get updated settings
        result = await db.execute(
            select(Setting).where(Setting.key.in_(["IPAPI_KEY", "CROWDSEC_API_KEY"]))
        )
        settings = result.scalars().all()
        return APIKeyResponse.from_settings(settings)

    except Exception as e:
        logger.error(f"Error updating API keys: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        async with AsyncSession(engine) as session:
            await session.execute(select(func.now()))
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.on_event("startup")
async def startup_event():
    """Initialize database tables on startup"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)