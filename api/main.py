from fastapi import FastAPI, Depends, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, update
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging
import traceback
import psutil
import os
import json
import httpx
from database import get_db, Base, engine
from models import (
    Log, LogResponse, PaginatedLogsResponse,
    Rule, RuleResponse, RulesListResponse,
    APIKeys, APIKeyResponse
)
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="SIEM Box API", version="1.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Model for creating logs
class LogCreate(BaseModel):
    source: str
    message: str
    level: str = "INFO"
    log_metadata: Dict[str, Any] = {}

# Model for rule toggle
class RuleToggle(BaseModel):
    rule_id: str
    enabled: bool
    category: Optional[str] = None

# Model for bulk rule toggle
class BulkRuleToggle(BaseModel):
    enabled: bool

@app.post("/api/logs", response_model=LogResponse)
async def create_log(
    log_data: LogCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new log entry"""
    try:
        logger.info(f"Creating new log entry from source: {log_data.source}")
        
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
        
        logger.info(f"Successfully created log entry with id: {new_log.id}")
        return new_log
    except SQLAlchemyError as e:
        logger.error(f"Database error in create_log: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in create_log: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/api/logs", response_model=PaginatedLogsResponse)
async def get_logs(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=100),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None)
):
    """Get paginated logs with enhanced error handling and performance optimizations"""
    try:
        logger.info(f"Starting get_logs request: page={page}, page_size={page_size}")
        
        # Calculate offset
        offset = (page - 1) * page_size
        logger.info(f"Calculated offset: {offset}")
        
        # Build query with time range filter
        query = select(Log).order_by(desc(Log.timestamp))
        logger.info("Building base query")
        
        if start_time:
            query = query.where(Log.timestamp >= start_time)
            logger.info(f"Added start_time filter: {start_time}")
        if end_time:
            query = query.where(Log.timestamp <= end_time)
            logger.info(f"Added end_time filter: {end_time}")
        
        try:
            # Get total count with time range filter
            logger.info("Executing count query")
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await db.scalar(count_query)
            logger.info(f"Total log count: {total_count}")
            
            # Get paginated logs
            logger.info("Executing paginated query")
            result = await db.execute(
                query.offset(offset).limit(page_size)
            )
            logs = result.scalars().all()
            logger.info(f"Retrieved {len(logs)} logs for page {page}")
            
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
            logger.info("Successfully prepared response")
            return response
        except SQLAlchemyError as e:
            logger.error(f"Database error in get_logs query execution: {str(e)}")
            logger.error(f"Query details: offset={offset}, page_size={page_size}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in get_logs: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/api/rules")
async def get_rules():
    """Get all detection rules by proxying request to detection service"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://detection:8000/rules")
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch rules from detection service")
            
            # Get the response data
            data = response.json()
            rules = data.get("rules", [])
            
            # Map the rules to match frontend expectations
            mapped_rules = []
            for rule in rules:
                mapped_rule = {
                    "id": rule["id"],
                    "title": rule["title"],
                    "description": rule.get("description", ""),
                    "severity": rule.get("level", "medium"),  # Map 'level' to 'severity'
                    "enabled": rule.get("enabled", False),
                    "category": rule.get("category", "uncategorized")
                }
                mapped_rules.append(mapped_rule)
            
            return {
                "rules": mapped_rules,
                "total": len(mapped_rules)
            }
    except httpx.RequestError as e:
        logger.error(f"Error fetching rules from detection service: {str(e)}")
        raise HTTPException(status_code=503, detail="Detection service unavailable")
    except Exception as e:
        logger.error(f"Error getting rules: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rules/toggle")
async def toggle_rule(rule_data: RuleToggle):
    """Toggle a specific rule's enabled status by proxying to detection service"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://detection:8000/rules/toggle",
                json={"rule_id": rule_data.rule_id, "enabled": rule_data.enabled, "category": rule_data.category}
            )
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to toggle rule in detection service")
            return response.json()
    except httpx.RequestError as e:
        logger.error(f"Error toggling rule in detection service: {str(e)}")
        raise HTTPException(status_code=503, detail="Detection service unavailable")
    except Exception as e:
        logger.error(f"Error toggling rule: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rules/bulk-toggle")
async def bulk_toggle_rules(toggle_data: BulkRuleToggle):
    """Toggle all rules' enabled status by proxying to detection service"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://detection:8000/rules/bulk-toggle",
                json={"enabled": toggle_data.enabled}
            )
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to bulk toggle rules in detection service")
            return response.json()
    except httpx.RequestError as e:
        logger.error(f"Error bulk toggling rules in detection service: {str(e)}")
        raise HTTPException(status_code=503, detail="Detection service unavailable")
    except Exception as e:
        logger.error(f"Error bulk toggling rules: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/settings/api-keys", response_model=APIKeyResponse)
async def get_api_keys():
    """Get stored API keys"""
    try:
        # In a real application, these would be stored securely
        return APIKeyResponse(
            IPAPI_KEY=os.getenv("IPAPI_KEY", ""),
            CROWDSEC_API_KEY=os.getenv("CROWDSEC_API_KEY", "")
        )
    except Exception as e:
        logger.error(f"Error getting API keys: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/settings/api-keys", response_model=APIKeyResponse)
async def save_api_keys(api_keys: APIKeys):
    """Save API keys"""
    try:
        # In a real application, these would be stored securely
        # For now, we'll just return the keys as if they were saved
        return APIKeyResponse(
            IPAPI_KEY=api_keys.IPAPI_KEY,
            CROWDSEC_API_KEY=api_keys.CROWDSEC_API_KEY,
            crowdsec_validation={"valid": True}
        )
    except Exception as e:
        logger.error(f"Error saving API keys: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

# Initialize database tables
@app.on_event("startup")
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)