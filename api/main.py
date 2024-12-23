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
from database import get_db, Base, engine
from models import (
    Log, LogResponse, PaginatedLogsResponse,
    InternalLog, InternalLogResponse, PaginatedInternalLogsResponse,
    Rule, RuleResponse, RulesListResponse,
    APIKeys, APIKeyResponse, Setting
)
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
INTERNAL_SERVICES = {'api', 'collector', 'detection', 'iplookup', 'frontend'}

@app.post("/api/app-logs", response_model=InternalLogResponse)
async def create_internal_log(
    log_data: InternalLogResponse,
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

        # Build query with time range filter and exclude internal sources
        query = select(Log).where(
            not_(Log.source.in_(INTERNAL_SERVICES))
        ).order_by(desc(Log.timestamp))

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