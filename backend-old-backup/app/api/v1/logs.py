"""
SIEM BOX - Log API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timedelta
from uuid import UUID
import math

from app.db.database import get_db
from app.models.logs import ProcessedLog
from app.schemas.logs import LogIngestRequest, LogIngestResponse, LogResponse, ParsedLogResponse, PaginatedResponse
from app.services.detection_service import detection_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/ingest", response_model=LogIngestResponse)
async def ingest_log(
    log_entry: LogIngestRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Lightweight log ingestion endpoint that stores events directly in PostgreSQL
    and immediately triggers the detection engine.
    """
    try:
        processed_fields = log_entry.fields.copy() if log_entry.fields else {}
        base_context = {
            "source_ip": log_entry.source_ip,
            "hostname": log_entry.hostname,
            "app_name": log_entry.app_name,
            "protocol": log_entry.protocol,
            "source_port": log_entry.source_port
        }
        for key, value in base_context.items():
            if value is not None and key not in processed_fields:
                processed_fields[key] = value
        
        processed_log = ProcessedLog(
            timestamp=log_entry.timestamp,
            hostname=log_entry.hostname,
            source_ip=log_entry.source_ip,
            app_name=log_entry.app_name,
            raw_message=log_entry.raw_message,
            processed_fields=processed_fields or None,
            log_type=log_entry.log_type,
            severity=log_entry.severity,
            category=log_entry.category,
            source=log_entry.app_name or log_entry.hostname or "direct_ingest",
            cribl_pipeline=None
        )
        
        db.add(processed_log)
        await db.commit()
        await db.refresh(processed_log)
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to ingest log: {e}")
        raise HTTPException(status_code=500, detail="Failed to ingest log")
    
    # Run detection in the background for the newly ingested log
    try:
        await detection_service.run_detection_on_processed_logs(
            db, [str(processed_log.id)]
        )
    except Exception as e:
        # Do not fail ingestion if detection has issues
        logger.error(f"Detection run failed for log {processed_log.id}: {e}")
    
    return LogIngestResponse(
        success=True,
        log_id=str(processed_log.id),
        message="Log ingested successfully"
    )




@router.get("/parsed", response_model=PaginatedResponse[ParsedLogResponse])
async def get_parsed_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    hostname: Optional[str] = Query(None, description="Filter by hostname"),
    app_name: Optional[str] = Query(None, description="Filter by application name"),
    start_time: Optional[datetime] = Query(None, description="Filter logs after this time"),
    end_time: Optional[datetime] = Query(None, description="Filter logs before this time"),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve parsed logs with optional filtering and pagination
    
    Returns a paginated list of parsed log entries. For now, this creates mock parsed logs
    from raw logs until the parsing system is implemented.
    """
    try:
        # DEPRECATED: This endpoint returns mock data because in Pattern B architecture,
        # parsed logs should be stored in PostgreSQL after being received from Cribl HTTP destination
        
        # Return mock parsed logs for now
        items = []
        total_logs = 0
        
        # In a real implementation, you would query PostgreSQL for parsed logs
        # that were received from Cribl's HTTP destination
        
        # Calculate pagination info
        page = (skip // limit) + 1
        pages = 1
        
        return PaginatedResponse(
            items=items,
            total=total_logs,
            page=page,
            size=limit,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Failed to retrieve parsed logs: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve parsed logs: {str(e)}"
        )


@router.get("/", response_model=PaginatedResponse[LogResponse])
async def get_raw_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    hostname: Optional[str] = Query(None, description="Filter by hostname"),
    app_name: Optional[str] = Query(None, description="Filter by application name"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    start_time: Optional[datetime] = Query(None, description="Filter logs after this time"),
    end_time: Optional[datetime] = Query(None, description="Filter logs before this time"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    log_type: Optional[str] = Query(None, description="Filter by log type"),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve raw logs with optional filtering and pagination.
    Data is served directly from the local processed_logs table.
    """
    try:
        filters = []
        if hostname:
            filters.append(ProcessedLog.hostname == hostname)
        if app_name:
            filters.append(ProcessedLog.app_name == app_name)
        if source_ip:
            filters.append(ProcessedLog.source_ip == source_ip)
        if severity:
            filters.append(ProcessedLog.severity == severity)
        if log_type:
            filters.append(ProcessedLog.log_type == log_type)
        if start_time:
            filters.append(ProcessedLog.timestamp >= start_time)
        if end_time:
            filters.append(ProcessedLog.timestamp <= end_time)
        
        total_query = select(func.count(ProcessedLog.id))
        if filters:
            total_query = total_query.filter(*filters)
        total_result = await db.execute(total_query)
        total_logs = total_result.scalar() or 0
        
        query = select(ProcessedLog).order_by(desc(ProcessedLog.timestamp)).offset(skip).limit(limit)
        if filters:
            query = query.filter(*filters)
        
        result = await db.execute(query)
        logs = result.scalars().all()
        
        items = []
        for log in logs:
            items.append(LogResponse(
                id=str(log.id),
                timestamp=log.timestamp,
                source_ip=str(log.source_ip) if log.source_ip else None,
                hostname=log.hostname,
                source_type=log.app_name or log.source or log.hostname or "unknown",
                raw_message=log.raw_message or "",
                created_at=log.received_at or log.timestamp
            ))
        
        page = (skip // limit) + 1 if limit else 1
        pages = math.ceil(total_logs / limit) if limit and total_logs else 1
        
        return PaginatedResponse(
            items=items,
            total=total_logs,
            page=page,
            size=limit,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Failed to retrieve logs: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve logs"
        )


@router.get("/stats")
async def get_log_stats(db: AsyncSession = Depends(get_db)):
    """
    Get basic statistics about logs stored locally.
    """
    try:
        total_logs = (await db.execute(select(func.count(ProcessedLog.id)))).scalar() or 0
        
        recent_cutoff = datetime.utcnow() - timedelta(hours=1)
        recent_logs = (await db.execute(
            select(func.count(ProcessedLog.id)).filter(ProcessedLog.timestamp >= recent_cutoff)
        )).scalar() or 0
        
        top_sources_query = select(
            ProcessedLog.source,
            func.count(ProcessedLog.id).label("count")
        ).group_by(ProcessedLog.source).order_by(desc("count")).limit(5)
        top_sources = (await db.execute(top_sources_query)).all()
        
        log_types_query = select(
            ProcessedLog.log_type,
            func.count(ProcessedLog.id)
        ).group_by(ProcessedLog.log_type)
        log_types = {log_type or "unknown": count for log_type, count in (await db.execute(log_types_query)).all()}
        
        return {
            "total_logs": total_logs,
            "recent_logs": recent_logs,
            "log_rate_per_minute": round(recent_logs / 60, 2) if recent_logs else 0,
            "top_sources": [
                {"source": source or "unknown", "count": count}
                for source, count in top_sources
            ],
            "log_types": log_types,
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to generate log statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate statistics"
        )


@router.get("/stats/summary")
async def get_log_stats_summary(db: AsyncSession = Depends(get_db)):
    """
    Alias for /stats using local data.
    """
    return await get_log_stats(db=db)


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(
    log_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve a specific log entry by ID from the local database.
    """
    try:
        try:
            log_uuid = UUID(log_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Log not found")
        
        result = await db.execute(
            select(ProcessedLog).filter(ProcessedLog.id == log_uuid)
        )
        log = result.scalar_one_or_none()
        
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")
        
        return LogResponse(
            id=str(log.id),
            timestamp=log.timestamp,
            source_ip=str(log.source_ip) if log.source_ip else None,
            hostname=log.hostname,
            source_type=log.app_name or log.source or log.hostname or "unknown",
            raw_message=log.raw_message or "",
            created_at=log.received_at or log.timestamp
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve log {log_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve log"
        )
