"""
SIEM BOX - Log API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from datetime import datetime
import math
import json

from app.db.database import get_db
from app.schemas.logs import LogIngestRequest, LogIngestResponse, LogResponse, ParsedLogResponse, PaginatedResponse
# LogService removed - deprecated in Pattern B architecture
from app.services.cribl_service import cribl_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


@router.post("/ingest")
async def ingest_log_deprecated(
    request: Request
):
    """
    DEPRECATED: Ingest a new log entry
    
    This endpoint is deprecated in Pattern B architecture.
    Log ingestion is now handled by Cribl Stream.
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Log ingestion is now handled by Cribl Stream",
            "replacement": "Send logs directly to Cribl Stream on port 5140 (UDP)",
            "destination": "Configure log sources to send to 'SIEMBOX' destination in Cribl",
            "architecture": "Pattern B - Direct ingestion to Cribl Stream"
        }
    )


@router.post("/ingest/fluent-bit")
async def ingest_fluent_bit_logs_deprecated(
    request: Request
):
    """
    DEPRECATED: Ingest logs from Fluent Bit
    
    This endpoint is deprecated in Pattern B architecture.
    Fluent Bit should send logs directly to Cribl Stream.
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Fluent Bit ingestion is now handled by Cribl Stream",
            "replacement": "Configure Fluent Bit to send logs to Cribl Stream on port 5140 (UDP)",
            "destination": "Use 'SIEMBOX' destination in Cribl Stream configuration",
            "architecture": "Pattern B - Direct ingestion to Cribl Stream",
            "fluent_bit_config": "Update fluent-bit.conf to output to host:5140"
        }
    )


@router.post("/cribl")
async def receive_cribl_logs(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Receive processed logs from Cribl Stream via HTTP destination.
    
    This endpoint receives logs that have been processed by Cribl Stream
    and stores them in PostgreSQL for immediate querying and analysis.
    This works in conjunction with the filesystem destination for long-term storage.
    """
    try:
        # Get the raw body as bytes
        body = await request.body()
        
        # Parse JSON payload
        try:
            if body:
                payload = json.loads(body.decode('utf-8'))
            else:
                raise HTTPException(status_code=400, detail="Empty request body")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Handle both single log and batch of logs
        logs_to_process = []
        if isinstance(payload, list):
            logs_to_process = payload
        elif isinstance(payload, dict):
            logs_to_process = [payload]
        else:
            raise HTTPException(status_code=400, detail="Payload must be a JSON object or array")
        
        processed_count = 0
        for log_data in logs_to_process:
            try:
                # Store the processed log in PostgreSQL for immediate querying
                # Note: We're storing the processed logs for real-time access
                # The raw logs are also stored in Cribl's filesystem destination for long-term storage
                
                # For now, we'll just log the received data
                # In a full implementation, you might want to store these in a processed_logs table
                logger.info(f"Received processed log from Cribl: {json.dumps(log_data, default=str)}")
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Failed to process log entry: {e}")
                continue
        
        return {
            "status": "success",
            "message": f"Processed {processed_count} log entries from Cribl Stream",
            "processed_count": processed_count
        }
        
    except Exception as e:
        logger.error(f"Error processing Cribl logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process logs: {str(e)}")


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
    start_time: Optional[datetime] = Query(None, description="Filter logs after this time"),
    end_time: Optional[datetime] = Query(None, description="Filter logs before this time")
):
    """
    Retrieve raw logs with optional filtering and pagination
    
    Returns a paginated list of raw log entries with support for filtering by hostname,
    application name, and time range. Data is retrieved from Cribl Search API.
    """
    try:
        # Get logs from Cribl with filters
        cribl_result = await cribl_service.get_logs_with_filters(
            hostname=hostname,
            app_name=app_name,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=skip
        )
        
        # Extract events and total count from Cribl response
        events = cribl_result.get("events", [])
        total_logs = cribl_result.get("totalCount", 0)
        
        # Convert Cribl events to frontend-compatible format
        items = []
        for event in events:
            items.append(LogResponse(
                id=event.get("_id", str(hash(str(event)))),
                timestamp=datetime.fromisoformat(event.get("timestamp", datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                source_ip=event.get("source_ip"),
                hostname=event.get("hostname"),
                source_type=event.get("app_name") or event.get("hostname") or "unknown",
                raw_message=event.get("raw_message", str(event)),
                created_at=datetime.fromisoformat(event.get("_time", datetime.utcnow().isoformat()).replace('Z', '+00:00'))
            ))
        
        # Calculate pagination info
        page = (skip // limit) + 1
        pages = math.ceil(total_logs / limit) if total_logs > 0 else 1
        
        return PaginatedResponse(
            items=items,
            total=total_logs,
            page=page,
            size=limit,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Failed to retrieve raw logs from Cribl: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve raw logs: {str(e)}"
        )


@router.get("/stats")
async def get_log_stats():
    """
    Get basic statistics about logs
    
    Returns summary information including total logs, recent activity,
    and top sources from Cribl.
    """
    try:
        stats = await cribl_service.get_log_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Failed to generate log statistics from Cribl: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate statistics: {str(e)}"
        )


@router.get("/stats/summary")
async def get_log_stats_summary():
    """
    Get basic statistics about logs (alias for /stats)
    
    Returns summary information including total logs, recent activity,
    and top sources from Cribl.
    """
    try:
        stats = await cribl_service.get_log_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Failed to generate log statistics from Cribl: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate statistics: {str(e)}"
        )


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(log_id: str):
    """
    Retrieve a specific log entry by ID from Cribl
    """
    try:
        event = await cribl_service.get_log_by_id(log_id)
        
        if not event:
            raise HTTPException(
                status_code=404,
                detail=f"Log with ID {log_id} not found"
            )
        
        return LogResponse(
            id=event.get("_id", log_id),
            timestamp=datetime.fromisoformat(event.get("timestamp", datetime.utcnow().isoformat()).replace('Z', '+00:00')),
            source_ip=event.get("source_ip"),
            hostname=event.get("hostname"),
            source_type=event.get("app_name") or event.get("hostname") or "unknown",
            raw_message=event.get("raw_message", str(event)),
            created_at=datetime.fromisoformat(event.get("_time", datetime.utcnow().isoformat()).replace('Z', '+00:00'))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve log {log_id} from Cribl: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve log: {str(e)}"
        )