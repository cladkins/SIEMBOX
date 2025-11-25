"""
SIEM BOX - Health Check API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from datetime import datetime

from app.db.database import get_db
from app.schemas.logs import HealthCheckResponse
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=HealthCheckResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Health check endpoint
    
    Returns the current status of the SIEM BOX application including
    database connectivity and basic system information.
    """
    try:
        # Test database connection
        await db.execute(text("SELECT 1"))
        database_status = "connected"
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        database_status = "disconnected"
    
    return HealthCheckResponse(
        status="healthy" if database_status == "connected" else "unhealthy",
        timestamp=datetime.utcnow(),
        version=settings.app_version,
        database=database_status
    )


@router.get("/database")
async def database_health(db: AsyncSession = Depends(get_db)):
    """
    Detailed database health check
    
    Returns detailed information about database connectivity and performance.
    """
    try:
        # Test basic connectivity
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        
        # Test table existence
        tables_result = await db.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """))
        
        tables = [row[0] for row in tables_result.fetchall()]
        
        # Get database version
        version_result = await db.execute(text("SELECT version()"))
        version = version_result.scalar()
        
        return {
            "status": "healthy",
            "connection": "active",
            "tables": tables,
            "database_version": version,
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Database detailed health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Database health check failed: {str(e)}"
        )


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """
    Kubernetes-style readiness probe
    
    Returns 200 if the service is ready to accept traffic.
    """
    try:
        # Test database connection
        await db.execute(text("SELECT 1"))
        
        return {"status": "ready", "timestamp": datetime.utcnow()}
        
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail="Service not ready"
        )


@router.get("/live")
async def liveness_check():
    """
    Kubernetes-style liveness probe
    
    Returns 200 if the service is alive (basic application health).
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow(),
        "application": settings.app_name,
        "version": settings.app_version
    }