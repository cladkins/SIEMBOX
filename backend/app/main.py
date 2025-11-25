"""
SIEM BOX - Main FastAPI Application
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import sys
from datetime import datetime

from app.core.config import settings
from app.api.v1 import api_router
from app.db.database import init_db

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format=settings.log_format,
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="A self-hosted SIEM solution for homelab environments",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler for unhandled exceptions
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.on_event("startup")
async def startup_event():
    """
    Application startup event
    """
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")

    try:
        # Initialize database
        await init_db()
        logger.info("Database initialized successfully")

        # Start syslog server
        from app.services.syslog_service import syslog_server
        try:
            await syslog_server.start()
            logger.info("✅ Syslog server started on UDP 514")
        except PermissionError:
            logger.warning("⚠️  Cannot bind to port 514 (requires root/CAP_NET_BIND_SERVICE)")
            logger.warning("Syslog ingestion will not be available")
        except Exception as e:
            logger.error(f"Failed to start syslog server: {e}")

    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """
    Application shutdown event
    """
    logger.info(f"Shutting down {settings.app_name}")


# Include API router
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/")
async def root():
    """
    Root endpoint
    """
    return {
        "application": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "timestamp": datetime.utcnow(),
        "docs_url": "/docs",
        "api_prefix": settings.api_v1_prefix
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )