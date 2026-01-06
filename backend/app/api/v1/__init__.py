"""
SIEM BOX - API v1 Router
"""
from fastapi import APIRouter
from app.api.v1 import logs, health, parsing, detection, auth, alerts, notifications, vulnerabilities, dashboard
# Temporarily commenting out problematic imports
# from app.api.v1 import test_debug

api_router = APIRouter()

# Include routers with prefixes
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(parsing.router, prefix="/parsing", tags=["parsing"])
api_router.include_router(detection.router, prefix="/detection", tags=["detection"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
# Re-enabling notifications after converting all db.query() patterns
api_router.include_router(notifications.router, prefix="/notifications", tags=["notifications"])
# Re-enabling vulnerabilities and dashboard after fixing async issues
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
# api_router.include_router(test_debug.router, prefix="/test", tags=["debug"])