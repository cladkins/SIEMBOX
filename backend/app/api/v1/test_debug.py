"""
Debug test endpoint - completely isolated
"""
from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)
logger.info("test_debug module imported successfully")

router = APIRouter()

@router.get("/debug-test")
def debug_test():
    """Completely isolated debug test"""
    logger.info("Debug test endpoint called")
    return {"message": "Debug test working", "status": "success"}