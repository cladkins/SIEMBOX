"""
SIEM BOX - Log Service for Business Logic
DEPRECATED: Use the ingestion API and database queries directly.
"""
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class LogService:
    """
    DEPRECATED: Service class for log-related business logic
    
    In the lightweight architecture this wrapper is unnecessary.
    Log ingestion happens via /api/v1/logs/ingest and queries should target the processed_logs table directly.
    
    This class is kept for backward compatibility but should not be used.
    """
    
    @staticmethod
    def get_deprecation_notice() -> Dict[str, Any]:
        """
        Return deprecation notice for this service
        
        Returns:
            Dict containing deprecation information
        """
        return {
            "status": "deprecated",
            "message": "LogService has been removed; call the ingestion API or query processed_logs directly.",
            "replacement": "Use /api/v1/logs/ingest for writes and /api/v1/logs for reads.",
            "architecture": "Lightweight ingestion stores normalized events directly in PostgreSQL."
        }
