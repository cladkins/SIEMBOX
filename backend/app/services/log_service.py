"""
SIEM BOX - Log Service for Business Logic
DEPRECATED: This service is deprecated in Pattern B architecture.
Log ingestion and retrieval is now handled by Cribl Stream.
Use CriblService for log operations instead.
"""
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class LogService:
    """
    DEPRECATED: Service class for log-related business logic
    
    In Pattern B architecture, this service is deprecated.
    Log operations are now handled by:
    - CriblService: For log search and retrieval
    - Cribl Stream: For log ingestion and storage
    
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
            "message": "LogService is deprecated in Pattern B architecture",
            "replacement": "Use CriblService for log operations",
            "architecture": "Pattern B - Cribl Stream handles log storage and retrieval"
        }