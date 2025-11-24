"""
SIEM BOX - Log Parsing Service
DEPRECATED: Logs must be normalized before hitting the backend ingestion API.
"""
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class LogParser:
    """
    DEPRECATED: Log parsing engine with configurable rules
    
    In the lightweight architecture this service is deprecated.
    Parsing is expected to happen on the agent/forwarder that calls /api/v1/logs/ingest.
    
    This class is kept for backward compatibility but should not be used.
    """
    
    def __init__(self):
        logger.warning("LogParser is deprecated in Pattern B architecture. Use Cribl Stream pipelines instead.")
    
    @staticmethod
    def get_deprecation_notice() -> Dict[str, Any]:
        """
        Return deprecation notice for this service
        
        Returns:
            Dict containing deprecation information
        """
        return {
            "status": "deprecated",
            "message": "LogParser has been removed from the lightweight architecture.",
            "replacement": "Use lightweight agents (Fluent Bit, Vector, custom scripts, etc.) to parse and enrich events before calling /api/v1/logs/ingest.",
            "architecture": "Logs arrive pre-parsed and are stored directly in processed_logs."
        }


class ParsingService:
    """
    DEPRECATED: Service for managing log parsing operations
    
    In the lightweight architecture, parsing happens outside the backend.
    """
    
    def __init__(self):
        logger.warning("ParsingService is deprecated in Pattern B architecture. Use Cribl Stream instead.")
    
    @staticmethod
    def get_deprecation_notice() -> Dict[str, Any]:
        """
        Return deprecation notice for this service
        
        Returns:
            Dict containing deprecation information
        """
        return {
            "status": "deprecated",
            "message": "ParsingService has been removed; structured data should be sent directly to the ingestion endpoint.",
            "replacement": "Perform parsing on the source agent and include structured fields in the LogIngestRequest payload.",
            "architecture": "Backend focuses on storage, detection, and alerting."
        }
