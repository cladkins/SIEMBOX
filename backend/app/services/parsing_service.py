"""
SIEM BOX - Log Parsing Service
DEPRECATED: This service is deprecated in Pattern B architecture.
Log parsing is now handled by Cribl Stream pipelines.
"""
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class LogParser:
    """
    DEPRECATED: Log parsing engine with configurable rules
    
    In Pattern B architecture, this service is deprecated.
    Log parsing is now handled by:
    - Cribl Stream: Pipelines handle log parsing and enrichment
    - Cribl Packs: Pre-built parsing configurations for common log types
    
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
            "message": "LogParser is deprecated in Pattern B architecture",
            "replacement": "Use Cribl Stream pipelines for log parsing",
            "architecture": "Pattern B - Cribl Stream handles log parsing and enrichment"
        }


class ParsingService:
    """
    DEPRECATED: Service for managing log parsing operations
    
    In Pattern B architecture, this service is deprecated.
    Parsing operations are now handled by Cribl Stream.
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
            "message": "ParsingService is deprecated in Pattern B architecture",
            "replacement": "Use Cribl Stream for parsing operations",
            "architecture": "Pattern B - Cribl Stream handles all parsing logic"
        }