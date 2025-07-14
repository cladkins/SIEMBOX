"""
SIEM BOX - Parsing API Endpoints
DEPRECATED: These endpoints are deprecated in Pattern B architecture.
Log parsing is now handled by Cribl Stream pipelines.
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/deprecation-notice")
async def get_deprecation_notice() -> Dict[str, Any]:
    """
    Return deprecation notice for parsing endpoints
    """
    return {
        "status": "deprecated",
        "message": "Parsing endpoints are deprecated in Pattern B architecture",
        "replacement": "Use Cribl Stream pipelines for log parsing",
        "architecture": "Pattern B - Cribl Stream handles all parsing operations",
        "migration_guide": {
            "old_workflow": "Raw logs -> Database -> Parsing Service -> Parsed logs",
            "new_workflow": "Raw logs -> Cribl Stream pipelines -> Parsed logs (stored in Cribl)",
            "benefits": [
                "Real-time parsing during ingestion",
                "Better performance and scalability",
                "Built-in parsing for common log formats",
                "Visual pipeline configuration"
            ]
        }
    }


@router.post("/parse")
async def parse_logs_deprecated():
    """
    DEPRECATED: Parse raw logs using configured parsers
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Log parsing is now handled by Cribl Stream pipelines",
            "replacement": "Configure parsing pipelines in Cribl Stream",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.get("/parsed")
async def get_parsed_logs_deprecated():
    """
    DEPRECATED: Get parsed logs with optional filtering
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Parsed logs are now accessed via Cribl Search API",
            "replacement": "Use /api/v1/logs endpoints which query Cribl directly",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.get("/unparsed")
async def get_unparsed_logs_deprecated():
    """
    DEPRECATED: Get unparsed raw logs
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Raw logs are now stored and parsed in Cribl Stream",
            "replacement": "Configure parsing pipelines in Cribl Stream",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.get("/stats")
async def get_parsing_stats_deprecated():
    """
    DEPRECATED: Get parsing statistics
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Parsing statistics are available in Cribl Stream UI",
            "replacement": "Access Cribl Stream monitoring dashboard",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.get("/rules")
async def get_parsing_rules_deprecated():
    """
    DEPRECATED: Get list of available parsing rules/parsers
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Parsing rules are now configured as Cribl Stream pipelines",
            "replacement": "Manage pipelines in Cribl Stream UI",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.get("/parsers")
async def get_available_parsers_deprecated():
    """
    DEPRECATED: Get list of available parsers
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Parsers are now Cribl Stream functions and packs",
            "replacement": "Browse available packs in Cribl Stream",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.post("/auto-parse")
async def auto_parse_recent_logs_deprecated():
    """
    DEPRECATED: Automatically parse recent unparsed logs
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Parsing is now automatic in Cribl Stream pipelines",
            "replacement": "Configure real-time parsing pipelines in Cribl Stream",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )


@router.get("/parsed/{log_id}")
async def get_parsed_log_deprecated(log_id: str):
    """
    DEPRECATED: Get a specific parsed log by ID
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "Endpoint deprecated",
            "message": "Parsed logs are now accessed via Cribl Search API",
            "replacement": f"Use /api/v1/logs/{log_id} which queries Cribl directly",
            "documentation": "/api/v1/parsing/deprecation-notice"
        }
    )