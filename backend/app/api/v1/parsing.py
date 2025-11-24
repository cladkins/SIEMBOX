"""
SIEM BOX - Parsing API Endpoints
DEPRECATED: Logs arrive in structured form via the ingestion API.
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


def _deprecated_detail(reason: str) -> Dict[str, Any]:
    return {
        "error": "Endpoint deprecated",
        "message": "Log parsing is handled by the ingestion pipeline and lightweight agents before data reaches the API.",
        "reason": reason,
        "replacement": "Send structured events to /api/v1/logs/ingest with the fields you need for detection."
    }


@router.get("/deprecation-notice")
async def get_deprecation_notice() -> Dict[str, Any]:
    """
    Return deprecation notice for parsing endpoints
    """
    return {
        "status": "deprecated",
        "message": "Dedicated parsing endpoints were removed in the lightweight architecture.",
        "replacement": "Normalize logs on the forwarder/agent and include structured fields when calling /api/v1/logs/ingest.",
        "ingestion_guidance": {
            "workflow": "Log source -> lightweight parser/agent -> /api/v1/logs/ingest -> processed_logs table",
            "benefits": [
                "No additional parsing service to operate",
                "Consistent schema for detection rules",
                "Lower resource usage on the backend"
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
        detail=_deprecated_detail("Logs should be parsed before they reach the API.")
    )


@router.get("/parsed")
async def get_parsed_logs_deprecated():
    """
    DEPRECATED: Get parsed logs with optional filtering
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail("Use /api/v1/logs to query stored events.")
    )


@router.get("/unparsed")
async def get_unparsed_logs_deprecated():
    """
    DEPRECATED: Get unparsed raw logs
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail("Raw log storage is not provided; send structured data to /api/v1/logs/ingest.")
    )


@router.get("/stats")
async def get_parsing_stats_deprecated():
    """
    DEPRECATED: Get parsing statistics
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail("Parsing stats are no longer tracked server-side.")
    )


@router.get("/rules")
async def get_parsing_rules_deprecated():
    """
    DEPRECATED: Get list of available parsing rules/parsers
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail("Maintain parsing rules inside the agent or forwarder that sends logs.")
    )


@router.get("/parsers")
async def get_available_parsers_deprecated():
    """
    DEPRECATED: Get list of available parsers
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail("Choose or build parsers within your forwarding agent.")
    )


@router.post("/auto-parse")
async def auto_parse_recent_logs_deprecated():
    """
    DEPRECATED: Automatically parse recent unparsed logs
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail("Automatic parsing now occurs upstream before logs are ingested.")
    )


@router.get("/parsed/{log_id}")
async def get_parsed_log_deprecated(log_id: str):
    """
    DEPRECATED: Get a specific parsed log by ID
    """
    raise HTTPException(
        status_code=410,
        detail=_deprecated_detail(f"Use /api/v1/logs/{log_id} to retrieve stored events.")
    )
