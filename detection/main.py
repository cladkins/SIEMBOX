#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import json
import asyncio
from typing import Dict, Any, List
import aiohttp
import os
import yaml
import re
import shutil
import git
import time
import collections
import psutil
import traceback
from app_logger import setup_logging

# Set up logging with the new handler
logger = setup_logging("detection")

app = FastAPI(title="SIEMBox Detection Engine")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Internal services list
INTERNAL_SERVICES = {'api', 'collector', 'detection', 'iplookup', 'frontend', 'detections_page'}

# Global variable to store loaded rules
sigma_rules = []

# Global variable to store rule states
rule_states = {}

# Global stats tracking
stats = {
    "enabled_rules": 0,
    "total_rules": 0,
    "alerts_last_24h": 0,
    "processing_rate": 0,
    "status": "starting",
    "start_time": time.time(),
    "processed_logs": 0,
    "last_minute_logs": collections.deque(maxlen=60),
    "alerts": collections.deque(maxlen=1440),
    "rules_loaded": False,
    "processed_log_ids": collections.deque(maxlen=1000)  # Store recent log IDs
}

# API interaction functions
async def get_rule_states_from_api():
    """Get rule states from API service."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://api:8080/api/rule-states") as response:
                if response.status == 200:
                    return await response.json()
    except Exception as e:
        logger.error(f"Error getting rule states from API: {str(e)}")
    return {}

# These functions are no longer needed as the API now handles persistence directly
# async def update_rule_state_in_api(rule_id: str, enabled: bool):
#     """Update rule state in API service."""
#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.post(
#                 f"http://api:8080/api/rule-states/{rule_id}",
#                 json={"enabled": enabled}
#             ) as response:
#                 if response.status == 200:
#                     return True
#                 else:
#                     logger.error(f"API returned status {response.status} when updating rule state")
#     except Exception as e:
#         logger.error(f"Error updating rule state in API: {str(e)}")
#     return False
#
# async def update_bulk_rule_states_in_api(rule_states_dict: Dict[str, bool]):
#     """Update multiple rule states in API service."""
#     try:
#         # Extract the enabled value (should be the same for all rules)
#         if not rule_states_dict:
#             return False
#
#         # All rules should have the same enabled value in a bulk update
#         enabled = next(iter(rule_states_dict.values()))
#
#         async with aiohttp.ClientSession() as session:
#             async with session.post(
#                 "http://api:8080/api/rule-states/bulk",
#                 json={"enabled": enabled}
#             ) as response:
#                 if response.status == 200:
#                     return True
#                 else:
#                     logger.error(f"API returned status {response.status} when bulk updating rule states")
#     except Exception as e:
#         logger.error(f"Error updating bulk rule states in API: {str(e)}")
#     return False

class Alert(BaseModel):
    rule_id: str
    rule_name: str
    timestamp: datetime
    log_source: str
    matched_log: Dict[str, Any]
    severity: str

class Rule(BaseModel):
    id: str
    title: str
    description: str
    level: str
    detection: Dict[str, Any]
    logsource: Dict[str, str]
    enabled: bool = False
    category: str = ""

class RuleState(BaseModel):
    rule_id: str
    enabled: bool
    category: str = ""

# BulkRuleState model removed as it's no longer needed

def update_processing_stats():
    current_time = time.time()
    stats["last_minute_logs"].append((current_time, stats["processed_logs"]))
    if len(stats["last_minute_logs"]) > 1:
        oldest_time, oldest_count = stats["last_minute_logs"][0]
        newest_time, newest_count = stats["last_minute_logs"][-1]
        time_diff = newest_time - oldest_time
        if time_diff > 0:
            stats["processing_rate"] = int((newest_count - oldest_count) / time_diff)

def update_alert_stats(new_alert: bool = False):
    current_time = datetime.now()
    if new_alert:
        stats["alerts"].append(current_time)
    cutoff_time = current_time - timedelta(hours=24)
    while stats["alerts"] and stats["alerts"][0] < cutoff_time:
        stats["alerts"].popleft()
    stats["alerts_last_24h"] = len(stats["alerts"])
async def setup_rules_directory():
    """Verify the rules directory is properly set up."""
    rules_dir = "/app/rules"
    
    try:
        # Check if the rules directory exists
        if not os.path.exists(rules_dir):
            logger.error(f"Rules directory {rules_dir} does not exist")
            return False
            
        # Check if the rules subdirectory exists (this is where actual rules are in the Sigma repo)
        rules_subdir = os.path.join(rules_dir, "rules")
        if not os.path.exists(rules_subdir):
            logger.error(f"Rules subdirectory {rules_subdir} does not exist")
            return False
            
        # Count the number of rule files
        rule_count = 0
        for root, _, files in os.walk(rules_subdir):
            for file in files:
                if file.endswith('.yml') or file.endswith('.yaml'):
                    rule_count += 1
                    
        if rule_count == 0:
            logger.error("No rule files found in the rules directory")
            return False
            
        logger.info(f"Found {rule_count} rule files in the rules directory")
        return True
    except Exception as e:
        logger.error(f"Failed to verify rules directory: {str(e)}")
        return False
        return False

def get_rule_category(file_path: str, rules_dir: str) -> str:
    try:
        relative_path = os.path.relpath(file_path, os.path.join(rules_dir, "rules"))
        path_parts = os.path.dirname(relative_path).split(os.sep)
        category_path = '/'.join(filter(None, path_parts))
        return category_path if category_path else "uncategorized"
    except Exception as e:
        logger.error(f"Error extracting category from path {file_path}: {str(e)}")
        return "uncategorized"

async def load_rules():
    """Load all rules from the Sigma repository with retries."""
    rules = []
    rules_dir = "/app/rules"
    max_retries = 3
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            # Verify rules directory is properly set up
            if not await setup_rules_directory():
                logger.warning(f"Failed to verify rules directory (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    logger.error("Failed to verify rules directory after all retries")
                    stats["status"] = "degraded"
                    return rules

            rules_base_dir = os.path.join(rules_dir, "rules")
            
            # Count of processed files for logging
            processed_files = 0
            valid_rules = 0
            
            # Walk through all directories under rules/
            for root, _, files in os.walk(rules_base_dir):
                for file in files:
                    if file.endswith('.yml') or file.endswith('.yaml'):
                        processed_files += 1
                        try:
                            file_path = os.path.join(root, file)
                            with open(file_path) as f:
                                data = yaml.safe_load(f)
                                if not isinstance(data, dict):
                                    continue
                                    
                                if 'detection' not in data or 'title' not in data:
                                    continue
                                
                                # Valid rule found
                                valid_rules += 1
                                rule_id = data.get('id', os.path.splitext(file)[0])
                                category = get_rule_category(file_path, rules_dir)
                                enabled = rule_states.get(rule_id, False)
                                
                                rules.append(Rule(
                                    id=rule_id,
                                    title=data['title'],
                                    description=data.get('description', ''),
                                    level=data.get('level', 'medium'),
                                    detection=data['detection'],
                                    logsource=data.get('logsource', {}),
                                    enabled=enabled,
                                    category=category
                                ))
                                
                                # Log progress periodically
                                if valid_rules % 100 == 0:
                                    logger.info(f"Loaded {valid_rules} valid rules so far...")
                                    
                        except Exception as e:
                            logger.error(f"Error loading rule {file}: {str(e)}")
                            continue

            # Update stats
            stats["total_rules"] = len(rules)
            stats["enabled_rules"] = len([r for r in rules if r.enabled])
            stats["rules_loaded"] = True
            stats["status"] = "operational"
            logger.info(f"Successfully loaded {len(rules)} rules from {processed_files} processed files")
            return rules

        except Exception as e:
            logger.error(f"Error loading rules (attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                stats["status"] = "degraded"
                return rules

# Function removed - no longer needed

def match_rule(rule: Rule, log_entry: Dict[str, Any]) -> bool:
    try:
        # Check log source requirements
        if rule.logsource:
            source = log_entry.get('source', '').lower()
            if rule.logsource.get('product') and rule.logsource['product'].lower() not in source:
                return False
            if rule.logsource.get('service') and rule.logsource['service'].lower() not in source:
                return False

        # Get metadata from log entry
        metadata = log_entry.get('metadata', {}) or log_entry.get('log_metadata', {})
        logger.info(f"Processing rule {rule.id} against log entry metadata: {json.dumps(metadata)}")
        
        detection = rule.detection
        logger.info(f"Rule detection criteria: {json.dumps(detection)}")

        # Check if this rule should apply based on log source
        if 'product' in metadata and rule.logsource.get('product'):
            if metadata['product'].lower() != rule.logsource['product'].lower():
                return False
        if 'category' in metadata and rule.logsource.get('category'):
            if metadata['category'].lower() != rule.logsource['category'].lower():
                return False

        # Handle selection with field|contains
        if 'selection' in detection:
            selection = detection['selection']
            if not isinstance(selection, dict):
                return False

            # All fields in selection must match
            for field, values in selection.items():
                if '|contains' in field:
                    actual_field = field.split('|')[0]
                    field_value = str(metadata.get(actual_field, '')).lower()
                    if isinstance(values, list):
                        if not any(str(v).lower() in field_value for v in values):
                            return False
                    else:
                        if str(values).lower() not in field_value:
                            return False
                else:
                    # Exact match for fields without operators
                    field_value = str(metadata.get(field, '')).lower()
                    if isinstance(values, list):
                        if str(field_value).lower() not in [str(v).lower() for v in values]:
                            return False
                    else:
                        if str(field_value).lower() != str(values).lower():
                            return False
            return True  # Only return True if all fields matched

        # Handle keywords
        if 'keywords' in detection:
            log_str = json.dumps(log_entry).lower()
            keywords = detection['keywords']
            if isinstance(keywords, list):
                return any(kw.lower() in log_str for kw in keywords)
            return keywords.lower() in log_str

        logger.debug(f"Rule {rule.id} didn't match log entry: {json.dumps(log_entry)}")
        return False

    except Exception as e:
        logger.error(f"Error matching rule: {str(e)}")
        return False

def match_ocsf_rule(rule: Rule, log_entry: Dict[str, Any]) -> bool:
    """Match a rule against an OCSF log entry."""
    try:
        # Check log source requirements
        if rule.logsource:
            # Map OCSF category to Sigma logsource
            category_name = log_entry.get('category_name', '').lower()
            
            # Map common OCSF categories to Sigma logsource categories
            category_mapping = {
                'system': ['system', 'sysmon', 'windows', 'linux'],
                'network': ['network', 'proxy', 'firewall'],
                'identity & access management': ['auth', 'authentication', 'windows', 'linux'],
                'file system': ['file', 'filesystem', 'windows', 'linux'],
                'process': ['process', 'process_creation', 'windows', 'linux'],
                'database': ['database', 'db'],
                'application': ['application', 'web']
            }
            
            # Check if rule applies to this log category
            if rule.logsource.get('category'):
                rule_category = rule.logsource['category'].lower()
                mapped_categories = []
                
                # Find mapped categories for this OCSF category
                for ocsf_cat, sigma_cats in category_mapping.items():
                    if ocsf_cat.lower() in category_name:
                        mapped_categories.extend(sigma_cats)
                
                # If we have mapped categories but rule category doesn't match any
                if mapped_categories and rule_category not in mapped_categories:
                    return False
        
        # Get raw event from log entry
        raw_event = log_entry.get('raw_event', {})
        
        # Combine raw_event with top-level fields for more comprehensive matching
        combined_data = {**raw_event, **log_entry}
        
        logger.info(f"Processing rule {rule.id} against OCSF log entry: {json.dumps(combined_data)}")
        
        detection = rule.detection
        logger.info(f"Rule detection criteria: {json.dumps(detection)}")

        # Handle selection with field|contains
        if 'selection' in detection:
            selection = detection['selection']
            if not isinstance(selection, dict):
                return False

            # All fields in selection must match
            for field, values in selection.items():
                if '|contains' in field:
                    actual_field = field.split('|')[0]
                    field_value = str(combined_data.get(actual_field, '')).lower()
                    if isinstance(values, list):
                        if not any(str(v).lower() in field_value for v in values):
                            return False
                    else:
                        if str(values).lower() not in field_value:
                            return False
                else:
                    # Exact match for fields without operators
                    field_value = str(combined_data.get(field, '')).lower()
                    if isinstance(values, list):
                        if str(field_value).lower() not in [str(v).lower() for v in values]:
                            return False
                    else:
                        if str(field_value).lower() != str(values).lower():
                            return False
            return True  # Only return True if all fields matched

        # Handle keywords
        if 'keywords' in detection:
            log_str = json.dumps(combined_data).lower()
            keywords = detection['keywords']
            if isinstance(keywords, list):
                return any(kw.lower() in log_str for kw in keywords)
            return keywords.lower() in log_str

        logger.debug(f"Rule {rule.id} didn't match OCSF log entry: {json.dumps(log_entry)}")
        return False

    except Exception as e:
        logger.error(f"Error matching OCSF rule: {str(e)}")
        return False

@app.post("/analyze")
async def analyze_log(log_entry: Dict[str, Any]):
    try:
        # Determine log format (OCSF or standard)
        is_ocsf = log_entry.get('format') == 'ocsf' or 'category_name' in log_entry
        
        # Skip analysis for internal service logs (only for standard logs)
        if not is_ocsf and log_entry.get('source') in INTERNAL_SERVICES:
            return {"alerts": []}

        # Check for duplicate log processing
        log_id = log_entry.get('id')
        if log_id is not None:
            if log_id in stats["processed_log_ids"]:
                logger.info(f"Skipping duplicate log ID: {log_id}")
                return {"alerts": []}
            stats["processed_log_ids"].append(log_id)

        stats["processed_logs"] += 1
        update_processing_stats()

        # Find the first matching rule only
        matched_rule = None
        for rule in sigma_rules:
            if not rule.enabled:
                continue
                
            if is_ocsf:
                # For OCSF logs, use category_name for matching
                if match_ocsf_rule(rule, log_entry):
                    matched_rule = rule
                    break
            else:
                # For standard logs, use the existing match_rule function
                if match_rule(rule, log_entry):
                    matched_rule = rule
                    break

        if matched_rule:
            # Determine log source based on format
            log_source = log_entry.get('category_name', 'unknown') if is_ocsf else log_entry.get('source', 'unknown')
            
            alert = Alert(
                rule_id=matched_rule.id,
                rule_name=matched_rule.title,
                timestamp=datetime.now(),
                log_source=log_source,
                matched_log=log_entry,
                severity=matched_rule.level
            )
            update_alert_stats(new_alert=True)
            return {"alerts": [alert.dict()]}
        
        return {"alerts": []}
    except Exception as e:
        logger.error(f"Error analyzing log: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/rules")
async def list_rules():
    return {
        "total": len(sigma_rules),
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.level,
                "description": rule.description,
                "enabled": rule.enabled,
                "category": rule.category
            }
            for rule in sigma_rules
        ]
    }

@app.post("/rules/toggle")
async def toggle_rule(rule_state: RuleState):
    try:
        # Update local state
        rule_states[rule_state.rule_id] = rule_state.enabled
        rule_found = False
        
        for rule in sigma_rules:
            if rule.id == rule_state.rule_id:
                rule.enabled = rule_state.enabled
                rule_found = True
                break
        
        if not rule_found:
            raise HTTPException(status_code=404, detail=f"Rule {rule_state.rule_id} not found")
        
        # No need to persist to API anymore - API handles that directly
        
        stats["enabled_rules"] = len([r for r in sigma_rules if r.enabled])
        return {
            "success": True,
            "message": f"Rule {rule_state.rule_id} {'enabled' if rule_state.enabled else 'disabled'}"
        }
    except Exception as e:
        logger.error(f"Error toggling rule: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

# Bulk toggle endpoint removed as requested
    except Exception as e:
        logger.error(f"Error bulk toggling rules: {str(e)}")
        logger.error(f"Exception details: {traceback.format_exc()}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        return {
            "enabled_rules": stats["enabled_rules"],
            "total_rules": stats["total_rules"],
            "alerts_last_24h": stats["alerts_last_24h"],
            "processing_rate": stats["processing_rate"],
            "status": stats["status"],
            "uptime": int(time.time() - stats["start_time"]),
            "system_metrics": {
                "cpu_usage": cpu_usage,
                "memory_usage": memory.percent
            }
        }
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint with improved status reporting."""
    try:
        # Basic health criteria
        rules_dir_exists = os.path.exists("/app/rules")
        rules_loaded = stats["rules_loaded"]

        # Determine status
        if not rules_dir_exists:
            status = "degraded"
        elif not rules_loaded:
            status = "starting"
        else:
            status = stats["status"]

        return {
            "status": status,
            "rules_loaded": len(sigma_rules),
            "timestamp": datetime.now().isoformat(),
            "details": {
                "rules_dir_exists": rules_dir_exists,
                "rules_loaded": rules_loaded,
                "enabled_rules": stats["enabled_rules"]
            }
        }
    except Exception as e:
        logger.error(f"Error in health check: {str(e)}")
        return {
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.on_event("startup")
async def startup_event():
    """Initialize the detection engine with improved error handling and retries."""
    global sigma_rules, rule_states
    logger.info("Starting detection engine...")
    
    # Set initial status
    stats["status"] = "starting"
    
    # Wait a bit to ensure the rules directory is fully set up by the start.sh script
    logger.info("Waiting for rules directory to be fully set up...")
    await asyncio.sleep(5)
    
    # Maximum number of retries for API operations
    max_retries = 5
    retry_delay = 3  # seconds
    
    # Try to load rule states from API with retries
    for attempt in range(max_retries):
        try:
            # First load rule states from API
            api_states = await get_rule_states_from_api()
            if api_states:
                rule_states.update(api_states)
                logger.info(f"Loaded {len(api_states)} rule states from API")
            break  # Success, exit retry loop
        except Exception as e:
            logger.warning(f"Error loading rule states (attempt {attempt+1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Failed to load rule states after all retries")
    
    # Load rules (which has its own retry mechanism)
    try:
        sigma_rules = await load_rules()
        if sigma_rules:
            logger.info(f"Successfully loaded {len(sigma_rules)} detection rules")
            stats["status"] = "operational"
        else:
            logger.warning("No rules were loaded, service may be degraded")
            stats["status"] = "degraded"
    except Exception as e:
        logger.error(f"Error loading rules during startup: {str(e)}")
        stats["status"] = "degraded"
    
    # Start background task to periodically refresh rule states
    asyncio.create_task(refresh_rule_states_periodically())
        
    # Log startup completion status
    logger.info(f"Detection engine startup completed with status: {stats['status']}")

async def refresh_rule_states_periodically():
    """Periodically refresh rule states from API."""
    logger.info("Starting background task to refresh rule states")
    refresh_interval = 60  # seconds
    
    while True:
        await asyncio.sleep(refresh_interval)
        try:
            # Refresh rule states from API
            api_states = await get_rule_states_from_api()
            if api_states:
                # Update global rule_states
                rule_states.update(api_states)
                
                # Update rule enabled states in memory
                updated_count = 0
                for rule in sigma_rules:
                    if rule.id in api_states:
                        if rule.enabled != api_states[rule.id]:
                            rule.enabled = api_states[rule.id]
                            updated_count += 1
                
                # Update stats
                stats["enabled_rules"] = len([r for r in sigma_rules if r.enabled])
                
                if updated_count > 0:
                    logger.info(f"Refreshed rule states from API: updated {updated_count} rules, {stats['enabled_rules']} of {stats['total_rules']} rules enabled")
        except Exception as e:
            logger.error(f"Error refreshing rule states from API: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)