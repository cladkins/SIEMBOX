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

async def update_rule_state_in_api(rule_id: str, enabled: bool):
    """Update rule state in API service."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://api:8080/api/rule-states/{rule_id}",
                params={"enabled": enabled}
            ) as response:
                if response.status == 200:
                    return True
    except Exception as e:
        logger.error(f"Error updating rule state in API: {str(e)}")
    return False

async def update_bulk_rule_states_in_api(rule_states_dict: Dict[str, bool]):
    """Update multiple rule states in API service."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://api:8080/api/rule-states/bulk",
                json=rule_states_dict
            ) as response:
                if response.status == 200:
                    return True
    except Exception as e:
        logger.error(f"Error updating bulk rule states in API: {str(e)}")
    return False

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

class BulkRuleState(BaseModel):
    enabled: bool
    category: str = ""

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
        # Check if the rules directory exists and has content
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

@app.post("/analyze")
async def analyze_log(log_entry: Dict[str, Any]):
    try:
        # Skip analysis for internal service logs
        if log_entry.get('source') in INTERNAL_SERVICES:
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
            if rule.enabled and match_rule(rule, log_entry):
                matched_rule = rule
                break

        if matched_rule:
            alert = Alert(
                rule_id=matched_rule.id,
                rule_name=matched_rule.title,
                timestamp=datetime.now(),
                log_source=log_entry.get('source', 'unknown'),
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
        # Update local state first
        rule_states[rule_state.rule_id] = rule_state.enabled
        rule_found = False
        
        for rule in sigma_rules:
            if rule.id == rule_state.rule_id:
                rule.enabled = rule_state.enabled
                rule_found = True
                break
        
        if not rule_found:
            raise HTTPException(status_code=404, detail=f"Rule {rule_state.rule_id} not found")
        
        # Then try to persist to API
        if not await update_rule_state_in_api(rule_state.rule_id, rule_state.enabled):
            logger.warning(f"Failed to persist rule state to API for {rule_state.rule_id}")
        
        stats["enabled_rules"] = len([r for r in sigma_rules if r.enabled])
        return {
            "success": True,
            "message": f"Rule {rule_state.rule_id} {'enabled' if rule_state.enabled else 'disabled'}"
        }
    except Exception as e:
        logger.error(f"Error toggling rule: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rules/bulk-toggle")
async def bulk_toggle_rules(state: BulkRuleState):
    try:
        # Update local state first
        updated_rules = {}
        updated_count = 0
        
        for rule in sigma_rules:
            if state.category and rule.category != state.category:
                continue
            rule.enabled = state.enabled
            rule_states[rule.id] = state.enabled
            updated_rules[rule.id] = state.enabled
            updated_count += 1

        # Then try to persist to API
        if updated_count > 0:
            if not await update_bulk_rule_states_in_api(updated_rules):
                logger.warning(f"Failed to persist {updated_count} rule states to API")

        stats["enabled_rules"] = len([r for r in sigma_rules if r.enabled])
        category_msg = f" in category '{state.category}'" if state.category else ""
        return {
            "success": True,
            "message": f"{updated_count} rules{category_msg} {'enabled' if state.enabled else 'disabled'}",
            "updated_count": updated_count
        }
    except Exception as e:
        logger.error(f"Error bulk toggling rules: {str(e)}")
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
        
    # Log startup completion status
    logger.info(f"Detection engine startup completed with status: {stats['status']}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)