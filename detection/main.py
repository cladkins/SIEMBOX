from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime, timedelta
import logging
import json
import asyncio
from typing import Dict, Any, List
import aiohttp
import os
import yaml
import re
import shutil
import subprocess
import time
import collections
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="SIEMBox Detection Engine")

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
    "status": "operational",
    "start_time": time.time(),
    "processed_logs": 0,
    "last_minute_logs": collections.deque(maxlen=60),  # Store last minute's worth of logs
    "alerts": collections.deque(maxlen=1440)  # Store last 24 hours worth of alerts (1 minute intervals)
}

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
    enabled: bool = False  # Default to disabled
    category: str = ""     # Full category path

class RuleState(BaseModel):
    """Model for rule state updates."""
    rule_id: str
    enabled: bool
    category: str = ""

class BulkRuleState(BaseModel):
    """Model for bulk rule state updates."""
    enabled: bool
    category: str = ""  # Optional: to update rules of a specific category

def update_processing_stats():
    """Update processing rate statistics."""
    current_time = time.time()
    stats["last_minute_logs"].append((current_time, stats["processed_logs"]))
    
    # Calculate processing rate over the last minute
    if len(stats["last_minute_logs"]) > 1:
        oldest_time, oldest_count = stats["last_minute_logs"][0]
        newest_time, newest_count = stats["last_minute_logs"][-1]
        time_diff = newest_time - oldest_time
        if time_diff > 0:
            stats["processing_rate"] = int((newest_count - oldest_count) / time_diff)

def update_alert_stats(new_alert: bool = False):
    """Update alert statistics."""
    current_time = datetime.now()
    if new_alert:
        stats["alerts"].append(current_time)
    
    # Clean up old alerts (older than 24 hours)
    cutoff_time = current_time - timedelta(hours=24)
    while stats["alerts"] and stats["alerts"][0] < cutoff_time:
        stats["alerts"].popleft()
    
    stats["alerts_last_24h"] = len(stats["alerts"])

def setup_rules_directory():
    """Clone or update Sigma rules repository."""
    rules_dir = "/app/rules"
    try:
        # Create directory if it doesn't exist
        os.makedirs(rules_dir, exist_ok=True)
        
        # Check if it's already a git repo
        if os.path.exists(os.path.join(rules_dir, ".git")):
            logger.info("Updating Sigma rules repository...")
            result = subprocess.run(["git", "-C", rules_dir, "pull"], capture_output=True, text=True)
            if result.returncode == 0:
                return True
        
        # Clean directory contents but keep the directory
        for item in os.listdir(rules_dir):
            item_path = os.path.join(rules_dir, item)
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
        
        # Clone repository
        logger.info("Cloning Sigma rules repository...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/SigmaHQ/sigma.git", "."],
            cwd=rules_dir,
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to setup rules directory: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Failed to setup rules directory: {str(e)}")
        return False

def get_rule_category(file_path: str, rules_dir: str) -> str:
    """Extract category from rule file path."""
    try:
        # Remove rules_dir prefix and 'rules/' from path
        relative_path = os.path.relpath(file_path, os.path.join(rules_dir, "rules"))
        # Split path and remove filename
        path_parts = os.path.dirname(relative_path).split(os.sep)
        # Filter out empty strings and join with forward slashes
        category_path = '/'.join(filter(None, path_parts))
        return category_path if category_path else "uncategorized"
    except Exception as e:
        logger.error(f"Error extracting category from path {file_path}: {str(e)}")
        return "uncategorized"

def load_rules():
    """Load all rules from the Sigma repository."""
    rules = []
    rules_dir = "/app/rules"
    
    if not setup_rules_directory():
        logger.warning("Using existing rules directory without update")
    
    rules_base_dir = os.path.join(rules_dir, "rules")
    if not os.path.exists(rules_base_dir):
        logger.error(f"Rules directory not found: {rules_base_dir}")
        return rules

    # Walk through all directories under rules/
    for root, _, files in os.walk(rules_base_dir):
        for file in files:
            if file.endswith('.yml'):
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path) as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict):
                            if 'detection' in data and 'title' in data:
                                rule_id = data.get('id', file)
                                category = get_rule_category(file_path, rules_dir)
                                
                                # Use stored state or default to disabled
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
                except Exception as e:
                    logger.error(f"Error loading rule {file}: {str(e)}")
    
    # Update stats
    stats["total_rules"] = len(rules)
    stats["enabled_rules"] = len([r for r in rules if r.enabled])
    
    return rules

def match_rule(rule: Rule, log_entry: Dict[str, Any]) -> bool:
    """Check if a log entry matches a rule."""
    try:
        log_str = json.dumps(log_entry).lower()
        
        # Check log source
        if rule.logsource:
            source = log_entry.get('source', '').lower()
            if rule.logsource.get('product') and rule.logsource['product'].lower() not in source:
                return False
            if rule.logsource.get('service') and rule.logsource['service'].lower() not in source:
                return False
        
        # Check detection patterns
        detection = rule.detection
        if 'keywords' in detection:
            keywords = detection['keywords']
            if isinstance(keywords, list):
                return any(kw.lower() in log_str for kw in keywords)
            return keywords.lower() in log_str
        
        if 'selection' in detection:
            selection = detection['selection']
            if isinstance(selection, dict):
                return all(str(v).lower() in log_str for v in selection.values())
        
        return False
    except Exception as e:
        logger.error(f"Error matching rule: {str(e)}")
        return False

@app.post("/analyze")
async def analyze_log(log_entry: Dict[str, Any]):
    """Analyze a log entry against detection rules."""
    alerts = []
    try:
        stats["processed_logs"] += 1
        update_processing_stats()
        
        for rule in sigma_rules:
            if rule.enabled and match_rule(rule, log_entry):
                alert = Alert(
                    rule_id=rule.id,
                    rule_name=rule.title,
                    timestamp=datetime.now(),
                    log_source=log_entry.get('source', 'unknown'),
                    matched_log=log_entry,
                    severity=rule.level
                )
                alerts.append(alert)
                update_alert_stats(new_alert=True)
                
        return {"alerts": [alert.dict() for alert in alerts]}
    except Exception as e:
        logger.error(f"Error analyzing log: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/rules")
async def list_rules():
    """List all loaded rules."""
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
    """Toggle a rule's enabled state."""
    try:
        # Update rule state in memory
        rule_states[rule_state.rule_id] = rule_state.enabled
        
        # Update rule in sigma_rules list
        for rule in sigma_rules:
            if rule.id == rule_state.rule_id:
                rule.enabled = rule_state.enabled
                # Update stats
                stats["enabled_rules"] = len([r for r in sigma_rules if r.enabled])
                return {
                    "success": True,
                    "message": f"Rule {rule_state.rule_id} {'enabled' if rule_state.enabled else 'disabled'}"
                }
        
        raise HTTPException(status_code=404, detail=f"Rule {rule_state.rule_id} not found")
    except Exception as e:
        logger.error(f"Error toggling rule: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rules/bulk-toggle")
async def bulk_toggle_rules(state: BulkRuleState):
    """Toggle all rules or rules of a specific category."""
    try:
        updated_count = 0
        for rule in sigma_rules:
            # If category is specified, only update rules in that category
            if state.category and rule.category != state.category:
                continue
                
            rule.enabled = state.enabled
            rule_states[rule.id] = state.enabled
            updated_count += 1
        
        # Update stats
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
    """Get detection engine statistics."""
    try:
        # Get system metrics
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
    """Health check endpoint."""
    return {
        "status": stats["status"],
        "rules_loaded": len(sigma_rules),
        "timestamp": datetime.now().isoformat()
    }

@app.on_event("startup")
async def startup_event():
    """Initialize the detection engine."""
    global sigma_rules
    logger.info("Starting detection engine...")
    sigma_rules = load_rules()
    logger.info(f"Loaded {len(sigma_rules)} detection rules")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)