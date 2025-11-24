"""
SIEM BOX - Detection Engine Service
"""
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, and_, or_, select
from app.models.logs import ProcessedLog, ParsedLog, DetectionRule, Alert
from app.schemas.parsing import AlertCreate, DetectionRuleCreate
from app.services.notification_service import notification_service
import logging
import asyncio

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Security event detection engine with configurable rules
    """
    
    def __init__(self):
        self.rule_processors = {
            "threshold": self._process_threshold_rule,
            "pattern": self._process_pattern_rule,
            "correlation": self._process_correlation_rule,
            "anomaly": self._process_anomaly_rule
        }
        self.load_default_rules()
    
    def load_default_rules(self) -> List[DetectionRuleCreate]:
        """Load default detection rules"""
        default_rules = [
            {
                "name": "SSH Brute Force Attack",
                "description": "Detects multiple failed SSH login attempts from the same IP",
                "rule_type": "threshold",
                "severity": "high",
                "category": "brute_force",
                "conditions": {
                    "log_type": "authentication",
                    "field_conditions": {
                        "action": "Failed"
                    },
                    "threshold": {
                        "count": 5,
                        "time_window": 300,  # 5 minutes
                        "group_by": ["src_ip"]
                    }
                },
                "is_enabled": True
            },
            {
                "name": "High Volume Firewall Blocks",
                "description": "Detects high volume of blocked connections from single IP",
                "rule_type": "threshold", 
                "severity": "medium",
                "category": "network_scan",
                "conditions": {
                    "log_type": "firewall",
                    "field_conditions": {
                        "action": "BLOCK"
                    },
                    "threshold": {
                        "count": 20,
                        "time_window": 600,  # 10 minutes
                        "group_by": ["src_ip"]
                    }
                },
                "is_enabled": True
            },
            {
                "name": "Web Application Attack Patterns",
                "description": "Detects common web attack patterns in URLs",
                "rule_type": "pattern",
                "severity": "high",
                "category": "web_attack",
                "conditions": {
                    "log_type": "web_access",
                    "patterns": [
                        r"(?i)(union.*select|select.*from|insert.*into|delete.*from)",  # SQL injection
                        r"(?i)(<script|javascript:|onload=|onerror=)",  # XSS
                        r"(?i)(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/system32)",  # Path traversal
                        r"(?i)(cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)"  # Command injection
                    ],
                    "field": "url"
                },
                "is_enabled": True
            },
            {
                "name": "Suspicious User Agent",
                "description": "Detects suspicious or malicious user agents",
                "rule_type": "pattern",
                "severity": "medium",
                "category": "reconnaissance",
                "conditions": {
                    "log_type": "web_access",
                    "patterns": [
                        r"(?i)(nmap|nikto|sqlmap|burp|metasploit)",
                        r"(?i)(bot|crawler|spider|scraper)",
                        r"^$",  # Empty user agent
                        r"(?i)(curl|wget|python-requests)"
                    ],
                    "field": "user_agent"
                },
                "is_enabled": True
            },
            {
                "name": "Multiple Failed Logins Different Users",
                "description": "Detects attempts to login with multiple different usernames",
                "rule_type": "threshold",
                "severity": "medium",
                "category": "credential_stuffing",
                "conditions": {
                    "log_type": "authentication",
                    "field_conditions": {
                        "action": "Failed"
                    },
                    "threshold": {
                        "count": 10,
                        "time_window": 600,  # 10 minutes
                        "group_by": ["src_ip"],
                        "unique_field": "username"
                    }
                },
                "is_enabled": True
            },
            {
                "name": "Successful Login After Failed Attempts",
                "description": "Detects successful login after multiple failed attempts",
                "rule_type": "correlation",
                "severity": "high",
                "category": "successful_brute_force",
                "conditions": {
                    "sequence": [
                        {
                            "log_type": "authentication",
                            "field_conditions": {"action": "Failed"},
                            "min_count": 3,
                            "time_window": 300
                        },
                        {
                            "log_type": "authentication", 
                            "field_conditions": {"action": "Accepted"},
                            "time_window": 60
                        }
                    ],
                    "correlation_field": "src_ip"
                },
                "is_enabled": True
            },
            {
                "name": "HTTP Error Rate Spike",
                "description": "Detects unusual spike in HTTP error responses",
                "rule_type": "anomaly",
                "severity": "medium",
                "category": "application_error",
                "conditions": {
                    "log_type": "web_access",
                    "field_conditions": {
                        "status_code": ["4xx", "5xx"]
                    },
                    "anomaly": {
                        "baseline_window": 3600,  # 1 hour baseline
                        "detection_window": 300,  # 5 minute detection window
                        "threshold_multiplier": 3.0,
                        "min_baseline_count": 10
                    }
                },
                "is_enabled": True
            }
        ]
        
        return [DetectionRuleCreate(**rule) for rule in default_rules]
    
    async def apply_rules(self, db: AsyncSession, parsed_log_ids: List[str], 
                   rule_ids: Optional[List[str]] = None) -> Tuple[int, int, List[str]]:
        """
        Apply detection rules to parsed logs
        
        Returns:
            Tuple of (alerts_generated, rules_applied, errors)
        """
        alerts_generated = 0
        rules_applied = 0
        errors = []
        created_alerts: List[Alert] = []
        
        # Get rules to apply
        query = select(DetectionRule).filter(DetectionRule.is_enabled == True)
        if rule_ids:
            query = query.filter(DetectionRule.id.in_(rule_ids))
        
        result = await db.execute(query)
        rules = result.scalars().all()
        
        for rule in rules:
            try:
                rule_alerts = self._apply_single_rule(db, rule, parsed_log_ids)
                alerts_generated += len(rule_alerts)
                rules_applied += 1
                
                # Create alert records
                new_alerts: List[Alert] = []
                for alert_data in rule_alerts:
                    alert = Alert(**alert_data.dict())
                    db.add(alert)
                    new_alerts.append(alert)
                created_alerts.extend(new_alerts)
                    
            except Exception as e:
                logger.error(f"Error applying rule {rule.name}: {e}")
                errors.append(f"Rule {rule.name}: {str(e)}")
        
        try:
            await db.commit()
            
            # Send notifications for created alerts (async in background)
            if created_alerts:
                self._send_alert_notifications_background(db, created_alerts)
                
        except Exception as e:
            await db.rollback()
            logger.error(f"Database error during detection: {e}")
            errors.append(f"Database error: {str(e)}")
        
        return alerts_generated, rules_applied, errors
    
    async def apply_rules_to_processed_logs(self, db: AsyncSession, processed_log_ids: List[str], 
                                           rule_ids: Optional[List[str]] = None) -> Tuple[int, int, List[str]]:
        """
        Apply detection rules to processed logs stored locally
        
        Returns:
            Tuple of (alerts_generated, rules_applied, errors)
        """
        alerts_generated = 0
        rules_applied = 0
        errors = []
        created_alerts: List[Alert] = []
        
        # Get rules to apply
        query = select(DetectionRule).filter(DetectionRule.is_enabled == True)
        if rule_ids:
            query = query.filter(DetectionRule.id.in_(rule_ids))
        
        result = await db.execute(query)
        rules = result.scalars().all()
        
        for rule in rules:
            try:
                rule_alerts = await self._apply_single_rule_to_processed_logs(db, rule, processed_log_ids)
                alerts_generated += len(rule_alerts)
                rules_applied += 1
                
                # Create alert records
                new_alerts: List[Alert] = []
                for alert_data in rule_alerts:
                    alert = Alert(**alert_data.dict())
                    db.add(alert)
                    new_alerts.append(alert)
                created_alerts.extend(new_alerts)
                    
            except Exception as e:
                logger.error(f"Error applying rule {rule.name} to processed logs: {e}")
                errors.append(f"Rule {rule.name}: {str(e)}")
        
        try:
            await db.commit()
            
            # Send notifications for created alerts (async in background)
            if created_alerts:
                self._send_alert_notifications_background(db, created_alerts)
                
        except Exception as e:
            await db.rollback()
            logger.error(f"Database error during detection: {e}")
            errors.append(f"Database error: {str(e)}")
        
        return alerts_generated, rules_applied, errors
    
    async def _apply_single_rule_to_processed_logs(self, db: AsyncSession, rule: DetectionRule,
                                                 processed_log_ids: List[str]) -> List[AlertCreate]:
        """Apply a single detection rule to processed logs"""
        
        rule_type = rule.rule_type
        if rule_type not in self.rule_processors:
            raise ValueError(f"Unknown rule type: {rule_type}")
        
        # Create a modified processor for processed logs
        if rule_type == "threshold":
            return await self._process_threshold_rule_processed_logs(db, rule, processed_log_ids)
        elif rule_type == "pattern":
            return await self._process_pattern_rule_processed_logs(db, rule, processed_log_ids)
        elif rule_type == "correlation":
            return await self._process_correlation_rule_processed_logs(db, rule, processed_log_ids)
        elif rule_type == "anomaly":
            return await self._process_anomaly_rule_processed_logs(db, rule, processed_log_ids)
        else:
            raise ValueError(f"Rule type {rule_type} not implemented for processed logs")
    
    async def _process_threshold_rule_processed_logs(self, db: AsyncSession, rule: DetectionRule,
                                                   processed_log_ids: List[str]) -> List[AlertCreate]:
        """Process threshold-based detection rules for processed logs"""
        alerts = []
        conditions = rule.conditions
        
        # Build base query for ProcessedLog instead of ParsedLog
        query = select(ProcessedLog)
        
        # Filter by log type
        if "log_type" in conditions:
            query = query.filter(ProcessedLog.log_type == conditions["log_type"])
        
        # Apply time window
        threshold_config = conditions["threshold"]
        time_window = threshold_config["time_window"]
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        query = query.filter(ProcessedLog.timestamp >= cutoff_time)

        result = await db.execute(query)
        logs = result.scalars().all()

        # Apply field conditions in Python to support multiple dialects
        field_conditions = conditions.get("field_conditions", {})
        if field_conditions:
            filtered_logs = []
            for log in logs:
                processed_fields = log.processed_fields or {}
                if all(str(processed_fields.get(field)) == str(value) for field, value in field_conditions.items()):
                    filtered_logs.append(log)
            logs = filtered_logs
        
        # Group by specified fields
        group_by_fields = threshold_config.get("group_by", [])
        
        if group_by_fields:
            # Execute query to get logs
            grouped_logs = {}
            
            for log in logs:
                # Create grouping key
                key_parts = []
                for field in group_by_fields:
                    value = log.processed_fields.get(field, "unknown")
                    key_parts.append(str(value))
                group_key = "|".join(key_parts)
                
                if group_key not in grouped_logs:
                    grouped_logs[group_key] = []
                grouped_logs[group_key].append(log)
            
            # Check thresholds for each group
            threshold_count = threshold_config["count"]
            
            for group_key, group_logs in grouped_logs.items():
                if len(group_logs) >= threshold_count:
                    # Check for unique field requirement
                    if "unique_field" in threshold_config:
                        unique_field = threshold_config["unique_field"]
                        unique_values = set()
                        for log in group_logs:
                            value = log.processed_fields.get(unique_field)
                            if value:
                                unique_values.add(value)
                        
                        if len(unique_values) < threshold_count:
                            continue
                    
                    # Create alert
                    alert_data = self._create_alert_data_for_processed_log(
                        rule, group_logs[0], 
                        f"Threshold exceeded: {len(group_logs)} events in {time_window}s",
                        {"group_key": group_key, "event_count": len(group_logs), "events": [str(log.id) for log in group_logs]}
                    )
                    alerts.append(alert_data)
        
        return alerts
    
    async def _process_pattern_rule_processed_logs(self, db: AsyncSession, rule: DetectionRule,
                                                 processed_log_ids: List[str]) -> List[AlertCreate]:
        """Process pattern-based detection rules for processed logs"""
        alerts = []
        conditions = rule.conditions
        
        # Build base query
        query = select(ProcessedLog)
        
        # Filter by log type
        if "log_type" in conditions:
            query = query.filter(ProcessedLog.log_type == conditions["log_type"])
        
        # Get field to check
        field_name = conditions.get("field", "message")
        patterns = conditions.get("patterns", [])
        
        result = await db.execute(query)
        logs = result.scalars().all()
        
        for log in logs:
            # Check both processed_fields and direct attributes
            if field_name in log.processed_fields:
                field_value = log.processed_fields[field_name]
            else:
                field_value = getattr(log, field_name, log.raw_message)
            
            if not field_value:
                continue
            
            # Check each pattern
            for pattern in patterns:
                import re
                if re.search(pattern, str(field_value)):
                    alert_data = self._create_alert_data_for_processed_log(
                        rule, log,
                        f"Suspicious pattern detected in {field_name}",
                        {"matched_pattern": pattern, "field_value": field_value}
                    )
                    alerts.append(alert_data)
                    break  # Only create one alert per log
        
        return alerts
    
    async def _process_correlation_rule_processed_logs(self, db: AsyncSession, rule: DetectionRule,
                                                     processed_log_ids: List[str]) -> List[AlertCreate]:
        """Process correlation-based detection rules for processed logs"""
        # Implementation similar to existing correlation but using ProcessedLog
        # This would be more complex and require adaptation of the existing logic
        return []
    
    async def _process_anomaly_rule_processed_logs(self, db: AsyncSession, rule: DetectionRule,
                                                 processed_log_ids: List[str]) -> List[AlertCreate]:
        """Process anomaly-based detection rules for processed logs"""
        # Implementation similar to existing anomaly but using ProcessedLog
        # This would be more complex and require adaptation of the existing logic
        return []
    
    def _create_alert_data_for_processed_log(self, rule: DetectionRule, log: ProcessedLog, 
                                           description: str, additional_data: Dict[str, Any]) -> AlertCreate:
        """Create alert data structure for processed log"""
        
        alert_data = {
            "log_id": str(log.id),
            "rule_name": rule.name,
            "timestamp": log.timestamp.isoformat(),
            "source_info": {
                "hostname": log.hostname,
                "source_ip": str(log.source_ip) if log.source_ip else None,
                "app_name": log.app_name
            }
        }
        alert_data.update(additional_data)
        
        return AlertCreate(
            processed_log_id=log.id,
            detection_rule_id=rule.id,
            title=f"{rule.name} - {log.hostname or 'Unknown'}",
            description=description,
            severity=rule.severity,
            category=rule.category,
            alert_data=alert_data
        )
    
    def _send_alert_notifications_background(self, db: AsyncSession, alerts: List[Alert]):
        """Send notifications for alerts in background"""
        try:
            # Get alert IDs
            alert_ids = [str(alert.id) for alert in alerts]
            
            # Send notifications asynchronously
            asyncio.create_task(
                notification_service.send_notifications(db, alert_ids)
            )
            
            logger.info(f"Initiated notifications for {len(alert_ids)} alerts")
            
        except Exception as e:
            logger.error(f"Error initiating alert notifications: {e}")
    
    def _apply_single_rule(self, db: AsyncSession, rule: DetectionRule,
                          parsed_log_ids: List[str]) -> List[AlertCreate]:
        """Apply a single detection rule"""
        
        rule_type = rule.rule_type
        if rule_type not in self.rule_processors:
            raise ValueError(f"Unknown rule type: {rule_type}")
        
        processor = self.rule_processors[rule_type]
        return processor(db, rule, parsed_log_ids)
    
    def _process_threshold_rule(self, db: AsyncSession, rule: DetectionRule,
                               parsed_log_ids: List[str]) -> List[AlertCreate]:
        """Process threshold-based detection rules"""
        alerts = []
        conditions = rule.conditions
        
        # Build base query
        query = select(ParsedLog)
        
        # Filter by log type
        if "log_type" in conditions:
            query = query.filter(ParsedLog.log_type == conditions["log_type"])
        
        # Apply field conditions
        if "field_conditions" in conditions:
            for field, value in conditions["field_conditions"].items():
                query = query.filter(ParsedLog.parsed_fields[field].astext == value)
        
        # Apply time window
        threshold_config = conditions["threshold"]
        time_window = threshold_config["time_window"]
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        query = query.filter(ParsedLog.parsed_at >= cutoff_time)
        
        # Group by specified fields
        group_by_fields = threshold_config.get("group_by", [])
        
        if group_by_fields:
            # Get logs grouped by the specified fields
            logs = query.all()
            grouped_logs = {}
            
            for log in logs:
                # Create grouping key
                key_parts = []
                for field in group_by_fields:
                    value = log.parsed_fields.get(field, "unknown")
                    key_parts.append(str(value))
                group_key = "|".join(key_parts)
                
                if group_key not in grouped_logs:
                    grouped_logs[group_key] = []
                grouped_logs[group_key].append(log)
            
            # Check thresholds for each group
            threshold_count = threshold_config["count"]
            
            for group_key, group_logs in grouped_logs.items():
                if len(group_logs) >= threshold_count:
                    # Check for unique field requirement
                    if "unique_field" in threshold_config:
                        unique_field = threshold_config["unique_field"]
                        unique_values = set()
                        for log in group_logs:
                            value = log.parsed_fields.get(unique_field)
                            if value:
                                unique_values.add(value)
                        
                        if len(unique_values) < threshold_count:
                            continue
                    
                    # Create alert
                    alert_data = self._create_alert_data(
                        rule, group_logs[0], 
                        f"Threshold exceeded: {len(group_logs)} events in {time_window}s",
                        {"group_key": group_key, "event_count": len(group_logs), "events": [log.id for log in group_logs]}
                    )
                    alerts.append(alert_data)
        
        return alerts
    
    def _process_pattern_rule(self, db: AsyncSession, rule: DetectionRule,
                             parsed_log_ids: List[str]) -> List[AlertCreate]:
        """Process pattern-based detection rules"""
        alerts = []
        conditions = rule.conditions
        
        # Build base query
        query = select(ParsedLog)
        
        # Filter by log type
        if "log_type" in conditions:
            query = query.filter(ParsedLog.log_type == conditions["log_type"])
        
        # Get field to check
        field_name = conditions.get("field", "message")
        patterns = conditions.get("patterns", [])
        
        logs = query.all()
        
        for log in logs:
            field_value = log.parsed_fields.get(field_name, "")
            if not field_value:
                continue
            
            # Check each pattern
            for pattern in patterns:
                import re
                if re.search(pattern, str(field_value)):
                    alert_data = self._create_alert_data(
                        rule, log,
                        f"Suspicious pattern detected in {field_name}",
                        {"matched_pattern": pattern, "field_value": field_value}
                    )
                    alerts.append(alert_data)
                    break  # Only create one alert per log
        
        return alerts
    
    def _process_correlation_rule(self, db: AsyncSession, rule: DetectionRule,
                                 parsed_log_ids: List[str]) -> List[AlertCreate]:
        """Process correlation-based detection rules"""
        alerts = []
        conditions = rule.conditions
        
        sequence = conditions.get("sequence", [])
        correlation_field = conditions.get("correlation_field")
        
        if len(sequence) < 2 or not correlation_field:
            return alerts
        
        # Process sequence events
        for i in range(len(sequence) - 1):
            current_event = sequence[i]
            next_event = sequence[i + 1]
            
            # Find logs matching current event
            current_logs = self._find_logs_matching_conditions(db, current_event)
            
            # For each current log, look for matching next event
            for current_log in current_logs:
                correlation_value = current_log.parsed_fields.get(correlation_field)
                if not correlation_value:
                    continue
                
                # Look for next event within time window
                time_window = next_event.get("time_window", 300)
                start_time = current_log.parsed_at
                end_time = start_time + timedelta(seconds=time_window)
                
                next_logs = self._find_logs_matching_conditions(
                    db, next_event, 
                    start_time=start_time, 
                    end_time=end_time,
                    correlation_field=correlation_field,
                    correlation_value=correlation_value
                )
                
                if next_logs:
                    alert_data = self._create_alert_data(
                        rule, current_log,
                        f"Correlated events detected: {current_event.get('description', 'event')} followed by {next_event.get('description', 'event')}",
                        {
                            "correlation_field": correlation_field,
                            "correlation_value": correlation_value,
                            "sequence_events": [current_log.id] + [log.id for log in next_logs]
                        }
                    )
                    alerts.append(alert_data)
        
        return alerts
    
    def _process_anomaly_rule(self, db: AsyncSession, rule: DetectionRule,
                             parsed_log_ids: List[str]) -> List[AlertCreate]:
        """Process anomaly-based detection rules"""
        alerts = []
        conditions = rule.conditions
        
        anomaly_config = conditions.get("anomaly", {})
        baseline_window = anomaly_config.get("baseline_window", 3600)
        detection_window = anomaly_config.get("detection_window", 300)
        threshold_multiplier = anomaly_config.get("threshold_multiplier", 3.0)
        min_baseline_count = anomaly_config.get("min_baseline_count", 10)
        
        # Calculate time windows
        now = datetime.utcnow()
        detection_start = now - timedelta(seconds=detection_window)
        baseline_start = detection_start - timedelta(seconds=baseline_window)
        
        # Build base query
        base_query = select(ParsedLog)
        
        # Filter by log type
        if "log_type" in conditions:
            base_query = base_query.filter(ParsedLog.log_type == conditions["log_type"])
        
        # Apply field conditions
        if "field_conditions" in conditions:
            for field, values in conditions["field_conditions"].items():
                if isinstance(values, list):
                    # Handle special cases like "4xx", "5xx"
                    if any("xx" in v for v in values):
                        or_conditions = []
                        for value in values:
                            if value == "4xx":
                                or_conditions.append(ParsedLog.parsed_fields[field].astext.like("4%"))
                            elif value == "5xx":
                                or_conditions.append(ParsedLog.parsed_fields[field].astext.like("5%"))
                            else:
                                or_conditions.append(ParsedLog.parsed_fields[field].astext == value)
                        base_query = base_query.filter(or_(*or_conditions))
                    else:
                        base_query = base_query.filter(ParsedLog.parsed_fields[field].astext.in_(values))
                else:
                    base_query = base_query.filter(ParsedLog.parsed_fields[field].astext == values)
        
        # Get baseline count
        baseline_query = base_query.filter(
            and_(
                ParsedLog.parsed_at >= baseline_start,
                ParsedLog.parsed_at < detection_start
            )
        )
        baseline_count = baseline_query.count()
        
        if baseline_count < min_baseline_count:
            return alerts  # Not enough baseline data
        
        # Get detection window count
        detection_query = base_query.filter(ParsedLog.parsed_at >= detection_start)
        detection_count = detection_query.count()
        
        # Calculate expected rate and threshold
        baseline_rate = baseline_count / (baseline_window / detection_window)
        threshold = baseline_rate * threshold_multiplier
        
        if detection_count > threshold:
            # Get a representative log for the alert
            representative_log = detection_query.first()
            if representative_log:
                alert_data = self._create_alert_data(
                    rule, representative_log,
                    f"Anomalous activity detected: {detection_count} events vs baseline {baseline_rate:.1f}",
                    {
                        "detection_count": detection_count,
                        "baseline_rate": baseline_rate,
                        "threshold": threshold,
                        "multiplier": threshold_multiplier
                    }
                )
                alerts.append(alert_data)
        
        return alerts
    
    def _find_logs_matching_conditions(self, db: AsyncSession, conditions: Dict[str, Any],
                                     start_time: Optional[datetime] = None,
                                     end_time: Optional[datetime] = None,
                                     correlation_field: Optional[str] = None,
                                     correlation_value: Optional[str] = None) -> List[ParsedLog]:
        """Find logs matching specific conditions"""
        
        query = select(ParsedLog)
        
        # Filter by log type
        if "log_type" in conditions:
            query = query.filter(ParsedLog.log_type == conditions["log_type"])
        
        # Apply field conditions
        if "field_conditions" in conditions:
            for field, value in conditions["field_conditions"].items():
                query = query.filter(ParsedLog.parsed_fields[field].astext == value)
        
        # Apply time range
        if start_time:
            query = query.filter(ParsedLog.parsed_at >= start_time)
        if end_time:
            query = query.filter(ParsedLog.parsed_at <= end_time)
        
        # Apply correlation filter
        if correlation_field and correlation_value:
            query = query.filter(ParsedLog.parsed_fields[correlation_field].astext == correlation_value)
        
        logs = query.all()
        
        # Check minimum count requirement
        min_count = conditions.get("min_count", 1)
        if len(logs) >= min_count:
            return logs
        
        return []
    
    def _create_alert_data(self, rule: DetectionRule, log: ParsedLog, 
                          description: str, additional_data: Dict[str, Any]) -> AlertCreate:
        """Create alert data structure"""
        
        alert_data = {
            "log_id": str(log.id),
            "rule_name": rule.name,
            "timestamp": log.parsed_at.isoformat(),
            "source_info": {
                "hostname": log.parsed_fields.get("hostname"),
                "src_ip": log.parsed_fields.get("src_ip"),
                "app_name": log.parsed_fields.get("app_name")
            }
        }
        alert_data.update(additional_data)
        
        return AlertCreate(
            parsed_log_id=log.id,
            detection_rule_id=rule.id,
            title=f"{rule.name} - {log.parsed_fields.get('hostname', 'Unknown')}",
            description=description,
            severity=rule.severity,
            category=rule.category,
            alert_data=alert_data
        )


class DetectionService:
    """
    Service for managing detection operations
    """
    
    def __init__(self):
        self.engine = DetectionEngine()
    
    async def initialize_default_rules(self, db: AsyncSession) -> int:
        """Initialize default detection rules in database"""
        default_rules = self.engine.load_default_rules()
        created_count = 0
        
        for rule_data in default_rules:
            # Check if rule already exists
            result = await db.execute(select(DetectionRule).filter(DetectionRule.name == rule_data.name))
            existing_rule = result.scalar_one_or_none()
            if not existing_rule:
                rule = DetectionRule(**rule_data.dict())
                db.add(rule)
                created_count += 1
        
        await db.commit()
        return created_count
    
    async def run_detection(self, db: AsyncSession, parsed_log_ids: Optional[List[str]] = None,
                     rule_ids: Optional[List[str]] = None) -> Tuple[int, int, List[str]]:
        """Run detection on parsed logs (DEPRECATED - use run_detection_on_processed_logs)"""
        
        if parsed_log_ids is None:
            # Get recent unprocessed logs
            result = await db.execute(select(ParsedLog).filter(
                ParsedLog.parsed_at >= datetime.utcnow() - timedelta(hours=1)
            ))
            recent_logs = result.scalars().all()
            parsed_log_ids = [str(log.id) for log in recent_logs]
        
        return await self.engine.apply_rules(db, parsed_log_ids, rule_ids)
    
    async def run_detection_on_processed_logs(self, db: AsyncSession, processed_log_ids: List[str],
                                            rule_ids: Optional[List[str]] = None) -> Tuple[int, int, List[str]]:
        """Run detection on processed logs stored locally"""
        return await self.engine.apply_rules_to_processed_logs(db, processed_log_ids, rule_ids)
    
    async def get_detection_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get detection statistics"""
        
        # Rule statistics
        total_rules_result = await db.execute(select(func.count(DetectionRule.id)))
        total_rules = total_rules_result.scalar()
        
        enabled_rules_result = await db.execute(select(func.count(DetectionRule.id)).filter(DetectionRule.is_enabled == True))
        enabled_rules = enabled_rules_result.scalar()
        
        # Alert statistics
        total_alerts_result = await db.execute(select(func.count(Alert.id)))
        total_alerts = total_alerts_result.scalar()
        
        open_alerts_result = await db.execute(select(func.count(Alert.id)).filter(Alert.status == "open"))
        open_alerts = open_alerts_result.scalar()
        
        # Recent alerts (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_alerts_result = await db.execute(select(func.count(Alert.id)).filter(Alert.triggered_at >= recent_cutoff))
        recent_alerts = recent_alerts_result.scalar()
        
        # Alert severity distribution
        severity_stats_result = await db.execute(
            select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        )
        severity_distribution = {severity: count for severity, count in severity_stats_result.all()}
        
        # Alert category distribution
        category_stats_result = await db.execute(
            select(Alert.category, func.count(Alert.id)).group_by(Alert.category)
        )
        category_distribution = {category: count for category, count in category_stats_result.all()}
        
        return {
            "rules": {
                "total": total_rules,
                "enabled": enabled_rules,
                "disabled": total_rules - enabled_rules
            },
            "alerts": {
                "total": total_alerts,
                "open": open_alerts,
                "recent_24h": recent_alerts
            },
            "severity_distribution": severity_distribution,
            "category_distribution": category_distribution
        }


# Global detection service instance
detection_service = DetectionService()
