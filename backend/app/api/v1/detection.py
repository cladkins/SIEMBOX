"""
SIEM BOX - Detection API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import List, Optional
from app.db.database import get_db
from app.models.logs import DetectionRule, Alert
from app.schemas.parsing import (
    DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleResponse,
    DetectionRequest, DetectionResponse
)
from app.services.detection_service import detection_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/rules", response_model=DetectionRuleResponse)
async def create_detection_rule(
    rule: DetectionRuleCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new detection rule
    """
    try:
        # Check if rule with same name exists
        result = await db.execute(select(DetectionRule).filter(DetectionRule.name == rule.name))
        existing_rule = result.scalar_one_or_none()
        if existing_rule:
            raise HTTPException(
                status_code=400,
                detail=f"Detection rule with name '{rule.name}' already exists"
            )
        
        # Create new rule
        db_rule = DetectionRule(**rule.dict())
        db.add(db_rule)
        await db.commit()
        await db.refresh(db_rule)
        
        logger.info(f"Created detection rule: {db_rule.name}")
        return DetectionRuleResponse.model_validate(db_rule)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating detection rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules", response_model=List[DetectionRuleResponse])
async def get_detection_rules(
    enabled_only: bool = False,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detection rules with optional filtering
    """
    try:
        query = select(DetectionRule)
        
        if enabled_only:
            query = query.filter(DetectionRule.is_enabled == True)
        
        if category:
            query = query.filter(DetectionRule.category == category)
            
        if severity:
            query = query.filter(DetectionRule.severity == severity)
        
        query = query.order_by(DetectionRule.created_at.desc())
        result = await db.execute(query)
        rules = result.scalars().all()
        
        return [DetectionRuleResponse.model_validate(rule) for rule in rules]
        
    except Exception as e:
        logger.error(f"Error retrieving detection rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/initialize")
async def initialize_default_rules(db: AsyncSession = Depends(get_db)):
    """
    Initialize default detection rules
    """
    try:
        # Check if rules already exist
        result = await db.execute(select(func.count(DetectionRule.id)))
        existing_count = result.scalar()
        if existing_count > 0:
            return {
                "message": f"Detection rules already exist ({existing_count} rules found)",
                "rules_created": 0
            }
        
        # Create default rules
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
                        "time_window": 300,
                        "group_by": ["src_ip"]
                    }
                },
                "is_enabled": True
            },
            {
                "name": "Multiple Failed Logins",
                "description": "Detects multiple failed login attempts",
                "rule_type": "threshold",
                "severity": "medium",
                "category": "authentication",
                "conditions": {
                    "log_type": "authentication",
                    "field_conditions": {
                        "status": "failed"
                    },
                    "threshold": {
                        "count": 3,
                        "time_window": 180,
                        "group_by": ["username"]
                    }
                },
                "is_enabled": True
            },
            {
                "name": "Suspicious Network Activity",
                "description": "Detects unusual network connection patterns",
                "rule_type": "pattern",
                "severity": "medium",
                "category": "network",
                "conditions": {
                    "log_type": "network",
                    "field_conditions": {
                        "action": "blocked"
                    }
                },
                "is_enabled": True
            }
        ]
        
        rules_created = 0
        for rule_data in default_rules:
            db_rule = DetectionRule(**rule_data)
            db.add(db_rule)
            rules_created += 1
        
        await db.commit()
        
        logger.info(f"Initialized {rules_created} default detection rules")
        return {
            "message": f"Successfully created {rules_created} default detection rules",
            "rules_created": rules_created
        }
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Error initializing default rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def get_detection_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific detection rule by ID
    """
    try:
        result = await db.execute(select(DetectionRule).filter(DetectionRule.id == rule_id))
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        return DetectionRuleResponse.model_validate(rule)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving detection rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_detection_rule(
    rule_id: str,
    rule_update: DetectionRuleUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update a detection rule
    """
    try:
        result = await db.execute(select(DetectionRule).filter(DetectionRule.id == rule_id))
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        # Update fields
        update_data = rule_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(rule, field, value)
        
        await db.commit()
        await db.refresh(rule)
        
        logger.info(f"Updated detection rule: {rule.name}")
        return DetectionRuleResponse.model_validate(rule)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating detection rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rules/{rule_id}")
async def delete_detection_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a detection rule
    """
    try:
        result = await db.execute(select(DetectionRule).filter(DetectionRule.id == rule_id))
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        # Check if rule has associated alerts
        alert_result = await db.execute(select(func.count(Alert.id)).filter(Alert.detection_rule_id == rule_id))
        alert_count = alert_result.scalar()
        
        if alert_count > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete rule with {alert_count} associated alerts. Disable the rule instead."
            )
        
        db.delete(rule)
        await db.commit()
        
        logger.info(f"Deleted detection rule: {rule.name}")
        return {"message": "Detection rule deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting detection rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run", response_model=DetectionResponse)
async def run_detection(
    request: DetectionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Run detection rules on parsed logs
    """
    try:
        # Validate parsed log IDs
        parsed_log_ids = [str(log_id) for log_id in request.parsed_log_ids]
        
        # Validate rule IDs if provided
        rule_ids = None
        if request.rule_ids:
            rule_ids = [str(rule_id) for rule_id in request.rule_ids]
            existing_result = await db.execute(select(func.count(DetectionRule.id)).filter(DetectionRule.id.in_(rule_ids)))
            existing_rules = existing_result.scalar()
            if existing_rules != len(rule_ids):
                raise HTTPException(
                    status_code=400,
                    detail="One or more detection rule IDs not found"
                )
        
        # Run detection in background
        background_tasks.add_task(
            _run_detection_background,
            db, parsed_log_ids, rule_ids
        )
        
        return DetectionResponse(
            success=True,
            alerts_generated=0,  # Will be updated in background
            rules_applied=0,
            errors=[]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating detection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_detection_background(db: AsyncSession, parsed_log_ids: List[str], rule_ids: Optional[List[str]]):
    """Background task for running detection"""
    try:
        alerts_generated, rules_applied, errors = await detection_service.run_detection(
            db, parsed_log_ids, rule_ids
        )
        logger.info(f"Detection completed: {alerts_generated} alerts, {rules_applied} rules applied")
        
        if errors:
            logger.warning(f"Detection errors: {errors}")
            
    except Exception as e:
        logger.error(f"Background detection failed: {e}")


@router.post("/auto-detect")
async def auto_detect_recent_logs(
    background_tasks: BackgroundTasks,
    hours: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """
    Automatically run detection on recent parsed logs
    """
    try:
        # Run detection on recent logs
        background_tasks.add_task(
            _auto_detect_background,
            db, hours
        )
        
        return {
            "message": f"Started detection on logs from last {hours} hour(s)",
            "hours": hours
        }
        
    except Exception as e:
        logger.error(f"Error initiating auto-detection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _auto_detect_background(db: AsyncSession, hours: int):
    """Background task for auto-detection"""
    try:
        alerts_generated, rules_applied, errors = await detection_service.run_detection(db)
        logger.info(f"Auto-detection completed: {alerts_generated} alerts, {rules_applied} rules applied")
        
        if errors:
            logger.warning(f"Auto-detection errors: {errors}")
            
    except Exception as e:
        logger.error(f"Auto-detection failed: {e}")


@router.post("/initialize-rules")
async def initialize_default_rules(db: AsyncSession = Depends(get_db)):
    """
    Initialize default detection rules
    """
    try:
        created_count = await detection_service.initialize_default_rules(db)
        
        return {
            "message": f"Initialized {created_count} default detection rules",
            "created_count": created_count
        }
        
    except Exception as e:
        logger.error(f"Error initializing default rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_detection_stats(db: AsyncSession = Depends(get_db)):
    """
    Get detection statistics
    """
    try:
        stats = await detection_service.get_detection_stats(db)
        return stats
        
    except Exception as e:
        logger.error(f"Error retrieving detection stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/{rule_id}/enable")
async def enable_detection_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Enable a detection rule
    """
    try:
        result = await db.execute(select(DetectionRule).filter(DetectionRule.id == rule_id))
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        rule.is_enabled = True
        await db.commit()
        
        logger.info(f"Enabled detection rule: {rule.name}")
        return {"message": "Detection rule enabled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error enabling detection rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/{rule_id}/disable")
async def disable_detection_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Disable a detection rule
    """
    try:
        result = await db.execute(select(DetectionRule).filter(DetectionRule.id == rule_id))
        rule = result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        rule.is_enabled = False
        await db.commit()
        
        logger.info(f"Disabled detection rule: {rule.name}")
        return {"message": "Detection rule disabled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error disabling detection rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))