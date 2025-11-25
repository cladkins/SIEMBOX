"""
SIEM BOX - Alerts API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, and_, select, func
from typing import List, Optional
from datetime import datetime, timedelta
from app.db.database import get_db
from app.models.logs import Alert, DetectionRule, ParsedLog
from app.schemas.parsing import (
    AlertResponse, AlertUpdate,
    NotificationRequest, NotificationResponse
)
# from app.services.notification_service import notification_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/test")
async def test_endpoint():
    """
    Simple test endpoint without any dependencies
    """
    return {"message": "Test endpoint working", "status": "success"}

@router.get("/test-isolated")
def test_isolated_endpoint():
    """
    Completely isolated test endpoint - not even async
    """
    return {"message": "Isolated test endpoint working", "status": "success"}

@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    hours: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    Get alerts with optional filtering
    """
    try:
        logger.info(f"Getting alerts with filters: status={status}, severity={severity}, category={category}, hours={hours}, limit={limit}, offset={offset}")
        
        # Build the query
        query = select(Alert).order_by(desc(Alert.triggered_at))
        
        # Apply filters
        if status:
            query = query.filter(Alert.status == status)
        
        if severity:
            query = query.filter(Alert.severity == severity)
            
        if category:
            query = query.filter(Alert.category == category)
            
        if hours:
            # Filter by alerts from the last N hours
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(Alert.triggered_at >= cutoff_time)
        
        # Apply pagination
        query = query.limit(limit).offset(offset)
        
        # Execute query
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        logger.info(f"Found {len(alerts)} alerts")
        
        # Convert to response format
        alert_responses = []
        for alert in alerts:
            try:
                alert_response = AlertResponse.model_validate(alert)
                alert_responses.append(alert_response)
            except Exception as e:
                logger.error(f"Error converting alert {alert.id} to response: {e}")
                continue
        
        return alert_responses
        
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific alert by ID
    """
    try:
        query = select(Alert).filter(Alert.id == alert_id)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return AlertResponse.model_validate(alert)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    alert_update: AlertUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update an alert
    """
    try:
        query = select(Alert).filter(Alert.id == alert_id)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Update fields
        update_data = alert_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(alert, field, value)
        
        # Set resolved timestamp if status changed to resolved
        if alert_update.status == "resolved" and alert.resolved_at is None:
            alert.resolved_at = datetime.utcnow()
        elif alert_update.status != "resolved":
            alert.resolved_at = None
        
        await db.commit()
        await db.refresh(alert)
        
        logger.info(f"Updated alert {alert_id}: status={alert.status}")
        return AlertResponse.model_validate(alert)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Acknowledge an alert (mark as investigating)
    """
    try:
        query = select(Alert).filter(Alert.id == alert_id)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        if alert.status == "resolved":
            raise HTTPException(status_code=400, detail="Cannot acknowledge resolved alert")
        
        alert.status = "investigating"
        await db.commit()
        
        logger.info(f"Acknowledged alert {alert_id}")
        return {"message": "Alert acknowledged successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Resolve an alert
    """
    try:
        query = select(Alert).filter(Alert.id == alert_id)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        alert.status = "resolved"
        alert.resolved_at = datetime.utcnow()
        await db.commit()
        
        logger.info(f"Resolved alert {alert_id}")
        return {"message": "Alert resolved successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error resolving alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Mark an alert as false positive
    """
    try:
        query = select(Alert).filter(Alert.id == alert_id)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        alert.status = "false_positive"
        alert.resolved_at = datetime.utcnow()
        await db.commit()
        
        logger.info(f"Marked alert {alert_id} as false positive")
        return {"message": "Alert marked as false positive"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error marking alert {alert_id} as false positive: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulk-update")
async def bulk_update_alerts(
    alert_ids: List[str],
    status: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Bulk update multiple alerts
    """
    try:
        # Validate status
        valid_statuses = ["open", "investigating", "resolved", "false_positive"]
        if status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Must be one of: {valid_statuses}"
            )
        
        # Update alerts
        updated_count = 0
        for alert_id in alert_ids:
            query = select(Alert).filter(Alert.id == alert_id)
            result = await db.execute(query)
            alert = result.scalar_one_or_none()
            if alert:
                alert.status = status
                if status in ["resolved", "false_positive"]:
                    alert.resolved_at = datetime.utcnow()
                else:
                    alert.resolved_at = None
                updated_count += 1
        
        await db.commit()
        
        logger.info(f"Bulk updated {updated_count} alerts to status: {status}")
        return {
            "message": f"Updated {updated_count} alerts",
            "updated_count": updated_count,
            "status": status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error bulk updating alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/summary")
async def get_alert_summary(db: AsyncSession = Depends(get_db)):
    """
    Get alert summary statistics
    """
    try:
        # Total alerts
        total_query = select(func.count(Alert.id))
        total_result = await db.execute(total_query)
        total_alerts = total_result.scalar()
        
        # Alerts by status
        open_query = select(func.count(Alert.id)).filter(Alert.status == "open")
        open_result = await db.execute(open_query)
        open_alerts = open_result.scalar()
        
        investigating_query = select(func.count(Alert.id)).filter(Alert.status == "investigating")
        investigating_result = await db.execute(investigating_query)
        investigating_alerts = investigating_result.scalar()
        
        resolved_query = select(func.count(Alert.id)).filter(Alert.status == "resolved")
        resolved_result = await db.execute(resolved_query)
        resolved_alerts = resolved_result.scalar()
        
        false_positive_query = select(func.count(Alert.id)).filter(Alert.status == "false_positive")
        false_positive_result = await db.execute(false_positive_query)
        false_positive_alerts = false_positive_result.scalar()
        
        # Alerts by severity
        critical_query = select(func.count(Alert.id)).filter(Alert.severity == "critical")
        critical_result = await db.execute(critical_query)
        critical_alerts = critical_result.scalar()
        
        high_query = select(func.count(Alert.id)).filter(Alert.severity == "high")
        high_result = await db.execute(high_query)
        high_alerts = high_result.scalar()
        
        medium_query = select(func.count(Alert.id)).filter(Alert.severity == "medium")
        medium_result = await db.execute(medium_query)
        medium_alerts = medium_result.scalar()
        
        low_query = select(func.count(Alert.id)).filter(Alert.severity == "low")
        low_result = await db.execute(low_query)
        low_alerts = low_result.scalar()
        
        # Recent alerts (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_query = select(func.count(Alert.id)).filter(Alert.triggered_at >= recent_cutoff)
        recent_result = await db.execute(recent_query)
        recent_alerts = recent_result.scalar()
        
        # Top categories (last 7 days)
        week_cutoff = datetime.utcnow() - timedelta(days=7)
        category_query = select(Alert.category, func.count(Alert.id)).filter(
            Alert.triggered_at >= week_cutoff
        ).group_by(Alert.category).order_by(func.count(Alert.id).desc()).limit(5)
        category_result = await db.execute(category_query)
        category_stats = category_result.all()
        
        return {
            "total_alerts": total_alerts,
            "status_distribution": {
                "open": open_alerts,
                "investigating": investigating_alerts,
                "resolved": resolved_alerts,
                "false_positive": false_positive_alerts
            },
            "severity_distribution": {
                "critical": critical_alerts,
                "high": high_alerts,
                "medium": medium_alerts,
                "low": low_alerts
            },
            "recent_24h": recent_alerts,
            "top_categories_7d": [
                {"category": category, "count": count}
                for category, count in category_stats
            ]
        }
        
    except Exception as e:
        logger.error(f"Error retrieving alert summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/timeline")
async def get_alert_timeline(
    hours: int = 24,
    db: AsyncSession = Depends(get_db)
):
    """
    Get alert timeline data for charts
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get alerts grouped by hour
        from sqlalchemy import func, extract
        
        query = select(
            func.date_trunc('hour', Alert.triggered_at).label('hour'),
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.triggered_at >= cutoff_time
        ).group_by(
            func.date_trunc('hour', Alert.triggered_at),
            Alert.severity
        ).order_by('hour')
        
        result = await db.execute(query)
        timeline_data = result.all()
        
        # Format data for frontend
        timeline = {}
        for hour, severity, count in timeline_data:
            hour_str = hour.isoformat()
            if hour_str not in timeline:
                timeline[hour_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            timeline[hour_str][severity] = count
        
        return {
            "timeline": timeline,
            "hours": hours
        }
        
    except Exception as e:
        logger.error(f"Error retrieving alert timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/notify", response_model=NotificationResponse)
async def send_notifications(
    request: NotificationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Send notifications for alerts
    """
    try:
        # Validate alert IDs
        alert_ids = [str(alert_id) for alert_id in request.alert_ids]
        query = select(func.count(Alert.id)).filter(Alert.id.in_(alert_ids))
        result = await db.execute(query)
        existing_alerts = result.scalar()
        
        if existing_alerts != len(alert_ids):
            raise HTTPException(
                status_code=400,
                detail="One or more alert IDs not found"
            )
        
        # Send notifications in background
        background_tasks.add_task(
            _send_notifications_background,
            db, alert_ids, request.notification_types
        )
        
        return NotificationResponse(
            success=True,
            sent_count=0,  # Will be updated in background
            failed_count=0,
            errors=[]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating notifications: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _send_notifications_background(
    db: AsyncSession,
    alert_ids: List[str],
    notification_types: Optional[List[str]]
):
    """Background task for sending notifications"""
    try:
        # sent_count, failed_count, errors = await notification_service.send_notifications(
        #     db, alert_ids, notification_types
        # )
        sent_count, failed_count, errors = 0, 0, []
        logger.info(f"Notifications completed: {sent_count} sent, {failed_count} failed")
        
        if errors:
            logger.warning(f"Notification errors: {errors}")
            
    except Exception as e:
        logger.error(f"Background notification sending failed: {e}")


@router.get("/{alert_id}/context")
async def get_alert_context(
    alert_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get additional context for an alert (related logs, rule details, etc.)
    """
    try:
        query = select(Alert).filter(Alert.id == alert_id)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Get the parsed log
        parsed_log_query = select(ParsedLog).filter(ParsedLog.id == alert.parsed_log_id)
        parsed_log_result = await db.execute(parsed_log_query)
        parsed_log = parsed_log_result.scalar_one_or_none()
        
        # Get the detection rule
        detection_rule_query = select(DetectionRule).filter(DetectionRule.id == alert.detection_rule_id)
        detection_rule_result = await db.execute(detection_rule_query)
        detection_rule = detection_rule_result.scalar_one_or_none()
        
        # Get related alerts (same source IP, same rule, etc.)
        related_alerts = []
        if parsed_log and parsed_log.parsed_fields:
            src_ip = parsed_log.parsed_fields.get("src_ip")
            if src_ip:
                # Find other alerts from same source IP in last 24 hours
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                related_query = select(Alert).join(ParsedLog).filter(
                    and_(
                        Alert.id != alert_id,
                        Alert.triggered_at >= cutoff_time,
                        ParsedLog.parsed_fields["src_ip"].astext == src_ip
                    )
                ).limit(10)
                related_result = await db.execute(related_query)
                related_alerts_data = related_result.scalars().all()
                related_alerts = [AlertResponse.model_validate(a) for a in related_alerts_data]
        
        context = {
            "alert": AlertResponse.model_validate(alert),
            "parsed_log": parsed_log.to_dict() if parsed_log else None,
            "detection_rule": detection_rule.to_dict() if detection_rule else None,
            "related_alerts": related_alerts
        }
        
        return context
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert context for {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))