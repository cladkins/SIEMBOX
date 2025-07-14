"""
SIEM BOX - Notifications API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, and_, select, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from app.db.database import get_db
from app.models.logs import Alert, NotificationChannel, NotificationHistory, NotificationTemplate
from app.schemas.notifications import (
    NotificationChannelCreate, NotificationChannelUpdate, NotificationChannelResponse,
    NotificationHistoryResponse, SendNotificationRequest, SendNotificationResponse,
    TestNotificationRequest, TestNotificationResponse, NotificationStatsResponse,
    NotificationConfigResponse, BulkNotificationRequest, BulkNotificationResponse,
    NotificationTemplateCreate, NotificationTemplateResponse
)
from app.services.notification_service import notification_service
import logging
import uuid

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/channels", response_model=List[NotificationChannelResponse])
async def get_notification_channels(
    enabled_only: bool = False,
    channel_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get all notification channels
    """
    try:
        query = select(NotificationChannel)
        
        if enabled_only:
            query = query.filter(NotificationChannel.enabled == True)
        
        if channel_type:
            query = query.filter(NotificationChannel.type == channel_type)
        
        query = query.order_by(NotificationChannel.created_at)
        result = await db.execute(query)
        channels = result.scalars().all()
        
        return [NotificationChannelResponse.model_validate(channel) for channel in channels]
        
    except Exception as e:
        logger.error(f"Error retrieving notification channels: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/channels", response_model=NotificationChannelResponse)
async def create_notification_channel(
    channel_data: NotificationChannelCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new notification channel
    """
    try:
        # Check if channel name already exists
        query = select(NotificationChannel).filter(
            NotificationChannel.name == channel_data.name
        )
        result = await db.execute(query)
        existing = result.scalar_one_or_none()
        
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Notification channel with name '{channel_data.name}' already exists"
            )
        
        # Create new channel
        channel = NotificationChannel(
            id=uuid.uuid4(),
            name=channel_data.name,
            type=channel_data.type.value,
            enabled=True,
            config=channel_data.config,
            min_severity=channel_data.min_severity.value,
            categories=channel_data.categories,
            exclude_categories=channel_data.exclude_categories,
            rate_limit_per_hour=channel_data.rate_limit_per_hour
        )
        
        db.add(channel)
        await db.commit()
        await db.refresh(channel)
        
        # Update notification service configuration
        notification_service.update_config(channel_data.type.value, channel_data.config)
        
        logger.info(f"Created notification channel: {channel.name} ({channel.type})")
        return NotificationChannelResponse.model_validate(channel)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating notification channel: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def get_notification_channel(
    channel_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific notification channel
    """
    try:
        query = select(NotificationChannel).filter(
            NotificationChannel.id == channel_id
        )
        result = await db.execute(query)
        channel = result.scalar_one_or_none()
        
        if not channel:
            raise HTTPException(status_code=404, detail="Notification channel not found")
        
        return NotificationChannelResponse.model_validate(channel)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving notification channel {channel_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def update_notification_channel(
    channel_id: str,
    channel_update: NotificationChannelUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update a notification channel
    """
    try:
        query = select(NotificationChannel).filter(
            NotificationChannel.id == channel_id
        )
        result = await db.execute(query)
        channel = result.scalar_one_or_none()
        
        if not channel:
            raise HTTPException(status_code=404, detail="Notification channel not found")
        
        # Update fields
        update_data = channel_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field == "min_severity" and value:
                setattr(channel, field, value.value)
            else:
                setattr(channel, field, value)
        
        await db.commit()
        await db.refresh(channel)
        
        # Update notification service configuration if config changed
        if channel_update.config:
            notification_service.update_config(channel.type, channel_update.config)
        
        logger.info(f"Updated notification channel: {channel.name}")
        return NotificationChannelResponse.model_validate(channel)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating notification channel {channel_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/channels/{channel_id}")
async def delete_notification_channel(
    channel_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a notification channel
    """
    try:
        query = select(NotificationChannel).filter(
            NotificationChannel.id == channel_id
        )
        result = await db.execute(query)
        channel = result.scalar_one_or_none()
        
        if not channel:
            raise HTTPException(status_code=404, detail="Notification channel not found")
        
        # Check if channel has notification history
        count_query = select(func.count(NotificationHistory.id)).filter(
            NotificationHistory.channel_id == channel_id
        )
        count_result = await db.execute(count_query)
        history_count = count_result.scalar()
        
        if history_count > 0:
            # Soft delete - just disable the channel
            channel.enabled = False
            await db.commit()
            message = f"Notification channel '{channel.name}' disabled (has history)"
        else:
            # Hard delete
            await db.delete(channel)
            await db.commit()
            message = f"Notification channel '{channel.name}' deleted"
        
        logger.info(message)
        return {"message": message}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting notification channel {channel_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send", response_model=SendNotificationResponse)
async def send_notifications(
    request: SendNotificationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Send notifications for specific alerts
    """
    try:
        # Validate alert IDs
        alert_ids = [str(alert_id) for alert_id in request.alert_ids]
        count_query = select(func.count(Alert.id)).filter(Alert.id.in_(alert_ids))
        count_result = await db.execute(count_query)
        existing_alerts = count_result.scalar()
        
        if existing_alerts != len(alert_ids):
            raise HTTPException(
                status_code=400,
                detail="One or more alert IDs not found"
            )
        
        # Get channel types to use
        notification_types = None
        if request.channel_ids:
            query = select(NotificationChannel).filter(
                NotificationChannel.id.in_([str(cid) for cid in request.channel_ids])
            )
            result = await db.execute(query)
            channels = result.scalars().all()
            notification_types = [channel.type for channel in channels]
        
        # Send notifications in background
        background_tasks.add_task(
            _send_notifications_background,
            db, alert_ids, notification_types, request.force_send
        )
        
        return SendNotificationResponse(
            success=True,
            sent_count=0,  # Will be updated in background
            failed_count=0,
            skipped_count=0,
            errors=[],
            notification_ids=[]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating notifications: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test", response_model=TestNotificationResponse)
async def test_notification_channel(
    request: TestNotificationRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Send a test notification to verify channel configuration
    """
    try:
        query = select(NotificationChannel).filter(
            NotificationChannel.id == request.channel_id
        )
        result = await db.execute(query)
        channel = result.scalar_one_or_none()
        
        if not channel:
            raise HTTPException(status_code=404, detail="Notification channel not found")
        
        # Update notification service with channel config
        notification_service.update_config(channel.type, channel.config)
        
        # Send test notification
        success = notification_service.test_notification(channel.type)
        
        if success:
            return TestNotificationResponse(
                success=True,
                message="Test notification sent successfully",
                sent_at=datetime.utcnow()
            )
        else:
            return TestNotificationResponse(
                success=False,
                message="Test notification failed",
                error="Failed to send test notification"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing notification channel: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history", response_model=List[NotificationHistoryResponse])
async def get_notification_history(
    alert_id: Optional[str] = None,
    channel_id: Optional[str] = None,
    status: Optional[str] = None,
    hours: Optional[int] = 24,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    Get notification history with optional filtering
    """
    try:
        query = select(NotificationHistory)
        
        # Apply filters
        if alert_id:
            query = query.filter(NotificationHistory.alert_id == alert_id)
        
        if channel_id:
            query = query.filter(NotificationHistory.channel_id == channel_id)
        
        if status:
            query = query.filter(NotificationHistory.status == status)
        
        if hours:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(NotificationHistory.created_at >= cutoff_time)
        
        # Apply pagination and ordering
        query = query.order_by(desc(NotificationHistory.created_at)).offset(offset).limit(limit)
        result = await db.execute(query)
        history = result.scalars().all()
        
        return [NotificationHistoryResponse.model_validate(record) for record in history]
        
    except Exception as e:
        logger.error(f"Error retrieving notification history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=NotificationStatsResponse)
async def get_notification_stats(db: AsyncSession = Depends(get_db)):
    """
    Get notification statistics and metrics
    """
    try:
        # Get overall stats
        sent_query = select(func.count(NotificationHistory.id)).filter(
            NotificationHistory.status == "sent"
        )
        sent_result = await db.execute(sent_query)
        total_sent = sent_result.scalar()
        
        failed_query = select(func.count(NotificationHistory.id)).filter(
            NotificationHistory.status == "failed"
        )
        failed_result = await db.execute(failed_query)
        total_failed = failed_result.scalar()
        
        success_rate = (total_sent / (total_sent + total_failed) * 100) if (total_sent + total_failed) > 0 else 0
        
        # Get stats by channel
        channels = {}
        channels_query = select(NotificationChannel)
        channels_result = await db.execute(channels_query)
        all_channels = channels_result.scalars().all()
        
        for channel in all_channels:
            channel_sent_query = select(func.count(NotificationHistory.id)).filter(
                and_(
                    NotificationHistory.channel_id == channel.id,
                    NotificationHistory.status == "sent"
                )
            )
            channel_sent_result = await db.execute(channel_sent_query)
            channel_sent = channel_sent_result.scalar()
            
            channel_failed_query = select(func.count(NotificationHistory.id)).filter(
                and_(
                    NotificationHistory.channel_id == channel.id,
                    NotificationHistory.status == "failed"
                )
            )
            channel_failed_result = await db.execute(channel_failed_query)
            channel_failed = channel_failed_result.scalar()
            
            channels[str(channel.id)] = {
                "name": channel.name,
                "type": channel.type,
                "enabled": channel.enabled,
                "sent": channel_sent,
                "failed": channel_failed,
                "success_rate": (channel_sent / (channel_sent + channel_failed) * 100) if (channel_sent + channel_failed) > 0 else 0
            }
        
        # Get recent activity (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_activity = []
        
        recent_query = select(NotificationHistory).filter(
            NotificationHistory.created_at >= recent_cutoff
        ).order_by(desc(NotificationHistory.created_at)).limit(10)
        recent_result = await db.execute(recent_query)
        recent_notifications = recent_result.scalars().all()
        
        for notification in recent_notifications:
            recent_activity.append({
                "id": str(notification.id),
                "alert_id": str(notification.alert_id),
                "channel_type": notification.channel_type,
                "status": notification.status,
                "created_at": notification.created_at.isoformat()
            })
        
        return NotificationStatsResponse(
            total_sent=total_sent,
            total_failed=total_failed,
            success_rate=success_rate,
            channels=channels,
            recent_activity=recent_activity,
            rate_limits={}  # TODO: Implement rate limiting stats
        )
        
    except Exception as e:
        logger.error(f"Error retrieving notification stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config", response_model=NotificationConfigResponse)
async def get_notification_config(db: AsyncSession = Depends(get_db)):
    """
    Get complete notification configuration
    """
    try:
        # Get all channels
        query = select(NotificationChannel)
        result = await db.execute(query)
        channels = result.scalars().all()
        channel_responses = [NotificationChannelResponse.model_validate(channel) for channel in channels]
        
        # Get notification service stats
        stats = notification_service.get_notification_stats(db)
        
        return NotificationConfigResponse(
            channels=channel_responses,
            global_settings={
                "rate_limiting": {"enabled": True},
                "deduplication": {"enabled": True}
            },
            health_status=stats.get("configuration_status", {})
        )
        
    except Exception as e:
        logger.error(f"Error retrieving notification config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _send_notifications_background(
    db: AsyncSession,
    alert_ids: List[str],
    notification_types: Optional[List[str]],
    force_send: bool = False
):
    """Background task for sending notifications"""
    try:
        sent_count, failed_count, errors = await notification_service.send_notifications(
            db, alert_ids, notification_types
        )
        logger.info(f"Notifications completed: {sent_count} sent, {failed_count} failed")
        
        if errors:
            logger.warning(f"Notification errors: {errors}")
            
    except Exception as e:
        logger.error(f"Background notification sending failed: {e}")


# Template Management Endpoints
@router.get("/templates", response_model=List[NotificationTemplateResponse])
async def get_notification_templates(
    channel_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get notification templates
    """
    try:
        query = select(NotificationTemplate)
        
        if channel_type:
            query = query.filter(NotificationTemplate.channel_type == channel_type)
        
        query = query.order_by(NotificationTemplate.created_at)
        result = await db.execute(query)
        templates = result.scalars().all()
        
        return [NotificationTemplateResponse.model_validate(template) for template in templates]
        
    except Exception as e:
        logger.error(f"Error retrieving notification templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/templates", response_model=NotificationTemplateResponse)
async def create_notification_template(
    template_data: NotificationTemplateCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new notification template
    """
    try:
        template = NotificationTemplate(
            id=uuid.uuid4(),
            name=template_data.name,
            channel_type=template_data.channel_type.value,
            subject_template=template_data.subject_template,
            body_template=template_data.body_template,
            enabled=True
        )
        
        db.add(template)
        await db.commit()
        await db.refresh(template)
        
        logger.info(f"Created notification template: {template.name}")
        return NotificationTemplateResponse.model_validate(template)
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating notification template: {e}")
        raise HTTPException(status_code=500, detail=str(e))