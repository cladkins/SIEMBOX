"""
SIEM BOX - Alert Service
"""
import logging
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, and_, or_, desc, select
from app.models.logs import Alert, DetectionRule, ParsedLog
from app.schemas.detection import (
    AlertCreate, AlertUpdate, AlertResponse, AlertQueryParams,
    AlertStatus, SeverityLevel
)
from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)


class AlertService:
    """
    Service for managing security alerts
    """
    
    async def create_alert(self, db: AsyncSession, alert_data: AlertCreate) -> Alert:
        """
        Create a new alert
        """
        try:
            # Validate that the parsed log exists
            result = await db.execute(select(ParsedLog).filter(ParsedLog.id == alert_data.parsed_log_id))
            parsed_log = result.scalar_one_or_none()
            if not parsed_log:
                raise ValueError(f"Parsed log {alert_data.parsed_log_id} not found")
            
            # Validate that the detection rule exists
            result = await db.execute(select(DetectionRule).filter(DetectionRule.id == alert_data.detection_rule_id))
            detection_rule = result.scalar_one_or_none()
            if not detection_rule:
                raise ValueError(f"Detection rule {alert_data.detection_rule_id} not found")
            
            # Create alert
            alert = Alert(
                parsed_log_id=alert_data.parsed_log_id,
                detection_rule_id=alert_data.detection_rule_id,
                title=alert_data.title,
                description=alert_data.description,
                severity=alert_data.severity,
                category=alert_data.category,
                status=alert_data.status,
                alert_data=alert_data.alert_data,
                triggered_at=datetime.utcnow()
            )
            
            db.add(alert)
            await db.commit()
            await db.refresh(alert)
            
            logger.info(f"Created alert: {alert.title} (ID: {alert.id})")
            
            # Send notification asynchronously
            try:
                import asyncio
                asyncio.create_task(
                    notification_service.send_alert_notification(db, str(alert.id))
                )
            except Exception as e:
                logger.warning(f"Failed to send alert notification: {e}")
            
            return alert
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating alert: {e}")
            raise
    
    async def get_alert(self, db: AsyncSession, alert_id: str) -> Optional[Alert]:
        """
        Get a specific alert by ID
        """
        try:
            result = await db.execute(select(Alert).filter(Alert.id == alert_id))
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error retrieving alert {alert_id}: {e}")
            raise
    
    async def get_alerts(self, db: AsyncSession, params: AlertQueryParams) -> Tuple[List[Alert], int]:
        """
        Get alerts with filtering and pagination
        """
        try:
            query = select(Alert)
            
            # Apply filters
            if params.status:
                query = query.filter(Alert.status == params.status)
            
            if params.severity:
                query = query.filter(Alert.severity == params.severity)
            
            if params.category:
                query = query.filter(Alert.category == params.category)
            
            if params.rule_id:
                query = query.filter(Alert.detection_rule_id == params.rule_id)
            
            if params.start_date:
                query = query.filter(Alert.triggered_at >= params.start_date)
            
            if params.end_date:
                query = query.filter(Alert.triggered_at <= params.end_date)
            
            # Get total count
            count_result = await db.execute(select(func.count()).select_from(query.subquery()))
            total_count = count_result.scalar()
            
            # Apply pagination and ordering
            result = await db.execute(query.order_by(desc(Alert.triggered_at)).offset(params.offset).limit(params.limit))
            alerts = result.scalars().all()
            
            return alerts, total_count
            
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            raise
    
    async def update_alert(self, db: AsyncSession, alert_id: str, update_data: AlertUpdate) -> Optional[Alert]:
        """
        Update an alert
        """
        try:
            result = await db.execute(select(Alert).filter(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                return None
            
            # Update fields
            if update_data.status is not None:
                old_status = alert.status
                alert.status = update_data.status
                
                # Set timestamps based on status changes
                if update_data.status == AlertStatus.acknowledged and old_status != AlertStatus.acknowledged:
                    alert.acknowledged_at = datetime.utcnow()
                elif update_data.status == AlertStatus.resolved and old_status != AlertStatus.resolved:
                    alert.resolved_at = datetime.utcnow()
            
            if update_data.notes is not None:
                alert.notes = update_data.notes
            
            await db.commit()
            await db.refresh(alert)
            
            logger.info(f"Updated alert {alert_id}: status={alert.status}")
            return alert
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error updating alert {alert_id}: {e}")
            raise
    
    async def delete_alert(self, db: AsyncSession, alert_id: str) -> bool:
        """
        Delete an alert
        """
        try:
            result = await db.execute(select(Alert).filter(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                return False
            
            await db.delete(alert)
            await db.commit()
            
            logger.info(f"Deleted alert {alert_id}")
            return True
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error deleting alert {alert_id}: {e}")
            raise
    
    async def acknowledge_alert(self, db: AsyncSession, alert_id: str, notes: Optional[str] = None) -> Optional[Alert]:
        """
        Acknowledge an alert
        """
        update_data = AlertUpdate(status=AlertStatus.acknowledged, notes=notes)
        return await self.update_alert(db, alert_id, update_data)
    
    async def resolve_alert(self, db: AsyncSession, alert_id: str, notes: Optional[str] = None) -> Optional[Alert]:
        """
        Resolve an alert
        """
        update_data = AlertUpdate(status=AlertStatus.resolved, notes=notes)
        return await self.update_alert(db, alert_id, update_data)
    
    async def mark_false_positive(self, db: AsyncSession, alert_id: str, notes: Optional[str] = None) -> Optional[Alert]:
        """
        Mark an alert as false positive
        """
        update_data = AlertUpdate(status=AlertStatus.false_positive, notes=notes)
        return await self.update_alert(db, alert_id, update_data)
    
    async def get_alert_statistics(self, db: AsyncSession, days: int = 30) -> Dict[str, Any]:
        """
        Get alert statistics for the specified number of days
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Total alerts
            total_result = await db.execute(select(func.count(Alert.id)))
            total_alerts = total_result.scalar()
            recent_result = await db.execute(select(func.count(Alert.id)).filter(Alert.triggered_at >= cutoff_date))
            recent_alerts = recent_result.scalar()
            
            # Status distribution
            status_result = await db.execute(select(Alert.status, func.count(Alert.id)).group_by(Alert.status))
            status_stats = status_result.all()
            status_distribution = {status: count for status, count in status_stats}
            
            # Severity distribution
            severity_result = await db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity))
            severity_stats = severity_result.all()
            severity_distribution = {severity: count for severity, count in severity_stats}
            
            # Category distribution
            category_result = await db.execute(select(Alert.category, func.count(Alert.id)).group_by(Alert.category))
            category_stats = category_result.all()
            category_distribution = {category: count for category, count in category_stats}
            
            # Recent trends (daily counts for the last 7 days)
            daily_trends = []
            for i in range(7):
                day_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                
                day_count_result = await db.execute(select(func.count(Alert.id)).filter(
                    and_(Alert.triggered_at >= day_start, Alert.triggered_at < day_end)
                ))
                day_count = day_count_result.scalar()
                
                daily_trends.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "count": day_count
                })
            
            # Top detection rules by alert count
            top_rules_result = await db.execute(
                select(
                    DetectionRule.name,
                    func.count(Alert.id).label('alert_count')
                ).join(Alert).group_by(DetectionRule.name).order_by(
                    desc(func.count(Alert.id))
                ).limit(10)
            )
            top_rules = top_rules_result.all()
            
            top_rules_data = [{"rule_name": name, "alert_count": count} for name, count in top_rules]
            
            return {
                "total_alerts": total_alerts,
                "recent_alerts": recent_alerts,
                "status_distribution": status_distribution,
                "severity_distribution": severity_distribution,
                "category_distribution": category_distribution,
                "daily_trends": daily_trends,
                "top_detection_rules": top_rules_data,
                "period_days": days
            }
            
        except Exception as e:
            logger.error(f"Error retrieving alert statistics: {e}")
            raise
    
    async def get_open_alerts_count(self, db: AsyncSession) -> int:
        """
        Get count of open alerts
        """
        try:
            result = await db.execute(select(func.count(Alert.id)).filter(Alert.status == AlertStatus.open))
            return result.scalar()
        except Exception as e:
            logger.error(f"Error getting open alerts count: {e}")
            raise
    
    async def get_critical_alerts(self, db: AsyncSession, limit: int = 10) -> List[Alert]:
        """
        Get recent critical alerts
        """
        try:
            result = await db.execute(select(Alert).filter(
                and_(
                    Alert.severity == SeverityLevel.critical,
                    Alert.status == AlertStatus.open
                )
            ).order_by(desc(Alert.triggered_at)).limit(limit))
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Error retrieving critical alerts: {e}")
            raise
    
    async def bulk_update_alerts(self, db: AsyncSession, alert_ids: List[str], update_data: AlertUpdate) -> int:
        """
        Bulk update multiple alerts
        """
        try:
            updated_count = 0
            
            for alert_id in alert_ids:
                alert = await self.update_alert(db, alert_id, update_data)
                if alert:
                    updated_count += 1
            
            logger.info(f"Bulk updated {updated_count} alerts")
            return updated_count
            
        except Exception as e:
            logger.error(f"Error in bulk update: {e}")
            raise
    
    async def get_alerts_by_rule(self, db: AsyncSession, rule_id: str, limit: int = 100) -> List[Alert]:
        """
        Get alerts generated by a specific detection rule
        """
        try:
            result = await db.execute(select(Alert).filter(
                Alert.detection_rule_id == rule_id
            ).order_by(desc(Alert.triggered_at)).limit(limit))
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Error retrieving alerts for rule {rule_id}: {e}")
            raise


# Global alert service instance
alert_service = AlertService()