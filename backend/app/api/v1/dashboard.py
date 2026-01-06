"""
SIEM BOX - Dashboard API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc, select
from typing import Dict, Any, List
from datetime import datetime, timedelta
import logging

from app.db.database import get_db
from app.core.deps import get_current_active_user
from app.models.users import User
from app.models.logs import ProcessedLog, Alert
from app.models.vulnerabilities import Asset, VulnerabilityScan, Vulnerability
from app.schemas.vulnerabilities import DashboardStats as VulnDashboardStats
from app.services.vulnerability_service import vulnerability_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get comprehensive dashboard statistics combining all SIEM modules
    """
    try:
        # Get current time for calculations
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        last_30d = now - timedelta(days=30)

        # === LOG STATISTICS ===
        try:
            total_logs = (await db.execute(select(func.count(ProcessedLog.id)))).scalar() or 0
            recent_logs_24h = (await db.execute(
                select(func.count(ProcessedLog.id)).filter(ProcessedLog.timestamp >= last_24h)
            )).scalar() or 0
            logs_last_7d = (await db.execute(
                select(func.count(ProcessedLog.id)).filter(ProcessedLog.timestamp >= last_7d)
            )).scalar() or 0
            logs_last_30d = (await db.execute(
                select(func.count(ProcessedLog.id)).filter(ProcessedLog.timestamp >= last_30d)
            )).scalar() or 0
            
            top_sources_query = select(
                ProcessedLog.source,
                func.count(ProcessedLog.id).label("count")
            ).group_by(ProcessedLog.source).order_by(desc("count")).limit(5)
            top_sources = [
                {"source": source or "unknown", "count": count}
                for source, count in (await db.execute(top_sources_query)).all()
            ]
            
            log_stats = {
                "total_logs": total_logs,
                "total_raw_logs": total_logs,
                "recent_logs_24h": recent_logs_24h,
                "logs_last_7d": logs_last_7d,
                "logs_last_30d": logs_last_30d,
                "top_sources": top_sources,
                "architecture": "Direct ingestion"
            }
            
        except Exception as e:
            logger.warning(f"Error getting log stats: {e}")
            log_stats = {
                "total_logs": 0,
                "total_raw_logs": 0,
                "recent_logs_24h": 0,
                "logs_last_7d": 0,
                "logs_last_30d": 0,
                "top_sources": [],
                "architecture": "Direct ingestion"
            }

        # === VULNERABILITY STATISTICS ===
        try:
            vuln_stats = await vulnerability_service.get_vulnerability_stats(db)
            
            # Get recent vulnerability scans
            recent_scans_query = select(VulnerabilityScan).order_by(
                desc(VulnerabilityScan.created_at)
            ).limit(5)
            recent_scans_result = await db.execute(recent_scans_query)
            recent_scans = recent_scans_result.scalars().all()
            
            # Get top vulnerabilities by severity
            top_vulns_query = select(Vulnerability).filter(
                Vulnerability.status == 'open'
            ).order_by(
                desc(Vulnerability.cvss_score)
            ).limit(10)
            top_vulns_result = await db.execute(top_vulns_query)
            top_vulnerabilities = top_vulns_result.scalars().all()
            
            # Map vulnerability service stats to dashboard format
            vuln_data = vuln_stats['vulnerabilities']
            vulnerability_stats = {
                "total_vulnerabilities": vuln_data['total'],
                "critical_count": vuln_data['critical'],
                "high_count": vuln_data['high'],
                "medium_count": vuln_data['medium'],
                "low_count": vuln_data['low'],
                "info_count": vuln_data['info'],
                "open_count": vuln_data['open'],
                "fixed_count": vuln_data['fixed'],
                "false_positive_count": vuln_data['false_positive'],
                "risk_accepted_count": 0,  # Not tracked in current service
                "recent_scans": [
                    {
                        "id": str(scan.id),
                        "scan_name": scan.scan_name,
                        "status": scan.status,
                        "vulnerabilities_found": scan.vulnerabilities_found,
                        "created_at": scan.created_at.isoformat() if scan.created_at else None
                    } for scan in recent_scans
                ],
                "top_vulnerabilities": [
                    {
                        "id": str(vuln.id),
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "cvss_score": vuln.cvss_score,
                        "cve_id": vuln.cve_id
                    } for vuln in top_vulnerabilities
                ]
            }
            
            # Map asset stats
            asset_data = vuln_stats['assets']
            asset_stats = {
                "total_assets": asset_data['total'],
                "active_assets": asset_data['active'],
                "inactive_assets": asset_data['total'] - asset_data['active'],
                "scanned_assets": asset_data['total'],  # Assume all assets are scanned
                "vulnerable_assets": asset_data['vulnerable']
            }
            
            # Map scan stats
            scan_data = vuln_stats['scans']
            scan_stats = {
                "total_scans": scan_data['total'],
                "completed_scans": scan_data['completed'],
                "failed_scans": scan_data['failed'],
                "running_scans": scan_data['running'],
                "scheduled_scans": 0  # Not tracked in current service
            }
            
        except Exception as e:
            logger.warning(f"Error getting vulnerability stats: {e}")
            vulnerability_stats = {
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "open_count": 0,
                "fixed_count": 0,
                "false_positive_count": 0,
                "risk_accepted_count": 0,
                "recent_scans": [],
                "top_vulnerabilities": []
            }
            asset_stats = {
                "total_assets": 0,
                "active_assets": 0,
                "inactive_assets": 0,
                "scanned_assets": 0,
                "vulnerable_assets": 0
            }
            scan_stats = {
                "total_scans": 0,
                "completed_scans": 0,
                "failed_scans": 0,
                "running_scans": 0,
                "scheduled_scans": 0
            }

        # === ALERT STATISTICS ===
        try:
            total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
            open_alerts = (await db.execute(
                select(func.count(Alert.id)).filter(Alert.status == "open")
            )).scalar() or 0
            acknowledged_alerts = (await db.execute(
                select(func.count(Alert.id)).filter(Alert.status == "investigating")
            )).scalar() or 0
            resolved_alerts = (await db.execute(
                select(func.count(Alert.id)).filter(Alert.status == "resolved")
            )).scalar() or 0
            recent_alerts_24h = (await db.execute(
                select(func.count(Alert.id)).filter(Alert.triggered_at >= last_24h)
            )).scalar() or 0
            
            severity_counts_query = select(
                Alert.severity,
                func.count(Alert.id)
            ).group_by(Alert.severity)
            severity_counts = {severity or "unknown": count for severity, count in (await db.execute(severity_counts_query)).all()}
            
            alert_stats = {
                "total_alerts": total_alerts,
                "open_alerts": open_alerts,
                "acknowledged_alerts": acknowledged_alerts,
                "resolved_alerts": resolved_alerts,
                "critical_alerts": severity_counts.get("critical", 0),
                "high_alerts": severity_counts.get("high", 0),
                "medium_alerts": severity_counts.get("medium", 0),
                "low_alerts": severity_counts.get("low", 0),
                "recent_alerts_24h": recent_alerts_24h
            }
        except Exception as e:
            logger.warning(f"Error getting alert stats: {e}")
            alert_stats = {
                "total_alerts": 0,
                "open_alerts": 0,
                "acknowledged_alerts": 0,
                "resolved_alerts": 0,
                "critical_alerts": 0,
                "high_alerts": 0,
                "medium_alerts": 0,
                "low_alerts": 0,
                "recent_alerts_24h": 0
            }

        # === SYSTEM STATISTICS ===
        system_stats = {
            "uptime": "N/A",  # Would need to track application start time
            "last_updated": now.isoformat(),
            "database_status": "connected",  # Since we got here, DB is connected
            "active_connections": 1  # Placeholder
        }

        # === COMBINED RESPONSE ===
        return {
            "timestamp": now.isoformat(),
            "log_stats": log_stats,
            "vulnerability_stats": vulnerability_stats,
            "asset_stats": asset_stats,
            "scan_stats": scan_stats,
            "alert_stats": alert_stats,
            "system_stats": system_stats,
            
            # Legacy compatibility fields for existing frontend
            "total_logs": log_stats["total_logs"],
            "recent_logs": log_stats["recent_logs_24h"],
            "total_vulnerabilities": vulnerability_stats["total_vulnerabilities"],
            "critical_vulnerabilities": vulnerability_stats["critical_count"],
            "high_vulnerabilities": vulnerability_stats["high_count"],
            "medium_vulnerabilities": vulnerability_stats["medium_count"],
            "low_vulnerabilities": vulnerability_stats["low_count"],
            "total_assets": asset_stats["total_assets"],
            "active_assets": asset_stats["active_assets"],
            "total_scans": scan_stats["total_scans"],
            "running_scans": scan_stats["running_scans"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/log-volume")
async def get_log_volume_data(
    hours: int = 24,
    db: AsyncSession = Depends(get_db)
):
    """
    Get log volume data for charts
    """
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Get log volume by hour using processed logs
        log_volume_query = select(
            func.date_trunc('hour', ProcessedLog.timestamp).label('hour'),
            func.count(ProcessedLog.id).label('count')
        ).filter(
            ProcessedLog.timestamp >= start_time
        ).group_by(
            func.date_trunc('hour', ProcessedLog.timestamp)
        ).order_by('hour')
        log_volume_result = await db.execute(log_volume_query)
        log_volume = log_volume_result.all()
        
        return {
            "data": [
                {
                    "timestamp": hour.isoformat() if hour else None,
                    "count": count
                } for hour, count in log_volume
            ],
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving log volume data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/top-sources")
async def get_top_sources(
    limit: int = 10,
    db: AsyncSession = Depends(get_db)
):
    """
    Get top log sources by source IP
    """
    try:
        query = select(
            ProcessedLog.source_ip,
            func.count(ProcessedLog.id).label("count")
        ).group_by(
            ProcessedLog.source_ip
        ).order_by(
            desc("count")
        ).limit(limit)
        
        result = await db.execute(query)
        rows = result.all()
        
        return {
            "data": [
                {
                    "source_ip": source_ip or "unknown",
                    "count": count
                } for source_ip, count in rows
            ],
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Error retrieving top sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alert-trends")
async def get_alert_trends(
    hours: int = 24,
    db: AsyncSession = Depends(get_db)
):
    """
    Get alert trends grouped by severity over time
    """
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        query = select(
            func.date_trunc('hour', Alert.triggered_at).label('hour'),
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.triggered_at >= start_time
        ).group_by(
            func.date_trunc('hour', Alert.triggered_at),
            Alert.severity
        ).order_by('hour')
        
        result = await db.execute(query)
        rows = result.all()
        
        data = [
            {
                "timestamp": hour.isoformat() if hour else None,
                "severity": severity or "unknown",
                "count": count
            }
            for hour, severity, count in rows
        ]
        
        return {
            "data": data,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving alert trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerability-trends")
async def get_vulnerability_trends(
    days: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """
    Get vulnerability trends over time
    """
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get vulnerability counts by day and severity
        vuln_trends_query = select(
            func.date_trunc('day', Vulnerability.first_detected).label('day'),
            Vulnerability.severity,
            func.count(Vulnerability.id).label('count')
        ).filter(
            Vulnerability.first_detected >= start_date
        ).group_by(
            func.date_trunc('day', Vulnerability.first_detected),
            Vulnerability.severity
        ).order_by('day')
        vuln_trends_result = await db.execute(vuln_trends_query)
        vuln_trends = vuln_trends_result.all()
        
        # Organize data by day
        trends_by_day = {}
        for day, severity, count in vuln_trends:
            day_str = day.isoformat() if day else None
            if day_str not in trends_by_day:
                trends_by_day[day_str] = {
                    "timestamp": day_str,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            trends_by_day[day_str][severity] = count
        
        return {
            "data": list(trends_by_day.values()),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving vulnerability trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))
