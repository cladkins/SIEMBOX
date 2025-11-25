"""
SIEM BOX - Vulnerability Scanning API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, and_, or_, func, select
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from app.db.database import get_db
from app.models.vulnerabilities import (
    Asset, VulnerabilityScan, Vulnerability, ScanSchedule, CVEDatabase
)
from app.schemas.vulnerabilities import (
    AssetResponse, AssetCreate, AssetUpdate, AssetDiscoveryRequest,
    VulnerabilityScanResponse, VulnerabilityScanCreate, VulnerabilityScanUpdate,
    VulnerabilityResponse, VulnerabilityCreate, VulnerabilityUpdate,
    ScanScheduleResponse, ScanScheduleCreate, ScanScheduleUpdate,
    CVEDatabaseResponse, CVEDatabaseCreate, CVEDatabaseUpdate,
    ScanRequest, ScanStatusResponse, BulkVulnerabilityUpdate,
    DashboardStats, ExportRequest, ExportResponse
)
from app.schemas.logs import PaginatedResponse
from app.services.vulnerability_service import vulnerability_service
import logging
from uuid import UUID

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


async def _start_scan_job(
    scan_request: ScanRequest,
    db: AsyncSession
) -> Dict[str, str]:
    """Shared logic for kicking off vulnerability scans."""
    scan_create = VulnerabilityScanCreate(
        scan_name=scan_request.scan_name,
        scan_type=scan_request.scan_type,
        target=",".join(scan_request.targets),
        scan_config=scan_request.scan_config
    )
    scan_id = await vulnerability_service.start_scan(db, scan_create)
    logger.info(f"Started scan {scan_id}: {scan_request.scan_name}")
    return {"scan_id": scan_id, "message": "Scan started successfully"}


async def _start_asset_discovery_job(
    db: AsyncSession,
    discovery_request: AssetDiscoveryRequest
) -> Dict[str, str]:
    """Shared logic for kicking off asset discovery scans."""
    scan_id = await vulnerability_service.discover_assets(
        db,
        discovery_request.target,
        discovery_request.discovery_method,
        discovery_request.scan_config
    )
    logger.info(f"Started asset discovery for {discovery_request.target}")
    return {
        "scan_id": scan_id,
        "message": f"Asset discovery started for {discovery_request.target}"
    }


# Asset Management Endpoints
@router.get("/assets", response_model=List[AssetResponse])
async def get_assets(
    active_only: bool = Query(False, description="Return only active assets"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    limit: int = Query(100, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get assets with optional filtering
    """
    try:
        query = select(Asset)
        
        if active_only:
            query = query.filter(Asset.is_active == True)
        
        if asset_type:
            query = query.filter(Asset.asset_type == asset_type)
        
        result = await db.execute(query.order_by(desc(Asset.last_seen)).offset(offset).limit(limit))
        assets = result.scalars().all()
        return [AssetResponse.model_validate(asset) for asset in assets]
        
    except Exception as e:
        logger.error(f"Error retrieving assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific asset by ID
    """
    try:
        result = await db.execute(select(Asset).filter(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        return AssetResponse.model_validate(asset)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assets", response_model=AssetResponse)
async def create_asset(
    asset: AssetCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new asset
    """
    try:
        # Check if asset with same IP already exists
        result = await db.execute(select(Asset).filter(Asset.ip_address == asset.ip_address))
        existing_asset = result.scalar_one_or_none()
        if existing_asset:
            raise HTTPException(status_code=400, detail="Asset with this IP address already exists")
        
        db_asset = Asset(**asset.dict())
        db.add(db_asset)
        await db.commit()
        await db.refresh(db_asset)
        
        logger.info(f"Created asset {db_asset.id}: {asset.ip_address}")
        return AssetResponse.model_validate(db_asset)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/assets/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: UUID,
    asset_update: AssetUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update an asset
    """
    try:
        result = await db.execute(select(Asset).filter(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Update fields
        update_data = asset_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(asset, field, value)
        
        await db.commit()
        await db.refresh(asset)
        
        logger.info(f"Updated asset {asset_id}")
        return AssetResponse.model_validate(asset)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete an asset
    """
    try:
        result = await db.execute(select(Asset).filter(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        await db.delete(asset)
        await db.commit()
        
        logger.info(f"Deleted asset {asset_id}")
        return {"message": "Asset deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Vulnerability Scan Endpoints
@router.get("/scans", response_model=List[VulnerabilityScanResponse])
async def get_scans(
    status: Optional[str] = Query(None, description="Filter by scan status"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    limit: int = Query(100, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get vulnerability scans with optional filtering
    """
    try:
        query = select(VulnerabilityScan)
        
        if status:
            query = query.filter(VulnerabilityScan.status == status)
        
        if scan_type:
            query = query.filter(VulnerabilityScan.scan_type == scan_type)
        
        result = await db.execute(query.order_by(desc(VulnerabilityScan.created_at)).offset(offset).limit(limit))
        scans = result.scalars().all()
        return [VulnerabilityScanResponse.model_validate(scan) for scan in scans]
        
    except Exception as e:
        logger.error(f"Error retrieving scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}", response_model=VulnerabilityScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific scan by ID
    """
    try:
        result = await db.execute(select(VulnerabilityScan).filter(VulnerabilityScan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return VulnerabilityScanResponse.model_validate(scan)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scans", response_model=Dict[str, str])
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new vulnerability scan
    """
    try:
        return await _start_scan_job(scan_request, db)
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scans/start", response_model=Dict[str, str])
async def start_scan_compat(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Compatibility endpoint matching /scans/start used by the frontend.
    """
    try:
        return await _start_scan_job(scan_request, db)
    except Exception as e:
        logger.error(f"Error starting scan via /scans/start: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get current scan status
    """
    try:
        status_info = vulnerability_service.get_scan_status(str(scan_id))
        
        if status_info['status'] == 'unknown':
            # Check database for completed scans
            result = await db.execute(select(VulnerabilityScan).filter(VulnerabilityScan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                return ScanStatusResponse(
                    scan_id=scan_id,
                    status=scan.status,
                    progress=scan.progress,
                    message=scan.error_message
                )
            else:
                raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanStatusResponse(
            scan_id=scan_id,
            status=status_info['status'],
            progress=status_info['progress']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan status {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Cancel a running scan
    """
    try:
        success = await vulnerability_service.cancel_scan(db, str(scan_id))
        
        if not success:
            raise HTTPException(status_code=400, detail="Cannot cancel scan")
        
        logger.info(f"Cancelled scan {scan_id}")
        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Vulnerability Management Endpoints
@router.get("/", response_model=PaginatedResponse[VulnerabilityResponse])
async def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    asset_id: Optional[UUID] = Query(None, description="Filter by asset ID"),
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    limit: int = Query(100, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get vulnerabilities with optional filtering
    """
    try:
        # Build the base query
        query = select(Vulnerability)
        
        if severity:
            query = query.filter(Vulnerability.severity == severity)
        
        if status:
            query = query.filter(Vulnerability.status == status)
        
        if asset_id:
            query = query.filter(Vulnerability.asset_id == asset_id)
        
        if cve_id:
            query = query.filter(Vulnerability.cve_id == cve_id)
        
        # Get total count for pagination
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Get the actual data
        result = await db.execute(query.order_by(desc(Vulnerability.first_detected)).offset(offset).limit(limit))
        vulnerabilities = result.scalars().all()
        
        # Calculate pagination info
        page = (offset // limit) + 1 if limit > 0 else 1
        pages = (total + limit - 1) // limit if limit > 0 else 1
        
        return PaginatedResponse(
            items=[VulnerabilityResponse.model_validate(vuln) for vuln in vulnerabilities],
            total=total,
            page=page,
            size=limit,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_vulnerability_stats(db: AsyncSession = Depends(get_db)):
    """
    Get vulnerability statistics (for frontend compatibility)
    """
    try:
        stats = await vulnerability_service.get_vulnerability_stats(db)
        # Return just the vulnerability stats portion that the frontend expects
        return stats['vulnerabilities']
        
    except Exception as e:
        logger.error(f"Error retrieving vulnerability stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulk-update")
async def bulk_update_vulnerabilities(
    bulk_update: BulkVulnerabilityUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Bulk update multiple vulnerabilities
    """
    try:
        updated_count = 0
        
        for vulnerability_id in bulk_update.vulnerability_ids:
            result = await db.execute(select(Vulnerability).filter(Vulnerability.id == vulnerability_id))
            vulnerability = result.scalar_one_or_none()
            if vulnerability:
                if bulk_update.status:
                    vulnerability.status = bulk_update.status
                if bulk_update.risk_accepted is not None:
                    vulnerability.risk_accepted = bulk_update.risk_accepted
                updated_count += 1
        
        await db.commit()
        
        logger.info(f"Bulk updated {updated_count} vulnerabilities")
        return {
            "message": f"Updated {updated_count} vulnerabilities",
            "updated_count": updated_count
        }
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Error bulk updating vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Asset Discovery Endpoints
@router.post("/discover")
async def discover_assets(
    discovery_request: Optional[AssetDiscoveryRequest] = None,
    network_range: Optional[str] = Query(
        None,
        description="Fallback network range to scan (e.g., 192.168.1.0/24)"
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Discover assets in network range (legacy compatibility + new body payload)
    """
    try:
        if not discovery_request and not network_range:
            raise HTTPException(status_code=400, detail="Target network range is required")
        
        if discovery_request is None:
            request = AssetDiscoveryRequest(target=network_range or "")
        else:
            request = discovery_request
        return await _start_asset_discovery_job(db, request)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting asset discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assets/discover")
async def discover_assets_compat(
    discovery_request: AssetDiscoveryRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Compatibility endpoint expected by the frontend (/assets/discover).
    """
    try:
        return await _start_asset_discovery_job(db, discovery_request)
    except Exception as e:
        logger.error(f"Error starting asset discovery via /assets/discover: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Statistics and Dashboard Endpoints
@router.get("/stats/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """
    Get vulnerability dashboard statistics
    """
    try:
        stats = await vulnerability_service.get_vulnerability_stats(db)
        
        # Get recent scans
        result = await db.execute(
            select(VulnerabilityScan)
            .order_by(desc(VulnerabilityScan.created_at))
            .limit(5)
        )
        recent_scans = result.scalars().all()
        
        # Get top vulnerabilities by severity
        result = await db.execute(
            select(Vulnerability)
            .filter(Vulnerability.status == 'open')
            .order_by(desc(Vulnerability.cvss_score))
            .limit(10)
        )
        top_vulnerabilities = result.scalars().all()
        
        return DashboardStats(
            vulnerability_stats=stats['vulnerabilities'],
            asset_stats=stats['assets'],
            scan_stats=stats['scans'],
            recent_scans=[VulnerabilityScanResponse.model_validate(scan) for scan in recent_scans],
            top_vulnerabilities=[VulnerabilityResponse.model_validate(vuln) for vuln in top_vulnerabilities]
        )
        
    except Exception as e:
        logger.error(f"Error retrieving dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/summary")
async def get_vulnerability_summary(db: AsyncSession = Depends(get_db)):
    """
    Get vulnerability summary statistics
    """
    try:
        stats = await vulnerability_service.get_vulnerability_stats(db)
        return stats
        
    except Exception as e:
        logger.error(f"Error retrieving vulnerability summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# CVE Database Endpoints
@router.get("/cve/{cve_id}", response_model=CVEDatabaseResponse)
async def get_cve_info(
    cve_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get CVE information from local database
    """
    try:
        result = await db.execute(select(CVEDatabase).filter(CVEDatabase.cve_id == cve_id))
        cve = result.scalar_one_or_none()
        
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return CVEDatabaseResponse.model_validate(cve)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cve/update")
async def update_cve_database(
    background_tasks: BackgroundTasks,
    days_back: int = Query(7, ge=1, le=30, description="Number of days to update"),
    db: AsyncSession = Depends(get_db)
):
    """
    Update CVE database from NVD
    """
    try:
        # Start CVE update in background
        background_tasks.add_task(
            _update_cve_database_background,
            db, days_back
        )
        
        return {"message": f"CVE database update started for last {days_back} days"}
        
    except Exception as e:
        logger.error(f"Error starting CVE database update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _update_cve_database_background(db: AsyncSession, days_back: int):
    """Background task for updating CVE database"""
    try:
        updated_count = await vulnerability_service.cve_manager.update_cve_database(db, days_back)
        logger.info(f"CVE database update completed: {updated_count} records updated")
        
    except Exception as e:
        logger.error(f"CVE database update failed: {e}")


# Export Endpoints
@router.post("/export", response_model=ExportResponse)
async def export_vulnerabilities(
    export_request: ExportRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Export vulnerability data
    """
    try:
        # For now, return a simple response
        # In a full implementation, this would generate the export file
        export_id = UUID("00000000-0000-0000-0000-000000000000")  # Placeholder
        
        return ExportResponse(
            export_id=export_id,
            status="pending",
            created_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Error starting export: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Scan Schedule Endpoints (for future implementation)
@router.get("/schedules", response_model=List[ScanScheduleResponse])
async def get_scan_schedules(
    enabled_only: bool = Query(False, description="Return only enabled schedules"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan schedules
    """
    try:
        query = select(ScanSchedule)
        
        if enabled_only:
            query = query.filter(ScanSchedule.is_enabled == True)
        
        result = await db.execute(query.order_by(desc(ScanSchedule.created_at)))
        schedules = result.scalars().all()
        return [ScanScheduleResponse.model_validate(schedule) for schedule in schedules]
        
    except Exception as e:
        logger.error(f"Error retrieving scan schedules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/schedules", response_model=ScanScheduleResponse)
async def create_scan_schedule(
    schedule: ScanScheduleCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new scan schedule
    """
    try:
        db_schedule = ScanSchedule(**schedule.dict())
        db.add(db_schedule)
        await db.commit()
        await db.refresh(db_schedule)
        
        logger.info(f"Created scan schedule {db_schedule.id}: {schedule.name}")
        return ScanScheduleResponse.model_validate(db_schedule)
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating scan schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vulnerability_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific vulnerability by ID
    """
    try:
        result = await db.execute(select(Vulnerability).filter(Vulnerability.id == vulnerability_id))
        vulnerability = result.scalar_one_or_none()
        
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        return VulnerabilityResponse.model_validate(vulnerability)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving vulnerability {vulnerability_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vulnerability_id: UUID,
    vulnerability_update: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update a vulnerability
    """
    try:
        result = await db.execute(select(Vulnerability).filter(Vulnerability.id == vulnerability_id))
        vulnerability = result.scalar_one_or_none()
        
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        update_data = vulnerability_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(vulnerability, field, value)
        
        await db.commit()
        await db.refresh(vulnerability)
        
        logger.info(f"Updated vulnerability {vulnerability_id}: status={vulnerability.status}")
        return VulnerabilityResponse.model_validate(vulnerability)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating vulnerability {vulnerability_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{vulnerability_id}")
async def delete_vulnerability(
    vulnerability_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a vulnerability
    """
    try:
        result = await db.execute(select(Vulnerability).filter(Vulnerability.id == vulnerability_id))
        vulnerability = result.scalar_one_or_none()
        
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        await db.delete(vulnerability)
        await db.commit()
        
        logger.info(f"Deleted vulnerability {vulnerability_id}")
        return {"message": "Vulnerability deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting vulnerability {vulnerability_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
