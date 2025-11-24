"""
SIEM BOX - Vulnerability Scanning Schemas
"""
from pydantic import BaseModel, Field, validator, IPvAnyAddress
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from uuid import UUID


# Asset Schemas
class AssetBase(BaseModel):
    ip_address: IPvAnyAddress = Field(..., description="IP address of the asset")
    hostname: Optional[str] = Field(None, description="Hostname if resolved")
    mac_address: Optional[str] = Field(None, description="MAC address if available")
    asset_type: Optional[str] = Field(None, description="Type of asset")
    operating_system: Optional[str] = Field(None, description="Operating system detected")
    os_version: Optional[str] = Field(None, description="OS version if detected")
    open_ports: Optional[Dict[str, Any]] = Field(None, description="List of open ports and services")
    services: Optional[Dict[str, Any]] = Field(None, description="Detected services and versions")
    discovery_method: Optional[str] = Field(None, description="How the asset was discovered")
    confidence_score: Optional[float] = Field(None, ge=0, le=1, description="Confidence in asset identification")
    asset_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional asset metadata")


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    asset_type: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: Optional[Dict[str, Any]] = None
    services: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    discovery_method: Optional[str] = None
    confidence_score: Optional[float] = Field(None, ge=0, le=1)
    asset_metadata: Optional[Dict[str, Any]] = None


class AssetDiscoveryRequest(BaseModel):
    target: str = Field(..., description="Network range or host to discover")
    discovery_method: Optional[str] = Field(None, description="Discovery method (default nmap)")
    scan_config: Optional[Dict[str, Any]] = Field(
        None,
        description="Discovery scan configuration overrides"
    )


class AssetResponse(AssetBase):
    id: UUID
    is_active: bool
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Vulnerability Scan Schemas
class VulnerabilityScanBase(BaseModel):
    scan_name: str = Field(..., description="Human-readable scan name")
    scan_type: str = Field(..., description="Type of scan (nmap, trivy, custom)")
    target: str = Field(..., description="Scan target (IP, range, container, etc.)")
    scan_config: Optional[Dict[str, Any]] = Field(None, description="Scan configuration parameters")


class VulnerabilityScanCreate(VulnerabilityScanBase):
    asset_id: Optional[UUID] = Field(None, description="Asset ID for asset-specific scans")


class VulnerabilityScanUpdate(BaseModel):
    scan_name: Optional[str] = None
    status: Optional[str] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    error_message: Optional[str] = None
    raw_output: Optional[str] = None


class VulnerabilityScanResponse(VulnerabilityScanBase):
    id: UUID
    asset_id: Optional[UUID]
    scanner_version: Optional[str]
    status: str
    progress: int
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Vulnerability Schemas
class VulnerabilityBase(BaseModel):
    cve_id: Optional[str] = Field(None, description="CVE identifier if available")
    vulnerability_id: Optional[str] = Field(None, description="Scanner-specific vulnerability ID")
    title: str = Field(..., description="Vulnerability title/name")
    description: Optional[str] = Field(None, description="Detailed vulnerability description")
    severity: str = Field(..., description="Vulnerability severity")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS base score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    component: Optional[str] = Field(None, description="Affected software component")
    version: Optional[str] = Field(None, description="Affected version")
    port: Optional[int] = Field(None, description="Affected port if applicable")
    service: Optional[str] = Field(None, description="Affected service")
    category: Optional[str] = Field(None, description="Vulnerability category")
    attack_vector: Optional[str] = Field(None, description="Attack vector")
    attack_complexity: Optional[str] = Field(None, description="Attack complexity")
    solution: Optional[str] = Field(None, description="Recommended solution/fix")
    references: Optional[Dict[str, Any]] = Field(None, description="External references and links")
    scanner_data: Optional[Dict[str, Any]] = Field(None, description="Additional scanner-specific data")

    @validator('severity')
    def validate_severity(cls, v):
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        if v.lower() not in valid_severities:
            raise ValueError(f'Severity must be one of: {valid_severities}')
        return v.lower()


class VulnerabilityCreate(VulnerabilityBase):
    scan_id: UUID = Field(..., description="Scan ID that found this vulnerability")
    asset_id: Optional[UUID] = Field(None, description="Asset ID where vulnerability was found")


class VulnerabilityUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_vector: Optional[str] = None
    solution: Optional[str] = None
    references: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    risk_accepted: Optional[bool] = None
    scanner_data: Optional[Dict[str, Any]] = None

    @validator('severity')
    def validate_severity(cls, v):
        if v is not None:
            valid_severities = ['critical', 'high', 'medium', 'low', 'info']
            if v.lower() not in valid_severities:
                raise ValueError(f'Severity must be one of: {valid_severities}')
            return v.lower()
        return v

    @validator('status')
    def validate_status(cls, v):
        if v is not None:
            valid_statuses = ['open', 'investigating', 'fixed', 'false_positive']
            if v.lower() not in valid_statuses:
                raise ValueError(f'Status must be one of: {valid_statuses}')
            return v.lower()
        return v


class VulnerabilityResponse(VulnerabilityBase):
    id: UUID
    scan_id: UUID
    asset_id: Optional[UUID]
    status: str
    risk_accepted: bool
    first_detected: datetime
    last_detected: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Scan Schedule Schemas
class ScanScheduleBase(BaseModel):
    name: str = Field(..., description="Schedule name")
    description: Optional[str] = Field(None, description="Schedule description")
    scan_type: str = Field(..., description="Type of scan to run")
    targets: List[str] = Field(..., description="List of scan targets")
    scan_config: Optional[Dict[str, Any]] = Field(None, description="Scan configuration parameters")
    schedule_type: str = Field(..., description="Schedule type (cron, interval)")
    cron_expression: Optional[str] = Field(None, description="Cron expression for scheduling")
    interval_minutes: Optional[int] = Field(None, gt=0, description="Interval in minutes for periodic scans")

    @validator('schedule_type')
    def validate_schedule_type(cls, v):
        valid_types = ['cron', 'interval']
        if v.lower() not in valid_types:
            raise ValueError(f'Schedule type must be one of: {valid_types}')
        return v.lower()

    @validator('cron_expression')
    def validate_cron_expression(cls, v, values):
        if values.get('schedule_type') == 'cron' and not v:
            raise ValueError('Cron expression is required for cron schedule type')
        return v

    @validator('interval_minutes')
    def validate_interval_minutes(cls, v, values):
        if values.get('schedule_type') == 'interval' and not v:
            raise ValueError('Interval minutes is required for interval schedule type')
        return v


class ScanScheduleCreate(ScanScheduleBase):
    pass


class ScanScheduleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scan_type: Optional[str] = None
    targets: Optional[List[str]] = None
    scan_config: Optional[Dict[str, Any]] = None
    schedule_type: Optional[str] = None
    cron_expression: Optional[str] = None
    interval_minutes: Optional[int] = Field(None, gt=0)
    is_enabled: Optional[bool] = None


class ScanScheduleResponse(ScanScheduleBase):
    id: UUID
    is_enabled: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    total_runs: int
    successful_runs: int
    failed_runs: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# CVE Database Schemas
class CVEDatabaseBase(BaseModel):
    cve_id: str = Field(..., description="CVE identifier")
    description: Optional[str] = Field(None, description="CVE description")
    published_date: Optional[datetime] = Field(None, description="CVE publication date")
    modified_date: Optional[datetime] = Field(None, description="CVE last modification date")
    cvss_v2_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS v2 base score")
    cvss_v2_vector: Optional[str] = Field(None, description="CVSS v2 vector string")
    cvss_v3_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS v3 base score")
    cvss_v3_vector: Optional[str] = Field(None, description="CVSS v3 vector string")
    severity: Optional[str] = Field(None, description="Severity level based on CVSS score")
    affected_products: Optional[Dict[str, Any]] = Field(None, description="List of affected products and versions")
    references: Optional[Dict[str, Any]] = Field(None, description="External references and links")
    cwe_ids: Optional[List[str]] = Field(None, description="Associated CWE identifiers")
    attack_vector: Optional[str] = Field(None, description="Attack vector")
    attack_complexity: Optional[str] = Field(None, description="Attack complexity")
    source: Optional[str] = Field(None, description="Data source (NVD, MITRE, etc.)")


class CVEDatabaseCreate(CVEDatabaseBase):
    pass


class CVEDatabaseUpdate(BaseModel):
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    cvss_v2_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v2_vector: Optional[str] = None
    cvss_v3_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v3_vector: Optional[str] = None
    severity: Optional[str] = None
    affected_products: Optional[Dict[str, Any]] = None
    references: Optional[Dict[str, Any]] = None
    cwe_ids: Optional[List[str]] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    source: Optional[str] = None


class CVEDatabaseResponse(CVEDatabaseBase):
    id: UUID
    last_updated: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Scan Request Schemas
class ScanRequest(BaseModel):
    scan_name: str = Field(..., description="Name for the scan")
    scan_type: str = Field(..., description="Type of scan to perform")
    targets: List[str] = Field(..., description="List of targets to scan")
    scan_config: Optional[Dict[str, Any]] = Field(None, description="Additional scan configuration")

    @validator('scan_type')
    def validate_scan_type(cls, v):
        valid_types = ['nmap', 'trivy', 'custom']
        if v.lower() not in valid_types:
            raise ValueError(f'Scan type must be one of: {valid_types}')
        return v.lower()


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: str
    progress: int
    message: Optional[str] = None


# Bulk Operations Schemas
class BulkVulnerabilityUpdate(BaseModel):
    vulnerability_ids: List[UUID] = Field(..., description="List of vulnerability IDs to update")
    status: Optional[str] = Field(None, description="New status for vulnerabilities")
    risk_accepted: Optional[bool] = Field(None, description="Risk acceptance status")

    @validator('status')
    def validate_status(cls, v):
        if v is not None:
            valid_statuses = ['open', 'investigating', 'fixed', 'false_positive']
            if v.lower() not in valid_statuses:
                raise ValueError(f'Status must be one of: {valid_statuses}')
            return v.lower()
        return v


# Statistics and Reporting Schemas
class VulnerabilityStats(BaseModel):
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    open_count: int
    fixed_count: int
    false_positive_count: int
    risk_accepted_count: int


class AssetStats(BaseModel):
    total_assets: int
    active_assets: int
    inactive_assets: int
    scanned_assets: int
    vulnerable_assets: int


class ScanStats(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    scheduled_scans: int


class DashboardStats(BaseModel):
    vulnerability_stats: VulnerabilityStats
    asset_stats: AssetStats
    scan_stats: ScanStats
    recent_scans: List[VulnerabilityScanResponse]
    top_vulnerabilities: List[VulnerabilityResponse]


# Export Schemas
class ExportRequest(BaseModel):
    format: str = Field(..., description="Export format (pdf, csv, json)")
    filters: Optional[Dict[str, Any]] = Field(None, description="Filters to apply")
    include_details: bool = Field(True, description="Include detailed information")

    @validator('format')
    def validate_format(cls, v):
        valid_formats = ['pdf', 'csv', 'json']
        if v.lower() not in valid_formats:
            raise ValueError(f'Format must be one of: {valid_formats}')
        return v.lower()


class ExportResponse(BaseModel):
    export_id: UUID
    status: str
    download_url: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
