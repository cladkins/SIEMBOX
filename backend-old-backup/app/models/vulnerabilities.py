"""
SIEM BOX - Vulnerability Scanning Models
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID, INET as PostgresINET, JSONB as PostgresJSONB
from sqlalchemy import TIMESTAMP, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.database import Base
import uuid

# Database-agnostic type decorators
def UUID():
    """Database-agnostic UUID type"""
    from sqlalchemy import TypeDecorator, String
    from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
    import uuid as uuid_module
    
    class UniversalUUID(TypeDecorator):
        impl = String
        cache_ok = True
        
        def load_dialect_impl(self, dialect):
            if dialect.name == 'postgresql':
                return dialect.type_descriptor(PostgresUUID(as_uuid=True))
            else:
                return dialect.type_descriptor(String(36))
        
        def process_bind_param(self, value, dialect):
            if value is None:
                return value
            elif dialect.name == 'postgresql':
                return value
            else:
                if isinstance(value, uuid_module.UUID):
                    return str(value)
                return value
        
        def process_result_value(self, value, dialect):
            if value is None:
                return value
            elif dialect.name == 'postgresql':
                return value
            else:
                if isinstance(value, str):
                    return uuid_module.UUID(value)
                return value
    
    return UniversalUUID()

def INET_TYPE():
    """Database-agnostic INET type"""
    from sqlalchemy import TypeDecorator, String
    from sqlalchemy.dialects.postgresql import INET as PostgresINET
    
    class UniversalINET(TypeDecorator):
        impl = String
        cache_ok = True
        
        def load_dialect_impl(self, dialect):
            if dialect.name == 'postgresql':
                return dialect.type_descriptor(PostgresINET())
            else:
                return dialect.type_descriptor(String(45))  # Max length for IPv6
    
    return UniversalINET()

def JSON_TYPE():
    """Database-agnostic JSON type"""
    from sqlalchemy import TypeDecorator, JSON
    from sqlalchemy.dialects.postgresql import JSONB as PostgresJSONB
    
    class UniversalJSON(TypeDecorator):
        impl = JSON
        cache_ok = True
        
        def load_dialect_impl(self, dialect):
            if dialect.name == 'postgresql':
                return dialect.type_descriptor(PostgresJSONB())
            else:
                return dialect.type_descriptor(JSON())
    
    return UniversalJSON()


class Asset(Base):
    """
    Network assets discovered during scanning
    """
    __tablename__ = "assets"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Asset identification
    ip_address = Column(INET_TYPE(), nullable=False, unique=True, index=True,
                       comment="IP address of the asset")
    hostname = Column(String(255), nullable=True, index=True,
                     comment="Hostname if resolved")
    mac_address = Column(String(17), nullable=True, index=True,
                        comment="MAC address if available")
    
    # Asset classification
    asset_type = Column(String(50), nullable=True, index=True,
                       comment="Type of asset (server, workstation, router, etc.)")
    operating_system = Column(String(100), nullable=True,
                             comment="Operating system detected")
    os_version = Column(String(50), nullable=True,
                       comment="OS version if detected")
    
    # Network information
    open_ports = Column(JSON_TYPE(), nullable=True,
                       comment="List of open ports and services")
    services = Column(JSON_TYPE(), nullable=True,
                     comment="Detected services and versions")
    
    # Asset status
    is_active = Column(Boolean, default=True, index=True,
                      comment="Whether the asset is currently active")
    last_seen = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True,
                      comment="Last time asset was detected")
    
    # Discovery information
    discovery_method = Column(String(50), nullable=True,
                             comment="How the asset was discovered")
    confidence_score = Column(Float, nullable=True,
                             comment="Confidence in asset identification (0-1)")
    
    # Additional metadata
    asset_metadata = Column(JSON_TYPE(), nullable=True,
                           comment="Additional asset metadata")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    vulnerability_scans = relationship("VulnerabilityScan", back_populates="asset")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")

    def __repr__(self):
        return f"<Asset(id={self.id}, ip={self.ip_address}, hostname={self.hostname})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "asset_type": self.asset_type,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "open_ports": self.open_ports,
            "services": self.services,
            "is_active": self.is_active,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "discovery_method": self.discovery_method,
            "confidence_score": self.confidence_score,
            "asset_metadata": self.asset_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class VulnerabilityScan(Base):
    """
    Vulnerability scan metadata and configuration
    """
    __tablename__ = "vulnerability_scans"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to asset (optional for network-wide scans)
    asset_id = Column(UUID(), ForeignKey("assets.id"), nullable=True, index=True)
    
    # Scan metadata
    scan_name = Column(String(255), nullable=False,
                      comment="Human-readable scan name")
    scan_type = Column(String(50), nullable=False, index=True,
                      comment="Type of scan (nmap, trivy, custom)")
    target = Column(String(255), nullable=False,
                   comment="Scan target (IP, range, container, etc.)")
    
    # Scan configuration
    scan_config = Column(JSON_TYPE(), nullable=True,
                        comment="Scan configuration parameters")
    scanner_version = Column(String(50), nullable=True,
                            comment="Version of scanner used")
    
    # Scan status
    status = Column(String(20), nullable=False, default="pending", index=True,
                   comment="Scan status (pending, running, completed, failed)")
    progress = Column(Integer, default=0,
                     comment="Scan progress percentage (0-100)")
    
    # Scan results summary
    vulnerabilities_found = Column(Integer, default=0,
                                  comment="Total vulnerabilities found")
    critical_count = Column(Integer, default=0,
                           comment="Number of critical vulnerabilities")
    high_count = Column(Integer, default=0,
                       comment="Number of high severity vulnerabilities")
    medium_count = Column(Integer, default=0,
                         comment="Number of medium severity vulnerabilities")
    low_count = Column(Integer, default=0,
                      comment="Number of low severity vulnerabilities")
    
    # Timing information
    started_at = Column(TIMESTAMP(timezone=True), nullable=True,
                       comment="When the scan started")
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True,
                         comment="When the scan completed")
    duration_seconds = Column(Integer, nullable=True,
                             comment="Scan duration in seconds")
    
    # Error handling
    error_message = Column(Text, nullable=True,
                          comment="Error message if scan failed")
    
    # Scan output
    raw_output = Column(Text, nullable=True,
                       comment="Raw scanner output")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerability_scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

    def __repr__(self):
        return f"<VulnerabilityScan(id={self.id}, name={self.scan_name}, status={self.status})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "scan_name": self.scan_name,
            "scan_type": self.scan_type,
            "target": self.target,
            "scan_config": self.scan_config,
            "scanner_version": self.scanner_version,
            "status": self.status,
            "progress": self.progress,
            "vulnerabilities_found": self.vulnerabilities_found,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "raw_output": self.raw_output,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Vulnerability(Base):
    """
    Individual vulnerability findings
    """
    __tablename__ = "vulnerabilities"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    scan_id = Column(UUID(), ForeignKey("vulnerability_scans.id"), nullable=False, index=True)
    asset_id = Column(UUID(), ForeignKey("assets.id"), nullable=True, index=True)
    
    # Vulnerability identification
    cve_id = Column(String(20), nullable=True, index=True,
                   comment="CVE identifier if available")
    vulnerability_id = Column(String(100), nullable=True, index=True,
                             comment="Scanner-specific vulnerability ID")
    title = Column(String(500), nullable=False,
                  comment="Vulnerability title/name")
    description = Column(Text, nullable=True,
                        comment="Detailed vulnerability description")
    
    # Severity and scoring
    severity = Column(String(20), nullable=False, index=True,
                     comment="Vulnerability severity (critical, high, medium, low)")
    cvss_score = Column(Float, nullable=True,
                       comment="CVSS base score (0-10)")
    cvss_vector = Column(String(100), nullable=True,
                        comment="CVSS vector string")
    
    # Affected component
    component = Column(String(255), nullable=True,
                      comment="Affected software component")
    version = Column(String(100), nullable=True,
                    comment="Affected version")
    port = Column(Integer, nullable=True,
                 comment="Affected port if applicable")
    service = Column(String(100), nullable=True,
                    comment="Affected service")
    
    # Vulnerability details
    category = Column(String(100), nullable=True, index=True,
                     comment="Vulnerability category")
    attack_vector = Column(String(50), nullable=True,
                          comment="Attack vector (network, local, etc.)")
    attack_complexity = Column(String(20), nullable=True,
                              comment="Attack complexity (low, high)")
    
    # Remediation
    solution = Column(Text, nullable=True,
                     comment="Recommended solution/fix")
    references = Column(JSON_TYPE(), nullable=True,
                       comment="External references and links")
    
    # Status tracking
    status = Column(String(20), nullable=False, default="open", index=True,
                   comment="Vulnerability status (open, investigating, fixed, false_positive)")
    risk_accepted = Column(Boolean, default=False,
                          comment="Whether risk has been accepted")
    
    # Discovery information
    first_detected = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True,
                           comment="When vulnerability was first detected")
    last_detected = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), index=True,
                          comment="When vulnerability was last detected")
    
    # Additional data
    scanner_data = Column(JSON_TYPE(), nullable=True,
                         comment="Additional scanner-specific data")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    scan = relationship("VulnerabilityScan", back_populates="vulnerabilities")
    asset = relationship("Asset", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, cve={self.cve_id}, severity={self.severity})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "scan_id": str(self.scan_id),
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "cve_id": self.cve_id,
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "component": self.component,
            "version": self.version,
            "port": self.port,
            "service": self.service,
            "category": self.category,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "solution": self.solution,
            "references": self.references,
            "status": self.status,
            "risk_accepted": self.risk_accepted,
            "first_detected": self.first_detected.isoformat() if self.first_detected else None,
            "last_detected": self.last_detected.isoformat() if self.last_detected else None,
            "scanner_data": self.scanner_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class ScanSchedule(Base):
    """
    Scheduled vulnerability scans configuration
    """
    __tablename__ = "scan_schedules"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # Schedule metadata
    name = Column(String(255), nullable=False,
                 comment="Schedule name")
    description = Column(Text, nullable=True,
                        comment="Schedule description")
    
    # Scan configuration
    scan_type = Column(String(50), nullable=False,
                      comment="Type of scan to run")
    targets = Column(JSON_TYPE(), nullable=False,
                    comment="List of scan targets")
    scan_config = Column(JSON_TYPE(), nullable=True,
                        comment="Scan configuration parameters")
    
    # Schedule configuration
    schedule_type = Column(String(20), nullable=False, index=True,
                          comment="Schedule type (cron, interval)")
    cron_expression = Column(String(100), nullable=True,
                            comment="Cron expression for scheduling")
    interval_minutes = Column(Integer, nullable=True,
                             comment="Interval in minutes for periodic scans")
    
    # Schedule status
    is_enabled = Column(Boolean, default=True, index=True,
                       comment="Whether the schedule is active")
    last_run = Column(TIMESTAMP(timezone=True), nullable=True,
                     comment="Last time schedule was executed")
    next_run = Column(TIMESTAMP(timezone=True), nullable=True, index=True,
                     comment="Next scheduled execution time")
    
    # Execution tracking
    total_runs = Column(Integer, default=0,
                       comment="Total number of executions")
    successful_runs = Column(Integer, default=0,
                            comment="Number of successful executions")
    failed_runs = Column(Integer, default=0,
                        comment="Number of failed executions")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<ScanSchedule(id={self.id}, name={self.name}, enabled={self.is_enabled})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "scan_type": self.scan_type,
            "targets": self.targets,
            "scan_config": self.scan_config,
            "schedule_type": self.schedule_type,
            "cron_expression": self.cron_expression,
            "interval_minutes": self.interval_minutes,
            "is_enabled": self.is_enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "failed_runs": self.failed_runs,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class CVEDatabase(Base):
    """
    Local CVE database for vulnerability information
    """
    __tablename__ = "cve_database"
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4, index=True)
    
    # CVE identification
    cve_id = Column(String(20), nullable=False, unique=True, index=True,
                   comment="CVE identifier")
    
    # CVE details
    description = Column(Text, nullable=True,
                        comment="CVE description")
    published_date = Column(TIMESTAMP(timezone=True), nullable=True, index=True,
                           comment="CVE publication date")
    modified_date = Column(TIMESTAMP(timezone=True), nullable=True,
                          comment="CVE last modification date")
    
    # CVSS scoring
    cvss_v2_score = Column(Float, nullable=True,
                          comment="CVSS v2 base score")
    cvss_v2_vector = Column(String(100), nullable=True,
                           comment="CVSS v2 vector string")
    cvss_v3_score = Column(Float, nullable=True,
                          comment="CVSS v3 base score")
    cvss_v3_vector = Column(String(100), nullable=True,
                           comment="CVSS v3 vector string")
    
    # Severity classification
    severity = Column(String(20), nullable=True, index=True,
                     comment="Severity level based on CVSS score")
    
    # Affected products
    affected_products = Column(JSON_TYPE(), nullable=True,
                              comment="List of affected products and versions")
    
    # References and links
    references = Column(JSON_TYPE(), nullable=True,
                       comment="External references and links")
    
    # Additional metadata
    cwe_ids = Column(JSON_TYPE(), nullable=True,
                    comment="Associated CWE identifiers")
    attack_vector = Column(String(50), nullable=True,
                          comment="Attack vector")
    attack_complexity = Column(String(20), nullable=True,
                              comment="Attack complexity")
    
    # Data source tracking
    source = Column(String(50), nullable=True,
                   comment="Data source (NVD, MITRE, etc.)")
    last_updated = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(),
                         comment="Last time CVE data was updated")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<CVEDatabase(id={self.id}, cve_id={self.cve_id}, severity={self.severity})>"
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": str(self.id),
            "cve_id": self.cve_id,
            "description": self.description,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "modified_date": self.modified_date.isoformat() if self.modified_date else None,
            "cvss_v2_score": self.cvss_v2_score,
            "cvss_v2_vector": self.cvss_v2_vector,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_vector": self.cvss_v3_vector,
            "severity": self.severity,
            "affected_products": self.affected_products,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "source": self.source,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }