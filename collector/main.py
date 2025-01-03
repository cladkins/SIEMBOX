from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
import json
import asyncio
from typing import Dict, Any, Optional, Set
import aiofiles
import os
import aiohttp
import time
import psutil
import re
from app_logger import setup_logging
from cef_utils import CEFParser, CEFFormatter, is_cef_log, normalize_log

# Set up logging with the new handler
logger = setup_logging("collector", "http://api:8080")

app = FastAPI(title="SIEMBox Log Collector")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global stats tracking
stats = {
    "total_logs": 0,
    "logs_per_minute": 0,
    "active_connections": 0,
    "last_log_received": None,
    "status": "operational",
    "minute_counter": 0,
    "last_minute_reset": time.time(),
    "ip_addresses_analyzed": 0,
    "cef_logs_received": 0,
    "cef_parse_errors": 0
}

# IP address regex pattern
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
PRIVATE_IP_PATTERNS = [
    r'^10\.',
    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    r'^192\.168\.',
    r'^127\.',
]

class CEFLogEntry(BaseModel):
    """CEF log entry model"""
    cef_version: str = Field(default="0")
    device_vendor: str = Field(default="SIEMBox")
    device_product: str = Field(default="Collector")
    device_version: str = Field(default="1.0")
    signature_id: str = Field(default="0")
    name: str
    severity: str = Field(default="0")
    extensions: Dict[str, Any] = Field(default_factory=dict)

class LogEntry(BaseModel):
    """Generic log entry model that can handle both CEF and standard formats"""
    source: str
    timestamp: Optional[datetime] = None
    level: str = "INFO"
    message: str
    metadata: Dict[str, Any] = {}
    cef_format: bool = False
    cef_data: Optional[CEFLogEntry] = None

class LogForwarder:
    def __init__(self):
        self.api_url = os.getenv('API_URL', 'http://api:8080')
        self.retry_count = int(os.getenv('RETRY_COUNT', '3'))
        self.backoff_factor = float(os.getenv('BACKOFF_FACTOR', '1.5'))
        self.session: Optional[aiohttp.ClientSession] = None
        self.is_ready = False
        self.ip_batch: Set[str] = set()
        self.last_ip_batch_time = time.time()
        self.ip_batch_interval = 60  # Process IP batch every minute

    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private."""
        return any(re.match(pattern, ip) for pattern in PRIVATE_IP_PATTERNS)

    def extract_ips(self, log_data: dict) -> Set[str]:
        """Extract unique public IP addresses from log data."""
        log_str = json.dumps(log_data)
        ip_addresses = set(re.findall(IP_PATTERN, log_str))
        return {ip for ip in ip_addresses if not self.is_private_ip(ip)}

    async def process_ip_batch(self):
        """Process batch of IPs with the iplookup service."""
        if not self.ip_batch:
            return

        try:
            async with self.session.get(f'{self.api_url}/api/settings/api-keys') as response:
                if response.status == 200:
                    keys = await response.json()
                    crowdsec_key = keys.get('CROWDSEC_API_KEY')
                    if crowdsec_key:
                        headers = {'X-Api-Key': crowdsec_key}
                        for ip in self.ip_batch:
                            try:
                                async with self.session.get(f'{self.api_url}/iplookup/lookup/{ip}', headers=headers) as lookup_response:
                                    if lookup_response.status == 200:
                                        stats["ip_addresses_analyzed"] += 1
                            except Exception as e:
                                logger.error(f"Error looking up IP {ip}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing IP batch: {str(e)}")
        finally:
            self.ip_batch.clear()
            self.last_ip_batch_time = time.time()

    async def start(self):
        """Initialize the aiohttp session."""
        if not self.session:
            self.session = aiohttp.ClientSession()
        await self.wait_for_api()

    async def wait_for_api(self):
        """Wait for API to become available."""
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                if not self.session:
                    self.session = aiohttp.ClientSession()
                async with self.session.get(f'{self.api_url}/health') as response:
                    if response.status == 200:
                        self.is_ready = True
                        logger.info("Successfully connected to API")
                        return
            except Exception as e:
                logger.warning(f"API not ready (attempt {attempt + 1}/{max_attempts}): {str(e)}")
                await asyncio.sleep(min(2 ** attempt, 30))
        logger.warning("Could not establish initial API connection, will retry during operation")

    async def stop(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None

    async def forward_log(self, log_data: dict) -> bool:
        """Forward log entry to API service and process IPs."""
        if not self.session:
            await self.start()

        try:
            # Extract and add IPs to batch
            ips = self.extract_ips(log_data)
            self.ip_batch.update(ips)

            # Process IP batch if interval has elapsed
            if time.time() - self.last_ip_batch_time >= self.ip_batch_interval:
                await self.process_ip_batch()

            # Normalize log data to include CEF fields
            normalized_data = normalize_log(log_data)

            # Forward log to API
            async with self.session.post(f'{self.api_url}/api/logs', json=normalized_data) as response:
                if response.status != 200:
                    text = await response.text()
                    logger.error(f"Failed to forward log to API: {text}")
                    return False

            # Update stats
            stats["total_logs"] += 1
            stats["minute_counter"] += 1
            stats["last_log_received"] = datetime.now().isoformat()

            # Reset minute counter if needed
            current_time = time.time()
            if current_time - stats["last_minute_reset"] >= 60:
                stats["logs_per_minute"] = stats["minute_counter"]
                stats["minute_counter"] = 0
                stats["last_minute_reset"] = current_time

            logger.info("Successfully forwarded log to API")
            return True

        except Exception as e:
            logger.error(f"Error forwarding log to API: {str(e)}")
            stats["status"] = "degraded"
            raise

class LogMonitor:
    def __init__(self, log_forwarder: LogForwarder):
        self.log_file = "/var/log/collector/syslog.json"
        self.last_position = 0
        self.last_inode = None
        self.forwarder = log_forwarder
        self.buffer = []
        self.buffer_size = int(os.getenv('BUFFER_SIZE', '100'))
        self.flush_interval = int(os.getenv('FLUSH_INTERVAL', '5'))
        self.is_ready = False

    async def ensure_log_file(self):
        """Ensure log file exists and is accessible."""
        try:
            if not os.path.exists(self.log_file):
                async with aiofiles.open(self.log_file, mode='w') as f:
                    await f.write('')
            self.is_ready = True
            return True
        except Exception as e:
            logger.error(f"Error ensuring log file exists: {str(e)}")
            return False

    async def process_log_line(self, line: str) -> Optional[dict]:
        """Process a log line, handling both CEF and JSON formats."""
        try:
            if is_cef_log(line):
                stats["cef_logs_received"] += 1
                parsed = CEFParser.parse(line)
                if parsed:
                    return parsed
                stats["cef_parse_errors"] += 1
                return None
            else:
                return json.loads(line)
        except json.JSONDecodeError:
            logger.error(f"Invalid log format: {line}")
            return None

    async def flush_buffer(self):
        """Flush the buffer of log entries."""
        if not self.buffer:
            return

        logger.info(f"Flushing {len(self.buffer)} log entries")
        for log_data in self.buffer:
            try:
                await self.forwarder.forward_log(log_data)
            except Exception as e:
                logger.error(f"Failed to forward log during flush: {str(e)}")
                stats["status"] = "degraded"
        self.buffer.clear()

    def get_file_inode(self) -> Optional[int]:
        """Get the inode of the log file."""
        try:
            return os.stat(self.log_file).st_ino
        except (FileNotFoundError, OSError):
            return None

    async def monitor(self):
        """Monitor syslog.json file for new entries with rotation handling."""
        if not await self.ensure_log_file():
            return

        while True:
            try:
                current_inode = self.get_file_inode()
                if current_inode is None:
                    logger.warning(f"Log file {self.log_file} does not exist")
                    await asyncio.sleep(1)
                    continue

                # Check for file rotation
                if self.last_inode is not None and current_inode != self.last_inode:
                    logger.info("Log file rotation detected")
                    self.last_position = 0
                    self.last_inode = current_inode

                if os.path.exists(self.log_file):
                    async with aiofiles.open(self.log_file, mode='r') as f:
                        await f.seek(self.last_position)
                        while line := await f.readline():
                            if line.strip():
                                log_data = await self.process_log_line(line.strip())
                                if log_data:
                                    self.buffer.append(log_data)
                                    if len(self.buffer) >= self.buffer_size:
                                        await self.flush_buffer()
                        self.last_position = await f.tell()

                # Periodic buffer flush
                if self.buffer and len(self.buffer) > 0:
                    await self.flush_buffer()

            except Exception as e:
                logger.error(f"Error monitoring syslog file: {str(e)}")
                stats["status"] = "degraded"

            await asyncio.sleep(self.flush_interval)

log_forwarder = LogForwarder()
log_monitor = LogMonitor(log_forwarder)

@app.post("/logs")
async def receive_log(log_entry: LogEntry):
    """Receive logs via HTTP POST."""
    try:
        if not log_entry.timestamp:
            log_entry.timestamp = datetime.now()

        log_data = log_entry.dict()
        
        # If CEF data is provided, use it
        if log_entry.cef_format and log_entry.cef_data:
            log_data = {
                **log_entry.cef_data.dict(),
                'timestamp': log_entry.timestamp,
                'source': log_entry.source
            }
            stats["cef_logs_received"] += 1

        success = await log_forwarder.forward_log(log_data)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to forward log to API")

        logger.info(f"Received and forwarded log from {log_entry.source}")
        return {"status": "success", "message": "Log received and forwarded"}
    except Exception as e:
        logger.error(f"Error processing log: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    """Get collector statistics."""
    try:
        # Get network connections count
        connections = len(psutil.net_connections())
        stats["active_connections"] = connections

        return {
            "total_logs": stats["total_logs"],
            "logs_per_minute": stats["logs_per_minute"],
            "active_connections": stats["active_connections"],
            "last_log_received": stats["last_log_received"],
            "ip_addresses_analyzed": stats["ip_addresses_analyzed"],
            "cef_logs_received": stats["cef_logs_received"],
            "cef_parse_errors": stats["cef_parse_errors"],
            "status": stats["status"]
        }
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Enhanced health check endpoint with startup grace period."""
    try:
        # During startup, consider the service healthy if basic requirements are met
        syslog_exists = os.path.exists("/var/log/collector/syslog.json")

        # Basic health criteria
        basic_health = {
            "syslog_file": {
                "exists": syslog_exists,
                "size": os.path.getsize("/var/log/collector/syslog.json") if syslog_exists else 0,
                "last_modified": datetime.fromtimestamp(os.path.getmtime("/var/log/collector/syslog.json")).isoformat() if syslog_exists else None
            },
            "buffer": {
                "size": len(log_monitor.buffer),
                "max_size": log_monitor.buffer_size
            }
        }

        # During startup phase, return healthy if basic requirements are met
        if not log_forwarder.is_ready:
            return {
                "status": "starting" if syslog_exists else "degraded",
                "timestamp": datetime.now().isoformat(),
                "components": basic_health
            }

        # Full health check when not in startup
        api_healthy = False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'{log_forwarder.api_url}/health') as response:
                    api_healthy = response.status == 200
        except Exception:
            pass

        basic_health["api_connection"] = {
            "status": "healthy" if api_healthy else "unhealthy",
            "url": log_forwarder.api_url
        }

        return {
            "status": "healthy" if (syslog_exists and api_healthy) else "degraded",
            "timestamp": datetime.now().isoformat(),
            "components": basic_health
        }
    except Exception as e:
        logger.error(f"Error in health check: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def startup_event():
    """Initialize necessary resources on startup."""
    logger.info("Log Collector service starting up...")
    await log_forwarder.start()
    asyncio.create_task(log_monitor.monitor())

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    logger.info("Log Collector service shutting down...")
    await log_monitor.flush_buffer()
    await log_forwarder.stop()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)