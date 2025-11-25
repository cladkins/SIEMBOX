"""
SIEM BOX - Syslog Ingestion Service
Listens on UDP 514 for syslog messages and ingests them into the database
"""
import asyncio
import re
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.models.logs import ProcessedLog
from app.services.detection_service import detection_service
from app.core.config import settings

logger = logging.getLogger(__name__)

# Syslog severity mapping (RFC 5424)
SYSLOG_SEVERITY_MAP = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug"
}

# Syslog facility mapping (RFC 5424)
SYSLOG_FACILITY_MAP = {
    0: "kernel",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7"
}


class SyslogParser:
    """Parse syslog messages in RFC 3164 and RFC 5424 formats"""

    # RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    RFC3164_PATTERN = re.compile(
        r'^<(?P<pri>\d+)>'
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MESSAGE
    RFC5424_PATTERN = re.compile(
        r'^<(?P<pri>\d+)>'
        r'(?P<version>\d+)\s+'
        r'(?P<timestamp>\S+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<appname>\S+)\s+'
        r'(?P<procid>\S+)\s+'
        r'(?P<msgid>\S+)\s+'
        r'(?P<structured_data>\[.*?\]|-)\s*'
        r'(?P<message>.*)$'
    )

    @staticmethod
    def parse(raw_message: str, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Parse a syslog message and return structured data

        Args:
            raw_message: Raw syslog message string
            source_ip: IP address of the source

        Returns:
            Dict with parsed fields or None if parsing fails
        """
        # Try RFC 5424 first (newer format)
        match = SyslogParser.RFC5424_PATTERN.match(raw_message)
        if match:
            return SyslogParser._parse_rfc5424(match, raw_message, source_ip)

        # Try RFC 3164 (legacy format - most common)
        match = SyslogParser.RFC3164_PATTERN.match(raw_message)
        if match:
            return SyslogParser._parse_rfc3164(match, raw_message, source_ip)

        # Unstructured syslog (just message)
        logger.warning(f"Could not parse syslog format: {raw_message[:100]}")
        return SyslogParser._parse_unstructured(raw_message, source_ip)

    @staticmethod
    def _parse_rfc5424(match: re.Match, raw_message: str, source_ip: str) -> Dict[str, Any]:
        """Parse RFC 5424 format syslog"""
        pri = int(match.group('pri'))
        severity_num = pri & 0x07
        facility_num = pri >> 3

        timestamp_str = match.group('timestamp')
        hostname = match.group('hostname')
        app_name = match.group('appname')
        message = match.group('message')

        # Parse ISO 8601 timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            timestamp = datetime.utcnow()

        return {
            'timestamp': timestamp,
            'hostname': hostname if hostname != '-' else 'unknown',
            'source_ip': source_ip,
            'app_name': app_name if app_name != '-' else 'syslog',
            'raw_message': raw_message,
            'severity': SYSLOG_SEVERITY_MAP.get(severity_num, 'info'),
            'log_type': 'syslog',
            'category': SYSLOG_FACILITY_MAP.get(facility_num, 'syslog'),
            'source': f'syslog:{hostname}',
            'processed_fields': {
                'facility': SYSLOG_FACILITY_MAP.get(facility_num, 'unknown'),
                'severity_num': severity_num,
                'facility_num': facility_num,
                'message': message,
                'format': 'rfc5424'
            }
        }

    @staticmethod
    def _parse_rfc3164(match: re.Match, raw_message: str, source_ip: str) -> Dict[str, Any]:
        """Parse RFC 3164 format syslog (most common)"""
        pri = int(match.group('pri'))
        severity_num = pri & 0x07
        facility_num = pri >> 3

        timestamp_str = match.group('timestamp')
        hostname = match.group('hostname')
        tag = match.group('tag')
        message = match.group('message')

        # Parse BSD syslog timestamp (no year)
        try:
            current_year = datetime.utcnow().year
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except:
            timestamp = datetime.utcnow()

        # Detect log type from tag/message
        log_type = SyslogParser._detect_log_type(tag, message)

        # Extract fields based on log type
        fields = SyslogParser._extract_fields(tag, message, log_type)
        fields.update({
            'facility': SYSLOG_FACILITY_MAP.get(facility_num, 'unknown'),
            'severity_num': severity_num,
            'facility_num': facility_num,
            'tag': tag,
            'format': 'rfc3164'
        })

        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'source_ip': source_ip,
            'app_name': tag,
            'raw_message': raw_message,
            'severity': SYSLOG_SEVERITY_MAP.get(severity_num, 'info'),
            'log_type': log_type,
            'category': SYSLOG_FACILITY_MAP.get(facility_num, 'syslog'),
            'source': f'syslog:{hostname}',
            'processed_fields': fields
        }

    @staticmethod
    def _parse_unstructured(raw_message: str, source_ip: str) -> Dict[str, Any]:
        """Parse unstructured syslog message"""
        return {
            'timestamp': datetime.utcnow(),
            'hostname': 'unknown',
            'source_ip': source_ip,
            'app_name': 'syslog',
            'raw_message': raw_message,
            'severity': 'info',
            'log_type': 'syslog',
            'category': 'syslog',
            'source': f'syslog:{source_ip}',
            'processed_fields': {
                'message': raw_message,
                'format': 'unstructured'
            }
        }

    @staticmethod
    def _detect_log_type(tag: str, message: str) -> str:
        """Detect log type from tag and message content"""
        tag_lower = tag.lower()
        message_lower = message.lower()

        # Authentication logs
        if any(x in tag_lower for x in ['sshd', 'auth', 'login', 'sudo']):
            return 'authentication'

        # Firewall logs
        if any(x in tag_lower for x in ['firewall', 'pf', 'iptables', 'ufw']):
            return 'firewall'
        if any(x in message_lower for x in ['block', 'drop', 'deny', 'accept', 'allow']):
            return 'firewall'

        # Web logs
        if any(x in tag_lower for x in ['nginx', 'apache', 'httpd']):
            return 'web_access'

        # System logs
        if any(x in tag_lower for x in ['kernel', 'systemd', 'cron']):
            return 'system'

        return 'syslog'

    @staticmethod
    def _extract_fields(tag: str, message: str, log_type: str) -> Dict[str, Any]:
        """Extract structured fields from message based on log type"""
        fields = {'message': message}

        # SSH authentication
        if log_type == 'authentication' and 'ssh' in tag.lower():
            if 'failed password' in message.lower():
                fields['action'] = 'Failed'
                # Extract username and source IP
                match = re.search(r'for (?:invalid user )?(\S+) from (\S+)', message)
                if match:
                    fields['user'] = match.group(1)
                    fields['src_ip'] = match.group(2)
            elif 'accepted' in message.lower():
                fields['action'] = 'Accepted'
                match = re.search(r'for (\S+) from (\S+)', message)
                if match:
                    fields['user'] = match.group(1)
                    fields['src_ip'] = match.group(2)

        # Firewall logs
        elif log_type == 'firewall':
            # Common firewall patterns
            if 'block' in message.lower() or 'drop' in message.lower() or 'deny' in message.lower():
                fields['action'] = 'BLOCK'
            elif 'accept' in message.lower() or 'allow' in message.lower():
                fields['action'] = 'ALLOW'

            # Extract IPs and ports
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
            if len(ip_matches) >= 2:
                fields['src_ip'] = ip_matches[0]
                fields['dst_ip'] = ip_matches[1]

            port_match = re.search(r'(?:DPT|dst_port|dport)[=:](\d+)', message)
            if port_match:
                fields['dst_port'] = int(port_match.group(1))

        return fields


class SyslogServer:
    """UDP Syslog Server for ingesting syslog messages"""

    def __init__(self, host: str = '0.0.0.0', port: int = 514):
        self.host = host
        self.port = port
        self.parser = SyslogParser()
        self.session_maker = None

    async def start(self):
        """Start the syslog server"""
        logger.info(f"Starting syslog server on {self.host}:{self.port}")

        # Create async database session maker
        engine = create_async_engine(settings.database_url, echo=False)
        self.session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        # Create UDP endpoint
        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self),
            local_addr=(self.host, self.port)
        )

        logger.info(f"✅ Syslog server listening on UDP {self.host}:{self.port}")

        return transport

    async def process_message(self, data: bytes, addr: tuple):
        """Process incoming syslog message"""
        try:
            # Decode message
            raw_message = data.decode('utf-8', errors='ignore').strip()
            source_ip = addr[0]

            logger.debug(f"Received syslog from {source_ip}: {raw_message[:100]}")

            # Parse syslog message
            parsed = self.parser.parse(raw_message, source_ip)
            if not parsed:
                logger.warning(f"Failed to parse syslog message from {source_ip}")
                return

            # Create database session
            async with self.session_maker() as db:
                # Create ProcessedLog entry
                processed_log = ProcessedLog(
                    timestamp=parsed['timestamp'],
                    hostname=parsed['hostname'],
                    source_ip=parsed['source_ip'],
                    app_name=parsed['app_name'],
                    raw_message=parsed['raw_message'],
                    processed_fields=parsed['processed_fields'],
                    log_type=parsed['log_type'],
                    severity=parsed['severity'],
                    category=parsed['category'],
                    source=parsed['source'],
                    cribl_pipeline=None
                )

                db.add(processed_log)
                await db.commit()
                await db.refresh(processed_log)

                logger.info(f"✅ Syslog ingested from {source_ip}: {parsed['app_name']} - {parsed['log_type']}")

                # Run detection
                try:
                    await detection_service.run_detection_on_processed_logs(
                        db, [str(processed_log.id)]
                    )
                except Exception as e:
                    logger.error(f"Detection failed for syslog {processed_log.id}: {e}")

        except Exception as e:
            logger.error(f"Error processing syslog message from {addr[0]}: {e}")


class SyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol for syslog messages"""

    def __init__(self, server: SyslogServer):
        self.server = server
        super().__init__()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming datagram"""
        asyncio.create_task(self.server.process_message(data, addr))

    def error_received(self, exc):
        logger.error(f"Syslog protocol error: {exc}")


# Global syslog server instance
syslog_server = SyslogServer()
