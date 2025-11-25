#!/usr/bin/env python3
"""
SIEM BOX - Minimal Syslog Server
Just receives syslog and stores it. Nothing fancy.
"""
import asyncio
import asyncpg
import re
import sys
from datetime import datetime

# Configuration (from environment or defaults)
import os

SYSLOG_HOST = os.getenv('SYSLOG_HOST', '0.0.0.0')
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', '514'))
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', '5432'))
DB_NAME = os.getenv('DB_NAME', 'siembox')
DB_USER = os.getenv('DB_USER', 'siembox')
DB_PASS = os.getenv('DB_PASS', 'siembox')

# Syslog regex (RFC 3164)
# Format: <PRI>TIMESTAMP HOSTNAME MESSAGE
SYSLOG_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<message>.*)$'
)

class MinimalSyslogServer:
    """Dead simple syslog server"""

    def __init__(self):
        self.db_pool = None
        self.stats = {'received': 0, 'stored': 0, 'errors': 0}

    async def init_db(self):
        """Initialize database connection pool"""
        print(f"[DB] Connecting to PostgreSQL at {DB_HOST}:{DB_PORT}/{DB_NAME}")
        try:
            self.db_pool = await asyncpg.create_pool(
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                min_size=2,
                max_size=10
            )
            print("[DB] ✅ Connected to database")
            return True
        except Exception as e:
            print(f"[DB] ❌ Failed to connect: {e}")
            return False

    def parse_syslog(self, raw_message: str, source_ip: str) -> dict:
        """Parse syslog message"""
        match = SYSLOG_PATTERN.match(raw_message)

        if match:
            # Parsed syslog
            timestamp_str = match.group('timestamp')
            hostname = match.group('hostname')
            message = match.group('message')

            # Parse timestamp (add current year since syslog doesn't include it)
            try:
                current_year = datetime.now().year
                timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            except:
                timestamp = datetime.now()

            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'source_ip': source_ip,
                'message': message,
                'raw_syslog': raw_message
            }
        else:
            # Unparseable syslog - just store what we got
            return {
                'timestamp': datetime.now(),
                'hostname': 'unknown',
                'source_ip': source_ip,
                'message': raw_message,
                'raw_syslog': raw_message
            }

    async def store_log(self, log_data: dict):
        """Store log in database"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO logs (timestamp, hostname, source_ip, message, raw_syslog)
                    VALUES ($1, $2, $3, $4, $5)
                ''', log_data['timestamp'], log_data['hostname'], log_data['source_ip'],
                    log_data['message'], log_data['raw_syslog'])

            self.stats['stored'] += 1
            print(f"[STORE] ✅ {log_data['hostname']} → {log_data['message'][:60]}...")
            return True

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[STORE] ❌ Error: {e}")
            return False

    async def handle_syslog(self, data: bytes, addr: tuple):
        """Handle incoming syslog message"""
        self.stats['received'] += 1
        source_ip = addr[0]

        try:
            # Decode message
            raw_message = data.decode('utf-8', errors='ignore').strip()

            if not raw_message:
                return

            print(f"[RECV] {source_ip} → {raw_message[:80]}...")

            # Parse syslog
            log_data = self.parse_syslog(raw_message, source_ip)

            # Store in database
            await self.store_log(log_data)

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[ERROR] Failed to process syslog from {source_ip}: {e}")

    async def start(self):
        """Start the syslog server"""
        # Initialize database
        if not await self.init_db():
            print("[FATAL] Cannot connect to database. Exiting.")
            return

        # Create UDP endpoint
        print(f"[SYSLOG] Starting server on {SYSLOG_HOST}:{SYSLOG_PORT}")

        loop = asyncio.get_running_loop()

        class SyslogProtocol(asyncio.DatagramProtocol):
            def __init__(self, server):
                self.server = server
                super().__init__()

            def datagram_received(self, data: bytes, addr: tuple):
                asyncio.create_task(self.server.handle_syslog(data, addr))

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self),
            local_addr=(SYSLOG_HOST, SYSLOG_PORT)
        )

        print(f"[SYSLOG] ✅ Listening on UDP {SYSLOG_HOST}:{SYSLOG_PORT}")
        print(f"[READY] Send test: echo '<134>Nov 24 12:34:56 test-host test message' | nc -u -w1 localhost 514")
        print()

        # Print stats every 30 seconds
        while True:
            await asyncio.sleep(30)
            print(f"[STATS] Received: {self.stats['received']} | Stored: {self.stats['stored']} | Errors: {self.stats['errors']}")

async def main():
    """Main entry point"""
    print("=" * 60)
    print("SIEM BOX - Minimal Syslog Server")
    print("=" * 60)
    print()

    server = MinimalSyslogServer()

    try:
        await server.start()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Stopping server...")
    except Exception as e:
        print(f"[FATAL] {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
