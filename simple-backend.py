#!/usr/bin/env python3
"""
SIEM BOX - Simple Backend for React UI
Combines syslog ingestion with API endpoints the React frontend expects
"""
import asyncio
import asyncpg
import re
import os
import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional

# Configuration
SYSLOG_HOST = os.getenv('SYSLOG_HOST', '0.0.0.0')
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', '514'))
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', '5432'))
DB_NAME = os.getenv('DB_NAME', 'siembox')
DB_USER = os.getenv('DB_USER', 'siembox')
DB_PASS = os.getenv('DB_PASS', 'siembox')
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me-in-production')

# Syslog regex (RFC 3164)
SYSLOG_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<message>.*)$'
)

# Pydantic models for API
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800
    user: Dict

class LogResponse(BaseModel):
    id: int
    timestamp: str
    hostname: Optional[str]
    source_ip: str
    source_type: str
    raw_message: str
    created_at: str

class PaginatedLogsResponse(BaseModel):
    items: List[LogResponse]
    total: int
    page: int
    size: int
    pages: int

# FastAPI app
app = FastAPI(title="SIEM BOX Simple Backend")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
db_pool = None

# Syslog server
class SyslogServer:
    def __init__(self):
        self.stats = {'received': 0, 'stored': 0, 'errors': 0}

    def parse_syslog(self, raw_message: str, source_ip: str) -> dict:
        """Parse syslog message"""
        match = SYSLOG_PATTERN.match(raw_message)

        if match:
            timestamp_str = match.group('timestamp')
            hostname = match.group('hostname')
            message = match.group('message')

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
            async with db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO logs (timestamp, hostname, source_ip, message, raw_syslog)
                    VALUES ($1, $2, $3, $4, $5)
                ''', log_data['timestamp'], log_data['hostname'], log_data['source_ip'],
                    log_data['message'], log_data['raw_syslog'])

            self.stats['stored'] += 1
            print(f"[SYSLOG] ✅ {log_data['hostname']} from {log_data['source_ip']}")
            return True

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[SYSLOG] ❌ Error: {e}")
            return False

    async def handle_syslog(self, data: bytes, addr: tuple):
        """Handle incoming syslog message"""
        self.stats['received'] += 1
        source_ip = addr[0]

        try:
            raw_message = data.decode('utf-8', errors='ignore').strip()
            if not raw_message:
                return

            log_data = self.parse_syslog(raw_message, source_ip)
            await self.store_log(log_data)

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[SYSLOG] ❌ Failed to process from {source_ip}: {e}")

    async def start(self):
        """Start syslog server"""
        print(f"[SYSLOG] Starting on {SYSLOG_HOST}:{SYSLOG_PORT}")

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

syslog_server = SyslogServer()

# Auth helpers
def create_token(username: str) -> str:
    """Create JWT token"""
    payload = {
        'sub': username,
        'user_id': 1,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Startup/shutdown
@app.on_event("startup")
async def startup():
    """Initialize database and syslog server"""
    global db_pool

    print(f"[DB] Connecting to PostgreSQL at {DB_HOST}:{DB_PORT}/{DB_NAME}")
    try:
        db_pool = await asyncpg.create_pool(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            min_size=2,
            max_size=10
        )
        print("[DB] ✅ Connected to database")
    except Exception as e:
        print(f"[DB] ❌ Failed to connect: {e}")
        raise

    # Start syslog server
    try:
        await syslog_server.start()
    except Exception as e:
        print(f"[SYSLOG] ⚠️  Failed to start: {e}")

@app.on_event("shutdown")
async def shutdown():
    """Close connections"""
    if db_pool:
        await db_pool.close()
        print("[DB] Closed database connection")

# API Endpoints

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "app": "SIEM BOX Simple Backend",
        "status": "running",
        "syslog": {
            "received": syslog_server.stats['received'],
            "stored": syslog_server.stats['stored'],
            "errors": syslog_server.stats['errors']
        }
    }

@app.get("/api/v1/health")
async def health():
    """Health check"""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval('SELECT 1')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

@app.post("/api/v1/auth/login")
async def login(credentials: LoginRequest) -> LoginResponse:
    """Login endpoint - accepts admin/admin123"""
    if credentials.username == "admin" and credentials.password == "admin123":
        token = create_token(credentials.username)
        return LoginResponse(
            access_token=token,
            user={
                "username": "admin",
                "email": "admin@siembox.local",
                "is_active": True,
                "is_superuser": True,
                "id": 1
            }
        )
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/v1/logs")
async def get_logs(
    limit: int = 50,
    skip: int = 0,
    _user: dict = Depends(verify_token)
) -> PaginatedLogsResponse:
    """Get logs - matches React frontend expectations"""
    try:
        # Get total count
        async with db_pool.acquire() as conn:
            total = await conn.fetchval('SELECT COUNT(*) FROM logs')

            # Get logs
            rows = await conn.fetch('''
                SELECT id, timestamp, hostname, source_ip, message, raw_syslog, created_at
                FROM logs
                ORDER BY id DESC
                LIMIT $1 OFFSET $2
            ''', limit, skip)

        items = []
        for row in rows:
            items.append(LogResponse(
                id=row['id'],
                timestamp=row['timestamp'].isoformat() if row['timestamp'] else datetime.now().isoformat(),
                hostname=row['hostname'],
                source_ip=row['source_ip'],
                source_type=row['hostname'] or 'syslog',
                raw_message=row['raw_syslog'],
                created_at=row['created_at'].isoformat() if row['created_at'] else datetime.now().isoformat()
            ))

        page = (skip // limit) + 1 if limit else 1
        pages = (total + limit - 1) // limit if limit else 1

        return PaginatedLogsResponse(
            items=items,
            total=total,
            page=page,
            size=limit,
            pages=pages
        )

    except Exception as e:
        print(f"[API] Error getting logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/dashboard/stats")
async def get_dashboard_stats(_user: dict = Depends(verify_token)):
    """Get dashboard stats"""
    try:
        async with db_pool.acquire() as conn:
            total_logs = await conn.fetchval('SELECT COUNT(*) FROM logs')

            # Get logs from last 24h
            logs_24h = await conn.fetchval('''
                SELECT COUNT(*) FROM logs
                WHERE created_at >= NOW() - INTERVAL '24 hours'
            ''')

        return {
            "total_logs": total_logs,
            "logs_last_24h": logs_24h,
            "total_alerts": 0,  # No alerts yet
            "open_alerts": 0,
            "critical_alerts": 0,
            "alerts_last_24h": 0,
            "syslog_stats": syslog_server.stats
        }

    except Exception as e:
        print(f"[API] Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("SIEM BOX - Simple Backend for React UI")
    print("=" * 60)
    print()
    print("Starting on http://0.0.0.0:8000")
    print("Docs: http://localhost:8000/docs")
    print("React UI: http://localhost:3000")
    print()

    uvicorn.run(app, host="0.0.0.0", port=8000)
