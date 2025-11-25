#!/usr/bin/env python3
"""
SIEM BOX - Minimal API
Just serves logs from the database. Nothing else.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncpg
from datetime import datetime
from typing import List, Dict

# Configuration (from environment or defaults)
import os

DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', '5432'))
DB_NAME = os.getenv('DB_NAME', 'siembox')
DB_USER = os.getenv('DB_USER', 'siembox')
DB_PASS = os.getenv('DB_PASS', 'siembox')

app = FastAPI(title="SIEM BOX Minimal API")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database pool
db_pool = None

@app.on_event("startup")
async def startup():
    """Initialize database connection"""
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

@app.on_event("shutdown")
async def shutdown():
    """Close database connection"""
    global db_pool
    if db_pool:
        await db_pool.close()
        print("[DB] Closed database connection")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "app": "SIEM BOX Minimal API",
        "status": "running",
        "endpoints": {
            "/logs": "Get recent logs",
            "/logs/count": "Get total log count",
            "/health": "Health check"
        }
    }

@app.get("/health")
async def health():
    """Health check"""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval('SELECT 1')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

@app.get("/logs/count")
async def get_log_count():
    """Get total log count"""
    try:
        async with db_pool.acquire() as conn:
            count = await conn.fetchval('SELECT COUNT(*) FROM logs')
        return {"count": count}
    except Exception as e:
        return {"error": str(e)}

@app.get("/logs")
async def get_logs(limit: int = 50, offset: int = 0) -> List[Dict]:
    """
    Get recent logs

    Args:
        limit: Number of logs to return (default 50, max 1000)
        offset: Number of logs to skip (default 0)
    """
    if limit > 1000:
        limit = 1000

    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, timestamp, hostname, source_ip, message, raw_syslog, created_at
                FROM logs
                ORDER BY id DESC
                LIMIT $1 OFFSET $2
            ''', limit, offset)

        logs = []
        for row in rows:
            logs.append({
                "id": row['id'],
                "timestamp": row['timestamp'].isoformat() if row['timestamp'] else None,
                "hostname": row['hostname'],
                "source_ip": row['source_ip'],
                "message": row['message'],
                "raw_syslog": row['raw_syslog'],
                "created_at": row['created_at'].isoformat() if row['created_at'] else None
            })

        return logs

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("SIEM BOX - Minimal API")
    print("=" * 60)
    print()
    print("Starting API server on http://0.0.0.0:8000")
    print("Docs: http://localhost:8000/docs")
    print()

    uvicorn.run(app, host="0.0.0.0", port=8000)
