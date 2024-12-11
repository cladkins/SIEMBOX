from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from datetime import datetime
import json
import logging
import asyncio
from typing import Dict, Any
import aiofiles

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="SIEMBox Log Collector")

class LogEntry(BaseModel):
    source: str
    timestamp: datetime = None
    level: str = "INFO"
    message: str
    metadata: Dict[str, Any] = {}

async def write_log_to_file(log_entry: dict):
    """Write log entry to file asynchronously."""
    timestamp = datetime.now().strftime("%Y%m%d")
    filename = f"/var/log/collector/{timestamp}.json"
    
    async with aiofiles.open(filename, mode='a') as f:
        await f.write(json.dumps(log_entry) + "\n")

@app.post("/logs")
async def receive_log(log_entry: LogEntry):
    """Receive logs via HTTP POST."""
    try:
        if not log_entry.timestamp:
            log_entry.timestamp = datetime.now()

        log_data = log_entry.dict()
        await write_log_to_file(log_data)
        
        logger.info(f"Received log from {log_entry.source}")
        return {"status": "success", "message": "Log received"}
    
    except Exception as e:
        logger.error(f"Error processing log: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.on_event("startup")
async def startup_event():
    """Initialize necessary resources on startup."""
    logger.info("Log Collector service starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    logger.info("Log Collector service shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
