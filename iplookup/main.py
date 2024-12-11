from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress
from datetime import datetime
import logging
import json
import aiohttp
import os
import redis
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="SIEMBox IP Lookup Service")

# Initialize Redis connection
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'redis'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=0
)

class IPLookupResult(BaseModel):
    ip: str
    country: str
    city: Optional[str]
    isp: Optional[str]
    is_threat: bool
    threat_score: Optional[float]
    threat_types: list[str] = []
    cached: bool = False

async def get_ip_info(ip: str) -> Dict[str, Any]:
    """Get IP information from ip-api.com."""
    cache_key = f"ip_info:{ip}"
    
    # Check cache first
    cached_data = redis_client.get(cache_key)
    if cached_data:
        return {**json.loads(cached_data), "cached": True}
    
    # Fetch from API if not in cache
    api_key = os.getenv('IPAPI_KEY')
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('status') == 'success':
                    # Cache for 24 hours
                    redis_client.setex(cache_key, 86400, json.dumps(data))
                    return {**data, "cached": False}
    
    raise HTTPException(status_code=500, detail="Failed to fetch IP information")

async def get_threat_info(ip: str) -> Dict[str, Any]:
    """Get threat information from CrowdSec API."""
    cache_key = f"threat_info:{ip}"
    
    # Check cache first
    cached_data = redis_client.get(cache_key)
    if cached_data:
        return {**json.loads(cached_data), "cached": True}
    
    # Fetch from API if not in cache
    api_key = os.getenv('CROWDSEC_API_KEY')
    url = f"https://api.crowdsec.net/v2/signal/ip/{ip}"
    headers = {"x-api-key": api_key}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                threat_info = {
                    "is_threat": bool(data.get('signals', [])),
                    "threat_score": data.get('score', 0),
                    "threat_types": [s.get('scenario') for s in data.get('signals', [])]
                }
                # Cache for 1 hour
                redis_client.setex(cache_key, 3600, json.dumps(threat_info))
                return {**threat_info, "cached": False}
    
    return {"is_threat": False, "threat_score": 0, "threat_types": [], "cached": False}

@app.get("/lookup/{ip}", response_model=IPLookupResult)
async def lookup_ip(ip: IPvAnyAddress):
    """Look up information about an IP address."""
    try:
        # Fetch IP info and threat info concurrently
        ip_str = str(ip)
        ip_info, threat_info = await asyncio.gather(
            get_ip_info(ip_str),
            get_threat_info(ip_str)
        )
        
        return IPLookupResult(
            ip=ip_str,
            country=ip_info.get('country', 'Unknown'),
            city=ip_info.get('city'),
            isp=ip_info.get('isp'),
            is_threat=threat_info.get('is_threat', False),
            threat_score=threat_info.get('threat_score'),
            threat_types=threat_info.get('threat_types', []),
            cached=ip_info.get('cached', False) and threat_info.get('cached', False)
        )
    
    except Exception as e:
        logger.error(f"Error looking up IP {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
