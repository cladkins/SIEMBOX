from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, IPvAnyAddress
from datetime import datetime, timedelta
import logging
import json
import aiohttp
import os
import redis
import asyncio
from typing import Dict, Any, Optional, List
from collections import deque
import time
import psutil

# Configure logging with more detail
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

# Global stats tracking
stats = {
    "lookup_count": 0,
    "cache_hits": 0,
    "total_lookups": 0,
    "threat_detections": 0,
    "api_quota_remaining": 0,
    "start_time": time.time(),
    "status": "operational"
}

# Constants for rate limiting
IPAPI_BATCH_SIZE = 100
IPAPI_REQUESTS_PER_MINUTE = 45
CROWDSEC_BATCH_SIZE = 5  # Reduced batch size to avoid rate limits
CROWDSEC_REQUESTS_PER_DAY = 50  # Community tier limit
BATCH_INTERVAL = 60  # Seconds between batches
VALIDATION_INTERVAL = 60  # Seconds between validation attempts
CROWDSEC_REQUEST_DELAY = 2  # Seconds between CrowdSec requests
CROWDSEC_CACHE_TTL = 3600 * 12  # Cache CrowdSec results for 12 hours

# Known DNS servers to skip CrowdSec lookup
KNOWN_DNS_SERVERS = {
    "1.1.1.1",  # Cloudflare
    "1.0.0.1",  # Cloudflare
    "8.8.8.8",  # Google
    "8.8.4.4",  # Google
    "9.9.9.9",  # Quad9
    "49.112.112.112",  # Quad9
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
    "8.26.56.26",     # Comodo
    "8.20.247.20"     # Comodo
}

# Default response for known DNS servers
DNS_SERVER_RESPONSE = {
    "is_threat": False,
    "threat_score": 0,
    "threat_types": [],
    "cached": True
}

# Request queues
ipapi_queue = deque()
crowdsec_queue = deque()
processing_lock = asyncio.Lock()

def get_crowdsec_api_key(x_crowdsec_key: Optional[str] = Header(None, alias="x-api-key")) -> Optional[str]:
    """Get CrowdSec API key from environment or header."""
    return x_crowdsec_key or os.getenv('CROWDSEC_API_KEY')

class IPLookupResult(BaseModel):
    ip: str
    country: str
    country_code: str
    region: str
    region_name: str
    city: str
    zip: str
    latitude: float
    longitude: float
    timezone: str
    isp: str
    org: str
    as_number: str
    as_name: str
    is_threat: bool
    threat_score: Optional[float]
    threat_types: list[str] = []
    cached: bool = False
    queued: bool = False

class APIStatus(BaseModel):
    ipapi_mode: str
    ipapi_requests_remaining: Optional[int]
    ipapi_next_reset: Optional[str]
    ipapi_queue_size: int
    crowdsec_mode: str
    crowdsec_requests_remaining: Optional[int]
    crowdsec_next_reset: Optional[str]
    crowdsec_queue_size: int
    batch_size: int

async def validate_crowdsec_key(api_key: str) -> bool:
    """Validate CrowdSec API key by making a test request."""
    if not api_key:
        logger.error("No API key provided")
        return False

    # Check if we've validated recently
    cache_key = f"crowdsec_validation_attempt:{api_key}"
    if redis_client.get(cache_key):
        logger.info("Using cached validation result")
        return redis_client.get(f"crowdsec_key_valid:{api_key}") == b'1'
        
    # Set validation attempt flag
    redis_client.setex(cache_key, VALIDATION_INTERVAL, '1')
        
    # Use a test IP for validation
    url = "https://cti.api.crowdsec.net/v2/smoke/192.0.2.1"  # Using TEST-NET-1 IP instead of DNS server
    headers = {
        "x-api-key": api_key,
        "User-Agent": "SIEMBox/1.0"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                logger.info(f"CrowdSec validation response status: {response.status}")
                response_text = await response.text()
                logger.info(f"CrowdSec validation response: {response_text}")
                
                if response.status == 200:
                    try:
                        data = await response.json()
                        # Cache the successful validation
                        redis_client.setex(f"crowdsec_key_valid:{api_key}", 3600, '1')
                        return True
                    except json.JSONDecodeError:
                        logger.error("Failed to parse JSON response")
                        return False
                elif response.status == 429:
                    logger.warning("Rate limit exceeded, using cached result if available")
                    cached_result = redis_client.get(f"crowdsec_key_valid:{api_key}")
                    return cached_result == b'1' if cached_result else False
                else:
                    logger.error(f"CrowdSec validation failed with status {response.status}")
                    return False
    except Exception as e:
        logger.error(f"Error validating CrowdSec API key: {str(e)}")
        return False

def is_using_paid_ipapi() -> bool:
    """Check if using paid IP-API key."""
    return bool(os.getenv('IPAPI_KEY'))

async def is_using_crowdsec(api_key: Optional[str] = None) -> bool:
    """Check if using CrowdSec API and if the key is valid."""
    api_key = api_key or os.getenv('CROWDSEC_API_KEY')
    if not api_key:
        return False
    
    # Check Redis for cached validation result
    cache_key = f"crowdsec_key_valid:{api_key}"
    cached_result = redis_client.get(cache_key)
    
    if cached_result is not None:
        return cached_result == b'1'
    
    # If not cached, validate
    is_valid = await validate_crowdsec_key(api_key)
    # Cache the result for 1 hour
    redis_client.setex(cache_key, 3600, '1' if is_valid else '0')
    return is_valid

def get_ipapi_rate_limit_key() -> str:
    """Get Redis key for IP-API rate limiting."""
    return "ip_api_rate_limit"

def get_crowdsec_rate_limit_key() -> str:
    """Get Redis key for CrowdSec rate limiting."""
    return "crowdsec_api_rate_limit"

def get_ipapi_requests_remaining() -> int:
    """Get remaining IP-API requests for current window."""
    if is_using_paid_ipapi():
        return -1  # Unlimited for paid tier
    
    count = redis_client.get(get_ipapi_rate_limit_key())
    if count is None:
        redis_client.set(get_ipapi_rate_limit_key(), IPAPI_REQUESTS_PER_MINUTE, ex=BATCH_INTERVAL)
        return IPAPI_REQUESTS_PER_MINUTE
    return int(count)

def get_crowdsec_requests_remaining() -> int:
    """Get remaining CrowdSec requests for current window."""
    count = redis_client.get(get_crowdsec_rate_limit_key())
    if count is None:
        redis_client.set(get_crowdsec_rate_limit_key(), CROWDSEC_REQUESTS_PER_DAY, ex=86400)  # 24 hours
        return CROWDSEC_REQUESTS_PER_DAY
    return int(count)

async def process_ipapi_queue():
    """Process queued IP-API requests in batches."""
    global ipapi_queue
    
    async with processing_lock:
        if not ipapi_queue:
            return
        
        batch = []
        while ipapi_queue and len(batch) < IPAPI_BATCH_SIZE:
            batch.append(ipapi_queue.popleft())
        
        redis_client.set(get_ipapi_rate_limit_key(), IPAPI_REQUESTS_PER_MINUTE, ex=BATCH_INTERVAL)
        
        for ip, future in batch:
            try:
                result = await get_ip_info_internal(ip)
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)

async def process_crowdsec_queue():
    """Process queued CrowdSec requests in batches."""
    global crowdsec_queue
    
    async with processing_lock:
        if not crowdsec_queue:
            return
        
        batch = []
        while crowdsec_queue and len(batch) < CROWDSEC_BATCH_SIZE:
            batch.append(crowdsec_queue.popleft())
        
        try:
            results = await get_threat_info_batch([ip for ip, _ in batch])
            for (ip, future), result in zip(batch, results):
                future.set_result(result)
            
            # Add delay between batches to avoid rate limits
            await asyncio.sleep(CROWDSEC_REQUEST_DELAY)
        except Exception as e:
            for _, future in batch:
                if not future.done():
                    future.set_exception(e)

async def get_ip_info_internal(ip: str) -> Dict[str, Any]:
    """Internal function to get IP information."""
    stats["total_lookups"] += 1
    
    cache_key = f"ip_info:{ip}"
    cached_data = redis_client.get(cache_key)
    if cached_data:
        stats["cache_hits"] += 1
        return {**json.loads(cached_data), "cached": True}
    
    api_key = os.getenv('IPAPI_KEY')
    if api_key:
        url = f"https://pro.ip-api.com/json/{ip}?key={api_key}&fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname"
    else:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('status') == 'success':
                    redis_client.setex(cache_key, 86400, json.dumps(data))
                    stats["lookup_count"] += 1
                    return {**data, "cached": False}
    
    raise HTTPException(status_code=500, detail="Failed to fetch IP information")

async def get_threat_info_batch(ips: List[str], api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get threat information for multiple IPs."""
    api_key = api_key or os.getenv('CROWDSEC_API_KEY')
    if not api_key:
        return [{"is_threat": False, "threat_score": 0, "threat_types": [], "cached": False} for _ in ips]
    
    results = []
    
    for ip in ips:
        # Skip CrowdSec lookup for known DNS servers
        if ip in KNOWN_DNS_SERVERS:
            results.append(DNS_SERVER_RESPONSE)
            continue
            
        cache_key = f"threat_info:{ip}"
        cached_data = redis_client.get(cache_key)
        
        if cached_data:
            threat_info = json.loads(cached_data)
            if threat_info.get("is_threat", False):
                stats["threat_detections"] += 1
            results.append({**threat_info, "cached": True})
            continue
        
        url = f"https://cti.api.crowdsec.net/v2/smoke/{ip}"
        headers = {
            "x-api-key": api_key,
            "User-Agent": "SIEMBox/1.0"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    logger.info(f"CrowdSec threat info response status for IP {ip}: {response.status}")
                    response_text = await response.text()
                    logger.info(f"CrowdSec threat info response for IP {ip}: {response_text}")
                    
                    if response.status == 200:
                        data = await response.json()
                        # Map CrowdSec response to our threat info format
                        threat_info = {
                            "is_threat": data.get('reputation', 'unknown') in ['malicious', 'suspicious'],
                            "threat_score": data.get('background_noise_score', 0),
                            "threat_types": [b.get('label') for b in data.get('behaviors', [])]
                        }
                        if threat_info["is_threat"]:
                            stats["threat_detections"] += 1
                        redis_client.setex(cache_key, CROWDSEC_CACHE_TTL, json.dumps(threat_info))
                        results.append({**threat_info, "cached": False})
                        
                        # Decrement daily limit
                        redis_client.decr(get_crowdsec_rate_limit_key())
                        
                        # Add delay between requests to avoid rate limits
                        await asyncio.sleep(CROWDSEC_REQUEST_DELAY)
                        continue
                    elif response.status == 429:
                        # If rate limited, use cached data if available
                        cached_data = redis_client.get(cache_key)
                        if cached_data:
                            results.append({**json.loads(cached_data), "cached": True})
                            continue
                        # Add longer delay when rate limited
                        await asyncio.sleep(CROWDSEC_REQUEST_DELAY * 2)
        except Exception as e:
            logger.error(f"Error fetching threat info for {ip}: {str(e)}")
            stats["status"] = "degraded"
        
        results.append({"is_threat": False, "threat_score": 0, "threat_types": [], "cached": False})
    
    return results

async def get_threat_info(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Get threat information with rate limiting and queueing."""
    # Return default response for known DNS servers
    if ip in KNOWN_DNS_SERVERS:
        return DNS_SERVER_RESPONSE
        
    api_key = api_key or os.getenv('CROWDSEC_API_KEY')
    if not api_key:
        return {"is_threat": False, "threat_score": 0, "threat_types": [], "cached": False}
    
    remaining = get_crowdsec_requests_remaining()
    stats["api_quota_remaining"] = remaining
    
    if remaining > 0:
        results = await get_threat_info_batch([ip], api_key)
        return results[0]
    
    # Queue request
    future = asyncio.Future()
    crowdsec_queue.append((ip, future))
    
    if len(crowdsec_queue) >= CROWDSEC_BATCH_SIZE:
        asyncio.create_task(process_crowdsec_queue())
    
    try:
        result = await future
        return {**result, "queued": True}
    except Exception as e:
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/lookup/{ip}", response_model=IPLookupResult)
async def lookup_ip(ip: IPvAnyAddress, x_crowdsec_key: Optional[str] = Header(None, alias="x-api-key")):
    """Look up information about an IP address."""
    try:
        ip_str = str(ip)
        ip_info, threat_info = await asyncio.gather(
            get_ip_info_internal(ip_str),
            get_threat_info(ip_str, x_crowdsec_key)
        )
        
        return IPLookupResult(
            ip=ip_str,
            country=ip_info.get('country', 'Unknown'),
            country_code=ip_info.get('countryCode', ''),
            region=ip_info.get('region', ''),
            region_name=ip_info.get('regionName', ''),
            city=ip_info.get('city', ''),
            zip=ip_info.get('zip', ''),
            latitude=ip_info.get('lat', 0.0),
            longitude=ip_info.get('lon', 0.0),
            timezone=ip_info.get('timezone', ''),
            isp=ip_info.get('isp', ''),
            org=ip_info.get('org', ''),
            as_number=ip_info.get('as', ''),
            as_name=ip_info.get('asname', ''),
            is_threat=threat_info.get('is_threat', False),
            threat_score=threat_info.get('threat_score'),
            threat_types=threat_info.get('threat_types', []),
            cached=ip_info.get('cached', False) and threat_info.get('cached', False),
            queued=threat_info.get('queued', False)
        )
    except Exception as e:
        logger.error(f"Error looking up IP {ip}: {str(e)}")
        stats["status"] = "degraded"
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    """Get IP lookup service statistics."""
    try:
        # Calculate cache hit rate
        cache_hit_rate = (stats["cache_hits"] / stats["total_lookups"] * 100) if stats["total_lookups"] > 0 else 0
        
        # Get system metrics
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        return {
            "lookup_count": stats["lookup_count"],
            "cache_hit_rate": round(cache_hit_rate, 2),
            "threat_detections": stats["threat_detections"],
            "api_quota_remaining": stats["api_quota_remaining"],
            "status": stats["status"],
            "uptime": int(time.time() - stats["start_time"]),
            "system_metrics": {
                "cpu_usage": cpu_usage,
                "memory_usage": memory.percent
            }
        }
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/validate/crowdsec")
async def validate_crowdsec(x_crowdsec_key: Optional[str] = Header(None, alias="x-api-key")):
    """Validate CrowdSec API key and return status."""
    api_key = get_crowdsec_api_key(x_crowdsec_key)
    if not api_key:
        return {"valid": False, "message": "No API key provided"}
    
    is_valid = await validate_crowdsec_key(api_key)
    if is_valid:
        # Cache the validation result
        cache_key = f"crowdsec_key_valid:{api_key}"
        redis_client.setex(cache_key, 3600, '1')
        
        return {
            "valid": True,
            "message": "API key is valid",
            "requests_remaining": get_crowdsec_requests_remaining()
        }
    else:
        return {"valid": False, "message": "Invalid API key"}

@app.get("/api/status")
async def get_api_status(x_crowdsec_key: Optional[str] = Header(None, alias="x-api-key")):
    """Get current API status."""
    api_key = get_crowdsec_api_key(x_crowdsec_key)
    ipapi_remaining = get_ipapi_requests_remaining()
    crowdsec_remaining = get_crowdsec_requests_remaining()
    
    ipapi_next_reset = None
    if not is_using_paid_ipapi():
        ttl = redis_client.ttl(get_ipapi_rate_limit_key())
        if ttl > 0:
            ipapi_next_reset = (datetime.now() + timedelta(seconds=ttl)).isoformat()
    
    crowdsec_next_reset = None
    crowdsec_mode = "disabled"
    
    if api_key:
        # Use cached validation result if available
        cache_key = f"crowdsec_key_valid:{api_key}"
        cached_result = redis_client.get(cache_key)
        if cached_result is not None:
            crowdsec_mode = "enabled" if cached_result == b'1' else "invalid"
        else:
            is_valid = await validate_crowdsec_key(api_key)
            crowdsec_mode = "enabled" if is_valid else "invalid"
            redis_client.setex(cache_key, 3600, '1' if is_valid else '0')
        
        if crowdsec_mode == "enabled":
            ttl = redis_client.ttl(get_crowdsec_rate_limit_key())
            if ttl > 0:
                crowdsec_next_reset = (datetime.now() + timedelta(seconds=ttl)).isoformat()
    
    return APIStatus(
        ipapi_mode="paid" if is_using_paid_ipapi() else "free",
        ipapi_requests_remaining=ipapi_remaining if ipapi_remaining >= 0 else None,
        ipapi_next_reset=ipapi_next_reset,
        ipapi_queue_size=len(ipapi_queue),
        crowdsec_mode=crowdsec_mode,
        crowdsec_requests_remaining=crowdsec_remaining if crowdsec_mode == "enabled" else None,
        crowdsec_next_reset=crowdsec_next_reset,
        crowdsec_queue_size=len(crowdsec_queue),
        batch_size=IPAPI_BATCH_SIZE
    )

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": stats["status"],
        "timestamp": datetime.now().isoformat(),
        "ipapi_mode": "paid" if is_using_paid_ipapi() else "free",
        "crowdsec_mode": "enabled" if os.getenv('CROWDSEC_API_KEY') else "disabled"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)