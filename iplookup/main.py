from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, IPvAnyAddress
from datetime import datetime, timedelta
import logging
import json
import aiohttp
import os
import redis
import asyncio
from typing import Dict, Any, Optional, List, Set, Tuple
from collections import deque
import time
import psutil
import re

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="SIEMBox IP Lookup Service")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8080",
        "http://frontend:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Redis connection
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'redis'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=0,
    decode_responses=True
)

# API URLs
API_URL = "http://api:8080"

# Global stats tracking
stats = {
    "lookup_count": 0,
    "cache_hits": 0,
    "total_lookups": 0,
    "threat_detections": 0,
    "api_quota_remaining": 50,  # Community tier: 50 requests per day
    "start_time": time.time(),
    "status": "operational"
}

# Constants for rate limiting
IPAPI_BATCH_SIZE = 100
IPAPI_REQUESTS_PER_MINUTE = 45
CROWDSEC_BATCH_SIZE = 5
CROWDSEC_REQUESTS_PER_DAY = 50  # Community tier limit
BATCH_INTERVAL = 60  # Seconds between batches
VALIDATION_INTERVAL = 60  # Seconds between validation attempts
CROWDSEC_REQUEST_DELAY = 2  # Seconds between CrowdSec requests
CROWDSEC_CACHE_TTL = 3600 * 12  # Cache CrowdSec results for 12 hours
API_KEY_CACHE_TTL = 300  # Cache API keys for 5 minutes

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

class Location(BaseModel):
    country: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0

class Behavior(BaseModel):
    name: str
    label: str
    description: str

class History(BaseModel):
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    days_age: int = 0

class AttackDetail(BaseModel):
    name: str
    label: str
    description: str
    references: List[str] = []

class Scores(BaseModel):
    aggressiveness: float = 0
    threat: float = 0
    trust: float = 0
    anomaly: float = 0
    total: float = 0

class ThreatInfo(BaseModel):
    ip_range_score: int = 0
    ip_range: Optional[str] = None
    as_name: Optional[str] = None
    as_num: int = 0
    location: Location = Location()
    reverse_dns: Optional[str] = None
    behaviors: List[Behavior] = []
    history: History = History()
    attack_details: List[AttackDetail] = []
    target_countries: Dict[str, int] = {}
    background_noise_score: int = 0
    scores: Dict[str, Scores] = {}
    references: List[str] = []

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
    reputation: str = "unknown"
    threat_score: Optional[float] = None
    threat_types: List[str] = []
    behaviors: List[Behavior] = []
    history: History = History()
    attack_details: List[AttackDetail] = []
    target_countries: Dict[str, int] = {}
    background_noise_score: int = 0
    scores: Dict[str, Scores] = {}
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

async def get_api_keys() -> Tuple[Optional[str], Optional[str]]:
    """Get API keys from the API Gateway with caching"""
    cache_key = "api_keys"
    cached_keys = redis_client.get(cache_key)
    
    if cached_keys:
        keys = json.loads(cached_keys)
        return keys.get("IPAPI_KEY"), keys.get("CROWDSEC_API_KEY")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_URL}/api/settings/api-keys") as response:
                if response.status == 200:
                    data = await response.json()
                    keys = {
                        "IPAPI_KEY": data.get("IPAPI_KEY", ""),
                        "CROWDSEC_API_KEY": data.get("CROWDSEC_API_KEY", "")
                    }
                    redis_client.setex(cache_key, API_KEY_CACHE_TTL, json.dumps(keys))
                    return keys["IPAPI_KEY"], keys["CROWDSEC_API_KEY"]
                else:
                    logger.error(f"Failed to fetch API keys: {response.status}")
                    return None, None
    except Exception as e:
        logger.error(f"Error fetching API keys: {str(e)}")
        return None, None

def get_crowdsec_api_key(x_crowdsec_key: Optional[str] = Header(None, alias="X-Api-Key")) -> Optional[str]:
    """Get CrowdSec API key from header or cached API keys"""
    if x_crowdsec_key:
        return x_crowdsec_key
    
    cache_key = "api_keys"
    cached_keys = redis_client.get(cache_key)
    if cached_keys:
        keys = json.loads(cached_keys)
        return keys.get("CROWDSEC_API_KEY")
    
    return None

async def validate_crowdsec_key(api_key: str) -> bool:
    """Validate CrowdSec API key by making a test request"""
    if not api_key:
        logger.error("No API key provided")
        return False

    # Check if we've validated recently
    cache_key = f"crowdsec_validation_attempt:{api_key}"
    if redis_client.get(cache_key):
        logger.info("Using cached validation result")
        return redis_client.get(f"crowdsec_key_valid:{api_key}") == '1'
        
    # Set validation attempt flag
    redis_client.setex(cache_key, VALIDATION_INTERVAL, '1')
        
    # Use Cloudflare's DNS (1.1.1.1) for validation
    url = "https://cti.api.crowdsec.net/v2/smoke/1.1.1.1"
    headers = {
        "X-Api-Key": api_key,
        "User-Agent": "SIEMBox/1.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                logger.info(f"CrowdSec validation response status: {response.status}")
                response_text = await response.text()
                logger.info(f"CrowdSec validation response: {response_text}")
                
                if response.status == 200:
                    # Cache the successful validation
                    redis_client.setex(f"crowdsec_key_valid:{api_key}", 3600, '1')
                    return True
                elif response.status == 429:
                    logger.warning("Rate limit exceeded during validation")
                    # Even if rate limited, we'll consider the key potentially valid
                    # and cache this state temporarily
                    redis_client.setex(f"crowdsec_key_valid:{api_key}", 3600, '1')
                    return True
                elif response.status == 403:
                    logger.error("Invalid API key")
                    return False
                else:
                    logger.error(f"CrowdSec validation failed with status {response.status}")
                    return False
    except Exception as e:
        logger.error(f"Error validating CrowdSec API key: {str(e)}")
        return False

async def is_using_paid_ipapi() -> bool:
    """Check if using paid IP-API key"""
    ipapi_key, _ = await get_api_keys()
    return bool(ipapi_key)

async def is_using_crowdsec(api_key: Optional[str] = None) -> bool:
    """Check if using CrowdSec API and if the key is valid"""
    if not api_key:
        _, api_key = await get_api_keys()
    
    if not api_key:
        return False
    
    # Check Redis for cached validation result
    cache_key = f"crowdsec_key_valid:{api_key}"
    cached_result = redis_client.get(cache_key)
    
    if cached_result is not None:
        return cached_result == '1'
    
    # If not cached, validate
    is_valid = await validate_crowdsec_key(api_key)
    # Cache the result for 1 hour
    redis_client.setex(cache_key, 3600, '1' if is_valid else '0')
    return is_valid

def get_ipapi_rate_limit_key() -> str:
    """Get Redis key for IP-API rate limiting"""
    return "ip_api_rate_limit"

def get_crowdsec_rate_limit_key() -> str:
    """Get Redis key for CrowdSec rate limiting"""
    return "crowdsec_api_rate_limit"

def get_ipapi_requests_remaining() -> int:
    """Get remaining IP-API requests for current window"""
    if is_using_paid_ipapi():
        return -1  # Unlimited for paid tier
    
    count = redis_client.get(get_ipapi_rate_limit_key())
    if count is None:
        redis_client.set(get_ipapi_rate_limit_key(), IPAPI_REQUESTS_PER_MINUTE, ex=BATCH_INTERVAL)
        return IPAPI_REQUESTS_PER_MINUTE
    return int(count)

def get_crowdsec_requests_remaining() -> int:
    """Get remaining CrowdSec requests for current window"""
    count = redis_client.get(get_crowdsec_rate_limit_key())
    if count is None:
        redis_client.set(get_crowdsec_rate_limit_key(), CROWDSEC_REQUESTS_PER_DAY, ex=86400)  # 24 hours
        return CROWDSEC_REQUESTS_PER_DAY
    return int(count)

@app.get("/validate/crowdsec")
async def validate_crowdsec(x_crowdsec_key: Optional[str] = Header(None, alias="X-Api-Key")):
    """Validate CrowdSec API key and return status"""
    api_key = get_crowdsec_api_key(x_crowdsec_key)
    if not api_key:
        return {"valid": False, "message": "No API key provided"}
    
    remaining_requests = get_crowdsec_requests_remaining()
    if remaining_requests <= 0:
        # If we're rate limited but have a cached validation, consider it valid
        cache_key = f"crowdsec_key_valid:{api_key}"
        if redis_client.get(cache_key) == '1':
            return {
                "valid": True,
                "message": "API key is rate limited but previously validated",
                "requests_remaining": 0,
                "rate_limited": True
            }
    
    is_valid = await validate_crowdsec_key(api_key)
    if is_valid:
        # Cache the validation result
        cache_key = f"crowdsec_key_valid:{api_key}"
        redis_client.setex(cache_key, 3600, '1')
        
        remaining = get_crowdsec_requests_remaining()
        if remaining <= 0:
            return {
                "valid": True,
                "message": "API key is valid but rate limited",
                "requests_remaining": 0,
                "rate_limited": True
            }
        
        return {
            "valid": True,
            "message": "API key is valid",
            "requests_remaining": remaining
        }
    else:
        return {"valid": False, "message": "Invalid API key"}

@app.get("/api/status")
async def get_api_status(x_crowdsec_key: Optional[str] = Header(None, alias="X-Api-Key")):
    """Get current API status"""
    api_key = get_crowdsec_api_key(x_crowdsec_key)
    ipapi_remaining = get_ipapi_requests_remaining()
    crowdsec_remaining = get_crowdsec_requests_remaining()
    
    ipapi_next_reset = None
    if not await is_using_paid_ipapi():
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
            crowdsec_mode = "enabled" if cached_result == '1' else "invalid"
        else:
            is_valid = await validate_crowdsec_key(api_key)
            crowdsec_mode = "enabled" if is_valid else "invalid"
            redis_client.setex(cache_key, 3600, '1' if is_valid else '0')
        
        if crowdsec_mode == "enabled":
            ttl = redis_client.ttl(get_crowdsec_rate_limit_key())
            if ttl > 0:
                crowdsec_next_reset = (datetime.now() + timedelta(seconds=ttl)).isoformat()
    
    return APIStatus(
        ipapi_mode="paid" if await is_using_paid_ipapi() else "free",
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
    """Health check endpoint"""
    try:
        # Check Redis connection
        redis_client.ping()
        
        # Check API Gateway connection
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_URL}/health") as response:
                if response.status != 200:
                    raise Exception("API Gateway health check failed")
        
        return {
            "status": stats["status"],
            "timestamp": datetime.now().isoformat(),
            "ipapi_mode": "paid" if await is_using_paid_ipapi() else "free",
            "crowdsec_mode": "enabled" if await is_using_crowdsec() else "disabled",
            "redis_connected": True,
            "api_gateway_connected": True
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        stats["status"] = "degraded"
        return {
            "status": "degraded",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)