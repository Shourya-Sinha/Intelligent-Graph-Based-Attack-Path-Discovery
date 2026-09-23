"""
Free rate limiting middleware — in-memory token bucket, no Redis needed.
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException

_buckets = defaultdict(list)
LIMIT = 60  # requests per minute per IP

async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    # clean
    _buckets[ip] = [t for t in _buckets[ip] if now - t < 60]
    if len(_buckets[ip]) >= LIMIT:
        raise HTTPException(429, "Rate limit exceeded (free tier: 60/min)")
    _buckets[ip].append(now)
    return await call_next(request)
