import time
from dataclasses import dataclass

from app.services.runtime import runtime

@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int
    limit: int
    count: int

class RateLimiter:
    async def allow(self, bucket: str, identity: str | None, limit: int, window_seconds: int = 60) -> RateLimitResult:
        if limit <= 0 or runtime.redis is None:
            return RateLimitResult(True, 0, limit, 0)

        window = int(time.time() // window_seconds)
        key = f"rate:{bucket}:{identity or 'unknown'}:{window}"
        count = await runtime.redis.incr(key)
        if count == 1:
            await runtime.redis.expire(key, window_seconds + 5)

        retry_after = window_seconds - int(time.time() % window_seconds)
        return RateLimitResult(count <= limit, retry_after, limit, count)

rate_limiter = RateLimiter()
