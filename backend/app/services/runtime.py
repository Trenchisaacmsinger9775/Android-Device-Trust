import asyncio
import time
import logging

import asyncpg
import redis.asyncio as redis

from app.core.config import settings
from app.db.migrations import run_migrations
from app.services.retention import cleanup_expired_records

logger = logging.getLogger("devicecheck.runtime")

class Runtime:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.redis: redis.Redis | None = None
        self.postgres: asyncpg.Pool | None = None
        self.retention_task: asyncio.Task | None = None

    async def start(self) -> None:
        self.redis = redis.from_url(settings.redis_url, decode_responses=False)
        for attempt in range(1, 16):
            try:
                self.postgres = await asyncpg.create_pool(settings.postgres_dsn, min_size=1, max_size=4)
                await run_migrations(self.postgres)
                await self._cleanup_retention_once()
                self.retention_task = asyncio.create_task(self._retention_loop())
                return
            except Exception as error:
                self.postgres = None
                logger.warning("postgres_unavailable", extra={"extra": {"attempt": attempt, "error": str(error)}})
                await asyncio.sleep(2)
        if settings.app_env == "prod":
            raise RuntimeError("postgres unavailable after startup retries")

    async def stop(self) -> None:
        if self.retention_task is not None:
            self.retention_task.cancel()
            try:
                await self.retention_task
            except asyncio.CancelledError:
                pass
        if self.redis is not None:
            await self.redis.aclose()
        if self.postgres is not None:
            await self.postgres.close()

    async def health(self) -> dict[str, str]:
        redis_status = "down"
        postgres_status = "down"
        if self.redis is not None:
            try:
                await self.redis.ping()
                redis_status = "ok"
            except Exception:
                redis_status = "down"
        if self.postgres is not None:
            try:
                async with self.postgres.acquire() as connection:
                    await connection.fetchval("select 1")
                postgres_status = "ok"
            except Exception:
                postgres_status = "down"
        return {"api": "ok", "redis": redis_status, "postgres": postgres_status}

    async def _retention_loop(self) -> None:
        while True:
            await asyncio.sleep(max(60, settings.retention_cleanup_interval_seconds))
            await self._cleanup_retention_once()

    async def _cleanup_retention_once(self) -> None:
        if self.postgres is None:
            return
        try:
            async with self.postgres.acquire() as connection:
                async with connection.transaction():
                    await cleanup_expired_records(connection)
        except Exception as error:
            logger.warning("retention_cleanup_failed", extra={"extra": {"error": str(error)}})

runtime = Runtime()
