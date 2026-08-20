import time
from collections.abc import Mapping

from app.services.runtime import runtime

class Stats:
    async def increment(self, name: str, amount: int = 1) -> None:
        if runtime.redis is None:
            return
        try:
            await runtime.redis.incrby(f"stats:{name}", amount)
        except Exception:
            return

    async def increment_dimension(self, name: str, value: str) -> None:
        if runtime.redis is None:
            return
        try:
            await runtime.redis.hincrby(f"stats:{name}", value, 1)
        except Exception:
            return

    async def snapshot(self) -> dict[str, object]:
        uptime = int(time.time() - runtime.started_at)
        if runtime.redis is None:
            return {"uptime_seconds": uptime, "counters": {}, "dimensions": {}}

        counters: dict[str, int] = {}
        async for key in runtime.redis.scan_iter("stats:*"):
            key_text = key.decode() if isinstance(key, bytes) else key
            kind = await runtime.redis.type(key)
            if kind == b"string":
                value = await runtime.redis.get(key)
                counters[key_text.removeprefix("stats:")] = int(value or 0)

        dimensions: dict[str, Mapping[str, int]] = {}
        for name in (
            "app_versions",
            "decisions",
            "decoder_status",
            "risk_decisions",
            "recognition_status",
            "emulator_classifications",
            "risk_reason_codes",
            "emulator_reason_codes",
        ):
            values = await runtime.redis.hgetall(f"stats:{name}")
            dimensions[name] = {
                (k.decode() if isinstance(k, bytes) else k): int(v)
                for k, v in values.items()
            }
        return {"uptime_seconds": uptime, "counters": counters, "dimensions": dimensions}

stats = Stats()
