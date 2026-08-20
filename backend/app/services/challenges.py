import base64
import secrets

from app.core.config import settings
from app.protocol.keys import derive_bytes, DOMAIN_CHALLENGE_HASH
from app.services.runtime import runtime

class ChallengeStoreUnavailable(RuntimeError):
    pass


def _key(challenge_hash: bytes) -> str:
    return f"challenge:{challenge_hash.hex()}"

class ChallengeService:
    async def issue(self) -> dict[str, object]:
        challenge = secrets.token_bytes(32)
        challenge_hash = derive_bytes(DOMAIN_CHALLENGE_HASH, challenge, 16)
        if runtime.redis is None:
            raise ChallengeStoreUnavailable()
        await runtime.redis.set(_key(challenge_hash), challenge, ex=settings.challenge_ttl_seconds, nx=True)
        return {
            "challenge": base64.b64encode(challenge).decode("ascii"),
            "expires_in": settings.challenge_ttl_seconds,
        }

    async def consume(self, challenge_hash: bytes) -> bytes | None:
        if runtime.redis is None:
            return None
        try:
            value = await runtime.redis.execute_command("GETDEL", _key(challenge_hash))
        except Exception:
            return None
        return bytes(value) if value is not None else None

challenges = ChallengeService()
