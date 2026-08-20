import os
from dataclasses import dataclass

class ConfigError(RuntimeError):
    pass

def _is_prod() -> bool:
    return os.getenv("APP_ENV", "dev") == "prod"

def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    if _is_prod():
        raise ConfigError(f"{name} must be set in production")
    return default

def _csv_env(name: str, default: str) -> set[str]:
    return {item.strip() for item in _env(name, default).split(",") if item.strip()}

def _hex_set_env(name: str, default: str) -> set[int]:
    values: set[int] = set()
    for item in _csv_env(name, default):
        try:
            values.add(int(item.removeprefix("0x"), 16))
        except ValueError:
            continue
    return values

@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "dev")
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8080"))
    app_keys: set[str] = None
    redis_url: str = _env("REDIS_URL", "redis://localhost:6379/0")
    postgres_dsn: str = _env("POSTGRES_DSN", "postgresql://devicecheck:devicecheck@localhost:5432/devicecheck")
    challenge_ttl_seconds: int = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))
    challenge_rate_limit_per_minute: int = int(os.getenv("CHALLENGE_RATE_LIMIT_PER_MINUTE", "60"))
    check_rate_limit_per_minute: int = int(os.getenv("CHECK_RATE_LIMIT_PER_MINUTE", "120"))
    max_attestation_bytes: int = int(os.getenv("MAX_ATTESTATION_BYTES", "262144"))
    datastore_hash_key: str = _env("DATASTORE_HASH_KEY", "dev-datastore-hash-key")
    datastore_retention_days: int = int(os.getenv("DATASTORE_RETENTION_DAYS", "30"))
    retention_cleanup_interval_seconds: int = int(os.getenv("RETENTION_CLEANUP_INTERVAL_SECONDS", "21600"))
    expected_package_name: str = _env("EXPECTED_PACKAGE_NAME", "com.reveny.devicecheck")
    expected_app_signers_digest64: set[int] = None
    expected_app_certificate_sha256: set[str] = None
    expected_text_crc32: set[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "app_keys", _csv_env("APP_KEYS", "72156d1c37c8e9fd52fdaf7d9ffcc9420a3f38a5095b8052abe104dfec066366"))
        object.__setattr__(self, "expected_app_signers_digest64", _hex_set_env("EXPECTED_APP_SIGNERS_DIGEST64", "65096e6741eae4ef"))
        object.__setattr__(self, "expected_app_certificate_sha256", {value.lower() for value in _csv_env("EXPECTED_APP_CERTIFICATE_SHA256", "63c5c229ebd0badf1c784f8988bb2884193abddcfe3e400c71c7980a29e763ee")})
        object.__setattr__(self, "expected_text_crc32", _hex_set_env("EXPECTED_TEXT_CRC32", "b87251ba,87262249"))
        if not self.app_keys:
            raise ConfigError("APP_KEYS must not be empty")

settings = Settings()
