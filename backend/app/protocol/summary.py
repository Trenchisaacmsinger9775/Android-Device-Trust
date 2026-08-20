from typing import Any

from app.protocol.codec import Record, flatten
from app.protocol.keys import hash64

def payload_hash(data: bytes) -> str:
    return f"{hash64(data):016x}"

def summarize(records: list[Record]) -> dict[str, Any]:
    flat = flatten(records)
    return {
        "field_count": len(records),
        "schema": flat.get("META_SCHEMA_VERSION"),
        "app_package": flat.get("APP_PACKAGE"),
        "app_version_native": flat.get("APP_VERSION"),
        "build_model": flat.get("BUILD_MODEL"),
        "build_manufacturer": flat.get("BUILD_MANUFACTURER"),
        "sensors_count": flat.get("SENSORS_COUNT"),
        "camera_count": flat.get("FP_CAMERA_COUNT"),
        "widevine_level": flat.get("FP_WIDEVINE_SECURITY_LEVEL"),
        "key_attestation_status": flat.get("KEY_ATTESTATION_STATUS"),
        "vulkan_status": flat.get("VULKAN_STATUS"),
        "native_elapsed_ns": flat.get("TIME_ELAPSED_MONO_NS"),
        "present": sorted(k for k, v in flat.items() if v is not None)[:80],
    }
