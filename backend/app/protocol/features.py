import hashlib
import hmac
import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.protocol.codec import Record, flatten

@dataclass(frozen=True)
class FeatureSnapshot:
    schema_version: int | None
    app_package: str | None
    app_version: str | None
    build_model: str | None
    build_manufacturer: str | None
    build_product: str | None
    build_device: str | None
    build_sdk: int | None
    build_release: str | None
    first_api_level: str | None
    abi_family: str | None
    soc_model: str | None
    soc_manufacturer: str | None
    gl_vendor: str | None
    gl_renderer: str | None
    vulkan_status: int | None
    vulkan_device_count: int | None
    sensors_count: int | None
    sensors_inventory_hash64: int | None
    camera_count: int | None
    camera_characteristics_hash64: int | None
    display_modes_hash64: int | None
    widevine_level: str | None
    widevine_id_hash64: int | None
    android_id_hash: str | None
    app_signers_digest64: int | None
    integrity_text_crc32: int | None
    claimed_model_key: str
    stable_fingerprint_hash: str
    stable_features: dict[str, Any]
    profile_features: dict[str, Any]
    volatile_features: dict[str, Any]

def extract_feature_snapshot(records: list[Record]) -> FeatureSnapshot:
    flat = flatten(records)
    text = _text_values(records)

    stable_features = _drop_none(
        {
            "build_brand": flat.get("BUILD_BRAND"),
            "build_product": flat.get("BUILD_PRODUCT"),
            "build_device": flat.get("BUILD_DEVICE"),
            "build_model": flat.get("BUILD_MODEL"),
            "build_manufacturer": flat.get("BUILD_MANUFACTURER"),
            "build_board": flat.get("BUILD_BOARD"),
            "build_sdk": flat.get("BUILD_SDK"),
            "build_release": flat.get("BUILD_RELEASE"),
            "build_supported_abis": _array_values(flat.get("BUILD_SUPPORTED_ABIS")),
            "prop_first_api_level": flat.get("PROP_FIRST_API_LEVEL"),
            "prop_cpu_abilist": flat.get("PROP_CPU_ABILIST"),
            "prop_soc_model": flat.get("PROP_SOC_MODEL"),
            "prop_soc_manufacturer": flat.get("PROP_SOC_MANUFACTURER"),
            "gl_vendor": flat.get("GPU_GL_VENDOR"),
            "gl_renderer": flat.get("GPU_GL_RENDERER"),
            "gl_version": flat.get("GPU_GL_VERSION"),
            "vulkan_status": flat.get("VULKAN_STATUS"),
            "vulkan_device_count": flat.get("VULKAN_DEVICE_COUNT"),
            "vulkan_device_types": flat.get("VULKAN_DEVICE_TYPES"),
            "vulkan_device_names": flat.get("VULKAN_DEVICE_NAMES"),
            "sensors_count": flat.get("SENSORS_COUNT"),
            "sensors_inventory_hash64": flat.get("SENSORS_INVENTORY_HASH64"),
            "sensors_full_report_hash64": flat.get("SENSORS_FULL_REPORT_HASH64"),
            "sensors_full_report_size": flat.get("SENSORS_FULL_REPORT_SIZE"),
            "camera_count": flat.get("FP_CAMERA_COUNT"),
            "camera_characteristics_hash64": flat.get("FP_CAMERA_CHARACTERISTICS_HASH64"),
            "camera_characteristics_size": flat.get("FP_CAMERA_CHARACTERISTICS_SIZE"),
            "display_modes_hash64": flat.get("FP_DISPLAY_MODES_HASH64"),
            "display_modes_size": flat.get("FP_DISPLAY_MODES_SIZE"),
            "widevine_level": flat.get("FP_WIDEVINE_SECURITY_LEVEL"),
            "widevine_id_hash64": flat.get("FP_WIDEVINE_ID_HASH64"),
            "android_id_hash": flat.get("ID_ANDROID_ID_HASH64"),
        }
    )

    profile_features = _drop_none(
        {
            "app_package": flat.get("APP_PACKAGE"),
            "app_version_native": flat.get("APP_VERSION"),
            "app_signers_digest64": flat.get("APP_SIGNERS_DIGEST64"),
            "build_fingerprint": flat.get("BUILD_FINGERPRINT"),
            "build_id": flat.get("BUILD_ID"),
            "build_type": flat.get("BUILD_TYPE"),
            "build_tags": flat.get("BUILD_TAGS"),
            "build_incremental": flat.get("BUILD_INCREMENTAL"),
            "display_metrics": flat.get("DISPLAY_METRICS"),
            "locale_current": flat.get("LOCALE_CURRENT"),
            "timezone_current": flat.get("TIMEZONE_CURRENT"),
            "sensors_feature_pairs": flat.get("SENSORS_FEATURE_PAIRS"),
            "sensors_full_report_summary": _summarize_lines(text.get("SENSORS_FULL_REPORT"), "sensor|", 80),
            "camera_characteristics_summary": _summarize_lines(text.get("FP_CAMERA_CHARACTERISTICS_BLOB"), "camera=", 20),
            "storage_data": flat.get("FP_STORAGE_DATA"),
            "storage_external": flat.get("FP_STORAGE_EXTERNAL"),
            "storage_cache": flat.get("FP_STORAGE_CACHE"),
            "settings_hash64": flat.get("FP_SETTINGS_HASH64"),
            "settings_size": flat.get("FP_SETTINGS_SIZE"),
            "telephony_hash64": flat.get("FP_TELEPHONY_HASH64"),
            "telephony_size": flat.get("FP_TELEPHONY_SIZE"),
            "gsf_present": flat.get("ID_GSF_PRESENT"),
        }
    )

    volatile_features = _drop_none(
        {
            "native_elapsed_ns": flat.get("TIME_ELAPSED_MONO_NS"),
            "process_api_level": flat.get("PROCESS_API_LEVEL"),
            "env_count": flat.get("ENV_COUNT"),
            "env_hash64": flat.get("ENV_HASH64"),
            "key_attestation_status": flat.get("KEY_ATTESTATION_STATUS"),
            "key_identity_status": flat.get("KEY_IDENTITY_STATUS"),
            "key_attestation_cert_count": _nested_value(flat.get("KEY_ATTESTATION_CERT_CHAIN"), "KEY_ATTESTATION_CERT_COUNT"),
            "key_identity_cert_count": _nested_value(flat.get("KEY_IDENTITY_CERT_CHAIN"), "KEY_IDENTITY_CERT_COUNT"),
            "battery": flat.get("FP_BATTERY"),
            "thermal_zones_hash64": flat.get("FP_THERMAL_ZONES_HASH64"),
            "thermal_zones_size": flat.get("FP_THERMAL_ZONES_SIZE"),
            "timeline": flat.get("FP_TIMELINE"),
            "java_properties_hash64": flat.get("JAVA_PROPERTIES_HASH64"),
            "java_properties_size": flat.get("JAVA_PROPERTIES_SIZE"),
            "integrity_text_hash64": flat.get("INTEGRITY_TEXT_HASH64"),
            "integrity_text_crc32": flat.get("INTEGRITY_TEXT_CRC32"),
            "integrity_text_size": flat.get("INTEGRITY_TEXT_SIZE"),
            "integrity_text_found": flat.get("INTEGRITY_TEXT_FOUND"),
        }
    )

    claimed_model_key = "|".join(
        str(value or "")
        for value in (
            flat.get("BUILD_MANUFACTURER"),
            flat.get("BUILD_MODEL"),
            flat.get("BUILD_PRODUCT"),
            flat.get("BUILD_DEVICE"),
            flat.get("BUILD_SDK"),
        )
    )

    return FeatureSnapshot(
        schema_version=_int_value(flat.get("META_SCHEMA_VERSION")),
        app_package=_str_value(flat.get("APP_PACKAGE")),
        app_version=_str_value(flat.get("APP_VERSION")),
        build_model=_str_value(flat.get("BUILD_MODEL")),
        build_manufacturer=_str_value(flat.get("BUILD_MANUFACTURER")),
        build_product=_str_value(flat.get("BUILD_PRODUCT")),
        build_device=_str_value(flat.get("BUILD_DEVICE")),
        build_sdk=_int_value(flat.get("BUILD_SDK")),
        build_release=_str_value(flat.get("BUILD_RELEASE")),
        first_api_level=_str_value(flat.get("PROP_FIRST_API_LEVEL")),
        abi_family=_abi_family(_str_value(flat.get("PROP_CPU_ABILIST")), _array_values(flat.get("BUILD_SUPPORTED_ABIS"))),
        soc_model=_str_value(flat.get("PROP_SOC_MODEL")),
        soc_manufacturer=_str_value(flat.get("PROP_SOC_MANUFACTURER")),
        gl_vendor=_str_value(flat.get("GPU_GL_VENDOR")),
        gl_renderer=_str_value(flat.get("GPU_GL_RENDERER")),
        vulkan_status=_int_value(flat.get("VULKAN_STATUS")),
        vulkan_device_count=_int_value(flat.get("VULKAN_DEVICE_COUNT")),
        sensors_count=_int_value(flat.get("SENSORS_COUNT")),
        sensors_inventory_hash64=_int_value(flat.get("SENSORS_INVENTORY_HASH64")),
        camera_count=_int_value(flat.get("FP_CAMERA_COUNT")),
        camera_characteristics_hash64=_int_value(flat.get("FP_CAMERA_CHARACTERISTICS_HASH64")),
        display_modes_hash64=_int_value(flat.get("FP_DISPLAY_MODES_HASH64")),
        widevine_level=_str_value(flat.get("FP_WIDEVINE_SECURITY_LEVEL")),
        widevine_id_hash64=_int_value(flat.get("FP_WIDEVINE_ID_HASH64")),
        android_id_hash=_str_value(flat.get("ID_ANDROID_ID_HASH64")),
        app_signers_digest64=_int_value(flat.get("APP_SIGNERS_DIGEST64")),
        integrity_text_crc32=_int_value(flat.get("INTEGRITY_TEXT_CRC32")),
        claimed_model_key=claimed_model_key,
        stable_fingerprint_hash=_stable_hash(stable_features),
        stable_features=stable_features,
        profile_features=profile_features,
        volatile_features=volatile_features,
    )

def hash_network_value(value: str | None) -> str | None:
    if not value:
        return None
    return hmac.new(settings.datastore_hash_key.encode(), value.encode(), hashlib.sha256).hexdigest()

def ip_prefix(value: str | None) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            return str(ipaddress.ip_network(f"{value}/24", strict=False))
        return str(ipaddress.ip_network(f"{value}/56", strict=False))
    except ValueError:
        return None

def json_dumps(value: dict[str, Any] | list[Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def _text_values(records: list[Record]) -> dict[str, str]:
    values: dict[str, str] = {}
    for record in records:
        if isinstance(record.value, list):
            values.update(_text_values(record.value))
        elif isinstance(record.value, bytes):
            text = _decode_text(record.value)
            if text is not None:
                values[record.name] = text
    return values

def _decode_text(value: bytes) -> str | None:
    if not value:
        return ""
    text = value.decode("utf-8", errors="replace")
    if "\ufffd" in text:
        return None
    return text

def _summarize_lines(text: str | None, prefix: str, limit: int) -> list[str] | None:
    if not text:
        return None
    lines = [line for line in text.splitlines() if line.startswith(prefix)]
    return lines[:limit]

def _array_values(value: Any) -> list[str] | None:
    if not isinstance(value, dict):
        return None
    items: list[tuple[int, str]] = []
    for key, item in value.items():
        if not key.startswith("ARRAY_ITEM_"):
            continue
        if isinstance(item, str):
            items.append((int(key.rsplit("_", 1)[1]), item))
    return [item for _, item in sorted(items)]

def _nested_value(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else None

def _stable_hash(features: dict[str, Any]) -> str:
    canonical = json_dumps(features)
    return hmac.new(settings.datastore_hash_key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

def _drop_none(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}

def _str_value(value: Any) -> str | None:
    return value if isinstance(value, str) else None

def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) else None

def _abi_family(cpu_abilist: str | None, supported_abis: list[str] | None) -> str | None:
    joined = ",".join(value for value in [cpu_abilist, *(supported_abis or [])] if value)
    if not joined:
        return None
    has_arm = "armeabi" in joined or "arm64" in joined
    has_x86 = "x86" in joined
    if has_arm and has_x86:
        return "mixed"
    if has_arm:
        return "arm"
    if has_x86:
        return "x86"
    return "other"
