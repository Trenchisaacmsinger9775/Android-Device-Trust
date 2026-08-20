from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.protocol.attestation import AttestationDetails
from app.protocol.codec import Record, flatten
from app.protocol.device_identity import DeviceIdentity
from app.protocol.features import FeatureSnapshot

FAMILY_CAPS = {
    "attestation": 5.0,
    "app_integrity": 5.0,
    "build_coherence": 4.5,
    "hardware_coherence": 5.0,
    "runtime_integrity": 4.0,
    "network_request": 3.0,
    "history_velocity": 4.0,
    "device_graph": 4.0,
    "cloud_phone_pattern": 3.0,
}

EMULATOR_CODES = {
    "mixed_arm_x86_abis",
    "native_bridge_properties_present",
    "vulkan_cpu_only",
    "low_sensor_count",
    "feature_sensor_desync",
}

MODIFIED_CODES = {
    "attestation_app_package_mismatch",
    "attestation_app_signature_mismatch",
    "attestation_challenge_mismatch",
    "fingerprint_unparseable",
    "fingerprint_incoherent",
    "first_api_after_current_sdk",
    "process_api_build_sdk_mismatch",
    "vulkan_unavailable_or_failed",
    "no_cameras",
    "camera_count_without_characteristics",
    "sensor_count_without_inventory_hash",
    "always_full_charging_battery",
}

ABNORMAL_CODES = {
    "app_signature_missing",
    "app_signature_mismatch",
    "native_text_crc_missing",
    "native_text_crc_mismatch",
    "slow_native_collection",
    "identity_cluster_mismatch",
    "stable_fingerprint_many_clusters",
    "cluster_many_device_identities",
}

@dataclass(frozen=True)
class RiskFinding:
    family: str
    code: str
    weight: float
    message: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "code": self.code,
            "weight": self.weight,
            "message": self.message,
            "evidence": self.evidence,
        }

@dataclass(frozen=True)
class RiskResult:
    score: float
    decision: str
    findings: list[RiskFinding]
    missing_signals: list[str]
    family_scores: dict[str, float]
    reason_codes: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "decision": self.decision,
            "findings": [finding.as_dict() for finding in self.findings],
            "missing_signals": self.missing_signals,
            "family_scores": self.family_scores,
            "reason_codes": self.reason_codes,
        }

    def coarse_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_codes": self.reason_codes,
            "missing_signals": self.missing_signals,
        }

@dataclass(frozen=True)
class EmulatorResult:
    score: float
    classification: str
    is_emulator: bool
    confidence: str
    factors: list[RiskFinding]
    protective_factors: list[RiskFinding]
    reason_codes: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "classification": self.classification,
            "is_emulator": self.is_emulator,
            "confidence": self.confidence,
            "factors": [factor.as_dict() for factor in self.factors],
            "protective_factors": [factor.as_dict() for factor in self.protective_factors],
            "reason_codes": self.reason_codes,
        }

    def coarse_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "is_emulator": self.is_emulator,
            "confidence": self.confidence,
            "reason_codes": self.reason_codes,
        }

@dataclass(frozen=True)
class EnvironmentResult:
    status: str
    title: str
    message: str
    is_emulator: bool
    is_modified: bool
    is_abnormal: bool
    reason_codes: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "title": self.title,
            "message": self.message,
            "is_emulator": self.is_emulator,
            "is_modified": self.is_modified,
            "is_abnormal": self.is_abnormal,
            "reason_codes": self.reason_codes,
        }

@dataclass(frozen=True)
class HistoryContext:
    device_seen_count: int = 0
    cluster_seen_count: int = 0
    stable_hash_cluster_count: int = 0
    matching_cluster_instance_count: int = 0
    ip_prefix_new_clusters_24h: int = 0
    user_agent_new_clusters_24h: int = 0
    device_request_count_24h: int = 0
    identity_cluster_mismatch: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_seen_count": self.device_seen_count,
            "cluster_seen_count": self.cluster_seen_count,
            "stable_hash_cluster_count": self.stable_hash_cluster_count,
            "matching_cluster_instance_count": self.matching_cluster_instance_count,
            "ip_prefix_new_clusters_24h": self.ip_prefix_new_clusters_24h,
            "user_agent_new_clusters_24h": self.user_agent_new_clusters_24h,
            "device_request_count_24h": self.device_request_count_24h,
            "identity_cluster_mismatch": self.identity_cluster_mismatch,
        }

def evaluate_risk(
    records: list[Record],
    identity: DeviceIdentity,
    features: FeatureSnapshot,
    attestation: AttestationDetails,
    history: HistoryContext | None = None,
) -> RiskResult:
    flat = flatten(records)
    findings: list[RiskFinding] = []
    history = history or HistoryContext()

    _attestation_findings(findings, identity, attestation, flat)
    _app_integrity_findings(findings, features)
    _build_findings(findings, flat)
    _abi_findings(findings, flat, features)
    _gpu_findings(findings, flat)
    _sensor_findings(findings, flat)
    _media_findings(findings, flat)
    _integrity_findings(findings, flat)
    _coherence_findings(findings, flat, features)
    _history_findings(findings, history)
    _cloud_phone_findings(findings, flat, features, history)
    _negative_findings(findings, identity, flat, history, attestation)

    family_scores = _family_scores(findings)
    score = round(sum(family_scores.values()), 2)
    if score >= 7:
        decision = "high_risk"
    elif score >= 3:
        decision = "review"
    else:
        decision = "low_risk"

    return RiskResult(
        score=max(score, 0),
        decision=decision,
        findings=findings,
        missing_signals=_missing(flat),
        family_scores=family_scores,
        reason_codes=_reason_codes(findings),
    )

def classify_emulator(risk: RiskResult) -> EmulatorResult:
    factors = [
        finding
        for finding in risk.findings
        if finding.weight > 0 and finding.code in EMULATOR_CODES
    ]
    protective = [
        finding
        for finding in risk.findings
        if finding.weight < 0 and finding.family in {"attestation", "hardware_coherence", "device_graph"}
    ]
    group_count = len({_emulator_group(finding.code) for finding in factors if finding.weight >= 1.0})
    score = round(sum(_family_scores(factors + protective).values()), 2)
    score = max(score, 0)

    if score >= 5 and group_count >= 2:
        classification = "likely_emulator"
        is_emulator = True
        confidence = "high"
    elif score >= 3 and group_count >= 2:
        classification = "possible_emulator"
        is_emulator = False
        confidence = "medium"
    elif score >= 2:
        classification = "weak_emulator_signal"
        is_emulator = False
        confidence = "low"
    else:
        classification = "no_emulator_signal"
        is_emulator = False
        confidence = "low"

    return EmulatorResult(score, classification, is_emulator, confidence, factors, protective, _reason_codes(factors))

def _emulator_group(code: str) -> str:
    if code in {"mixed_arm_x86_abis", "native_bridge_properties_present"}:
        return "abi_translation"
    if code in {"vulkan_cpu_only"}:
        return "gpu_virtualization"
    if code in {"low_sensor_count", "feature_sensor_desync"}:
        return "sensor_profile"
    return code

def classify_environment(risk: RiskResult, emulator: EmulatorResult) -> EnvironmentResult:
    positive_codes = {finding.code for finding in risk.findings if finding.weight > 0}
    abnormal_codes = sorted(positive_codes & ABNORMAL_CODES)
    modified_codes = sorted(positive_codes & MODIFIED_CODES)

    if abnormal_codes:
        return EnvironmentResult(
            "abnormal",
            "Abnormal environment",
            "Runtime modification signals were reported.",
            False,
            bool(modified_codes),
            True,
            abnormal_codes + modified_codes,
        )

    if emulator.is_emulator:
        return EnvironmentResult(
            "emulator",
            "Emulator detected",
            "Virtual device signals were reported.",
            True,
            bool(modified_codes),
            False,
            emulator.reason_codes + modified_codes,
        )

    if modified_codes:
        message = "Device environment appears modified."
        if emulator.classification in {"weak_emulator_signal", "possible_emulator"}:
            message = "Device environment appears modified. Possible emulator signals were also reported."
        return EnvironmentResult(
            "modified_environment",
            "Modified environment",
            message,
            False,
            True,
            False,
            modified_codes + emulator.reason_codes,
        )

    if emulator.classification in {"weak_emulator_signal", "possible_emulator"}:
        return EnvironmentResult(
            "modified_environment",
            "Modified environment",
            "Possible emulator signals were reported.",
            False,
            True,
            False,
            emulator.reason_codes,
        )

    return EnvironmentResult(
        "normal",
        "Device verified",
        "No emulator or modification signal was reported.",
        False,
        False,
        False,
        [],
    )

def _attestation_findings(findings: list[RiskFinding], identity: DeviceIdentity, attestation: AttestationDetails, flat: dict[str, Any]) -> None:
    if not (identity.status == "ok" and identity.signature_verified):
        weight = 2.0
        if identity.status in {"signature_invalid", "invalid_leaf_certificate"}:
            weight = 4.0
        findings.append(
            RiskFinding(
                "attestation",
                identity.status,
                weight,
                "Keystore identity is missing or did not verify.",
                identity.as_dict(),
            )
        )

    native_status = _int_from_any(flat.get("KEY_ATTESTATION_STATUS"))
    if native_status is not None and native_status != 0:
        findings.append(
            RiskFinding(
                "attestation",
                "native_attestation_failed",
                2.0,
                "Native key attestation probe returned a failure status.",
                {"key_attestation_status": native_status},
            )
        )

    if attestation.status != "ok":
        if identity.signature_verified:
            findings.append(
                RiskFinding(
                    "attestation",
                    f"attestation_{attestation.status}",
                    1.0,
                    "Key attestation extension was not available or could not be parsed.",
                    attestation.as_dict(),
                )
            )
        return

    if attestation.challenge_matches is False:
        findings.append(
            RiskFinding(
                "attestation",
                "attestation_challenge_mismatch",
                4.0,
                "Key attestation certificate challenge does not match this request.",
                attestation.as_dict(),
            )
        )

    if not attestation.root_trusted:
        findings.append(
            RiskFinding(
                "attestation",
                "attestation_chain_untrusted",
                4.0,
                "Key attestation chain does not terminate at a trusted Google attestation root.",
                {"root_sha256": attestation.root_sha256, "cert_chain_present": True},
            )
        )
    elif not attestation.chain_verified:
        findings.append(
            RiskFinding(
                "attestation",
                "attestation_chain_invalid",
                4.0,
                "Key attestation certificate chain signature validation failed.",
                {"root_sha256": attestation.root_sha256},
            )
        )
    if not attestation.app_id_present:
        findings.append(
            RiskFinding(
                "attestation",
                "attestation_app_id_missing",
                2.5,
                "Key attestation does not include Android application identity.",
                attestation.as_dict(),
            )
        )
    else:
        if attestation.app_id_package_match is False:
            findings.append(
                RiskFinding(
                    "attestation",
                    "attestation_app_package_mismatch",
                    5.0,
                    "Key attestation application identity does not match the expected package.",
                    attestation.as_dict(),
                )
            )
        if attestation.app_id_signature_match is False:
            findings.append(
                RiskFinding(
                    "attestation",
                    "attestation_app_signature_mismatch",
                    5.0,
                    "Key attestation application identity does not match the expected app signing certificate.",
                    attestation.as_dict(),
                )
            )

    if attestation.attestation_security_level == "Software" or attestation.keymaster_security_level == "Software":
        findings.append(
            RiskFinding(
                "attestation",
                "software_key_attestation",
                3.0,
                "Key attestation reports software security level.",
                attestation.as_dict(),
            )
        )
    if attestation.device_locked is False:
        findings.append(
            RiskFinding(
                "attestation",
                "verified_boot_unlocked",
                2.0,
                "Attestation root of trust reports an unlocked device.",
                attestation.as_dict(),
            )
        )
    if attestation.verified_boot_state in {"Unverified", "Failed"}:
        findings.append(
            RiskFinding(
                "attestation",
                "verified_boot_not_verified",
                2.5,
                "Attestation root of trust does not report verified boot.",
                attestation.as_dict(),
            )
        )

def _app_integrity_findings(findings: list[RiskFinding], features: FeatureSnapshot) -> None:
    if features.app_package != settings.expected_package_name:
        return

    _expected_value_finding(
        findings,
        code_missing="app_signature_missing",
        code_mismatch="app_signature_mismatch",
        message_missing="App signer digest was not reported.",
        message_mismatch="App signer digest does not match the expected release signer.",
        family="app_integrity",
        observed=features.app_signers_digest64,
        expected=settings.expected_app_signers_digest64,
        width=16,
        weight=5.0,
    )
    _expected_value_finding(
        findings,
        code_missing="native_text_crc_missing",
        code_mismatch="native_text_crc_mismatch",
        message_missing="Native text-section CRC was not reported.",
        message_mismatch="Native text-section CRC does not match the expected release memory image.",
        family="app_integrity",
        observed=features.integrity_text_crc32,
        expected=settings.expected_text_crc32,
        width=8,
        weight=4.0,
    )

def _expected_value_finding(
    findings: list[RiskFinding],
    *,
    code_missing: str,
    code_mismatch: str,
    message_missing: str,
    message_mismatch: str,
    family: str,
    observed: int | None,
    expected: set[int],
    width: int,
    weight: float,
) -> None:
    if not expected:
        return

    evidence = {
        "expected": sorted(_hex_value(value, width) for value in expected),
        "observed": _hex_value(observed, width) if observed is not None else None,
    }
    if observed is None or observed == 0:
        findings.append(RiskFinding(family, code_missing, weight, message_missing, evidence))
    elif observed not in expected:
        findings.append(RiskFinding(family, code_mismatch, weight, message_mismatch, evidence))


def _build_findings(findings: list[RiskFinding], flat: dict[str, Any]) -> None:
    parsed = _parse_fingerprint(_str(flat.get("BUILD_FINGERPRINT")))
    if parsed is None:
        findings.append(
            RiskFinding(
                "build_coherence",
                "fingerprint_unparseable",
                1.5,
                "Build fingerprint does not match the expected Android format.",
                {"fingerprint_present": flat.get("BUILD_FINGERPRINT") is not None},
            )
        )
    else:
        expected = {
            "brand": flat.get("BUILD_BRAND"),
            "product": flat.get("BUILD_PRODUCT"),
            "device": flat.get("BUILD_DEVICE"),
            "release": flat.get("BUILD_RELEASE"),
            "id": flat.get("BUILD_ID"),
            "incremental": flat.get("BUILD_INCREMENTAL"),
            "type": flat.get("BUILD_TYPE"),
            "tags": flat.get("BUILD_TAGS"),
        }
        mismatches = {key: {"fingerprint": parsed[key], "build": value} for key, value in expected.items() if value and parsed[key] != value}
        if mismatches:
            findings.append(
                RiskFinding(
                    "build_coherence",
                    "fingerprint_incoherent",
                    2.5,
                    "Build fingerprint fields do not match corresponding Build constants.",
                    {"mismatches": mismatches},
                )
            )

    first_api = _int_from_any(flat.get("PROP_FIRST_API_LEVEL"))
    sdk = _int_from_any(flat.get("BUILD_SDK"))
    if first_api is not None and sdk is not None and first_api > sdk:
        findings.append(
            RiskFinding(
                "build_coherence",
                "first_api_after_current_sdk",
                3.0,
                "ro.product.first_api_level is greater than current SDK.",
                {"first_api_level": first_api, "sdk": sdk},
            )
        )

def _abi_findings(findings: list[RiskFinding], flat: dict[str, Any], features: FeatureSnapshot) -> None:
    cpu_abilist = _str(flat.get("PROP_CPU_ABILIST")) or ""
    supported = ",".join(features.stable_features.get("build_supported_abis", []) or [])
    joined = f"{cpu_abilist},{supported}".lower()
    has_arm = "arm64" in joined or "armeabi" in joined
    has_x86 = "x86" in joined
    if has_arm and has_x86:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "mixed_arm_x86_abis",
                2.0,
                "Device reports both ARM and x86 ABI families.",
                {"cpu_abilist": cpu_abilist, "supported_abis": supported},
            )
        )

    bridge_props = {
        "isa_arm": flat.get("PROP_ISA_ARM"),
        "isa_arm64": flat.get("PROP_ISA_ARM64"),
        "native_bridge_exec": flat.get("PROP_NATIVE_BRIDGE_EXEC"),
        "native_bridge": flat.get("PROP_NATIVE_BRIDGE"),
    }
    if any(_str(value) and _str(value) not in {"0", "false"} for value in bridge_props.values()):
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "native_bridge_properties_present",
                2.0,
                "Native bridge or translated ISA properties are present.",
                bridge_props,
            )
        )

def _gpu_findings(findings: list[RiskFinding], flat: dict[str, Any]) -> None:
    vulkan_status = _int_from_any(flat.get("VULKAN_STATUS"))
    if vulkan_status is not None and vulkan_status != 0:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "vulkan_unavailable_or_failed",
                0.7,
                "Vulkan probe did not complete successfully.",
                {"vulkan_status": vulkan_status},
            )
        )
    device_types = (_str(flat.get("VULKAN_DEVICE_TYPES")) or "").lower()
    if device_types and all(part.strip() == "cpu" for part in device_types.split(",") if part.strip()):
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "vulkan_cpu_only",
                2.0,
                "All Vulkan physical devices are CPU devices.",
                {"vulkan_device_types": device_types},
            )
        )

def _sensor_findings(findings: list[RiskFinding], flat: dict[str, Any]) -> None:
    sensor_count = _int_from_any(flat.get("SENSORS_COUNT"))
    if sensor_count is not None and sensor_count < 5:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "low_sensor_count",
                1.5,
                "Sensor inventory is unusually small.",
                {"sensors_count": sensor_count},
            )
        )
    pairs = _str(flat.get("SENSORS_FEATURE_PAIRS")) or ""
    if "desync=1" in pairs or "mismatch=1" in pairs:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "feature_sensor_desync",
                1.5,
                "PackageManager feature flags disagree with visible default sensors.",
                {"feature_pairs": pairs},
            )
        )

def _media_findings(findings: list[RiskFinding], flat: dict[str, Any]) -> None:
    widevine_level = _str(flat.get("FP_WIDEVINE_SECURITY_LEVEL"))
    if widevine_level and widevine_level != "L1":
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "widevine_not_l1",
                0.8,
                "Widevine security level is not L1.",
                {"widevine_level": widevine_level},
            )
        )
    camera_count = _int_from_any(flat.get("FP_CAMERA_COUNT"))
    if camera_count == 0:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "no_cameras",
                1.0,
                "No cameras were visible to the app.",
                {"camera_count": camera_count},
            )
        )

def _integrity_findings(findings: list[RiskFinding], flat: dict[str, Any]) -> None:
    return

def _coherence_findings(findings: list[RiskFinding], flat: dict[str, Any], features: FeatureSnapshot) -> None:
    build_sdk = _int_from_any(flat.get("BUILD_SDK"))
    process_api = _int_from_any(flat.get("PROCESS_API_LEVEL"))
    if build_sdk is not None and process_api is not None and abs(build_sdk - process_api) > 1:
        findings.append(
            RiskFinding(
                "build_coherence",
                "process_api_build_sdk_mismatch",
                1.5,
                "Process API level does not match reported Build SDK.",
                {"build_sdk": build_sdk, "process_api_level": process_api},
            )
        )

    if features.camera_count is not None and features.camera_count > 0 and features.camera_characteristics_hash64 is None:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "camera_count_without_characteristics",
                1.2,
                "Camera count is present but camera characteristics hash is missing.",
                {"camera_count": features.camera_count},
            )
        )

    if features.sensors_count is not None and features.sensors_count > 0 and features.sensors_inventory_hash64 is None:
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "sensor_count_without_inventory_hash",
                1.2,
                "Sensor count is present but sensor inventory hash is missing.",
                {"sensors_count": features.sensors_count},
            )
        )

    elapsed_ns = _int_from_any(flat.get("TIME_ELAPSED_MONO_NS"))
    if elapsed_ns is not None and elapsed_ns > 8_000_000_000:
        findings.append(
            RiskFinding(
                "runtime_integrity",
                "slow_native_collection",
                0.8,
                "Native collection took longer than expected.",
                {"elapsed_ns": elapsed_ns},
            )
        )

def _history_findings(findings: list[RiskFinding], history: HistoryContext) -> None:
    if history.identity_cluster_mismatch:
        findings.append(
            RiskFinding(
                "device_graph",
                "identity_cluster_mismatch",
                4.0,
                "Verified device identity maps to a different stable cluster.",
                history.as_dict(),
            )
        )

    if history.stable_hash_cluster_count >= 5:
        findings.append(
            RiskFinding(
                "device_graph",
                "stable_fingerprint_many_clusters",
                2.5,
                "The same stable fingerprint appears across many clusters.",
                history.as_dict(),
            )
        )

    if history.matching_cluster_instance_count >= 5:
        findings.append(
            RiskFinding(
                "device_graph",
                "cluster_many_device_identities",
                2.0,
                "One stable cluster has many device identities.",
                history.as_dict(),
            )
        )

    if history.ip_prefix_new_clusters_24h >= 20:
        findings.append(
            RiskFinding(
                "network_request",
                "ip_prefix_high_new_cluster_velocity",
                2.5,
                "This IP prefix recently created many new device clusters.",
                history.as_dict(),
            )
        )
    elif history.ip_prefix_new_clusters_24h >= 5:
        findings.append(
            RiskFinding(
                "network_request",
                "ip_prefix_elevated_new_cluster_velocity",
                1.2,
                "This IP prefix recently created several new device clusters.",
                history.as_dict(),
            )
        )

    if history.device_request_count_24h >= 500:
        findings.append(
            RiskFinding(
                "history_velocity",
                "device_high_request_velocity",
                2.0,
                "This device identity has unusually high request velocity.",
                history.as_dict(),
            )
        )

def _cloud_phone_findings(findings: list[RiskFinding], flat: dict[str, Any], features: FeatureSnapshot, history: HistoryContext) -> None:
    battery = _str(flat.get("FP_BATTERY")) or ""
    battery_lower = battery.lower()
    if "level=100" in battery_lower and ("plugged=1" in battery_lower or "charging" in battery_lower):
        findings.append(
            RiskFinding(
                "cloud_phone_pattern",
                "always_full_charging_battery",
                0.8,
                "Battery state resembles an always-powered hosted device.",
                {"battery": battery[:160]},
            )
        )

    if history.ip_prefix_new_clusters_24h >= 5 and features.widevine_level == "L1" and history.stable_hash_cluster_count >= 3:
        findings.append(
            RiskFinding(
                "cloud_phone_pattern",
                "genuine_profile_high_prefix_velocity",
                1.5,
                "Genuine-looking hardware profile appears with high prefix velocity.",
                history.as_dict(),
            )
        )

def _negative_findings(
    findings: list[RiskFinding],
    identity: DeviceIdentity,
    flat: dict[str, Any],
    history: HistoryContext,
    attestation: AttestationDetails,
) -> None:
    if identity.status == "ok" and identity.signature_verified:
        findings.append(
            RiskFinding(
                "attestation",
                "keystore_signature_verified",
                -1.0,
                "Keystore challenge signature verified.",
                {"cert_count": identity.cert_count},
            )
        )
    if _str(flat.get("FP_WIDEVINE_SECURITY_LEVEL")) == "L1":
        findings.append(
            RiskFinding(
                "hardware_coherence",
                "widevine_l1",
                -0.4,
                "Widevine reports L1.",
                {},
            )
        )
    if attestation.attestation_security_level in {"TrustedEnvironment", "StrongBox"}:
        findings.append(
            RiskFinding(
                "attestation",
                "hardware_key_attestation",
                -1.0,
                "Key attestation reports hardware-backed security level.",
                {"attestation_security_level": attestation.attestation_security_level},
            )
        )
    if history.device_seen_count >= 3:
        findings.append(
            RiskFinding(
                "device_graph",
                "known_stable_device_identity",
                -0.8,
                "Verified device identity has stable prior history.",
                history.as_dict(),
            )
        )
    elif history.cluster_seen_count >= 3:
        findings.append(
            RiskFinding(
                "device_graph",
                "known_stable_device_cluster",
                -0.4,
                "Device cluster has stable prior history.",
                history.as_dict(),
            )
        )

def _family_scores(findings: list[RiskFinding]) -> dict[str, float]:
    raw: dict[str, float] = {}
    for finding in findings:
        raw[finding.family] = raw.get(finding.family, 0.0) + finding.weight

    scores: dict[str, float] = {}
    for family, value in raw.items():
        cap = FAMILY_CAPS.get(family, 4.0)
        scores[family] = round(min(max(value, -cap), cap), 2)
    return scores

def _reason_codes(findings: list[RiskFinding]) -> list[str]:
    return sorted({finding.code for finding in findings if finding.weight > 0})

def _missing(flat: dict[str, Any]) -> list[str]:
    required = (
        "BUILD_FINGERPRINT",
        "BUILD_MODEL",
        "BUILD_MANUFACTURER",
        "BUILD_SUPPORTED_ABIS",
        "SENSORS_COUNT",
        "SENSORS_FULL_REPORT_HASH64",
        "FP_CAMERA_COUNT",
        "FP_WIDEVINE_SECURITY_LEVEL",
        "VULKAN_STATUS",
        "KEY_ATTESTATION_STATUS",
    )
    return [name for name in required if flat.get(name) is None]

def _parse_fingerprint(value: str | None) -> dict[str, str] | None:
    if not value:
        return None
    parts = value.split("/")
    if len(parts) < 4:
        return None
    brand, product, rest = parts[0], parts[1], "/".join(parts[2:])
    device_split = rest.split(":", 1)
    if len(device_split) != 2:
        return None
    device, after_device = device_split
    release_split = after_device.split("/", 2)
    if len(release_split) != 3:
        return None
    release, build_id, after_id = release_split
    incremental_split = after_id.split(":", 1)
    if len(incremental_split) != 2:
        return None
    incremental, after_incremental = incremental_split
    type_split = after_incremental.split("/", 1)
    if len(type_split) != 2:
        return None
    build_type, tags = type_split
    return {
        "brand": brand,
        "product": product,
        "device": device,
        "release": release,
        "id": build_id,
        "incremental": incremental,
        "type": build_type,
        "tags": tags,
    }

def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None

def _hex_value(value: int | None, width: int) -> str | None:
    if value is None:
        return None
    return f"{value:0{width}x}"

def _int_from_any(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None

def _hash64(value: Any) -> str | None:
    return f"{value & 0xFFFFFFFFFFFFFFFF:016x}" if isinstance(value, int) else None
