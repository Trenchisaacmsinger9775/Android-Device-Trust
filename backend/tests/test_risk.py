from app.protocol.attestation import AttestationDetails
from app.protocol.codec import TYPE_STRING, TYPE_UINT64, Record
from app.core.config import settings
from app.protocol.device_identity import DeviceIdentity
from app.protocol.features import extract_feature_snapshot
from app.protocol.risk import HistoryContext, classify_emulator, classify_environment, evaluate_risk

def test_single_family_cannot_classify_likely_emulator() -> None:
    risk = evaluate_risk(
        _records(
            BUILD_FINGERPRINT="bad",
            BUILD_BRAND="other",
            BUILD_PRODUCT="product",
            BUILD_DEVICE="device",
            BUILD_RELEASE="15",
            BUILD_ID="AP1A",
            BUILD_INCREMENTAL="1",
            BUILD_TYPE="user",
            BUILD_TAGS="release-keys",
            BUILD_SDK=35,
            PROCESS_API_LEVEL=29,
            PROP_FIRST_API_LEVEL="40",
            FP_WIDEVINE_SECURITY_LEVEL="L1",
            KEY_ATTESTATION_STATUS=0,
        ),
        _verified_identity(),
        _features(),
        _hardware_attestation(),
    )

    emulator = classify_emulator(risk)
    environment = classify_environment(risk, emulator)

    assert risk.family_scores["build_coherence"] == 4.5
    assert emulator.classification == "no_emulator_signal"
    assert not emulator.is_emulator
    assert environment.status == "modified_environment"

def test_emulator_requires_correlated_families() -> None:
    records = _records(
        BUILD_FINGERPRINT="bad",
        BUILD_BRAND="other",
        BUILD_PRODUCT="product",
        BUILD_DEVICE="device",
        BUILD_RELEASE="15",
        BUILD_ID="AP1A",
        BUILD_INCREMENTAL="1",
        BUILD_TYPE="user",
        BUILD_TAGS="release-keys",
        BUILD_SDK=35,
        PROCESS_API_LEVEL=35,
        PROP_CPU_ABILIST="arm64-v8a,x86_64",
        VULKAN_STATUS=0,
        VULKAN_DEVICE_TYPES="cpu",
        SENSORS_COUNT=1,
        FP_CAMERA_COUNT=0,
        FP_WIDEVINE_SECURITY_LEVEL="L3",
        KEY_ATTESTATION_STATUS=0,
    )
    risk = evaluate_risk(records, _missing_identity(), extract_feature_snapshot(records), _software_attestation())

    emulator = classify_emulator(risk)
    environment = classify_environment(risk, emulator)

    assert risk.decision == "high_risk"
    assert emulator.classification == "likely_emulator"
    assert emulator.is_emulator
    assert environment.status == "emulator"
    assert "mixed_arm_x86_abis" in emulator.reason_codes

def test_media_and_attestation_signals_are_modified_not_emulator() -> None:
    records = _records(
        BUILD_FINGERPRINT="Google/pixel/pixel:15/AP1A/123:user/release-keys",
        BUILD_BRAND="Google",
        BUILD_PRODUCT="pixel",
        BUILD_DEVICE="pixel",
        BUILD_RELEASE="15",
        BUILD_ID="AP1A",
        BUILD_INCREMENTAL="123",
        BUILD_TYPE="user",
        BUILD_TAGS="release-keys",
        BUILD_SDK=35,
        PROCESS_API_LEVEL=35,
        SENSORS_COUNT=20,
        FP_CAMERA_COUNT=0,
        FP_WIDEVINE_SECURITY_LEVEL="L3",
        KEY_ATTESTATION_STATUS=1,
    )
    risk = evaluate_risk(records, _verified_identity(), extract_feature_snapshot(records), AttestationDetails("missing_extension"))

    emulator = classify_emulator(risk)
    environment = classify_environment(risk, emulator)

    assert emulator.classification == "no_emulator_signal"
    assert not emulator.is_emulator
    assert environment.status == "modified_environment"
    assert "widevine_not_l1" in risk.reason_codes
    assert "widevine_not_l1" not in environment.reason_codes
    assert "native_attestation_failed" in risk.reason_codes
    assert "native_attestation_failed" not in environment.reason_codes

def test_attestation_app_identity_mismatch_is_modified_not_emulator() -> None:
    records = _records(
        APP_PACKAGE="com.reveny.devicecheck",
        APP_SIGNERS_DIGEST64=0x65096e6741eae4ef,
        INTEGRITY_TEXT_CRC32=0xb87251ba,
    )
    attestation = AttestationDetails(
        status="ok",
        attestation_security_level="TrustedEnvironment",
        keymaster_security_level="TrustedEnvironment",
        root_of_trust_present=True,
        device_locked=True,
        verified_boot_state="Verified",
        verified_boot_hash_present=True,
        app_id_present=True,
        app_id_package_match=True,
        app_id_signature_match=False,
        chain_verified=True,
        root_trusted=True,
    )
    risk = evaluate_risk(records, _verified_identity(), extract_feature_snapshot(records), attestation)

    emulator = classify_emulator(risk)
    environment = classify_environment(risk, emulator)

    assert not emulator.is_emulator
    assert environment.status == "modified_environment"
    assert "attestation_app_signature_mismatch" in environment.reason_codes

def test_key_attestation_failure_is_risk_context_only() -> None:
    records = _records(
        BUILD_FINGERPRINT="Google/pixel/pixel:15/AP1A/123:user/release-keys",
        BUILD_BRAND="Google",
        BUILD_PRODUCT="pixel",
        BUILD_DEVICE="pixel",
        BUILD_RELEASE="15",
        BUILD_ID="AP1A",
        BUILD_INCREMENTAL="123",
        BUILD_TYPE="user",
        BUILD_TAGS="release-keys",
        BUILD_SDK=35,
        PROCESS_API_LEVEL=35,
        SENSORS_COUNT=20,
        SENSORS_INVENTORY_HASH64=123,
        FP_CAMERA_COUNT=2,
        FP_CAMERA_CHARACTERISTICS_HASH64=456,
        KEY_ATTESTATION_STATUS=1,
    )
    risk = evaluate_risk(records, _missing_identity(), extract_feature_snapshot(records), _software_attestation())

    emulator = classify_emulator(risk)
    environment = classify_environment(risk, emulator)

    assert "missing_cert_chain" in risk.reason_codes
    assert "native_attestation_failed" in risk.reason_codes
    assert "software_key_attestation" in risk.reason_codes
    assert "verified_boot_unlocked" in risk.reason_codes
    assert "verified_boot_not_verified" in risk.reason_codes
    assert environment.status == "normal"
    assert environment.reason_codes == []

def test_user_agent_velocity_is_not_a_risk_finding() -> None:
    records = _records(KEY_ATTESTATION_STATUS=0)
    risk = evaluate_risk(
        records,
        _verified_identity(),
        extract_feature_snapshot(records),
        _hardware_attestation(),
        HistoryContext(user_agent_new_clusters_24h=100),
    )

    assert "user_agent_high_new_cluster_velocity" not in risk.reason_codes

def test_stable_history_and_hardware_attestation_are_protective() -> None:
    records = _records(
        BUILD_FINGERPRINT="Google/pixel/pixel:15/AP1A/123:user/release-keys",
        BUILD_BRAND="Google",
        BUILD_PRODUCT="pixel",
        BUILD_DEVICE="pixel",
        BUILD_RELEASE="15",
        BUILD_ID="AP1A",
        BUILD_INCREMENTAL="123",
        BUILD_TYPE="user",
        BUILD_TAGS="release-keys",
        BUILD_MODEL="Pixel",
        BUILD_MANUFACTURER="Google",
        BUILD_SDK=35,
        PROCESS_API_LEVEL=35,
        SENSORS_COUNT=20,
        SENSORS_INVENTORY_HASH64=123,
        FP_CAMERA_COUNT=2,
        FP_CAMERA_CHARACTERISTICS_HASH64=456,
        FP_WIDEVINE_SECURITY_LEVEL="L1",
        KEY_ATTESTATION_STATUS=0,
    )

    risk = evaluate_risk(
        records,
        _verified_identity(),
        extract_feature_snapshot(records),
        _hardware_attestation(),
        HistoryContext(device_seen_count=8, cluster_seen_count=8),
    )

    assert risk.decision == "low_risk"
    assert risk.score == 0
    assert risk.reason_codes == []

def test_coarse_dicts_do_not_expose_weights_or_evidence() -> None:
    records = _records(BUILD_FINGERPRINT="bad", KEY_ATTESTATION_STATUS=1)
    risk = evaluate_risk(records, _missing_identity(), extract_feature_snapshot(records), AttestationDetails("missing_extension"))
    emulator = classify_emulator(risk)

    assert "score" not in risk.coarse_dict()
    assert "findings" not in risk.coarse_dict()
    assert "score" not in emulator.coarse_dict()
    assert "factors" not in emulator.coarse_dict()
    assert "reason_codes" in emulator.coarse_dict()

def test_app_integrity_mismatch_is_abnormal() -> None:
    original_expected = settings.expected_text_crc32
    object.__setattr__(settings, "expected_text_crc32", {0x9999})
    records = _records(
        APP_PACKAGE="com.reveny.devicecheck",
        APP_SIGNERS_DIGEST64=0x1111,
        INTEGRITY_TEXT_CRC32=0x3333,
        KEY_ATTESTATION_STATUS=0,
    )

    try:
        risk = evaluate_risk(records, _verified_identity(), extract_feature_snapshot(records), _hardware_attestation())
        emulator = classify_emulator(risk)
        environment = classify_environment(risk, emulator)

        assert environment.status == "abnormal"
        assert "app_signature_mismatch" in risk.reason_codes
        assert "native_text_crc_mismatch" in risk.reason_codes
        evidence = {finding.code: finding.evidence for finding in risk.findings if finding.family == "app_integrity"}
        assert evidence["app_signature_mismatch"]["observed"] == "0000000000001111"
        assert evidence["native_text_crc_mismatch"]["observed"] == "00003333"
    finally:
        object.__setattr__(settings, "expected_text_crc32", original_expected)

def _records(**values: object) -> list[Record]:
    records: list[Record] = []
    for name, value in values.items():
        record_type = TYPE_UINT64 if isinstance(value, int) else TYPE_STRING
        records.append(Record(name, b"", record_type, 0, b"", value))
    return records

def _features():
    return extract_feature_snapshot(_records())

def _verified_identity() -> DeviceIdentity:
    return DeviceIdentity(
        device_instance_id="device-instance",
        status="ok",
        public_key_sha256="00",
        leaf_cert_sha256="11",
        cert_count=2,
        signature_verified=True,
    )

def _missing_identity() -> DeviceIdentity:
    return DeviceIdentity(None, "missing_cert_chain")

def _hardware_attestation() -> AttestationDetails:
    return AttestationDetails(
        status="ok",
        attestation_security_level="TrustedEnvironment",
        keymaster_security_level="TrustedEnvironment",
        root_of_trust_present=True,
        device_locked=True,
        verified_boot_state="Verified",
        verified_boot_hash_present=True,
        app_id_present=True,
        app_id_package_match=True,
        app_id_signature_match=True,
        chain_verified=True,
        root_trusted=True,
    )

def _software_attestation() -> AttestationDetails:
    return AttestationDetails(
        status="ok",
        attestation_security_level="Software",
        keymaster_security_level="Software",
        root_of_trust_present=True,
        device_locked=False,
        verified_boot_state="Unverified",
    )
