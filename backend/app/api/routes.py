import base64
import hashlib
import ipaddress
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from app.core.config import settings
from app.core.ids import new_request_id
from app.protocol.attestation import derive_attestation_details
from app.protocol.cipher import parse_header, unseal
from app.protocol.device_identity import derive_device_identity
from app.protocol.errors import DecodeError
from app.protocol.features import extract_feature_snapshot
from app.protocol.risk import HistoryContext, classify_emulator, classify_environment, evaluate_risk
from app.protocol.summary import payload_hash, summarize
from app.services.challenges import ChallengeStoreUnavailable, challenges
from app.services.persistence import persistence
from app.services.rate_limit import rate_limiter
from app.services.runtime import runtime
from app.services.stats import stats

router = APIRouter()
logger = logging.getLogger("devicecheck.api")

class CheckRequest(BaseModel):
    app_version: str
    time: int
    attestation: str

@router.get("/health")
async def health() -> dict[str, str]:
    return await runtime.health()

@router.get("/challenge")
async def challenge(request: Request) -> dict[str, object]:
    rate = await rate_limiter.allow("challenge", _client_ip(request), settings.challenge_rate_limit_per_minute)
    if not rate.allowed:
        await stats.increment("challenges_rate_limited")
        raise HTTPException(status_code=429, detail="rate limited", headers={"Retry-After": str(rate.retry_after)})

    await stats.increment("challenges_issued")
    try:
        return await challenges.issue()
    except ChallengeStoreUnavailable:
        raise HTTPException(status_code=503, detail="challenge store unavailable")

@router.post("/check")
async def check(payload: CheckRequest, request: Request, x_app_key: str | None = Header(default=None)) -> dict[str, object]:
    request_id = new_request_id()
    client_ip = _client_ip(request)
    await stats.increment("checks_total")

    rate = await rate_limiter.allow("check", client_ip, settings.check_rate_limit_per_minute)
    if not rate.allowed:
        await stats.increment("checks_rate_limited")
        _log_request_rejected(request_id, request, "rate_limited", {"limit": rate.limit, "count": rate.count})
        raise HTTPException(status_code=429, detail="rate limited", headers={"Retry-After": str(rate.retry_after)})

    if not x_app_key or x_app_key not in settings.app_keys:
        await stats.increment("checks_rejected_app_key")
        _log_request_rejected(request_id, request, "invalid_app_key")
        raise HTTPException(status_code=401, detail="unauthorized")

    try:
        attestation = base64.b64decode(payload.attestation, validate=True)
    except Exception:
        await stats.increment("checks_bad_base64")
        _log_request_rejected(request_id, request, "invalid_base64")
        raise HTTPException(status_code=400, detail="invalid attestation")

    if len(attestation) > settings.max_attestation_bytes:
        await stats.increment("checks_too_large")
        _log_request_rejected(
            request_id,
            request,
            "attestation_too_large",
            {"size": len(attestation), "max_size": settings.max_attestation_bytes},
        )
        raise HTTPException(status_code=413, detail="attestation too large")

    try:
        header = parse_header(attestation)
    except DecodeError:
        await stats.increment("checks_bad_header")
        _log_request_rejected(request_id, request, "invalid_header", {"payload_hash": payload_hash(attestation)})
        raise HTTPException(status_code=400, detail="invalid attestation")

    challenge = await challenges.consume(header.challenge_hash)
    if challenge is None:
        await stats.increment("checks_challenge_missing")
        await stats.increment_dimension("decisions", "deny")
        _log_request_rejected(request_id, request, "challenge_missing_or_replayed", {"challenge_hash": header.challenge_hash.hex()})
        return _client_response(
            request_id=request_id,
            device_instance_id=None,
            device_cluster_id=None,
            environment={
                "status": "abnormal",
                "title": "Abnormal environment",
                "message": "The device check could not be verified.",
            },
            recognition=None,
            history=None,
        )

    try:
        decoded = unseal(attestation, challenge)
        summary = summarize(decoded.records)
        device_identity = derive_device_identity(decoded.records, challenge)
        attestation_details = derive_attestation_details(decoded.records, challenge)
        features = extract_feature_snapshot(decoded.records)
    except DecodeError as error:
        await stats.increment("checks_decode_failed")
        await stats.increment_dimension("decoder_status", "failed")
        logger.info("check_decode_failed", extra={"extra": {"request_id": request_id, "error": str(error), "payload_hash": payload_hash(attestation)}})
        raise HTTPException(status_code=400, detail="invalid attestation")

    if features.app_package != settings.expected_package_name:
        await stats.increment("checks_rejected_package")
        await stats.increment_dimension("decisions", "deny")
        logger.warning(
            "check_rejected_package",
            extra={
                "extra": {
                    "request_id": request_id,
                    "reason": "package_mismatch",
                    "package": features.app_package,
                    "expected_package": settings.expected_package_name,
                }
            },
        )
        raise HTTPException(status_code=403, detail="invalid package")

    try:
        history = await persistence.history_context(
            device_identity=device_identity,
            features=features,
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent"),
        )
    except Exception as error:
        history = HistoryContext()
        logger.warning("history_context_failed", extra={"extra": {"request_id": request_id, "error": str(error)}})

    risk = evaluate_risk(decoded.records, device_identity, features, attestation_details, history)
    emulator = classify_emulator(risk)
    environment = classify_environment(risk, emulator)

    await stats.increment("checks_decoded")
    await stats.increment_dimension("decoder_status", "ok")

    stored = None
    try:
        stored = await persistence.store_check(
            request_id=request_id,
            app_version=payload.app_version,
            client_time=payload.time,
            payload_hash=payload_hash(attestation),
            payload_size=len(attestation),
            summary=summary,
            device_identity=device_identity,
            features=features,
            attestation=attestation_details,
            history=history,
            risk=risk,
            emulator=emulator,
            decision="allow",
            reasons=["challenge_valid", "payload_decoded"],
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent"),
        )
    except Exception as error:
        await stats.increment("checks_store_failed")
        logger.error("check_store_failed", extra={"extra": {"request_id": request_id, "error": str(error)}})
        raise HTTPException(status_code=503, detail="persistence unavailable")
    await stats.increment_dimension("decisions", "allow")
    await stats.increment_dimension("app_versions", payload.app_version)
    await stats.increment_dimension("risk_decisions", risk.decision)
    await stats.increment_dimension("emulator_classifications", emulator.classification)
    await stats.increment_dimension("environment_statuses", environment.status)
    await stats.increment_dimension("recognition_status", stored.recognition_status if stored else "not_stored")
    for reason_code in risk.reason_codes[:12]:
        await stats.increment_dimension("risk_reason_codes", reason_code)
    for reason_code in emulator.reason_codes[:12]:
        await stats.increment_dimension("emulator_reason_codes", reason_code)

    _log_check_result(
        request_id=request_id,
        request=request,
        app_version=payload.app_version,
        device_instance_id=device_identity.device_instance_id,
        device_cluster_id=stored.device_cluster_id if stored else None,
        risk=risk,
        emulator=emulator,
        environment=environment,
        recognition=_recognition_response(stored),
        identity_status=device_identity.status,
        signature_verified=device_identity.signature_verified,
    )

    return _client_response(
        request_id=request_id,
        device_instance_id=device_identity.device_instance_id,
        device_cluster_id=stored.device_cluster_id if stored else None,
        environment={
            "status": environment.status,
            "title": environment.title,
            "message": environment.message,
        },
        recognition=stored,
        history=history,
    )

def _client_ip(request: Request) -> str | None:
    peer = request.client.host if request.client else None
    if _trusted_proxy_peer(peer):
        forwarded = (
            request.headers.get("cf-connecting-ip")
            or request.headers.get("x-real-ip")
            or request.headers.get("x-forwarded-for")
        )
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return peer

def _trusted_proxy_peer(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
        return address.is_loopback or address.is_private
    except ValueError:
        return False

def _recognition_response(stored: object) -> dict[str, object]:
    if stored is None:
        return {
            "stored": False,
            "status": "not_stored",
            "device_seen_before": False,
            "cluster_seen_before": False,
            "match_type": "none",
        }
    return {
        "stored": stored.stored,
        "status": stored.recognition_status,
        "device_seen_before": stored.device_seen_before,
        "cluster_seen_before": stored.cluster_seen_before,
        "match_type": stored.match_type,
    }

def _client_response(
    request_id: str,
    device_instance_id: str | None,
    device_cluster_id: str | None,
    environment: dict[str, str],
    recognition: object,
    history: HistoryContext | None,
) -> dict[str, object]:
    return {
        "display_identity": {
            "nonce": _display_uuid(request_id),
            "device_id": _display_uuid(device_instance_id),
            "cluster_id": _display_uuid(device_cluster_id),
        },
        "environment": environment,
        "recognition": _client_recognition_response(recognition, history),
    }

def _client_recognition_response(stored: object, history: HistoryContext | None) -> dict[str, bool]:
    recognized = False
    if stored is not None:
        recognized = bool(stored.device_seen_before or stored.cluster_seen_before)
    if history is not None:
        recognized = recognized or history.device_seen_count > 0 or history.cluster_seen_count > 0
    return {"known_device": recognized}

def _display_uuid(value: str | None) -> str | None:
    if not value:
        return None
    digest = hashlib.sha256(value.encode()).digest()[:16].hex()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"

def _log_request_rejected(request_id: str, request: Request, reason: str, evidence: dict[str, object] | None = None) -> None:
    logger.warning(
        "check_rejected",
        extra={
            "extra": {
                "request_id": request_id,
                "nonce": _display_uuid(request_id),
                "client": _client_ip(request),
                "reason": reason,
                "evidence": evidence or {},
            }
        },
    )

def _log_check_result(
    request_id: str,
    request: Request,
    app_version: str,
    device_instance_id: str | None,
    device_cluster_id: str | None,
    risk: object,
    emulator: object,
    environment: object,
    recognition: dict[str, object],
    identity_status: str,
    signature_verified: bool,
) -> None:
    abnormal = (
        risk.decision != "low_risk"
        or environment.status != "normal"
        or identity_status != "ok"
        or not signature_verified
    )

    extra = {
        "request_id": request_id,
        "nonce": _display_uuid(request_id),
        "client": _client_ip(request),
        "app_version": app_version,
        "device_id": _display_uuid(device_instance_id),
        "cluster_id": _display_uuid(device_cluster_id),
        "risk_decision": risk.decision,
        "risk_reason_codes": risk.reason_codes,
        "emulator_classification": emulator.classification,
        "emulator_is_emulator": emulator.is_emulator,
        "emulator_reason_codes": emulator.reason_codes,
        "environment_status": environment.status,
        "environment_reason_codes": environment.reason_codes,
        "recognition": recognition,
        "identity_status": identity_status,
        "signature_verified": signature_verified,
    }

    if abnormal:
        extra["risk_findings"] = [
            _compact_finding(finding)
            for finding in risk.findings
            if finding.weight > 0
        ]
        extra["app_integrity_failures"] = [
            _compact_finding(finding)
            for finding in risk.findings
            if finding.family == "app_integrity" and finding.weight > 0
        ]

    logger.info(
        "check_result",
        extra={
            "extra": extra
        },
    )

def _compact_finding(finding: object) -> dict[str, object]:
    return {
        "family": finding.family,
        "code": finding.code,
        "weight": finding.weight,
        "message": finding.message,
        "evidence": _compact_value(finding.evidence),
    }

def _compact_value(value: object, depth: int = 0) -> object:
    if isinstance(value, str):
        return value if len(value) <= 160 else f"{value[:157]}..."
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= 4:
        return "<nested>"
    if isinstance(value, dict):
        items = list(value.items())[:16]
        compact = {str(key): _compact_value(item, depth + 1) for key, item in items}
        if len(value) > len(items):
            compact["truncated"] = len(value) - len(items)
        return compact
    if isinstance(value, list):
        items = value[:16]
        compact = [_compact_value(item, depth + 1) for item in items]
        if len(value) > len(items):
            compact.append({"truncated": len(value) - len(items)})
        return compact
    return value
