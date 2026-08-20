import json
import uuid
from dataclasses import dataclass
from typing import Any

from app.protocol.attestation import AttestationDetails
from app.protocol.device_identity import DeviceIdentity
from app.protocol.features import FeatureSnapshot, hash_network_value, ip_prefix, json_dumps
from app.protocol.risk import EmulatorResult, HistoryContext, RiskResult
from app.services.retention import cleanup_expired_records
from app.services.runtime import runtime

@dataclass(frozen=True)
class StoredCheck:
    device_cluster_id: str | None
    feature_snapshot_id: str | None
    stored: bool
    recognition_status: str = "not_stored"
    device_seen_before: bool = False
    cluster_seen_before: bool = False
    match_type: str = "none"

class Persistence:
    async def history_context(
        self,
        *,
        device_identity: DeviceIdentity,
        features: FeatureSnapshot,
        client_ip: str | None,
        user_agent: str | None,
    ) -> HistoryContext:
        if runtime.postgres is None:
            return HistoryContext()

        network_prefix = ip_prefix(client_ip)
        user_agent_hash = hash_network_value(user_agent)
        async with runtime.postgres.acquire() as connection:
            device_row = None
            if device_identity.device_instance_id and device_identity.signature_verified:
                device_row = await connection.fetchrow(
                    """
                    select device_cluster_id, seen_count
                    from device_instances
                    where device_instance_id = $1
                    """,
                    device_identity.device_instance_id,
                )

            stable_rows = await connection.fetch(
                """
                select device_cluster_id, seen_count
                from device_clusters
                where stable_fingerprint_hash = $1 and claimed_model_key = $2
                limit 3
                """,
                features.stable_fingerprint_hash,
                features.claimed_model_key,
            )
            stable_cluster_id = stable_rows[0]["device_cluster_id"] if len(stable_rows) == 1 else None

            stable_count = await connection.fetchval(
                """
                select count(*)
                from device_clusters
                where stable_fingerprint_hash = $1
                """,
                features.stable_fingerprint_hash,
            )
            instance_count = 0
            if stable_cluster_id:
                instance_count = await connection.fetchval(
                    """
                    select count(*)
                    from device_instances
                    where device_cluster_id = $1
                    """,
                    stable_cluster_id,
                )

            ip_new_clusters = 0
            if network_prefix:
                ip_new_clusters = await connection.fetchval(
                    """
                    select count(distinct device_cluster_id)
                    from check_events
                    where ip_prefix = $1
                      and recognition_status = 'new_device_cluster'
                      and created_at > now() - interval '24 hours'
                    """,
                    network_prefix,
                )

            user_agent_new_clusters = 0
            if user_agent_hash:
                user_agent_new_clusters = await connection.fetchval(
                    """
                    select count(distinct device_cluster_id)
                    from check_events
                    where user_agent_hash = $1
                      and recognition_status = 'new_device_cluster'
                      and created_at > now() - interval '24 hours'
                    """,
                    user_agent_hash,
                )

            device_requests = 0
            if device_identity.device_instance_id and device_identity.signature_verified:
                device_requests = await connection.fetchval(
                    """
                    select count(*)
                    from check_events
                    where device_instance_id = $1
                      and created_at > now() - interval '24 hours'
                    """,
                    device_identity.device_instance_id,
                )

        device_cluster_id = device_row["device_cluster_id"] if device_row else None
        return HistoryContext(
            device_seen_count=int(device_row["seen_count"]) if device_row else 0,
            cluster_seen_count=int(stable_rows[0]["seen_count"]) if len(stable_rows) == 1 else 0,
            stable_hash_cluster_count=int(stable_count or 0),
            matching_cluster_instance_count=int(instance_count or 0),
            ip_prefix_new_clusters_24h=int(ip_new_clusters or 0),
            user_agent_new_clusters_24h=int(user_agent_new_clusters or 0),
            device_request_count_24h=int(device_requests or 0),
            identity_cluster_mismatch=bool(device_cluster_id and stable_cluster_id and device_cluster_id != stable_cluster_id),
        )

    async def store_check(
        self,
        *,
        request_id: str,
        app_version: str,
        client_time: int,
        payload_hash: str,
        payload_size: int,
        summary: dict[str, Any],
        device_identity: DeviceIdentity,
        features: FeatureSnapshot,
        attestation: AttestationDetails,
        history: HistoryContext,
        risk: RiskResult,
        emulator: EmulatorResult,
        decision: str,
        reasons: list[str],
        client_ip: str | None,
        user_agent: str | None,
    ) -> StoredCheck:
        if runtime.postgres is None:
            return StoredCheck(None, None, False)

        async with runtime.postgres.acquire() as connection:
            async with connection.transaction():
                recognition = await self._resolve_cluster(connection, device_identity, features, risk)
                cluster_id = recognition.device_cluster_id
                if device_identity.device_instance_id and device_identity.signature_verified:
                    await self._upsert_instance(connection, device_identity, cluster_id, risk)

                snapshot_id = str(uuid.uuid4())
                await connection.execute(
                    """
                    insert into device_feature_snapshots (
                        feature_snapshot_id,
                        device_cluster_id,
                        device_instance_id,
                        schema_version,
                        app_package,
                        app_version,
                        build_model,
                        build_manufacturer,
                        build_product,
                        build_device,
                        build_sdk,
                        build_release,
                        first_api_level,
                        abi_family,
                        soc_model,
                        soc_manufacturer,
                        gl_vendor,
                        gl_renderer,
                        vulkan_status,
                        vulkan_device_count,
                        sensors_count,
                        sensors_inventory_hash64,
                        camera_count,
                        camera_characteristics_hash64,
                        display_modes_hash64,
                        widevine_level,
                        widevine_id_hash64,
                        android_id_hash,
                        stable_features,
                        profile_features,
                        volatile_features
                    )
                    values (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                        $21, $22, $23, $24, $25, $26, $27, $28,
                        $29::jsonb, $30::jsonb, $31::jsonb
                    )
                    """,
                    snapshot_id,
                    cluster_id,
                    device_identity.device_instance_id if device_identity.signature_verified else None,
                    features.schema_version,
                    features.app_package,
                    features.app_version,
                    features.build_model,
                    features.build_manufacturer,
                    features.build_product,
                    features.build_device,
                    features.build_sdk,
                    features.build_release,
                    features.first_api_level,
                    features.abi_family,
                    features.soc_model,
                    features.soc_manufacturer,
                    features.gl_vendor,
                    features.gl_renderer,
                    features.vulkan_status,
                    features.vulkan_device_count,
                    features.sensors_count,
                    _hash64_text(features.sensors_inventory_hash64),
                    features.camera_count,
                    _hash64_text(features.camera_characteristics_hash64),
                    _hash64_text(features.display_modes_hash64),
                    features.widevine_level,
                    _hash64_text(features.widevine_id_hash64),
                    features.android_id_hash,
                    json_dumps(features.stable_features),
                    json_dumps(features.profile_features),
                    json_dumps(features.volatile_features),
                )

                await connection.execute(
                    """
                    insert into check_events (
                        request_id,
                        device_cluster_id,
                        device_instance_id,
                        feature_snapshot_id,
                        app_version,
                        client_time,
                        payload_hash,
                        payload_size,
                        schema_version,
                        field_count,
                        decode_status,
                        decision,
                        reasons,
                        ip_hash,
                        ip_prefix,
                        user_agent_hash,
                        identity_status,
                        signature_verified,
                        risk_score,
                        risk_decision,
                        risk_findings,
                        risk_family_scores,
                        risk_reason_codes,
                        missing_signals,
                        emulator_score,
                        emulator_classification,
                        emulator_is_emulator,
                        emulator_confidence,
                        emulator_factors,
                        emulator_reason_codes,
                        attestation_details,
                        history_signals,
                        coherence_signals,
                        recognition_status,
                        device_seen_before,
                        cluster_seen_before,
                        match_type,
                        summary
                    )
                    values (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13::jsonb, $14, $15, $16, $17, $18,
                        $19, $20, $21::jsonb, $22::jsonb, $23::jsonb, $24::jsonb,
                        $25, $26, $27, $28, $29::jsonb, $30::jsonb, $31::jsonb,
                        $32::jsonb, $33::jsonb, $34, $35, $36, $37, $38::jsonb
                    )
                    """,
                    request_id,
                    cluster_id,
                    device_identity.device_instance_id if device_identity.signature_verified else None,
                    snapshot_id,
                    app_version,
                    client_time,
                    payload_hash,
                    payload_size,
                    summary.get("schema"),
                    summary.get("field_count"),
                    "ok",
                    decision,
                    json.dumps(reasons),
                    hash_network_value(client_ip),
                    ip_prefix(client_ip),
                    hash_network_value(user_agent),
                    device_identity.status,
                    device_identity.signature_verified,
                    risk.score,
                    risk.decision,
                    json_dumps([finding.as_dict() for finding in risk.findings]),
                    json_dumps(risk.family_scores),
                    json_dumps(risk.reason_codes),
                    json_dumps(risk.missing_signals),
                    emulator.score,
                    emulator.classification,
                    emulator.is_emulator,
                    emulator.confidence,
                    json_dumps(emulator.as_dict()),
                    json_dumps(emulator.reason_codes),
                    json_dumps(attestation.as_dict()),
                    json_dumps(history.as_dict()),
                    json_dumps(_coherence_signals(risk)),
                    recognition.recognition_status,
                    recognition.device_seen_before,
                    recognition.cluster_seen_before,
                    recognition.match_type,
                    json_dumps(summary),
                )

                await cleanup_expired_records(connection)
                return StoredCheck(
                    cluster_id,
                    snapshot_id,
                    True,
                    recognition.recognition_status,
                    recognition.device_seen_before,
                    recognition.cluster_seen_before,
                    recognition.match_type,
                )

    async def _resolve_cluster(self, connection: Any, identity: DeviceIdentity, features: FeatureSnapshot, risk: RiskResult) -> StoredCheck:
        if identity.device_instance_id and identity.signature_verified:
            row = await connection.fetchrow(
                "select device_cluster_id from device_instances where device_instance_id = $1",
                identity.device_instance_id,
            )
            if row:
                cluster_id = row["device_cluster_id"]
                await self._touch_cluster(connection, cluster_id, risk)
                return StoredCheck(cluster_id, None, True, "known_device_instance", True, True, "keystore")

        rows = await connection.fetch(
            """
            select device_cluster_id
            from device_clusters
            where stable_fingerprint_hash = $1 and claimed_model_key = $2
            limit 2
            """,
            features.stable_fingerprint_hash,
            features.claimed_model_key,
        )
        if len(rows) == 1:
            cluster_id = rows[0]["device_cluster_id"]
            await self._touch_cluster(connection, cluster_id, risk)
            return StoredCheck(cluster_id, None, True, "known_device_cluster", False, True, "stable_fingerprint")

        cluster_id = str(uuid.uuid4())
        await connection.execute(
            """
            insert into device_clusters (
                device_cluster_id,
                stable_fingerprint_hash,
                claimed_model_key,
                seen_count,
                last_risk_score,
                last_risk_decision
            )
            values ($1, $2, $3, 1, $4, $5)
            """,
            cluster_id,
            features.stable_fingerprint_hash,
            features.claimed_model_key,
            risk.score,
            risk.decision,
        )
        return StoredCheck(cluster_id, None, True, "new_device_cluster", False, False, "new_cluster")

    async def _upsert_instance(self, connection: Any, identity: DeviceIdentity, cluster_id: str, risk: RiskResult) -> None:
        await connection.execute(
            """
            insert into device_instances (
                device_instance_id,
                device_cluster_id,
                public_key_sha256,
                leaf_cert_sha256,
                cert_count,
                signature_verified,
                attestation_status,
                seen_count,
                last_risk_score,
                last_risk_decision
            )
            values ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9)
            on conflict (device_instance_id) do update set
                device_cluster_id = excluded.device_cluster_id,
                public_key_sha256 = excluded.public_key_sha256,
                leaf_cert_sha256 = excluded.leaf_cert_sha256,
                cert_count = excluded.cert_count,
                signature_verified = excluded.signature_verified,
                attestation_status = excluded.attestation_status,
                last_risk_score = excluded.last_risk_score,
                last_risk_decision = excluded.last_risk_decision,
                last_seen_at = now(),
                seen_count = device_instances.seen_count + 1
            """,
            identity.device_instance_id,
            cluster_id,
            identity.public_key_sha256,
            identity.leaf_cert_sha256,
            identity.cert_count,
            identity.signature_verified,
            identity.status,
            risk.score,
            risk.decision,
        )

    async def _touch_cluster(self, connection: Any, cluster_id: str, risk: RiskResult) -> None:
        await connection.execute(
            """
            update device_clusters
            set last_seen_at = now(),
                seen_count = seen_count + 1,
                last_risk_score = $2,
                last_risk_decision = $3
            where device_cluster_id = $1
            """,
            cluster_id,
            risk.score,
            risk.decision,
        )

def _hash64_text(value: int | None) -> str | None:
    if value is None:
        return None
    return f"{value & 0xFFFFFFFFFFFFFFFF:016x}"

def _coherence_signals(risk: RiskResult) -> dict[str, object]:
    families = {
        finding.family
        for finding in risk.findings
        if finding.weight > 0 and finding.family.endswith("_coherence")
    }
    return {
        "families": sorted(families),
        "reason_codes": [
            finding.code
            for finding in risk.findings
            if finding.weight > 0 and finding.family.endswith("_coherence")
        ],
    }

persistence = Persistence()
