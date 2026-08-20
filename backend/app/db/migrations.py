import logging

import asyncpg

logger = logging.getLogger("devicecheck.migrations")
MIGRATION_LOCK_ID = 0x5D3C11E

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        create table if not exists schema_migrations (
            version integer primary key,
            applied_at timestamptz not null default now()
        );

        create table if not exists device_clusters (
            device_cluster_id text primary key,
            stable_fingerprint_hash text not null,
            claimed_model_key text not null,
            first_seen_at timestamptz not null default now(),
            last_seen_at timestamptz not null default now(),
            seen_count bigint not null default 0,
            match_version integer not null default 1
        );

        create index if not exists idx_device_clusters_match
            on device_clusters (stable_fingerprint_hash, claimed_model_key);

        create table if not exists device_instances (
            device_instance_id text primary key,
            device_cluster_id text not null references device_clusters(device_cluster_id),
            public_key_sha256 text,
            leaf_cert_sha256 text,
            cert_count integer not null default 0,
            signature_verified boolean not null default false,
            attestation_status text not null,
            first_seen_at timestamptz not null default now(),
            last_seen_at timestamptz not null default now(),
            seen_count bigint not null default 0
        );

        create index if not exists idx_device_instances_cluster
            on device_instances (device_cluster_id);

        create table if not exists device_feature_snapshots (
            feature_snapshot_id text primary key,
            device_cluster_id text not null references device_clusters(device_cluster_id),
            device_instance_id text references device_instances(device_instance_id),
            created_at timestamptz not null default now(),
            schema_version integer,
            app_package text,
            app_version text,
            build_model text,
            build_manufacturer text,
            build_product text,
            build_device text,
            build_sdk bigint,
            build_release text,
            first_api_level text,
            abi_family text,
            soc_model text,
            soc_manufacturer text,
            gl_vendor text,
            gl_renderer text,
            vulkan_status bigint,
            vulkan_device_count bigint,
            sensors_count bigint,
            sensors_inventory_hash64 text,
            camera_count bigint,
            camera_characteristics_hash64 text,
            display_modes_hash64 text,
            widevine_level text,
            widevine_id_hash64 text,
            android_id_hash text,
            stable_features jsonb not null,
            profile_features jsonb not null,
            volatile_features jsonb not null
        );

        create index if not exists idx_feature_snapshots_cluster_created
            on device_feature_snapshots (device_cluster_id, created_at desc);

        create table if not exists check_events (
            request_id text primary key,
            created_at timestamptz not null default now(),
            device_cluster_id text references device_clusters(device_cluster_id),
            device_instance_id text references device_instances(device_instance_id),
            feature_snapshot_id text references device_feature_snapshots(feature_snapshot_id),
            app_version text,
            client_time bigint,
            payload_hash text not null,
            payload_size integer not null,
            schema_version integer,
            field_count integer,
            decode_status text not null,
            decision text not null,
            reasons jsonb not null,
            ip_hash text,
            ip_prefix text,
            user_agent_hash text,
            identity_status text,
            signature_verified boolean not null default false,
            summary jsonb not null
        );

        create index if not exists idx_check_events_cluster_created
            on check_events (device_cluster_id, created_at desc);

        create index if not exists idx_check_events_created
            on check_events (created_at desc);
        """,
    ),
    (
        2,
        """
        alter table check_events
            add column if not exists risk_score double precision,
            add column if not exists risk_decision text,
            add column if not exists risk_findings jsonb,
            add column if not exists risk_family_scores jsonb,
            add column if not exists risk_reason_codes jsonb,
            add column if not exists missing_signals jsonb,
            add column if not exists emulator_score double precision,
            add column if not exists emulator_classification text,
            add column if not exists emulator_is_emulator boolean,
            add column if not exists emulator_confidence text,
            add column if not exists emulator_factors jsonb,
            add column if not exists emulator_reason_codes jsonb,
            add column if not exists attestation_details jsonb,
            add column if not exists history_signals jsonb,
            add column if not exists coherence_signals jsonb,
            add column if not exists recognition_status text,
            add column if not exists device_seen_before boolean,
            add column if not exists cluster_seen_before boolean,
            add column if not exists match_type text;

        alter table device_clusters
            add column if not exists last_risk_score double precision,
            add column if not exists last_risk_decision text;

        alter table device_instances
            add column if not exists last_risk_score double precision,
            add column if not exists last_risk_decision text;

        create index if not exists idx_check_events_recognition
            on check_events (recognition_status);

        create index if not exists idx_check_events_risk
            on check_events (risk_decision, risk_score);

        create index if not exists idx_check_events_emulator
            on check_events (emulator_classification, emulator_score);
        """,
    ),
    (
        3,
        """
        alter table check_events
            add column if not exists emulator_score double precision,
            add column if not exists emulator_classification text,
            add column if not exists emulator_is_emulator boolean,
            add column if not exists emulator_confidence text,
            add column if not exists emulator_factors jsonb,
            add column if not exists emulator_reason_codes jsonb;

        create index if not exists idx_check_events_emulator
            on check_events (emulator_classification, emulator_score);
        """,
    ),
    (
        4,
        """
        alter table check_events
            add column if not exists risk_family_scores jsonb,
            add column if not exists risk_reason_codes jsonb,
            add column if not exists emulator_reason_codes jsonb,
            add column if not exists attestation_details jsonb,
            add column if not exists history_signals jsonb,
            add column if not exists coherence_signals jsonb;

        create index if not exists idx_check_events_risk_reason_codes
            on check_events using gin (risk_reason_codes);

        create index if not exists idx_check_events_emulator_reason_codes
            on check_events using gin (emulator_reason_codes);
        """,
    ),
)

async def run_migrations(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as connection:
        await connection.execute("select pg_advisory_lock($1)", MIGRATION_LOCK_ID)
        try:
            await connection.execute(
                "create table if not exists schema_migrations (version integer primary key, applied_at timestamptz not null default now())"
            )
            rows = await connection.fetch("select version from schema_migrations")
            applied = {row["version"] for row in rows}
            for version, sql in MIGRATIONS:
                if version in applied:
                    continue
                async with connection.transaction():
                    await connection.execute(sql)
                    await connection.execute("insert into schema_migrations (version) values ($1)", version)
                logger.info("migration_applied", extra={"extra": {"version": version}})
        finally:
            await connection.execute("select pg_advisory_unlock($1)", MIGRATION_LOCK_ID)
