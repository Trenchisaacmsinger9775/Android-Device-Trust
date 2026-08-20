import logging
from typing import Any

from app.core.config import settings

logger = logging.getLogger("devicecheck.retention")

async def cleanup_expired_records(connection: Any) -> None:
    retention_days = max(1, settings.datastore_retention_days)
    deleted_events = await _execute_delete(
        connection,
        "delete from check_events where created_at < now() - make_interval(days => $1)",
        retention_days,
    )
    deleted_snapshots = await _execute_delete(
        connection,
        "delete from device_feature_snapshots where created_at < now() - make_interval(days => $1)",
        retention_days,
    )
    deleted_instances = await _execute_delete(
        connection,
        """
        delete from device_instances instances
        where instances.last_seen_at < now() - make_interval(days => $1)
          and not exists (
              select 1 from check_events events
              where events.device_instance_id = instances.device_instance_id
          )
          and not exists (
              select 1 from device_feature_snapshots snapshots
              where snapshots.device_instance_id = instances.device_instance_id
          )
        """,
        retention_days,
    )
    deleted_clusters = await _execute_delete(
        connection,
        """
        delete from device_clusters clusters
        where clusters.last_seen_at < now() - make_interval(days => $1)
          and not exists (
              select 1 from check_events events
              where events.device_cluster_id = clusters.device_cluster_id
          )
          and not exists (
              select 1 from device_feature_snapshots snapshots
              where snapshots.device_cluster_id = clusters.device_cluster_id
          )
          and not exists (
              select 1 from device_instances instances
              where instances.device_cluster_id = clusters.device_cluster_id
          )
        """,
        retention_days,
    )
    logger.debug(
        "retention_cleanup_finished",
        extra={
            "extra": {
                "retention_days": retention_days,
                "deleted_events": deleted_events,
                "deleted_snapshots": deleted_snapshots,
                "deleted_instances": deleted_instances,
                "deleted_clusters": deleted_clusters,
            }
        },
    )

async def _execute_delete(connection: Any, query: str, *args: object) -> int:
    status = await connection.execute(query, *args)
    try:
        return int(status.rsplit(" ", 1)[1])
    except (IndexError, ValueError):
        return 0
