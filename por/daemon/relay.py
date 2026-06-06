"""P-OR relay daemon."""

from __future__ import annotations

from typing import Sequence

from por.config import ClusterConfig, DaemonConfig, PorConfig
from por.log_events import PorLogEvent, emit_log_event
from por.node_runtime import WireNodeRuntime


def run_relay(*, config_path: str, node_id: str) -> int:
    cluster = ClusterConfig.load(config_path)
    runtime = WireNodeRuntime(cluster, node_id, role="relay")
    return runtime.serve_forever()


def run_relay_cluster(daemon: DaemonConfig, por_config: PorConfig) -> int:
    if daemon.supernode.enabled:
        from por.daemon.supernode import run_supernode_cluster

        return run_supernode_cluster(daemon, por_config)
    _emit_node_log(
        daemon,
        "daemon_start",
        fields={"supernode_enabled": False},
    )
    cluster = por_config.to_cluster_config()
    runtime = WireNodeRuntime(cluster, daemon.node_id, role="relay", logging=daemon.logging)
    return runtime.serve_forever()


def _emit_node_log(
    daemon: DaemonConfig,
    event: str,
    *,
    fields: dict[str, object] | None = None,
) -> None:
    emit_log_event(
        PorLogEvent(
            event=event,
            component="por-relay",
            node_id=daemon.node_id,
            role="relay",
            fields=fields or {},
        ),
        fmt=daemon.logging.fmt,
        redact_fields=frozenset(daemon.logging.redact_fields),
    )


def main(argv: Sequence[str] | None = None) -> int:
    from por.daemon.main import legacy_relay_main

    return legacy_relay_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
