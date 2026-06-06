"""tenet relay daemon."""

from __future__ import annotations

from typing import Sequence

from tenet.config import ClusterConfig, DaemonConfig, PorConfig
from tenet.log_events import PorLogEvent, emit_log_event
from tenet.mixnet.node_runtime import WireNodeRuntime


def run_relay(*, config_path: str, node_id: str) -> int:
    """Cluster-config relay over canonical binary UDP."""
    cluster = ClusterConfig.load(config_path)
    runtime = WireNodeRuntime(cluster, node_id, role="relay")
    return runtime.serve_forever()


def run_relay_cluster(daemon: DaemonConfig, por_config: PorConfig) -> int:
    """Production relay — uses QUIC+TLS when certs are configured."""
    if daemon.supernode.enabled:
        from tenet.edges.cli.supernode import run_supernode_cluster
        return run_supernode_cluster(daemon, por_config)

    _emit_node_log(daemon, "daemon_start",
                   fields={"supernode_enabled": False})
    cluster = por_config.to_cluster_config()
    runtime = WireNodeRuntime(cluster, daemon.node_id, role="relay",
                              logging=daemon.logging,
                              control_store_path=daemon.control.store_path,
                              control_bootstrap_path=daemon.control.bootstrap_path,
                              control_verify_keys=daemon.control.verify_keys,
                              control_threshold=daemon.control.threshold,
                              control_anti_entropy_interval_seconds=daemon.control.anti_entropy_interval_seconds,
                              control_sync_prefixes=daemon.control.sync_prefixes,
                              control_replication_factor=daemon.control.replication_factor)
    return _serve_with_tls(runtime, daemon)


def _serve_with_tls(runtime: WireNodeRuntime, daemon: DaemonConfig) -> int:
    """Serve via QUIC+TLS if certs configured, fall back to raw UDP."""
    tls = daemon.transport
    if tls.certfile and tls.keyfile:
        from tenet.mixnet.quic_runtime import serve_quic_forever
        return serve_quic_forever(runtime, certfile=tls.certfile, keyfile=tls.keyfile)
    if tls.dev_allow_insecure_tls:
        from tenet.mixnet.quic_runtime import serve_quic_forever
        return serve_quic_forever(runtime, dev_localhost=True)
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
            component="tenet-relay",
            node_id=daemon.node_id,
            role="relay",
            fields=fields or {},
        ),
        fmt=daemon.logging.fmt,
        redact_fields=frozenset(daemon.logging.redact_fields),
    )


def main(argv: Sequence[str] | None = None) -> int:
    from tenet.edges.cli.main import legacy_relay_main

    return legacy_relay_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
