"""tenet expert exit daemon."""

from __future__ import annotations

from typing import Sequence

from tenet.config import ClusterConfig, DaemonConfig, PorConfig
from tenet.log_events import PorLogEvent, emit_log_event
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.llm.provider import make_reply_handler


def run_expert(*, config_path: str, node_id: str) -> int:
    cluster = ClusterConfig.load(config_path)
    runtime = WireNodeRuntime(
        cluster, node_id, role="expert", reply_handler=make_reply_handler()
    )
    return runtime.serve_forever()


def run_expert_cluster(daemon: DaemonConfig, por_config: PorConfig) -> int:
    upnp_mapping = _try_upnp_on_startup(daemon)
    reach_state = _start_reach_registration(daemon)
    _emit_node_log(
        daemon, "daemon_start",
        fields={
            "supernode_enabled": daemon.supernode.enabled,
            "reach_registration": daemon.reach_registration.enabled,
            "upnp": upnp_mapping.method if upnp_mapping else "none",
            "upnp_port": upnp_mapping.external_port if upnp_mapping else None,
        },
    )
    cluster = por_config.to_cluster_config()
    runtime = WireNodeRuntime(
        cluster,
        daemon.node_id,
        role="expert",
        logging=daemon.logging,
        reply_handler=make_reply_handler(daemon.provider),
    )
    runtime.upnp_mapping = upnp_mapping
    tls = daemon.transport
    if tls.certfile and tls.keyfile:
        from tenet.mixnet.quic_runtime import serve_quic_forever
        return serve_quic_forever(runtime, certfile=tls.certfile, keyfile=tls.keyfile)
    if tls.dev_allow_insecure_tls:
        from tenet.mixnet.quic_runtime import serve_quic_forever
        return serve_quic_forever(runtime, dev_localhost=True)
    if reach_state is not None:
        _attach_reach_challenge_handler(runtime, daemon, reach_state)
        reach_heartbeat, reach_sock, _relay, _peer_id = reach_state
        bound_host, bound_port = reach_sock.getsockname()
        runtime._log(
            "started",
            fields={"wire": "binary", "addr": f"{bound_host}:{bound_port}"},
        )
        try:
            return runtime.serve_on_socket(reach_sock)
        finally:
            reach_heartbeat.stop()
            reach_sock.close()
    return runtime.serve_forever()


def _start_reach_registration(daemon: DaemonConfig):
    """Register expert opaque handle with a public reachability relay (item 12)."""
    reg = daemon.reach_registration
    if not reg.enabled:
        return None
    import socket

    from tenet.mixnet.reach_client import ReachHeartbeatThread, ReachRelayEndpoint, register_with_relay

    peer_id = reg.peer_id or daemon.node_id
    relay = ReachRelayEndpoint(reg.relay_host, reg.relay_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        register_with_relay(sock, relay, peer_id)
        _emit_node_log(
            daemon,
            "reach_registered",
            fields={"peer_id": peer_id, "relay": f"{relay.host}:{relay.port}"},
        )
    except (OSError, TimeoutError) as exc:
        _emit_node_log(
            daemon,
            "reach_register_failed",
            level="error",
            fields={"reason": str(exc)},
        )
        raise

    def _log(msg: str) -> None:
        _emit_node_log(daemon, "reach_client", level="info", fields={"detail": msg})

    thread = ReachHeartbeatThread(
        sock,
        relay,
        peer_id,
        interval_seconds=reg.heartbeat_interval_seconds,
        log=_log,
    )
    thread.start()
    return thread, sock, relay, peer_id


def _attach_reach_challenge_handler(
    runtime: WireNodeRuntime,
    _daemon: DaemonConfig,
    reach_state,
) -> None:
    from tenet.mixnet.reach_client import confirm_registration_challenge

    _thread, sock, relay, peer_id = reach_state

    def _handle_reach(data: bytes, addr: tuple[str, int]) -> None:
        try:
            handled = confirm_registration_challenge(sock, relay, peer_id, data, source=addr)
        except ValueError as exc:
            runtime._log(
                "reach_register_refresh_failed",
                level="warning",
                fields={"peer_id": peer_id, "reason": str(exc)},
            )
            return
        if handled:
            runtime._log(
                "reach_register_refresh_confirmed",
                fields={"peer_id": peer_id, "relay": f"{relay.host}:{relay.port}"},
            )

    runtime.on_reach_control = _handle_reach


def _try_upnp_on_startup(daemon: DaemonConfig):
    """Try UPnP/NAT-PMP port mapping on expert startup. Returns mapping or None."""
    try:
        from tenet.mixnet.upnp import try_port_mapping
        bind_port = daemon.transport.bind.port if daemon.transport.bind else 4433
        result = try_port_mapping(bind_port, lease_seconds=7200, description="tenet Expert")
        if result.success:
            _emit_node_log(daemon, "upnp_mapped", fields={
                "method": result.mapping.method,
                "external_port": result.mapping.external_port,
                "external_ip": result.mapping.external_ip,
                "lease_seconds": result.mapping.lease_seconds,
            })
            return result.mapping
        _emit_node_log(daemon, "upnp_failed", level="info",
                       fields={"error": result.error})
    except Exception as e:
        _emit_node_log(daemon, "upnp_error", level="warning",
                       fields={"error": str(e)})
    return None


def _emit_node_log(
    daemon: DaemonConfig,
    event: str,
    *,
    level: str = "info",
    fields: dict[str, object] | None = None,
) -> None:
    emit_log_event(
        PorLogEvent(
            event=event,
            component="tenet-expert",
            node_id=daemon.node_id,
            role="expert",
            level=level,
            fields=fields or {},
        ),
        fmt=daemon.logging.fmt,
        redact_fields=frozenset(daemon.logging.redact_fields),
    )


def main(argv: Sequence[str] | None = None) -> int:
    from tenet.edges.cli.main import legacy_expert_main

    return legacy_expert_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
