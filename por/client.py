"""P-OR client orchestrator and send path.

Layer 7 contract: all app payloads must come from ``prepare_expert_mode_request()``.
This module must not construct ``PromptRequestEnvelope`` directly.
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from sphinxmix.OutfoxClient import packet_create
from sphinxmix.OutfoxNode import circuit_packet_decrypt
from sphinxmix.OutfoxParams import OutfoxParams

from .config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig
from .directory import DiscoveryProvider
from .envelope import PromptRequestEnvelope
from .expert_mode import ExpertModeConfig, prepare_expert_mode_request
from .expert_route import RouteIntent
from .node_runtime import build_native_forward_plan
from .peer_address import ROUTE_RELAY, build_dial_plan, peer_address_record_from_dict, verify_record_signature
from .provider import stream_frontier_reply
from .transport_dial import DialTarget, resolve_dial_target
from .wire_frame import encode_forward, encode_shutdown, decode_datagram


@dataclass(frozen=True)
class ClientRunResult:
    selected_peer_id: str | None
    degraded_anonymity: bool
    fallback_used: bool
    response_text: str
    client_logs: str


@dataclass(frozen=True)
class _PeerAddressRouteResult:
    relay_path: tuple[str, ...]
    logs: tuple[str, ...]
    dial_target: DialTarget | None = None
    blocked_reason: str | None = None


def run_client_once(
    *,
    cluster: ClusterConfig,
    discovery_provider: DiscoveryProvider,
    prompt: str,
    requested_expertise: str | None = None,
    relay_path: Sequence[str] = (),
    timeout: float = 8.0,
    expert_mode_config: ExpertModeConfig | None = None,
    random_seed: int | None = None,
    peer_address_config: PeerAddressConfig | None = None,
    peer_address_records: Mapping[str, dict[str, object]] | None = None,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig] = (),
    dev_allow_untrusted_reachability_relays: bool = False,
    on_chunk: Callable[[dict[str, object]], None] | None = None,
    client_sock: socket.socket | None = None,
) -> ClientRunResult:
    """Plan one Expert Mode request and send the prepared envelope if selected.

    ``client_sock`` is an optional pre-bound socket on the cluster client
    address; callers that own the socket lifecycle (e.g. test harnesses holding
    a port open to avoid rebind races) pass it through to the send path.
    """

    intent = RouteIntent(
        prompt=prompt,
        requested_expertise=requested_expertise,
        random_seed=random_seed,
    )
    prepared = prepare_expert_mode_request(
        intent,
        discovery_provider,
        expert_mode_config or ExpertModeConfig(),
    )

    logs = [
        "client event=expert_plan selected={selected} degraded_anonymity={degraded} "
        "fallback_used={fallback} pool_tier={pool_tier}".format(
            selected=prepared.trace.selected_peer_id or "none",
            degraded=str(prepared.plan.pool.degraded_anonymity).lower(),
            fallback=str(not prepared.use_expert).lower(),
            pool_tier=prepared.trace.pool_tier,
        )
    ]

    if not prepared.use_expert or prepared.envelope is None:
        response = "".join(stream_frontier_reply(prompt, prepared.trace.fallback_reason))
        return ClientRunResult(
            selected_peer_id=None,
            degraded_anonymity=prepared.plan.pool.degraded_anonymity,
            fallback_used=True,
            response_text=response,
            client_logs="\n".join(logs),
        )

    selected_peer_id = prepared.envelope.selected_peer_id
    route_result = _plan_relay_path_from_peer_address(
        selected_peer_id=selected_peer_id,
        relay_path=tuple(relay_path),
        peer_address_config=peer_address_config,
        peer_address_records=(
            peer_address_records
            or _peer_address_records_from_discovery_provider(discovery_provider)
        ),
        trusted_reachability_relays=tuple(trusted_reachability_relays),
        dev_allow_untrusted_reachability_relays=dev_allow_untrusted_reachability_relays,
    )
    logs.extend(route_result.logs)
    if route_result.blocked_reason is not None:
        response = "".join(stream_frontier_reply(prompt, route_result.blocked_reason))
        return ClientRunResult(
            selected_peer_id=selected_peer_id,
            degraded_anonymity=prepared.plan.pool.degraded_anonymity,
            fallback_used=True,
            response_text=response,
            client_logs="\n".join(logs),
        )
    if not _routing_node_available(
        cluster,
        discovery_provider,
        selected_peer_id,
        relay_path=route_result.relay_path,
    ):
        response = "".join(stream_frontier_reply(prompt, "selected expert peer not in cluster"))
        logs.append("client event=selected_peer_missing fallback_used=true")
        return ClientRunResult(
            selected_peer_id=selected_peer_id,
            degraded_anonymity=prepared.plan.pool.degraded_anonymity,
            fallback_used=True,
            response_text=response,
            client_logs="\n".join(logs),
        )

    relay_path = route_result.relay_path
    forward_path = tuple(relay_path) + (selected_peer_id,)
    _validate_forward_path(cluster, forward_path, discovery_provider)
    response, stream_logs = send_prepared_envelope(
        cluster=cluster,
        forward_path=forward_path,
        envelope=prepared.envelope,
        timeout=timeout,
        on_chunk=on_chunk,
        dial_target=route_result.dial_target,
        discovery_provider=discovery_provider,
        client_sock=client_sock,
    )
    logs.extend(stream_logs)
    return ClientRunResult(
        selected_peer_id=selected_peer_id,
        degraded_anonymity=prepared.plan.pool.degraded_anonymity,
        fallback_used=False,
        response_text=response,
        client_logs="\n".join(logs),
    )


def send_prepared_envelope(
    *,
    cluster: ClusterConfig,
    forward_path: Sequence[str],
    envelope: PromptRequestEnvelope,
    timeout: float = 8.0,
    on_chunk: Callable[[dict[str, object]], None] | None = None,
    dial_target: DialTarget | None = None,
    discovery_provider: DiscoveryProvider | None = None,
    client_sock: socket.socket | None = None,
) -> tuple[str, list[str]]:
    """Send a prepared Layer 7 envelope via canonical binary UDP datagrams.

    ``client_sock`` lets a caller pass a socket already bound to the cluster
    client address. The caller then owns its lifecycle; this function will not
    close it. When omitted, a socket is bound and closed internally.
    """

    if not forward_path:
        raise ValueError("forward_path is required")
    _validate_forward_path(cluster, forward_path, discovery_provider)

    params = OutfoxParams(**cluster.params.outfox_kwargs())
    client_addr = (cluster.client.host, cluster.client.port)

    owns_client_sock = client_sock is None
    if client_sock is None:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind(client_addr)
    client_sock.settimeout(0.5)

    route_infos, circuit_setup, client_peel_keys = build_native_forward_plan(
        tuple(forward_path))
    kem_keys = [
        _kem_public_key(cluster, discovery_provider, node_id)
        for node_id in forward_path
    ]
    header, payload = packet_create(
        params, route_infos, kem_keys,
        envelope.to_json().encode("utf-8"),
        circuit_setup=circuit_setup,
    )

    if dial_target is not None:
        first_addr = (dial_target.host, dial_target.port)
        dial_note = (
            f"route_kind={dial_target.route_kind} relay_id={dial_target.relay_id or ''} "
            f"host={dial_target.host} port={dial_target.port}"
        )
    else:
        first_node = cluster.node(forward_path[0])
        first_addr = (first_node.host, first_node.port)
        dial_note = f"cluster_node={forward_path[0]}"

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        send_sock.sendto(encode_forward(header, payload), first_addr)

        chunks: list[str] = []
        logs = [
            f"client event=send_prepared_envelope selected={envelope.selected_peer_id or 'none'} "
            f"forward_path={'/'.join(forward_path)} wire=binary {dial_note}"
        ]
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _addr = client_sock.recvfrom(65535)
            except socket.timeout:
                continue
            kind, body, _ = decode_datagram(data, params.payload_size)
            if kind != "circuit":
                continue
            plain = circuit_packet_decrypt(params, client_peel_keys, body)
            if plain is None:
                logs.append("client event=stream_corrupt")
                continue
            chunk = json.loads(plain.decode("utf-8"))
            logs.append(f"client event=stream_chunk seq={chunk['seq']} bytes={len(chunk['data'])}")
            if chunk.get("done"):
                if on_chunk is not None:
                    on_chunk(chunk)
                break
            if on_chunk is not None:
                on_chunk(chunk)
            chunks.append(chunk["data"])
        else:
            raise TimeoutError("timed out waiting for streamed return path")
        return "".join(chunks), logs
    finally:
        if owns_client_sock:
            client_sock.close()
        send_sock.close()


def _plan_relay_path_from_peer_address(
    *,
    selected_peer_id: str | None,
    relay_path: tuple[str, ...],
    peer_address_config: PeerAddressConfig | None,
    peer_address_records: Mapping[str, dict[str, object]] | None,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig],
    dev_allow_untrusted_reachability_relays: bool = False,
) -> _PeerAddressRouteResult:
    """Use peer-address records for route planning without changing transport IO."""

    logs: list[str] = []
    if (
        selected_peer_id is None
        or peer_address_config is None
        or not peer_address_config.enabled
    ):
        return _PeerAddressRouteResult(relay_path=relay_path, logs=tuple(logs))

    records = peer_address_records or peer_address_config.records
    raw_record = records.get(selected_peer_id)
    if raw_record is None:
        logs.append(f"client event=peer_address_missing peer_id={selected_peer_id}")
        return _PeerAddressRouteResult(relay_path=relay_path, logs=tuple(logs))

    record = peer_address_record_from_dict(dict(raw_record))
    trusted_by_id = {relay.relay_id: relay for relay in trusted_reachability_relays}
    trusted_record_relays = [
        candidate
        for candidate in record.relay_candidates
        if candidate.relay_id in trusted_by_id
    ]
    if not trusted_record_relays and not dev_allow_untrusted_reachability_relays:
        reason = "peer_address_untrusted_relay"
        logs.append(
            f"client event=peer_address_rejected peer_id={selected_peer_id} reason={reason}"
        )
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=tuple(logs),
            blocked_reason=reason,
        )
    if trusted_record_relays:
        verified = any(
            verify_record_signature(record, trusted_by_id[candidate.relay_id].verify_key)
            for candidate in trusted_record_relays
        )
        if not verified:
            reason = "peer_address_bad_signature"
            logs.append(
                f"client event=peer_address_rejected peer_id={selected_peer_id} reason={reason}"
            )
            return _PeerAddressRouteResult(
                relay_path=relay_path,
                logs=tuple(logs),
                blocked_reason=reason,
            )
    elif dev_allow_untrusted_reachability_relays:
        logs.append(
            f"client event=peer_address_dev_untrusted_allowed peer_id={selected_peer_id}"
        )

    plan = build_dial_plan(
        record,
        allow_direct=peer_address_config.allow_direct,
        prefer_direct=peer_address_config.prefer_direct,
    )
    dial_target = resolve_dial_target(
        plan,
        trusted_reachability_relays,
        dev_allow_untrusted_reachability_relays=dev_allow_untrusted_reachability_relays,
    )
    if dial_target is None:
        reason = "peer_address_no_trusted_dial_target"
        logs.append(
            f"client event=peer_address_rejected peer_id={selected_peer_id} reason={reason}"
        )
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=tuple(logs),
            blocked_reason=reason,
        )
    primary_kind = plan.primary.kind if plan.primary else "none"
    logs.append(
        "client event=peer_address_plan peer_id={peer_id} contactable={contactable} "
        "primary={primary} fallback_count={fallback_count}".format(
            peer_id=selected_peer_id,
            contactable=str(plan.contactable).lower(),
            primary=primary_kind,
            fallback_count=len(plan.fallbacks),
        )
    )
    logs.append(
        "client event=dial_target peer_id={peer_id} route_kind={route_kind} "
        "transport={transport} relay_id={relay_id} host={host} port={port}".format(
            peer_id=selected_peer_id,
            route_kind=dial_target.route_kind,
            transport=dial_target.transport,
            relay_id=dial_target.relay_id or "",
            host=dial_target.host,
            port=dial_target.port,
        )
    )
    for warning in plan.warnings:
        logs.append(
            f"client event=peer_address_warning peer_id={selected_peer_id} warning={warning!r}"
        )

    if relay_path:
        logs.append(
            f"client event=peer_address_ignored_static_relay_path peer_id={selected_peer_id}"
        )

    if dial_target.route_kind != ROUTE_RELAY or not dial_target.relay_id:
        return _PeerAddressRouteResult(
            relay_path=(),
            logs=tuple(logs),
            dial_target=dial_target,
        )

    planned = (dial_target.relay_id,)
    logs.append(
        "client event=peer_address_relay_path peer_id={peer_id} relay_path={path}".format(
            peer_id=selected_peer_id,
            path="/".join(planned),
        )
    )
    return _PeerAddressRouteResult(relay_path=planned, logs=tuple(logs), dial_target=dial_target)


def _routing_node_available(
    cluster: ClusterConfig,
    discovery_provider: DiscoveryProvider,
    peer_id: str,
    *,
    relay_path: tuple[str, ...],
) -> bool:
    if peer_id in cluster.nodes:
        return True
    if relay_path and _kem_public_key_hex(discovery_provider, peer_id) is not None:
        return True
    return False


def _kem_public_key_hex(discovery_provider: DiscoveryProvider | None, node_id: str) -> str | None:
    if discovery_provider is None:
        return None
    getter = getattr(discovery_provider, "routing_kem_pk_hex", None)
    if getter is None:
        return None
    return getter(node_id)


def _kem_public_key(
    cluster: ClusterConfig,
    discovery_provider: DiscoveryProvider | None,
    node_id: str,
) -> bytes:
    if node_id in cluster.nodes:
        return bytes.fromhex(cluster.node(node_id).kem_pk_hex)
    kem_hex = _kem_public_key_hex(discovery_provider, node_id)
    if kem_hex is None:
        raise ValueError(f"no routing kem for node {node_id!r}")
    return bytes.fromhex(kem_hex)


def _validate_forward_path(
    cluster: ClusterConfig,
    forward_path: Sequence[str],
    discovery_provider: DiscoveryProvider | None = None,
) -> None:
    missing = [
        node_id
        for node_id in forward_path
        if node_id not in cluster.nodes
        and _kem_public_key_hex(discovery_provider, node_id) is None
    ]
    if missing:
        raise ValueError(f"forward_path contains unknown nodes: {', '.join(missing)}")


def _peer_address_records_from_discovery_provider(
    discovery_provider: DiscoveryProvider,
) -> Mapping[str, dict[str, object]] | None:
    getter = getattr(discovery_provider, "peer_address_records", None)
    if not callable(getter):
        return None
    records = getter()
    if isinstance(records, Mapping):
        return records
    return None
