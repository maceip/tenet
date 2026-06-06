"""tenet client orchestrator and send path.

Layer 7 contract: all app payloads must come from ``prepare_expert_mode_request()``.
This module must not construct ``PromptRequestEnvelope`` directly.
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence

from tenet.packet.OutfoxClient import packet_create
from tenet.packet.OutfoxNode import circuit_packet_decrypt
from tenet.packet.OutfoxParams import OutfoxParams

from tenet.config import (
    CAPABILITY_CONTROL_DHT,
    CAPABILITY_MIXNODE,
    ClusterConfig,
    PeerAddressConfig,
    ProviderConfig,
    TrustedReachabilityRelayConfig,
)
from tenet.experts.directory import DiscoveryProvider
from tenet.experts.directory import PrivateDiscoveryUnavailable
from tenet.envelope import PromptRequestEnvelope
from tenet.experts.expert_mode import (
    ExpertModeConfig,
    prepare_match_result_gossip_request,
    prepare_expert_mode_request,
    prepare_stable_name_request,
)
from tenet.experts.expert_route import RouteIntent
from tenet.handles import HandleResolution
from tenet.mixnet.control import query_commitment
from tenet.mixnet.node_runtime import build_native_forward_plan
from tenet.mixnet.peer_address import ROUTE_RELAY, build_dial_plan, peer_address_record_from_dict, verify_record_signature
from tenet.mixnet.planner import MixnetPlanningError, build_forward_plan, resolve_name_binding
from tenet.llm.provider import stream_frontier_reply
from tenet.mixnet.transport_dial import DialTarget, resolve_dial_target
from tenet.mixnet.wire_frame import encode_forward, encode_shutdown, decode_datagram
from tenet.protocol_invariants import ProtocolInvariantError, require_route_handle


@dataclass(frozen=True)
class ClientRunResult:
    selected_handle: str | None
    degraded_anonymity: bool
    fallback_used: bool
    response_text: str
    client_logs: str

    @property
    def selected_peer_id(self) -> str | None:
        """Compatibility alias for one schema transition."""

        return self.selected_handle


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
    service_name: str | None = None,
    relay_path: Sequence[str] = (),
    timeout: float = 8.0,
    expert_mode_config: ExpertModeConfig | None = None,
    random_seed: int | None = None,
    peer_address_config: PeerAddressConfig | None = None,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig] = (),
    dev_allow_untrusted_reachability_relays: bool = False,
    provider_config: ProviderConfig | None = None,
    on_chunk: Callable[[dict[str, object]], None] | None = None,
    client_sock: socket.socket | None = None,
    control_service=None,
    match_gossip_salt: str | None = None,
) -> ClientRunResult:
    """Plan one Expert Mode request and send the prepared envelope if selected.

    ``client_sock`` is an optional pre-bound socket on the cluster client
    address; callers that own the socket lifecycle (e.g. tests holding
    a port open to avoid rebind races) pass it through to the send path.
    """

    control_logs: list[str] = []
    stable_binding = None
    control_mix_path: tuple[str, ...] = ()
    pool_name_for_gossip = None
    if service_name:
        try:
            binding = resolve_name_binding(service_name, control_service=control_service)
        except MixnetPlanningError as exc:
            response = "".join(stream_frontier_reply(prompt, str(exc), provider_config))
            return ClientRunResult(
                selected_handle=None,
                degraded_anonymity=False,
                fallback_used=True,
                response_text=response,
                client_logs=f"client event=tenet_name_unresolved name={service_name} reason={exc}",
            )
        if binding.opaque_handle is not None:
            stable_binding = binding
        if binding.mix_path:
            control_mix_path = tuple(binding.mix_path)
        if binding.pool_name is not None:
            pool_name_for_gossip = binding.pool_name
        if binding.requested_expertise and requested_expertise is None:
            requested_expertise = binding.requested_expertise
        control_logs.append(
            "client event=tenet_name_bound name={name} kind={kind} transport={transport} expertise={expertise}".format(
                name=binding.name,
                kind=binding.name_kind,
                transport=binding.transport,
                expertise=binding.requested_expertise or "",
            )
        )

    intent = RouteIntent(
        prompt=prompt,
        requested_expertise=requested_expertise,
        random_seed=random_seed,
    )
    if stable_binding is not None and stable_binding.opaque_handle is not None:
        prepared = prepare_stable_name_request(
            intent,
            selected_handle=stable_binding.opaque_handle,
            config=expert_mode_config or ExpertModeConfig(),
            descriptor_hash=stable_binding.descriptor_hash,
        )
        control_logs.append(
            "client event=tenet_name_stable_bound name={name} handle={handle}".format(
                name=stable_binding.name,
                handle=stable_binding.opaque_handle,
            )
        )
    else:
        gossip = _prepare_from_match_gossip(
            intent=intent,
            control_service=control_service,
            pool_name=pool_name_for_gossip,
            salt=match_gossip_salt,
            config=expert_mode_config or ExpertModeConfig(),
        )
        if gossip is not None:
            prepared, gossip_logs = gossip
            control_logs.extend(gossip_logs)
        else:
            try:
                prepared = prepare_expert_mode_request(
                    intent,
                    discovery_provider,
                    expert_mode_config or ExpertModeConfig(),
                )
            except PrivateDiscoveryUnavailable:
                gossip = _prepare_from_match_gossip(
                    intent=intent,
                    control_service=control_service,
                    pool_name=pool_name_for_gossip,
                    salt=match_gossip_salt,
                    config=expert_mode_config or ExpertModeConfig(),
                )
                if gossip is None:
                    raise
                prepared, gossip_logs = gossip
                control_logs.extend(gossip_logs)

    logs = [
        *control_logs,
        "client event=expert_plan selected={selected} degraded_anonymity={degraded} "
        "fallback_used={fallback} pool_tier={pool_tier}".format(
            selected=prepared.trace.selected_handle or "none",
            degraded=str(prepared.plan.pool.degraded_anonymity).lower(),
            fallback=str(not prepared.use_expert).lower(),
            pool_tier=prepared.trace.pool_tier,
        )
    ]

    if not prepared.use_expert or prepared.envelope is None:
        gossip = _prepare_from_match_gossip(
            intent=intent,
            control_service=control_service,
            pool_name=pool_name_for_gossip,
            salt=match_gossip_salt,
            config=expert_mode_config or ExpertModeConfig(),
        )
        if gossip is not None:
            prepared, gossip_logs = gossip
            logs.extend(gossip_logs)
        else:
            reason = prepared.trace.fallback_reason or "no expert selected"
            response = "".join(stream_frontier_reply(prompt, reason, provider_config))
            return ClientRunResult(
                selected_handle=None,
                degraded_anonymity=prepared.plan.pool.degraded_anonymity,
                fallback_used=True,
                response_text=response,
                client_logs="\n".join(logs),
            )

    selected_handle = prepared.envelope.selected_handle
    try:
        selected_handle = require_route_handle(
            selected_handle,
            field="selected route target",
        )
    except ProtocolInvariantError:
        reason = "selected_route_target_not_opaque_handle"
        response = "".join(stream_frontier_reply(prompt, reason, provider_config))
        logs.append(
            "client event=route_target_rejected reason={reason} selected={selected}".format(
                reason=reason,
                selected=selected_handle or "none",
            )
        )
        return ClientRunResult(
            selected_handle=selected_handle,
            degraded_anonymity=prepared.plan.pool.degraded_anonymity,
            fallback_used=True,
            response_text=response,
            client_logs="\n".join(logs),
        )
    requested_mix_path = control_mix_path or tuple(relay_path)
    route_result = _plan_relay_path_for_mailbox_delivery(
        selected_handle=selected_handle,
        relay_path=requested_mix_path,
        peer_address_config=peer_address_config,
        discovery_provider=discovery_provider,
    )
    if route_result is None:
        route_result = _plan_relay_path_from_handle(
            selected_handle=selected_handle,
            relay_path=requested_mix_path,
            peer_address_config=peer_address_config,
            discovery_provider=discovery_provider,
            trusted_reachability_relays=tuple(trusted_reachability_relays),
            dev_allow_untrusted_reachability_relays=dev_allow_untrusted_reachability_relays,
        )
    if route_result is None:
        if peer_address_config is not None and peer_address_config.enabled:
            route_result = _PeerAddressRouteResult(
                relay_path=requested_mix_path,
                logs=("client event=handle_resolver_missing",),
                blocked_reason="handle_resolver_required",
            )
        else:
            route_result = _PeerAddressRouteResult(relay_path=requested_mix_path, logs=())
    logs.extend(route_result.logs)
    if route_result.blocked_reason is not None:
        response = "".join(stream_frontier_reply(prompt, route_result.blocked_reason, provider_config))
        return ClientRunResult(
            selected_handle=selected_handle,
            degraded_anonymity=prepared.plan.pool.degraded_anonymity,
            fallback_used=True,
            response_text=response,
            client_logs="\n".join(logs),
        )
    if not _routing_node_available(
        cluster,
        discovery_provider,
        selected_handle,
        relay_path=route_result.relay_path,
    ):
        response = "".join(
            stream_frontier_reply(prompt, "selected handle is not currently routeable", provider_config)
        )
        logs.append("client event=selected_handle_unrouteable fallback_used=true")
        return ClientRunResult(
            selected_handle=selected_handle,
            degraded_anonymity=prepared.plan.pool.degraded_anonymity,
            fallback_used=True,
            response_text=response,
            client_logs="\n".join(logs),
        )

    forward_plan = build_forward_plan(
        exit_handle=selected_handle,
        mix_path=route_result.relay_path,
        dial_target=route_result.dial_target,
        source="expert-selection",
        min_mix_hops=1 if route_result.relay_path else 0,
        known_mixnodes=_known_mixnode_ids(cluster, control_service),
    )
    logs.append(forward_plan.log_line())
    forward_path = forward_plan.forward_path
    _validate_forward_path(cluster, forward_path, discovery_provider)
    response, stream_logs = send_prepared_envelope(
        cluster=cluster,
        forward_path=forward_path,
        envelope=prepared.envelope,
        timeout=timeout,
        on_chunk=on_chunk,
        dial_target=forward_plan.dial_target,
        discovery_provider=discovery_provider,
        client_sock=client_sock,
    )
    logs.extend(stream_logs)
    return ClientRunResult(
        selected_handle=selected_handle,
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

    mailbox_delivery = _mailbox_delivery(discovery_provider)
    datagram = encode_forward(header, payload)
    if mailbox_delivery is not None and envelope.selected_handle == forward_path[-1]:
        logs = [
            f"client event=send_prepared_envelope selected={envelope.selected_handle or 'none'} "
            f"forward_path={'/'.join(forward_path)} wire=binary via=mailbox"
        ]
        packets = mailbox_delivery(
            envelope.selected_handle,
            datagram,
            timeout=timeout,
        )
        response, stream_logs = _read_stream_from_datagrams(
            params=params,
            client_peel_keys=client_peel_keys,
            datagrams=packets,
            on_chunk=on_chunk,
        )
        logs.extend(stream_logs)
        return response, logs

    owns_client_sock = client_sock is None
    if client_sock is None:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind(client_addr)
    client_sock.settimeout(0.5)

    try:
        request_repeats = max(1, int(os.environ.get("POR_CLIENT_REQUEST_REPEATS", "3")))
        request_repeat_delay = max(
            0.0, float(os.environ.get("POR_CLIENT_REQUEST_REPEAT_DELAY", "0.15"))
        )
        for repeat in range(request_repeats):
            client_sock.sendto(datagram, first_addr)
            if repeat < request_repeats - 1:
                time.sleep(request_repeat_delay)

        logs = [
            f"client event=send_prepared_envelope selected={envelope.selected_handle or 'none'} "
            f"forward_path={'/'.join(forward_path)} wire=binary {dial_note} "
            f"request_repeats={request_repeats}"
        ]
        response, stream_logs = _read_stream_from_socket(
            params=params,
            client_peel_keys=client_peel_keys,
            client_sock=client_sock,
            timeout=timeout,
            on_chunk=on_chunk,
        )
        logs.extend(stream_logs)
        return response, logs
    finally:
        if owns_client_sock:
            client_sock.close()


def _prepare_from_match_gossip(
    *,
    intent: RouteIntent,
    control_service,
    pool_name: str | None,
    salt: str | None,
    config: ExpertModeConfig,
):
    if control_service is None or pool_name is None or not salt:
        return None
    commitment = query_commitment(
        prompt=intent.prompt,
        pool_name=pool_name,
        requested_expertise=intent.requested_expertise,
        salt=salt,
    )
    results = control_service.match_results(
        pool_name=pool_name,
        query_commitment=commitment,
    )
    for result in results:
        signed = control_service.get(result.key)
        if signed is None:
            continue
        for candidate in result.candidates:
            if candidate.cover:
                continue
            prepared = prepare_match_result_gossip_request(
                intent,
                selected_handle=candidate.handle,
                matcher_id=result.matcher_id,
                result_key=result.key,
                attestation_ref=result.attestation_ref,
                record_issued_at=signed.record.issued_at,
                record_expires_at=signed.record.expires_at,
                config=config,
            )
            return prepared, (
                "client event=match_result_gossip_used source=cached_tee_signed live_tee_match=false "
                "selection_policy=prefer_signed_cached_tee_absent_reputation "
                "pool={pool} matcher={matcher} handle={handle} record_key={key} expires_at={expires}".format(
                    pool=pool_name,
                    matcher=result.matcher_id,
                    handle=candidate.handle,
                    key=result.key,
                    expires=signed.record.expires_at,
                ),
            )
    return None


def _known_mixnode_ids(
    cluster: ClusterConfig,
    control_service,
) -> tuple[str, ...]:
    node_ids = {
        node_id
        for node_id, node in cluster.nodes.items()
        if node.has_capability(CAPABILITY_MIXNODE)
        or node.has_capability(CAPABILITY_CONTROL_DHT)
    }
    if control_service is not None:
        peers = getattr(control_service, "mixnode_dht_peers", None)
        if callable(peers):
            try:
                node_ids.update(str(peer.node_id) for peer in peers())
            except Exception:
                pass
    return tuple(sorted(node_id for node_id in node_ids if node_id))


def _read_stream_from_socket(
    *,
    params: OutfoxParams,
    client_peel_keys: Sequence[bytes],
    client_sock: socket.socket,
    timeout: float,
    on_chunk: Callable[[dict[str, object]], None] | None,
) -> tuple[str, list[str]]:
    def datagrams() -> Iterable[bytes]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _addr = client_sock.recvfrom(65535)
            except socket.timeout:
                continue
            yield data

    return _read_stream_from_datagrams(
        params=params,
        client_peel_keys=client_peel_keys,
        datagrams=datagrams(),
        on_chunk=on_chunk,
    )


def _read_stream_from_datagrams(
    *,
    params: OutfoxParams,
    client_peel_keys: Sequence[bytes],
    datagrams: Iterable[bytes],
    on_chunk: Callable[[dict[str, object]], None] | None,
) -> tuple[str, list[str]]:
    chunks: dict[int, str] = {}
    expected_done_seq: int | None = None
    logs: list[str] = []
    for data in datagrams:
        kind, body, _ = decode_datagram(data, params.payload_size)
        if kind != "circuit":
            continue
        plain = circuit_packet_decrypt(params, client_peel_keys, body)
        if plain is None:
            logs.append("client event=stream_corrupt")
            continue
        chunk = json.loads(plain.decode("utf-8"))
        seq = int(chunk["seq"])
        if chunk.get("done"):
            expected_done_seq = seq
            logs.append(f"client event=stream_done seq={seq}")
            if on_chunk is not None:
                on_chunk(chunk)
        elif seq in chunks:
            logs.append(f"client event=stream_chunk_duplicate seq={seq}")
        else:
            data_text = str(chunk["data"])
            logs.append(f"client event=stream_chunk seq={seq} bytes={len(data_text)}")
            chunks[seq] = data_text
            if on_chunk is not None:
                on_chunk(chunk)
        if expected_done_seq is not None and all(
            seq in chunks for seq in range(expected_done_seq)
        ):
            return "".join(chunks[seq] for seq in range(expected_done_seq)), logs
    if expected_done_seq is None:
        detail = "no_done"
    else:
        missing = [seq for seq in range(expected_done_seq) if seq not in chunks]
        detail = f"missing_chunks={missing}"
    tail = "; ".join(logs[-12:])
    raise TimeoutError(f"timed out waiting for streamed return path ({detail}); {tail}")


def _plan_relay_path_from_peer_address(
    *,
    selected_handle: str | None,
    relay_path: tuple[str, ...],
    peer_address_config: PeerAddressConfig | None,
    peer_address_records: Mapping[str, dict[str, object]],
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig],
    dev_allow_untrusted_reachability_relays: bool = False,
) -> _PeerAddressRouteResult:
    """Use peer-address records for route planning without changing transport IO."""

    logs: list[str] = []
    if (
        selected_handle is None
        or peer_address_config is None
        or not peer_address_config.enabled
    ):
        return _PeerAddressRouteResult(relay_path=relay_path, logs=tuple(logs))

    raw_record = peer_address_records.get(selected_handle)
    if raw_record is None:
        logs.append(f"client event=peer_address_missing handle={selected_handle}")
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
            f"client event=peer_address_rejected handle={selected_handle} reason={reason}"
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
                f"client event=peer_address_rejected handle={selected_handle} reason={reason}"
            )
            return _PeerAddressRouteResult(
                relay_path=relay_path,
                logs=tuple(logs),
                blocked_reason=reason,
            )
    elif dev_allow_untrusted_reachability_relays:
        logs.append(
            f"client event=peer_address_dev_untrusted_allowed handle={selected_handle}"
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
            f"client event=peer_address_rejected handle={selected_handle} reason={reason}"
        )
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=tuple(logs),
            blocked_reason=reason,
        )
    primary_kind = plan.primary.kind if plan.primary else "none"
    logs.append(
        "client event=peer_address_plan handle={handle} contactable={contactable} "
        "primary={primary} fallback_count={fallback_count}".format(
            handle=selected_handle,
            contactable=str(plan.contactable).lower(),
            primary=primary_kind,
            fallback_count=len(plan.fallbacks),
        )
    )
    logs.append(
        "client event=dial_target handle={handle} route_kind={route_kind} "
        "transport={transport} relay_id={relay_id} host={host} port={port}".format(
            handle=selected_handle,
            route_kind=dial_target.route_kind,
            transport=dial_target.transport,
            relay_id=dial_target.relay_id or "",
            host=dial_target.host,
            port=dial_target.port,
        )
    )
    for warning in plan.warnings:
        logs.append(
            f"client event=peer_address_warning handle={selected_handle} warning={warning!r}"
        )

    if relay_path:
        logs.append(
            f"client event=peer_address_ignored_static_relay_path handle={selected_handle}"
        )

    if dial_target.route_kind != ROUTE_RELAY or not dial_target.relay_id:
        return _PeerAddressRouteResult(
            relay_path=(),
            logs=tuple(logs),
            dial_target=dial_target,
        )

    planned = (dial_target.relay_id,)
    logs.append(
        "client event=peer_address_relay_path handle={handle} relay_path={path}".format(
            handle=selected_handle,
            path="/".join(planned),
        )
    )
    return _PeerAddressRouteResult(relay_path=planned, logs=tuple(logs), dial_target=dial_target)


def _plan_relay_path_for_mailbox_delivery(
    *,
    selected_handle: str | None,
    relay_path: tuple[str, ...],
    peer_address_config: PeerAddressConfig | None,
    discovery_provider: DiscoveryProvider,
) -> _PeerAddressRouteResult | None:
    if (
        selected_handle is None
        or peer_address_config is None
        or not peer_address_config.enabled
        or not bool(getattr(discovery_provider, "mailbox_datagram_delivery_enabled", True))
        or not bool(getattr(discovery_provider, "mailbox_delivery_enabled", False))
    ):
        return None
    planner = getattr(discovery_provider, "relay_path_for_handle", None)
    if not callable(planner):
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=(f"client event=mailbox_delivery_missing handle={selected_handle}",),
            blocked_reason="mailbox_delivery_missing",
        )
    try:
        planned = tuple(str(node_id) for node_id in planner(selected_handle))
    except ValueError as exc:
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=(f"client event=mailbox_delivery_rejected handle={selected_handle} reason={exc}",),
            blocked_reason=str(exc),
        )
    if relay_path and relay_path != planned:
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=(f"client event=mailbox_delivery_rejected handle={selected_handle} reason=static_relay_path_conflict",),
            blocked_reason="mailbox_delivery_static_relay_path_conflict",
        )
    return _PeerAddressRouteResult(
        relay_path=planned,
        logs=(
            "client event=mailbox_delivery_plan handle={handle} relay_path={path}".format(
                handle=selected_handle,
                path="/".join(planned),
            ),
        ),
    )


def _plan_relay_path_from_handle(
    *,
    selected_handle: str | None,
    relay_path: tuple[str, ...],
    peer_address_config: PeerAddressConfig | None,
    discovery_provider: DiscoveryProvider,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig],
    dev_allow_untrusted_reachability_relays: bool = False,
) -> _PeerAddressRouteResult | None:
    if (
        selected_handle is None
        or peer_address_config is None
        or not peer_address_config.enabled
    ):
        return None
    resolver = getattr(discovery_provider, "resolve_handle", None)
    if not callable(resolver):
        return None
    resolution = resolver(selected_handle)
    if resolution is None:
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=(f"client event=handle_missing handle={selected_handle}",),
            blocked_reason="handle_unresolved",
        )
    if not isinstance(resolution, HandleResolution):
        try:
            resolution = HandleResolution(
                handle=str(resolution["handle"]),
                routing_kem_pk_hex=str(resolution["routing_kem_pk_hex"]),
                peer_address=dict(resolution["peer_address"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            return _PeerAddressRouteResult(
                relay_path=relay_path,
                logs=(f"client event=handle_rejected handle={selected_handle} reason=bad_resolution",),
                blocked_reason=f"bad_handle_resolution: {exc}",
            )
    if resolution.handle != selected_handle:
        return _PeerAddressRouteResult(
            relay_path=relay_path,
            logs=(f"client event=handle_rejected handle={selected_handle} reason=mismatch",),
            blocked_reason="handle_resolution_mismatch",
        )
    result = _plan_relay_path_from_peer_address(
        selected_handle=selected_handle,
        relay_path=relay_path,
        peer_address_config=peer_address_config,
        peer_address_records={selected_handle: resolution.peer_address},
        trusted_reachability_relays=trusted_reachability_relays,
        dev_allow_untrusted_reachability_relays=dev_allow_untrusted_reachability_relays,
    )
    return _PeerAddressRouteResult(
        relay_path=result.relay_path,
        logs=(
            f"client event=handle_resolved handle={selected_handle}",
            *result.logs,
        ),
        dial_target=result.dial_target,
        blocked_reason=result.blocked_reason,
    )


def _mailbox_delivery(
    discovery_provider: DiscoveryProvider | None,
) -> Callable[[str, bytes], Iterable[bytes]] | None:
    if discovery_provider is None:
        return None
    if not bool(getattr(discovery_provider, "mailbox_datagram_delivery_enabled", True)):
        return None
    if not bool(getattr(discovery_provider, "mailbox_delivery_enabled", False)):
        return None
    delivery = getattr(discovery_provider, "deliver_to_handle", None)
    if not callable(delivery):
        return None
    return delivery


def _routing_node_available(
    cluster: ClusterConfig,
    discovery_provider: DiscoveryProvider,
    handle: str,
    *,
    relay_path: tuple[str, ...],
) -> bool:
    try:
        require_route_handle(handle, field="routing node")
    except ProtocolInvariantError:
        return False
    if _kem_public_key_hex(discovery_provider, handle) is not None:
        return True
    return False


def _kem_public_key_hex(discovery_provider: DiscoveryProvider | None, node_id: str) -> str | None:
    if discovery_provider is None:
        return None
    try:
        require_route_handle(node_id, field="KEM lookup target")
    except ProtocolInvariantError:
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
