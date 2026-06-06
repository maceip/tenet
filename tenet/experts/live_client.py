"""Live attested enclave client: expert-mode send via mailbox delivery."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence

from tenet.experts.client import ClientRunResult, run_client_once
from tenet.config import (
    ClusterConfig,
    ExpertRoutingConfig,
    PeerAddressConfig,
    TrustedReachabilityRelayConfig,
)
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.experts.live_enclave import LiveEnclaveConfig, build_attested_client
from tenet.experts.matcher import PLAIN_MATCHER_V1
from tenet.mixnet.control.live_sync import CONTROL_SYNC_PREFIXES, sync_control_from_cluster
from tenet.mixnet.control.service import MixnetControlService


DEFAULT_MAILBOX_CLIENT = (
    Path(__file__).resolve().parent.parent.parent / "config" / "live-mailbox-client.json"
)


@dataclass(frozen=True)
class LiveMailboxClientConfig:
    cluster: ClusterConfig
    peer_address: PeerAddressConfig
    trusted_reachability_relays: tuple[TrustedReachabilityRelayConfig, ...]
    expert_mode: ExpertModeConfig

    @classmethod
    def load(cls, path: str | Path | None = None) -> "LiveMailboxClientConfig":
        config_path = Path(path) if path is not None else DEFAULT_MAILBOX_CLIENT
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("live mailbox client config must be a JSON object")
        cluster = ClusterConfig.from_dict(raw)
        peer_raw = raw.get("peer_address") or {}
        peer_address = PeerAddressConfig.from_dict(
            peer_raw if isinstance(peer_raw, dict) else {}
        )
        relays_raw = raw.get("trusted_reachability_relays") or ()
        if not isinstance(relays_raw, Sequence):
            raise TypeError("trusted_reachability_relays must be a sequence")
        relays = tuple(
            TrustedReachabilityRelayConfig.from_dict(item)
            for item in relays_raw
            if isinstance(item, Mapping)
        )
        routing_raw = raw.get("expert_routing")
        if routing_raw is not None and not isinstance(routing_raw, Mapping):
            raise TypeError("expert_routing must be an object")
        expert_mode = replace(
            ExpertModeConfig.from_routing(ExpertRoutingConfig.from_dict(routing_raw)),
            discovery_mode=PLAIN_MATCHER_V1,
            allow_public_discovery_fallback=False,
        )
        return cls(
            cluster=cluster,
            peer_address=peer_address,
            trusted_reachability_relays=relays,
            expert_mode=expert_mode,
        )


def send_live_enclave(
    enclave_config: LiveEnclaveConfig,
    mailbox_config: LiveMailboxClientConfig,
    *,
    prompt: str,
    requested_expertise: str | None = None,
    service_name: str | None = None,
    timeout: float = 30.0,
    random_seed: int | None = None,
    mailbox_datagram_delivery_enabled: bool | None = None,
    control_service: MixnetControlService | None = None,
    match_gossip_salt: str | None = None,
    control_sync_prefixes=CONTROL_SYNC_PREFIXES,
) -> ClientRunResult:
    """Attest, plan, and deliver one envelope through the live enclave mailbox."""
    client = build_attested_client(
        enclave_config,
        mailbox_datagram_delivery_enabled=mailbox_datagram_delivery_enabled,
    )
    client.establish()
    sync_control_from_cluster(
        control_service,
        mailbox_config.cluster,
        prefixes=control_sync_prefixes,
    )
    return run_client_once(
        cluster=mailbox_config.cluster,
        discovery_provider=client,
        prompt=prompt,
        requested_expertise=requested_expertise,
        service_name=service_name,
        timeout=timeout,
        expert_mode_config=mailbox_config.expert_mode,
        peer_address_config=mailbox_config.peer_address,
        trusted_reachability_relays=mailbox_config.trusted_reachability_relays,
        random_seed=random_seed,
        control_service=control_service,
        match_gossip_salt=match_gossip_salt,
    )


def send_live_enclave_summary(
    enclave_config: LiveEnclaveConfig,
    mailbox_config: LiveMailboxClientConfig,
    *,
    prompt: str,
    requested_expertise: str | None = None,
    service_name: str | None = None,
    timeout: float = 30.0,
    random_seed: int | None = None,
    mailbox_datagram_delivery_enabled: bool | None = None,
    control_service: MixnetControlService | None = None,
    match_gossip_salt: str | None = None,
    control_sync_prefixes=CONTROL_SYNC_PREFIXES,
) -> dict[str, object]:
    client = build_attested_client(
        enclave_config,
        mailbox_datagram_delivery_enabled=mailbox_datagram_delivery_enabled,
    )
    att = client.establish()
    sync_control_from_cluster(
        control_service,
        mailbox_config.cluster,
        prefixes=control_sync_prefixes,
    )
    result = run_client_once(
        cluster=mailbox_config.cluster,
        discovery_provider=client,
        prompt=prompt,
        requested_expertise=requested_expertise,
        service_name=service_name,
        timeout=timeout,
        expert_mode_config=mailbox_config.expert_mode,
        peer_address_config=mailbox_config.peer_address,
        trusted_reachability_relays=mailbox_config.trusted_reachability_relays,
        random_seed=random_seed,
        control_service=control_service,
        match_gossip_salt=match_gossip_salt,
    )
    return {
        "ok": not result.fallback_used and bool(result.response_text.strip()),
        "url": enclave_config.url,
        "prompt": prompt,
        "selected_handle": result.selected_handle,
        "selected_peer_id": result.selected_peer_id,
        "fallback_used": result.fallback_used,
        "degraded_anonymity": result.degraded_anonymity,
        "response_text": result.response_text,
        "via_mailbox": "via=mailbox" in result.client_logs,
        "attestation": {
            "platform": att.platform,
            "value_x_prefix": f"{att.value_x[:16]}...",
        },
    }
