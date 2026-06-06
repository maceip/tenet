"""The experts match/mailbox workload that runs on the enclave host.

This is the tenant in the Set B split: it owns the ``/v1/match``,
``/v1/routing-key``, ``/v1/relay-path``, and ``/v1/deliver`` endpoints and the
``DiscoveryResult`` wire (de)serialization. The generic host
(``tenet.enclave.enclave_plane``) knows none of this — it just dispatches the route table
this module hands it.

Wire is byte-identical to the previous in-line handler; only the code location
changed (experts capability, not enclave host).
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from typing import Iterable, Mapping

from tenet.experts.directory import DiscoveryRequest, DiscoveryResult
from tenet.enclave.enclave_plane import (
    DEFAULT_ENCLAVE_PLANE_TIMEOUT_SECONDS,
    AttestedEnclaveClient,
    JsonRoute,
    StreamRoute,
    make_enclave_handler,
)
from tenet.experts.expert_route import PeerCandidate, PeerObservation, RouteIntent
from tenet.experts.memory_index import MemoryManifest


class MatchWorkloadClient(AttestedEnclaveClient):
    """Attested client for the match/mailbox workload's endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = DEFAULT_ENCLAVE_PLANE_TIMEOUT_SECONDS,
        arc_credential=None,
        mailbox_datagram_delivery_enabled: bool = True,
    ) -> None:
        super().__init__(base_url, timeout=timeout, arc_credential=arc_credential)
        self.mailbox_delivery_enabled = True
        self.mailbox_datagram_delivery_enabled = mailbox_datagram_delivery_enabled

    def discover(self, request: DiscoveryRequest) -> DiscoveryResult:
        raw = self.post_json(
            "/v1/match",
            {
                "mode": request.mode,
                "max_records": request.max_records,
                "intent": asdict(request.intent),
            },
        )
        return _discovery_result_from_dict(raw)

    def routing_kem_pk_hex(self, handle: str) -> str | None:
        raw = self.post_json("/v1/routing-key", {"handle": handle})
        value = raw.get("routing_kem_pk_hex")
        return str(value) if value else None

    def relay_path_for_handle(self, handle: str) -> tuple[str, ...]:
        raw = self.post_json("/v1/relay-path", {"handle": handle})
        return tuple(str(item) for item in raw.get("relay_path", ()))

    def deliver_to_handle(self, handle: str, datagram: bytes, *, timeout: float) -> Iterable[bytes]:
        return self.post_sse(
            "/v1/deliver",
            {
                "handle": handle,
                "timeout": timeout,
                "datagram_b64": base64.b64encode(datagram).decode("ascii"),
            },
            timeout=timeout,
        )


def match_workload_routes(
    provider,
) -> tuple[dict[str, JsonRoute], dict[str, StreamRoute]]:
    """Build the host route table for a match/mailbox discovery provider."""

    def match(raw: Mapping[str, object]) -> dict[str, object]:
        request = DiscoveryRequest(
            intent=RouteIntent(**dict(raw["intent"])),
            mode=str(raw["mode"]),
            max_records=raw.get("max_records"),
        )
        return _discovery_result_to_dict(provider.discover(request))

    def routing_key(raw: Mapping[str, object]) -> dict[str, object]:
        return {"routing_kem_pk_hex": provider.routing_kem_pk_hex(str(raw["handle"]))}

    def relay_path(raw: Mapping[str, object]) -> dict[str, object]:
        return {"relay_path": list(provider.relay_path_for_handle(str(raw["handle"])))}

    def deliver(raw: Mapping[str, object]) -> Iterable[bytes]:
        handle = str(raw["handle"])
        timeout = float(raw.get("timeout", DEFAULT_ENCLAVE_PLANE_TIMEOUT_SECONDS))
        datagram = base64.b64decode(str(raw["datagram_b64"]))
        return provider.deliver_to_handle(handle, datagram, timeout=timeout)

    return (
        {"/v1/match": match, "/v1/routing-key": routing_key, "/v1/relay-path": relay_path},
        {"/v1/deliver": deliver},
    )


def make_plain_enclave_plane_handler(provider):
    """Mount the match/mailbox workload's routes on the generic enclave host."""
    routes, stream_routes = match_workload_routes(provider)
    return make_enclave_handler(routes, stream_routes)


# Back-compat alias: the workload client used to live in tenet.enclave.enclave_plane.
PlainEnclavePlaneHttpClient = MatchWorkloadClient


def _discovery_result_to_dict(result: DiscoveryResult) -> dict[str, object]:
    return {
        "candidates": [_candidate_to_dict(candidate) for candidate in result.candidates],
        "mode": result.mode,
        "snapshot_size": result.snapshot_size,
        "exact_query_sent": result.exact_query_sent,
        "private_query_used": result.private_query_used,
        "generated_at": result.generated_at,
        "note": result.note,
    }


def _discovery_result_from_dict(raw: dict[str, object]) -> DiscoveryResult:
    return DiscoveryResult(
        candidates=tuple(
            _candidate_from_dict(item)
            for item in raw.get("candidates", ())
            if isinstance(item, dict)
        ),
        mode=str(raw["mode"]),
        snapshot_size=int(raw["snapshot_size"]),
        exact_query_sent=bool(raw["exact_query_sent"]),
        private_query_used=bool(raw["private_query_used"]),
        generated_at=str(raw["generated_at"]),
        note=str(raw["note"]),
    )


def _candidate_to_dict(candidate: PeerCandidate) -> dict[str, object]:
    return {
        "manifest": json.loads(candidate.manifest.to_json()),
        "observation": (
            asdict(candidate.observation) if candidate.observation is not None else None
        ),
    }


def _candidate_from_dict(raw: dict[str, object]) -> PeerCandidate:
    manifest_raw = raw["manifest"]
    if not isinstance(manifest_raw, dict):
        raise ValueError("candidate manifest must be an object")
    observation_raw = raw.get("observation")
    observation = None
    if isinstance(observation_raw, dict):
        observation = PeerObservation(**observation_raw)
    return PeerCandidate(
        MemoryManifest.from_json(json.dumps(manifest_raw)),
        observation,
    )
