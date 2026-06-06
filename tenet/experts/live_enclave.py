"""Load checked-in trust policy for the live attested enclave plane."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from tenet.experts.directory import DiscoveryRequest
from tenet.enclave.enclave_attest import (
    AttestedEnclavePlaneClient,
    EnclaveTrustPolicy,
    SubprocessAttestedWorkloadVerifier,
)
from tenet.experts.match_workload import PlainEnclavePlaneHttpClient
from tenet.experts.expert_route import RouteIntent
from tenet.experts.matcher import PLAIN_MATCHER_V1


LIVE_ENCLAVE_SCHEMA = "por.live_enclave.v1"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "live-enclave.json"


@dataclass(frozen=True)
class LiveEnclaveConfig:
    url: str
    approved_value_x: tuple[str, ...]
    tls_spki_hash: str
    require_spki_pin: bool = True
    aw_bin: str = "aw"
    timeout: float = 30.0
    attested_workload_sha: str | None = None
    mailbox_datagram_delivery_enabled: bool = False

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "LiveEnclaveConfig":
        schema = str(raw.get("schema", ""))
        if schema and schema != LIVE_ENCLAVE_SCHEMA:
            raise ValueError(f"unsupported live enclave config schema: {schema!r}")
        url = str(raw.get("url", "")).rstrip("/")
        if not url.startswith("https://"):
            raise ValueError("live enclave url must use https://")
        approved_raw = raw.get("approved_value_x") or ()
        if isinstance(approved_raw, str):
            approved = (approved_raw,) if approved_raw else ()
        elif isinstance(approved_raw, Sequence):
            approved = tuple(str(item) for item in approved_raw)
        else:
            raise TypeError("approved_value_x must be a string or sequence")
        if not approved:
            raise ValueError("approved_value_x must not be empty")
        spki = str(raw.get("tls_spki_hash", "")).lower()
        if not spki:
            raise ValueError("tls_spki_hash is required")
        return cls(
            url=url,
            approved_value_x=approved,
            tls_spki_hash=spki,
            require_spki_pin=bool(raw.get("require_spki_pin", True)),
            aw_bin=str(raw.get("aw_bin", "aw")),
            timeout=float(raw.get("timeout", 30.0)),
            attested_workload_sha=_optional_str(raw.get("attested_workload_sha")),
            mailbox_datagram_delivery_enabled=bool(
                raw.get("mailbox_datagram_delivery_enabled", False)
            ),
        )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "LiveEnclaveConfig":
        config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("live enclave config must be a JSON object")
        return cls.from_dict(raw)


def build_attested_client(
    config: LiveEnclaveConfig,
    *,
    mailbox_datagram_delivery_enabled: bool | None = None,
) -> AttestedEnclavePlaneClient:
    delivery_enabled = (
        config.mailbox_datagram_delivery_enabled
        if mailbox_datagram_delivery_enabled is None
        else mailbox_datagram_delivery_enabled
    )
    inner = PlainEnclavePlaneHttpClient(
        config.url,
        timeout=config.timeout,
        mailbox_datagram_delivery_enabled=delivery_enabled,
    )
    policy = EnclaveTrustPolicy(
        approved_value_x=frozenset(config.approved_value_x),
        require_spki_pin=config.require_spki_pin,
    )
    verifier = SubprocessAttestedWorkloadVerifier(
        runcard_bin=config.aw_bin,
        timeout=config.timeout,
    )
    return AttestedEnclavePlaneClient(inner, verifier=verifier, policy=policy)


def check_live_enclave(config: LiveEnclaveConfig) -> dict[str, object]:
    """Verify attestation + policy; return summary dict for CLI/JSON output."""
    client = build_attested_client(config)
    att = client.establish()
    if att.tls_spki_hash.lower() != config.tls_spki_hash.lower():
        raise ValueError(
            f"tls_spki_hash mismatch: config={config.tls_spki_hash} "
            f"aw_check={att.tls_spki_hash}"
        )
    return {
        "ok": True,
        "url": config.url,
        "platform": att.platform,
        "value_x": att.value_x,
        "tls_spki_hash": att.tls_spki_hash,
        "pinned": bool(client.pinned_spki),
    }


def match_live_enclave(
    config: LiveEnclaveConfig,
    *,
    prompt: str,
    requested_expertise: str | None = None,
    max_records: int = 4,
) -> dict[str, object]:
    client = build_attested_client(config)
    client.establish()
    result = client.discover(
        DiscoveryRequest(
            RouteIntent(prompt=prompt, requested_expertise=requested_expertise),
            mode=PLAIN_MATCHER_V1,
            max_records=max_records,
        )
    )
    return {
        "mode": result.mode,
        "candidate_count": len(result.candidates),
        "candidates": [
            {
                "peer_id": candidate.manifest.peer_id,
            }
            for candidate in result.candidates
        ],
        "private_query_used": result.private_query_used,
    }


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None
