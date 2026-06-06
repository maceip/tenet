"""Shared configuration schema for tenet daemons.

This module is intentionally dependency-free. It gives the client, mixnode,
expert, gateway, and directory daemons one JSON-shaped config contract without
pulling daemon logic into packet processing.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from tenet.schema import normalize_schema, supports_schema


CONFIG_VERSION = "tenet.config.2026-06"

ROLE_CLIENT = "client"
ROLE_MIXNODE = "mixnode"
LEGACY_ROLE_RELAY = "relay"
ROLE_RELAY = ROLE_MIXNODE
ROLE_EXPERT = "expert"
ROLE_GATEWAY = "gateway"
ROLE_DIRECTORY = "directory"
VALID_ROLES = {ROLE_CLIENT, ROLE_RELAY, ROLE_EXPERT, ROLE_GATEWAY, ROLE_DIRECTORY}

CAPABILITY_CLIENT = "client"
CAPABILITY_MIXNODE = "mixnode"
CAPABILITY_EXPERT = "expert"
CAPABILITY_REACHABILITY_RELAY = "reachability_relay"
CAPABILITY_CONTROL_DHT = "control_dht"
CAPABILITY_MATCHER = "matcher"
CAPABILITY_MAILBOX = "mailbox"
CAPABILITY_TEE = "tee"
CAPABILITY_DIRECTORY = "directory"
VALID_NODE_CAPABILITIES = {
    CAPABILITY_CLIENT,
    CAPABILITY_MIXNODE,
    CAPABILITY_EXPERT,
    CAPABILITY_REACHABILITY_RELAY,
    CAPABILITY_CONTROL_DHT,
    CAPABILITY_MATCHER,
    CAPABILITY_MAILBOX,
    CAPABILITY_TEE,
    CAPABILITY_DIRECTORY,
}

TRANSPORT_UDP = "udp"
TRANSPORT_QUIC_H3 = "quic_h3"
TRANSPORT_QUIC_DATAGRAM = "quic_datagram"
VALID_TRANSPORTS = {TRANSPORT_UDP, TRANSPORT_QUIC_H3, TRANSPORT_QUIC_DATAGRAM}

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 0
DEFAULT_PAYLOAD_SIZE = 2048
# Legacy cluster configs use a wider route field than core OutfoxParams.
DEFAULT_ROUTING_SIZE = 96
DEFAULT_MAX_HOPS = 5
DEFAULT_CIRCUIT_TTL_SECONDS = 120
DEFAULT_MAX_DATAGRAM_FRAME_SIZE = 1200
DEFAULT_MAX_FRAME_SIZE = 1_048_576
DEFAULT_RECEIVE_QUEUE_SIZE = 1024
DEFAULT_CONTROL_SYNC_PREFIXES = (
    "trust/",
    "mixnode/",
    "pool/",
    "client/",
    "name/",
    "match/",
    "expert/",
    "topic/",
    "review/",
)


@dataclass(frozen=True)
class EndpointConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "EndpointConfig":
        raw = raw or {}
        return cls(
            host=str(raw.get("host", DEFAULT_HOST)),
            port=int(raw.get("port", DEFAULT_PORT)),
        ).validate()

    def validate(self) -> "EndpointConfig":
        if not self.host:
            raise ValueError("endpoint host is required")
        if not 0 <= int(self.port) <= 65535:
            raise ValueError("endpoint port must be 0..65535")
        return self


@dataclass(frozen=True)
class PeerEndpointConfig:
    peer_id: str
    endpoint: EndpointConfig
    transport: str = TRANSPORT_QUIC_H3
    kem_public_key_hex: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, peer_id: str, raw: Mapping[str, object]) -> "PeerEndpointConfig":
        endpoint = EndpointConfig.from_dict(raw)
        return cls(
            peer_id=str(raw.get("peer_id", peer_id)),
            endpoint=endpoint,
            transport=str(raw.get("transport", TRANSPORT_QUIC_H3)),
            kem_public_key_hex=_optional_str(raw.get("kem_public_key_hex") or raw.get("kem_pk")),
        ).validate()

    def validate(self) -> "PeerEndpointConfig":
        if not self.peer_id:
            raise ValueError("peer_id is required")
        if self.transport not in VALID_TRANSPORTS:
            raise ValueError(f"unsupported peer transport: {self.transport}")
        self.endpoint.validate()
        return self


@dataclass(frozen=True)
class PacketConfig:
    payload_size: int = DEFAULT_PAYLOAD_SIZE
    routing_size: int = DEFAULT_ROUTING_SIZE
    max_hops: int = DEFAULT_MAX_HOPS
    circuit_ttl_seconds: int = DEFAULT_CIRCUIT_TTL_SECONDS

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "PacketConfig":
        raw = raw or {}
        return cls(
            payload_size=int(raw.get("payload_size", DEFAULT_PAYLOAD_SIZE)),
            routing_size=int(raw.get("routing_size", DEFAULT_ROUTING_SIZE)),
            max_hops=int(raw.get("max_hops", DEFAULT_MAX_HOPS)),
            circuit_ttl_seconds=int(raw.get("circuit_ttl_seconds", DEFAULT_CIRCUIT_TTL_SECONDS)),
        ).validate()

    def validate(self) -> "PacketConfig":
        if self.payload_size <= 0:
            raise ValueError("payload_size must be positive")
        if self.routing_size <= 0:
            raise ValueError("routing_size must be positive")
        if self.max_hops <= 0:
            raise ValueError("max_hops must be positive")
        if self.circuit_ttl_seconds <= 0:
            raise ValueError("circuit_ttl_seconds must be positive")
        return self

    def outfox_kwargs(self) -> dict[str, int]:
        return {
            "payload_size": self.payload_size,
            "routing_size": self.routing_size,
            "max_hops": self.max_hops,
        }


@dataclass(frozen=True)
class ClusterNodeConfig:
    node_id: str
    host: str
    port: int
    kem_pk_hex: str
    kem_sk_hex: str = ""
    role: str = ROLE_MIXNODE
    capabilities: tuple[str, ...] = (CAPABILITY_MIXNODE, CAPABILITY_CONTROL_DHT)

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, node_id: str, raw: Mapping[str, object]) -> "ClusterNodeConfig":
        role = _normalize_role(str(raw.get("role", ROLE_MIXNODE)))
        return cls(
            node_id=str(raw.get("node_id", node_id)),
            host=str(raw.get("host", DEFAULT_HOST)),
            port=int(raw.get("port", DEFAULT_PORT)),
            kem_pk_hex=str(raw.get("kem_pk_hex", raw.get("kem_pk", ""))),
            kem_sk_hex=str(raw.get("kem_sk_hex", raw.get("kem_sk", ""))),
            role=role,
            capabilities=_capabilities_from_raw(raw.get("capabilities"), role),
        )

    def validate(self) -> "ClusterNodeConfig":
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.host:
            raise ValueError("node host is required")
        if not 0 <= int(self.port) <= 65535:
            raise ValueError("node port must be 0..65535")
        if not self.kem_pk_hex:
            raise ValueError("kem_pk_hex is required")
        if self.role not in {ROLE_MIXNODE, ROLE_EXPERT, "any"}:
            raise ValueError(f"unsupported cluster node role: {self.role}")
        _validate_capabilities(self.capabilities)
        return self

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def to_legacy_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "kem_pk": self.kem_pk_hex,
            "kem_sk": self.kem_sk_hex,
            "role": self.role,
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True)
class ClusterConfig:
    """Local cluster config for coordinated node startup.

    Used when multiple nodes share a config file (e.g. local development,
    integration tests). Relay addresses here are transport endpoints, not
    expert identities — experts are discovered via directory + REACH.
    """

    params: PacketConfig
    client: EndpointConfig
    nodes: dict[str, ClusterNodeConfig]

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ClusterConfig":
        nodes_raw = _mapping_or_none(raw.get("nodes")) or {}
        return cls(
            params=PacketConfig.from_dict(_mapping_or_none(raw.get("params") or raw.get("packet"))),
            client=EndpointConfig.from_dict(_mapping_or_none(raw.get("client"))),
            nodes={
                str(node_id): ClusterNodeConfig.from_dict(str(node_id), _mapping_or_empty(node_raw))
                for node_id, node_raw in nodes_raw.items()
            },
        )

    @classmethod
    def load(cls, path: str | Path) -> "ClusterConfig":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def validate(self) -> "ClusterConfig":
        self.params.validate()
        self.client.validate()
        if not self.nodes:
            raise ValueError("cluster config requires at least one node")
        for key, node in self.nodes.items():
            if key != node.node_id:
                raise ValueError(f"node map key {key!r} does not match node_id {node.node_id!r}")
            node.validate()
        return self

    def node(self, node_id: str) -> ClusterNodeConfig:
        try:
            return self.nodes[node_id]
        except KeyError as exc:
            raise KeyError(f"unknown cluster node_id: {node_id}") from exc

    def to_legacy_dict(self) -> dict[str, object]:
        return {
            "params": {
                "payload_size": self.params.payload_size,
                "routing_size": self.params.routing_size,
                "max_hops": self.params.max_hops,
            },
            "client": {"host": self.client.host, "port": self.client.port},
            "nodes": {
                node_id: node.to_legacy_dict()
                for node_id, node in self.nodes.items()
            },
        }


@dataclass(frozen=True)
class TransportConfig:
    kind: str = TRANSPORT_QUIC_H3
    bind: EndpointConfig = field(default_factory=EndpointConfig)
    verify_tls: bool = True
    dev_allow_insecure_tls: bool = False
    certfile: str | None = None
    keyfile: str | None = None
    alpn: str | None = None
    max_datagram_frame_size: int = DEFAULT_MAX_DATAGRAM_FRAME_SIZE
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE
    receive_queue_size: int = DEFAULT_RECEIVE_QUEUE_SIZE

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "TransportConfig":
        raw = raw or {}
        bind_raw = raw.get("bind")
        if bind_raw is None and ("host" in raw or "port" in raw):
            bind_raw = raw
        return cls(
            kind=str(raw.get("kind", raw.get("name", TRANSPORT_QUIC_H3))),
            bind=EndpointConfig.from_dict(_mapping_or_none(bind_raw)),
            verify_tls=_bool(raw.get("verify_tls", True)),
            dev_allow_insecure_tls=_bool(raw.get("dev_allow_insecure_tls", False)),
            certfile=_optional_str(raw.get("certfile")),
            keyfile=_optional_str(raw.get("keyfile")),
            alpn=_optional_str(raw.get("alpn")),
            max_datagram_frame_size=int(raw.get("max_datagram_frame_size", DEFAULT_MAX_DATAGRAM_FRAME_SIZE)),
            max_frame_size=int(raw.get("max_frame_size", raw.get("max_h3_message_size", DEFAULT_MAX_FRAME_SIZE))),
            receive_queue_size=int(raw.get("receive_queue_size", DEFAULT_RECEIVE_QUEUE_SIZE)),
        ).validate()

    def validate(self) -> "TransportConfig":
        if self.kind not in VALID_TRANSPORTS:
            raise ValueError(f"unsupported transport kind: {self.kind}")
        self.bind.validate()
        if not self.verify_tls and not self.dev_allow_insecure_tls:
            raise ValueError("verify_tls=false requires dev_allow_insecure_tls=true")
        if self.max_datagram_frame_size <= 0:
            raise ValueError("max_datagram_frame_size must be positive")
        if self.max_frame_size <= 0:
            raise ValueError("max_frame_size must be positive")
        if self.receive_queue_size <= 0:
            raise ValueError("receive_queue_size must be positive")
        return self


@dataclass(frozen=True)
class DirectoryConfig:
    mode: str = "public_snapshot_v1"
    snapshot_path: str | None = None
    refresh_interval_seconds: int = 60

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "DirectoryConfig":
        raw = raw or {}
        return cls(
            mode=str(raw.get("mode", "public_snapshot_v1")),
            snapshot_path=_optional_str(raw.get("snapshot_path")),
            refresh_interval_seconds=int(raw.get("refresh_interval_seconds", 60)),
        ).validate()

    def validate(self) -> "DirectoryConfig":
        if not self.mode:
            raise ValueError("directory mode is required")
        if self.refresh_interval_seconds <= 0:
            raise ValueError("refresh_interval_seconds must be positive")
        return self


@dataclass(frozen=True)
class ExpertRoutingConfig:
    min_pool_size: int = 3
    allow_degraded_pool: bool = True
    fallback_provider: str = "frontier"
    discovery_mode: str = "public_snapshot_v1"
    allow_public_discovery_fallback: bool = True
    require_hybrid_return: bool = True
    discovery_max_records: int | None = None

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "ExpertRoutingConfig":
        raw = raw or {}
        return cls(
            min_pool_size=int(raw.get("min_pool_size", 3)),
            allow_degraded_pool=_bool(raw.get("allow_degraded_pool", True)),
            fallback_provider=str(raw.get("fallback_provider", "frontier")),
            discovery_mode=str(raw.get("discovery_mode", "public_snapshot_v1")),
            allow_public_discovery_fallback=_bool(raw.get("allow_public_discovery_fallback", True)),
            require_hybrid_return=_bool(raw.get("require_hybrid_return", True)),
            discovery_max_records=_optional_int(raw.get("discovery_max_records")),
        ).validate()

    def validate(self) -> "ExpertRoutingConfig":
        if self.min_pool_size <= 0:
            raise ValueError("min_pool_size must be positive")
        if not self.fallback_provider:
            raise ValueError("fallback_provider is required")
        return self


@dataclass(frozen=True)
class ProviderConfig:
    provider: str = ""
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    stream: bool = True
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "ProviderConfig":
        raw = raw or {}
        return cls(
            provider=str(raw.get("provider", "")),
            model=_optional_str(raw.get("model")),
            base_url=_optional_str(raw.get("base_url")),
            api_key_env=_optional_str(raw.get("api_key_env")),
            stream=_bool(raw.get("stream", True)),
            timeout_seconds=float(raw.get("timeout_seconds", 60.0)),
        ).validate()

    def validate(self) -> "ProviderConfig":
        provider = self.provider.strip().lower()
        if not provider:
            raise ValueError("provider is required")
        if provider not in {"anthropic", "openai"}:
            raise ValueError(f"unsupported provider: {self.provider}")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        return self

    def resolve_api_key(self, env: Mapping[str, str] | None = None) -> str | None:
        if not self.api_key_env:
            return None
        source = os.environ if env is None else env
        return source.get(self.api_key_env)


@dataclass(frozen=True)
class PeerAddressConfig:
    enabled: bool = False
    allow_direct: bool = False
    prefer_direct: bool = False
    records: dict[str, dict[str, object]] = field(default_factory=dict)
    heartbeat_interval_seconds: int = 90
    registration_ttl_seconds: int = 270

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "PeerAddressConfig":
        raw = raw or {}
        return cls(
            enabled=_bool(raw.get("enabled", False)),
            allow_direct=_bool(raw.get("allow_direct", False)),
            prefer_direct=_bool(raw.get("prefer_direct", False)),
            records={
                str(peer_id): _mutable_mapping_copy(record_raw)
                for peer_id, record_raw in (_mapping_or_none(raw.get("records")) or {}).items()
            },
            heartbeat_interval_seconds=int(raw.get("heartbeat_interval_seconds", 90)),
            registration_ttl_seconds=int(raw.get("registration_ttl_seconds", 270)),
        ).validate()

    def validate(self) -> "PeerAddressConfig":
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        if self.registration_ttl_seconds <= 0:
            raise ValueError("registration_ttl_seconds must be positive")
        if self.prefer_direct and not self.allow_direct:
            raise ValueError("prefer_direct requires allow_direct")
        return self


@dataclass(frozen=True)
class TrustedReachabilityRelayConfig:
    relay_id: str
    host: str
    port: int
    verify_key: str

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "TrustedReachabilityRelayConfig":
        return cls(
            relay_id=str(raw.get("relay_id", "")),
            host=str(raw.get("host", DEFAULT_HOST)),
            port=int(raw.get("port", DEFAULT_PORT)),
            verify_key=str(raw.get("verify_key", "")),
        ).validate()

    def validate(self) -> "TrustedReachabilityRelayConfig":
        if not self.relay_id:
            raise ValueError("trusted reachability relay_id is required")
        if not self.host:
            raise ValueError("trusted reachability relay host is required")
        if not 0 < int(self.port) <= 65535:
            raise ValueError("trusted reachability relay port must be 1..65535")
        if not self.verify_key:
            raise ValueError("trusted reachability relay verify_key is required")
        try:
            bytes.fromhex(self.verify_key)
        except ValueError as exc:
            raise ValueError("trusted reachability relay verify_key must be hex") from exc
        return self


@dataclass(frozen=True)
class LocalHttpConfig:
    enabled: bool = False
    bind: EndpointConfig = field(default_factory=lambda: EndpointConfig(DEFAULT_HOST, 8766))
    path: str = "/v1/expert"
    status_path: str = "/v1/status"

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "LocalHttpConfig":
        raw = raw or {}
        bind_raw = raw.get("bind")
        if bind_raw is None and ("host" in raw or "port" in raw):
            bind_raw = raw
        return cls(
            enabled=_bool(raw.get("enabled", False)),
            bind=EndpointConfig.from_dict(_mapping_or_none(bind_raw)),
            path=str(raw.get("path", "/v1/expert")),
            status_path=str(raw.get("status_path", "/v1/status")),
        ).validate()

    def validate(self) -> "LocalHttpConfig":
        self.bind.validate()
        if not self.path.startswith("/"):
            raise ValueError("local_http.path must start with /")
        if not self.status_path.startswith("/"):
            raise ValueError("local_http.status_path must start with /")
        if self.status_path == self.path:
            raise ValueError("local_http.status_path must differ from local_http.path")
        return self


@dataclass(frozen=True)
class ClientConfig:
    directory_snapshot: str | None = None
    prompt: str | None = None
    expertise: str | None = None
    relay_path: tuple[str, ...] = ()
    timeout_seconds: float = 8.0
    random_seed: int | None = None
    max_concurrent_requests: int = 8
    trusted_reachability_relays: tuple[TrustedReachabilityRelayConfig, ...] = ()
    dev_allow_untrusted_reachability_relays: bool = False
    local_http: LocalHttpConfig = field(default_factory=LocalHttpConfig)

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "ClientConfig":
        raw = raw or {}
        return cls(
            directory_snapshot=_optional_str(raw.get("directory_snapshot") or raw.get("directory_snapshot_url")),
            prompt=_optional_str(raw.get("prompt")),
            expertise=_optional_str(raw.get("expertise")),
            relay_path=_string_tuple(raw.get("relay_path")),
            timeout_seconds=float(raw.get("timeout_seconds", raw.get("timeout", 8.0))),
            random_seed=_optional_int(raw.get("random_seed")),
            max_concurrent_requests=int(raw.get("max_concurrent_requests", 8)),
            trusted_reachability_relays=tuple(
                TrustedReachabilityRelayConfig.from_dict(_mapping_or_empty(item))
                for item in _sequence_or_empty(raw.get("trusted_reachability_relays"))
            ),
            dev_allow_untrusted_reachability_relays=_bool(
                raw.get("dev_allow_untrusted_reachability_relays", False)
            ),
            local_http=LocalHttpConfig.from_dict(_mapping_or_none(raw.get("local_http"))),
        ).validate()

    def validate(self) -> "ClientConfig":
        if self.timeout_seconds <= 0:
            raise ValueError("client timeout_seconds must be positive")
        if self.max_concurrent_requests <= 0:
            raise ValueError("client max_concurrent_requests must be positive")
        relay_ids = [relay.relay_id for relay in self.trusted_reachability_relays]
        if len(set(relay_ids)) != len(relay_ids):
            raise ValueError("trusted reachability relay_id values must be unique")
        return self


@dataclass(frozen=True)
class SupernodeConfig:
    enabled: bool = False
    public_ip: str | None = None
    relay_secret_hex: str | None = None
    advertise_relay: bool = False
    register_directory: bool = False
    accept_inbound_mix: bool = False
    promote_expert: bool = False

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "SupernodeConfig":
        raw = raw or {}
        return cls(
            enabled=_bool(raw.get("enabled", False)),
            public_ip=_optional_str(raw.get("public_ip")),
            relay_secret_hex=_optional_str(raw.get("relay_secret_hex")),
            advertise_relay=_bool(raw.get("advertise_relay", False)),
            register_directory=_bool(raw.get("register_directory", False)),
            accept_inbound_mix=_bool(raw.get("accept_inbound_mix", False)),
            promote_expert=_bool(raw.get("promote_expert", False)),
        ).validate()

    def validate(self) -> "SupernodeConfig":
        promoted = (
            self.advertise_relay
            or self.register_directory
            or self.accept_inbound_mix
            or self.promote_expert
        )
        if promoted and not self.enabled:
            raise ValueError("supernode promotion flags require supernode.enabled=true")
        if (self.advertise_relay or self.register_directory) and not self.public_ip:
            raise ValueError("supernode public_ip is required for relay advertisement or directory registration")
        if self.relay_secret_hex:
            try:
                secret = bytes.fromhex(self.relay_secret_hex)
            except ValueError as exc:
                raise ValueError("supernode.relay_secret_hex must be hex") from exc
            if len(secret) < 16:
                raise ValueError("supernode.relay_secret_hex must be at least 16 bytes")
        return self


@dataclass(frozen=True)
class ReachRegistrationConfig:
    """Expert-side REACH registration against a public reachability relay (item 12)."""

    enabled: bool = False
    relay_host: str = ""
    relay_port: int = 4433
    peer_id: str | None = None
    heartbeat_interval_seconds: float = 300.0

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "ReachRegistrationConfig":
        raw = raw or {}
        return cls(
            enabled=_bool(raw.get("enabled", False)),
            relay_host=str(raw.get("relay_host", "")),
            relay_port=int(raw.get("relay_port", 4433)),
            peer_id=_optional_str(raw.get("peer_id")),
            heartbeat_interval_seconds=float(raw.get("heartbeat_interval_seconds", 300.0)),
        ).validate()

    def validate(self) -> "ReachRegistrationConfig":
        if not self.enabled:
            return self
        if not self.relay_host:
            raise ValueError("reach_registration.relay_host is required when enabled")
        if not (1 <= self.relay_port <= 65535):
            raise ValueError("reach_registration.relay_port must be 1..65535")
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("reach_registration.heartbeat_interval_seconds must be positive")
        return self


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "info"
    fmt: str = "json"
    redact_fields: tuple[str, ...] = (
        "api_key",
        "authorization",
        "bearer",
        "prompt",
        "prompt_payload",
        "secret",
        "token",
    )

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "LoggingConfig":
        raw = raw or {}
        redact = raw.get("redact_fields", cls.redact_fields)
        return cls(
            level=str(raw.get("level", "info")).lower(),
            fmt=str(raw.get("fmt", "json")).lower(),
            redact_fields=tuple(str(item) for item in redact),
        ).validate()

    def validate(self) -> "LoggingConfig":
        if self.level not in {"debug", "info", "warning", "error"}:
            raise ValueError(f"unsupported log level: {self.level}")
        if self.fmt not in {"json", "plain"}:
            raise ValueError(f"unsupported log format: {self.fmt}")
        return self


@dataclass(frozen=True)
class ControlPlaneConfig:
    enabled: bool = True
    store_path: str | None = None
    bootstrap_path: str | None = None
    verify_keys: dict[str, str] = field(default_factory=dict)
    threshold: int = 1
    anti_entropy_interval_seconds: float = 0.0
    sync_prefixes: tuple[str, ...] = DEFAULT_CONTROL_SYNC_PREFIXES
    replication_factor: int = 5

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> "ControlPlaneConfig":
        raw = raw or {}
        verify_raw = _mapping_or_none(raw.get("verify_keys")) or {}
        prefixes_raw = raw.get("sync_prefixes")
        if prefixes_raw is None:
            prefixes_raw = DEFAULT_CONTROL_SYNC_PREFIXES
        if isinstance(prefixes_raw, str):
            prefixes = (prefixes_raw,)
        else:
            prefixes = tuple(str(item) for item in prefixes_raw)
        return cls(
            enabled=_bool(raw.get("enabled", True)),
            store_path=_optional_str(raw.get("store_path")),
            bootstrap_path=_optional_str(raw.get("bootstrap_path")),
            verify_keys={str(key): str(value) for key, value in verify_raw.items()},
            threshold=int(raw.get("threshold", 1)),
            anti_entropy_interval_seconds=float(
                raw.get("anti_entropy_interval_seconds", 0.0)
            ),
            sync_prefixes=prefixes,
            replication_factor=int(raw.get("replication_factor", 5)),
        )

    def validate(self) -> "ControlPlaneConfig":
        if self.threshold < 1:
            raise ValueError("control.threshold must be positive")
        if self.anti_entropy_interval_seconds < 0:
            raise ValueError("control.anti_entropy_interval_seconds must be non-negative")
        if self.replication_factor < 1:
            raise ValueError("control.replication_factor must be positive")
        if not self.sync_prefixes:
            raise ValueError("control.sync_prefixes must not be empty")
        if any(not prefix for prefix in self.sync_prefixes):
            raise ValueError("control.sync_prefixes entries must be non-empty")
        for key_id, key_hex in self.verify_keys.items():
            if not key_id:
                raise ValueError("control verify key id is required")
            try:
                bytes.fromhex(key_hex)
            except ValueError as exc:
                raise ValueError("control verify keys must be hex") from exc
        return self


@dataclass(frozen=True)
class DaemonConfig:
    node_id: str
    role: str
    capabilities: tuple[str, ...] = ()
    kem_pk_hex: str | None = None
    kem_sk_hex: str | None = None
    transport: TransportConfig = field(default_factory=TransportConfig)
    packet: PacketConfig = field(default_factory=PacketConfig)
    directory: DirectoryConfig = field(default_factory=DirectoryConfig)
    client: ClientConfig = field(default_factory=ClientConfig)
    expert_routing: ExpertRoutingConfig = field(default_factory=ExpertRoutingConfig)
    provider: ProviderConfig | None = None
    peer_address: PeerAddressConfig = field(default_factory=PeerAddressConfig)
    supernode: SupernodeConfig = field(default_factory=SupernodeConfig)
    reach_registration: ReachRegistrationConfig = field(default_factory=ReachRegistrationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    control: ControlPlaneConfig = field(default_factory=ControlPlaneConfig)
    peers: dict[str, PeerEndpointConfig] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "DaemonConfig":
        node_id = str(raw.get("node_id", ""))
        role = _normalize_role(str(raw.get("role", "")))
        peers_raw = _mapping_or_none(raw.get("peers")) or {}
        return cls(
            node_id=node_id,
            role=role,
            capabilities=_capabilities_from_raw(raw.get("capabilities"), role),
            kem_pk_hex=_optional_str(raw.get("kem_pk_hex") or raw.get("kem_pk")),
            kem_sk_hex=_optional_str(raw.get("kem_sk_hex") or raw.get("kem_sk")),
            transport=TransportConfig.from_dict(_mapping_or_none(raw.get("transport"))),
            packet=PacketConfig.from_dict(_mapping_or_none(raw.get("packet") or raw.get("params"))),
            directory=DirectoryConfig.from_dict(_mapping_or_none(raw.get("directory"))),
            client=ClientConfig.from_dict(_mapping_or_none(raw.get("client"))),
            expert_routing=ExpertRoutingConfig.from_dict(_mapping_or_none(raw.get("expert_routing"))),
            provider=(
                ProviderConfig.from_dict(_mapping_or_none(raw.get("provider")))
                if raw.get("provider") is not None
                else None
            ),
            peer_address=PeerAddressConfig.from_dict(_mapping_or_none(raw.get("peer_address"))),
            supernode=SupernodeConfig.from_dict(_mapping_or_none(raw.get("supernode"))),
            reach_registration=ReachRegistrationConfig.from_dict(
                _mapping_or_none(raw.get("reach_registration"))
            ),
            logging=LoggingConfig.from_dict(_mapping_or_none(raw.get("logging"))),
            control=ControlPlaneConfig.from_dict(_mapping_or_none(raw.get("control"))),
            peers={
                str(peer_id): PeerEndpointConfig.from_dict(str(peer_id), _mapping_or_empty(peer_raw))
                for peer_id, peer_raw in peers_raw.items()
            },
        ).validate()

    def validate(self) -> "DaemonConfig":
        if not self.node_id:
            raise ValueError("node_id is required")
        if self.role not in VALID_ROLES:
            raise ValueError(f"unsupported daemon role: {self.role}")
        _validate_capabilities(self.capabilities)
        self.transport.validate()
        self.packet.validate()
        self.directory.validate()
        self.client.validate()
        self.expert_routing.validate()
        if self.provider is not None:
            self.provider.validate()
        self.peer_address.validate()
        self.supernode.validate()
        self.reach_registration.validate()
        self.logging.validate()
        self.control.validate()
        for peer in self.peers.values():
            peer.validate()
        return self

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def cluster_node(self) -> ClusterNodeConfig:
        if not (
            self.has_capability(CAPABILITY_MIXNODE)
            or self.has_capability(CAPABILITY_EXPERT)
            or self.has_capability(CAPABILITY_CONTROL_DHT)
        ):
            raise ValueError(f"{self.node_id} role {self.role!r} is not a cluster node")
        if not self.kem_pk_hex or not self.kem_sk_hex:
            raise ValueError(f"{self.node_id} requires kem_pk_hex and kem_sk_hex")
        bind = self.transport.bind
        return ClusterNodeConfig(
            node_id=self.node_id,
            host=bind.host,
            port=bind.port,
            kem_pk_hex=self.kem_pk_hex,
            kem_sk_hex=self.kem_sk_hex,
            role=self.role,
            capabilities=self.capabilities,
        )


@dataclass(frozen=True)
class PorConfig:
    version: str = CONFIG_VERSION
    daemons: dict[str, DaemonConfig] = field(default_factory=dict)
    default_node_id: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def load(cls, path: str | Path) -> "PorConfig":
        return load_config(path)

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "PorConfig":
        if "daemons" not in raw:
            daemon = DaemonConfig.from_dict(raw)
            return cls(daemons={daemon.node_id: daemon}, default_node_id=daemon.node_id).validate()

        daemons_raw = _mapping_or_none(raw.get("daemons")) or {}
        daemons = {
            str(node_id): DaemonConfig.from_dict(
                {**_mapping_or_empty(value), "node_id": _mapping_or_empty(value).get("node_id", node_id)}
            )
            for node_id, value in daemons_raw.items()
        }
        return cls(
            version=normalize_schema(str(raw.get("version", CONFIG_VERSION)), CONFIG_VERSION),
            daemons=daemons,
            default_node_id=_optional_str(raw.get("default_node_id")),
        ).validate()

    def validate(self) -> "PorConfig":
        if not supports_schema(self.version, CONFIG_VERSION):
            raise ValueError(f"unsupported config version: {self.version}")
        if not self.daemons:
            raise ValueError("at least one daemon config is required")
        for key, daemon in self.daemons.items():
            if key != daemon.node_id:
                raise ValueError(f"daemon map key {key!r} does not match node_id {daemon.node_id!r}")
            daemon.validate()
        if self.default_node_id is not None and self.default_node_id not in self.daemons:
            raise ValueError("default_node_id is not present in daemons")
        return self

    def daemon(self, node_id: str | None = None) -> DaemonConfig:
        selected = node_id or self.default_node_id
        if selected is None:
            if len(self.daemons) == 1:
                return next(iter(self.daemons.values()))
            raise ValueError("node_id is required when config has multiple daemons")
        try:
            return self.daemons[selected]
        except KeyError as exc:
            raise KeyError(f"unknown daemon node_id: {selected}") from exc

    def client_daemon(self, node_id: str | None = None) -> DaemonConfig | None:
        if node_id is not None:
            daemon = self.daemon(node_id)
            if daemon.role != ROLE_CLIENT:
                raise ValueError(f"{node_id} is not a client daemon")
            return daemon
        clients = [daemon for daemon in self.daemons.values() if daemon.role == ROLE_CLIENT]
        if not clients:
            return None
        if self.default_node_id:
            default = self.daemons[self.default_node_id]
            if default.role == ROLE_CLIENT:
                return default
        return clients[0]

    def to_cluster_config(self, *, client_node_id: str | None = None) -> ClusterConfig:
        client = self.client_daemon(client_node_id)
        packet_source = client or self.daemon()
        nodes = {
            daemon.node_id: daemon.cluster_node()
            for daemon in self.daemons.values()
            if (
                daemon.has_capability(CAPABILITY_MIXNODE)
                or daemon.has_capability(CAPABILITY_EXPERT)
                or daemon.has_capability(CAPABILITY_CONTROL_DHT)
            )
        }
        if not nodes:
            raise ValueError(f"{CONFIG_VERSION} cluster view requires at least one mixnode or expert daemon")
        return ClusterConfig(
            params=packet_source.packet,
            client=client.transport.bind if client else EndpointConfig(),
            nodes=nodes,
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def supernode_directory_records(self) -> tuple[dict[str, object], ...]:
        """Return public reachability-assist advertisements implied by config.

        Runtime roles and local capability flags are intentionally not
        serialized here. The public record only exposes enough to bootstrap a
        protected reachability-assist contact.
        """

        records: list[dict[str, object]] = []
        for daemon in self.daemons.values():
            supernode = daemon.supernode
            if not (supernode.enabled and supernode.register_directory):
                continue
            bind = daemon.transport.bind
            public_host = supernode.public_ip or bind.host
            records.append(
                {
                    "node_id": daemon.node_id,
                    "public_ip": supernode.public_ip,
                    "reachability_handle": f"{daemon.node_id}@{public_host}:{bind.port}",
                    "endpoint": {
                        "host": public_host,
                        "port": bind.port,
                        "transport": daemon.transport.kind,
                    },
                }
            )
        return tuple(records)


def load_config(path: str | Path) -> PorConfig:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return PorConfig.from_dict(raw)


def write_config(config: PorConfig, path: str | Path) -> None:
    Path(path).write_text(config.to_json() + "\n", encoding="utf-8")


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    raise TypeError("expected string sequence")


def _sequence_or_empty(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError("expected sequence")
    return tuple(value)


def _mapping_or_none(value: object) -> Mapping[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError("expected mapping")
    return value


def _mapping_or_empty(value: object) -> Mapping[str, object]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("expected mapping")
    return value


def _mutable_mapping_copy(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError("expected mapping")
    return dict(value)


def _normalize_role(value: str) -> str:
    text = value.strip().lower()
    if text == LEGACY_ROLE_RELAY:
        return ROLE_MIXNODE
    return text


def _default_capabilities_for_role(role: str) -> tuple[str, ...]:
    if role == ROLE_CLIENT:
        return (CAPABILITY_CLIENT,)
    if role == ROLE_EXPERT:
        return (CAPABILITY_MIXNODE, CAPABILITY_CONTROL_DHT, CAPABILITY_EXPERT)
    if role == ROLE_MIXNODE:
        return (CAPABILITY_MIXNODE, CAPABILITY_CONTROL_DHT)
    if role == ROLE_DIRECTORY:
        return (CAPABILITY_DIRECTORY,)
    return ()


def _capabilities_from_raw(value: object, role: str) -> tuple[str, ...]:
    if value is None:
        return _default_capabilities_for_role(role)
    if isinstance(value, str):
        capabilities = (value,) if value else ()
    elif isinstance(value, Sequence):
        capabilities = tuple(str(item) for item in value)
    else:
        raise TypeError("capabilities must be a string sequence")
    normalized = tuple(dict.fromkeys(item.strip().lower() for item in capabilities if item))
    _validate_capabilities(normalized)
    return normalized


def _validate_capabilities(capabilities: Sequence[str]) -> None:
    invalid = sorted(set(capabilities) - VALID_NODE_CAPABILITIES)
    if invalid:
        raise ValueError("unsupported node capabilities: " + ", ".join(invalid))
