"""P-OR application-layer helpers.

The `por` package sits above `sphinxmix`. It contains product/control-plane
building blocks such as memory manifests, candidate matching, and request
envelopes. Relays should not import this package to process packets.
"""

__all__ = (
    "CandidatePool",
    "CandidateScore",
    "ChunkProof",
    "ClientConfig",
    "ClientRunResult",
    "ClientSessionStats",
    "ClusterConfig",
    "ClusterNodeConfig",
    "CONFIG_VERSION",
    "DaemonConfig",
    "DirectoryConfig",
    "DirectorySnapshot",
    "DirectorySnapshotFetchError",
    "DirectorySnapshotFormatError",
    "DiscoveryRequest",
    "DiscoveryProvider",
    "DiscoveryResult",
    "EndpointConfig",
    "ExpertRoutingConfig",
    "ExpertModeConfig",
    "ExpertModePreparedRequest",
    "ExpertModeTrace",
    "ExpertRoutePlan",
    "H3WebSocketClient",
    "H3WebSocketServer",
    "InMemorySessionTicketStore",
    "IndexConfig",
    "LocalHttpConfig",
    "LocalMemoryIndex",
    "LoggingConfig",
    "MemoryManifest",
    "PacketConfig",
    "PeerCandidate",
    "PeerAddressConfig",
    "PeerObservation",
    "PeerEndpointConfig",
    "PeerRecord",
    "PersistentClientSession",
    "PorConfig",
    "PorLogEvent",
    "PrivateDiscoveryUnavailable",
    "PromptRequestEnvelope",
    "ProviderConfig",
    "PublicManifestDirectory",
    "QuicDatagramClient",
    "QuicDatagramServer",
    "QuicEndpoint",
    "QuicTransportUnavailable",
    "write_localhost_self_signed_cert",
    "AddressChallenge",
    "AddressExposurePolicy",
    "DialPlan",
    "DialRoute",
    "DialTarget",
    "PeerAddressRecord",
    "PeerAddressRelay",
    "RelayCandidate",
    "RetrievalHit",
    "RouteIntent",
    "SupernodeConfig",
    "TrustedReachabilityRelayConfig",
    "UdpEndpoint",
    "build_dial_plan",
    "build_memory_index",
    "emit_log_event",
    "format_log_event",
    "load_config",
    "load_directory_snapshot",
    "load_public_snapshot_directory",
    "load_records_from_snapshot_file",
    "plan_expert_route",
    "prepare_expert_mode_request",
    "peer_address_record_from_dict",
    "resolve_dial_target",
    "run_client_once",
    "send_prepared_envelope",
    "send_prepared_envelope_via_plan",
    "score_manifest",
    "verify_chunk_proof",
    "verify_record_signature",
    "write_config",
)


def __getattr__(name):
    if name in __all__:
        if name in {
            "ClientRunResult",
            "ClientSessionStats",
            "PersistentClientSession",
            "run_client_once",
            "send_prepared_envelope",
        }:
            if name in {"ClientSessionStats", "PersistentClientSession"}:
                from .daemon import client
            else:
                from . import client

            return getattr(client, name)
        if name in {
            "CandidatePool",
            "CandidateScore",
            "ExpertRoutePlan",
            "PeerCandidate",
            "PeerObservation",
            "RouteIntent",
            "plan_expert_route",
        }:
            from . import expert_route

            return getattr(expert_route, name)
        if name in {
            "CONFIG_VERSION",
            "ClusterConfig",
            "ClusterNodeConfig",
            "ClientConfig",
            "DaemonConfig",
            "DirectoryConfig",
            "EndpointConfig",
            "ExpertRoutingConfig",
            "LocalHttpConfig",
            "LoggingConfig",
            "PacketConfig",
            "PeerAddressConfig",
            "PeerEndpointConfig",
            "PorConfig",
            "ProviderConfig",
            "SupernodeConfig",
            "TrustedReachabilityRelayConfig",
            "load_config",
            "write_config",
        }:
            from . import config

            return getattr(config, name)
        if name in {
            "DiscoveryRequest",
            "DiscoveryProvider",
            "DiscoveryResult",
            "DirectorySnapshot",
            "DirectorySnapshotFetchError",
            "DirectorySnapshotFormatError",
            "PeerRecord",
            "PrivateDiscoveryUnavailable",
            "PublicManifestDirectory",
            "load_directory_snapshot",
            "load_public_snapshot_directory",
            "load_records_from_snapshot_file",
        }:
            from . import directory

            return getattr(directory, name)
        if name in {"PromptRequestEnvelope"}:
            from . import envelope

            return getattr(envelope, name)
        if name in {
            "AddressChallenge",
            "AddressExposurePolicy",
            "DialPlan",
            "DialRoute",
            "PeerAddressRecord",
            "PeerAddressRelay",
            "RelayCandidate",
            "UdpEndpoint",
            "build_dial_plan",
            "peer_address_record_from_dict",
            "verify_record_signature",
        }:
            from . import peer_address

            return getattr(peer_address, name)
        if name in {
            "DialTarget",
            "resolve_dial_target",
            "send_prepared_envelope_via_plan",
        }:
            from . import transport_dial

            return getattr(transport_dial, name)
        if name in {
            "H3WebSocketClient",
            "H3WebSocketServer",
            "InMemorySessionTicketStore",
            "POR_DATAGRAM_ALPN",
            "POR_H3_ALPN",
            "POR_QUIC_ALPN",
            "QuicDatagramClient",
            "QuicDatagramServer",
            "QuicEndpoint",
            "QuicTransportUnavailable",
            "write_localhost_self_signed_cert",
        }:
            from . import quic_transport

            return getattr(quic_transport, name)
        if name in {"PorLogEvent", "emit_log_event", "format_log_event"}:
            from . import log_events

            return getattr(log_events, name)
        if name in {
            "ExpertModeConfig",
            "ExpertModePreparedRequest",
            "ExpertModeTrace",
            "prepare_expert_mode_request",
        }:
            from . import expert_mode

            return getattr(expert_mode, name)
        from . import memory_index

        return getattr(memory_index, name)
    raise AttributeError(name)
