"""Mixnet-bonded control plane.

Names, gossip/DHT records, and descriptors live here because they are not a
separate P2P transport. They feed the mixnet route planner and never resolve to
raw dial addresses.
"""

from tenet.mixnet.control.names import (
    TENET_NAME_SUFFIX,
    TenetName,
    TenetNameError,
    parse_tenet_name,
)
from tenet.mixnet.control.advertisement import (
    CLIENT_ADVERTISEMENT_SCHEMA,
    CapabilityDescriptor,
    ClientAdvertisement,
    TrustReceipt,
)
from tenet.mixnet.control.bootstrap import (
    BOOTSTRAP_SCHEMA,
    TRUST_UPDATE_KEY,
    ControlBootstrap,
)
from tenet.mixnet.control.descriptors import (
    ATTESTATION_RECEIPT_SCHEMA,
    CONTROL_DHT_PEER_SCHEMA,
    EXPERT_DESCRIPTOR_SCHEMA,
    HANDLE_ADDRESS_SCHEMA,
    MATCHER_CAPABILITY_SCHEMA,
    MIXNET_ROUTING_SCHEMA,
    REACHABILITY_ASSIST_SCHEMA,
    REVIEW_DESCRIPTOR_SCHEMA,
    SOFTWARE_IDENTITY_SCHEMA,
    TOPIC_DESCRIPTOR_SCHEMA,
    TRUST_UPDATE_SCHEMA,
    AttestationReceiptDescriptor,
    ControlDhtPeerDescriptor,
    ExpertDescriptor,
    HandleAddressRecord,
    MatcherCapabilityDescriptor,
    MixnetRoutingDescriptor,
    ReachabilityAssistDescriptor,
    ReviewDescriptor,
    SoftwareIdentityDescriptor,
    TopicDescriptor,
    TrustUpdateDescriptor,
)
from tenet.mixnet.control.match_result import (
    MATCH_RESULT_SCHEMA,
    MatchCandidateDescriptor,
    MatchResultDescriptor,
    query_commitment,
)
from tenet.mixnet.control.mixnode import MIXNODE_DESCRIPTOR_SCHEMA, MixnodeDescriptor
from tenet.mixnet.control.records import (
    ControlRecord,
    ControlRecordError,
    SignedControlRecord,
    RECORD_TYPE_ATTESTATION_RECEIPT,
    RECORD_TYPE_MIXNET_ROUTING,
    RECORD_TYPE_REACHABILITY_ASSIST,
    RECORD_TYPE_SOFTWARE_IDENTITY,
    RECORD_TYPE_TRUST_UPDATE,
    sign_control_record,
)
from tenet.mixnet.control.pools import POOL_DESCRIPTOR_SCHEMA, PoolDescriptor
from tenet.mixnet.control.store import PersistentControlStore
from tenet.mixnet.control.wire import (
    ControlWireMessage,
    control_get,
    control_have,
    control_put,
    decode_control_message,
    encode_control_message,
    is_control_datagram,
)
from tenet.mixnet.control.live_sync import CONTROL_SYNC_PREFIXES, sync_control_from_cluster
from tenet.mixnet.control.service import (
    MixnetControlService,
    MixnetRouteBinding,
    RouteBindingError,
)
from tenet.mixnet.control.dht import (
    ControlDhtPeer,
    ControlDhtPlan,
    dht_key_bytes,
    replication_plan,
    responsible_nodes,
    xor_distance,
)
# KademliaControlOverlay is intentionally *not* imported at module load time.
# It lives in a submodule that requires the optional "kademlia" distribution.
# We expose it via __getattr__ so that "from tenet.mixnet.control import Foo"
# for non-DHT symbols succeeds even when kademlia is not installed, but code
# that actually uses the control_dht capability can still do
#   from tenet.mixnet.control import KademliaControlOverlay
# (or direct submodule import) and will get the class (or ImportError at the
# point of use, which is the correct failure mode).

__all__ = [
    "TENET_NAME_SUFFIX",
    "CLIENT_ADVERTISEMENT_SCHEMA",
    "BOOTSTRAP_SCHEMA",
    "CapabilityDescriptor",
    "ClientAdvertisement",
    "ControlBootstrap",
    "ControlRecord",
    "ControlDhtPeer",
    "ControlDhtPlan",
    "ControlRecordError",
    "ATTESTATION_RECEIPT_SCHEMA",
    "EXPERT_DESCRIPTOR_SCHEMA",
    "MIXNET_ROUTING_SCHEMA",
    "REACHABILITY_ASSIST_SCHEMA",
    "SOFTWARE_IDENTITY_SCHEMA",
    "TRUST_UPDATE_SCHEMA",
    "AttestationReceiptDescriptor",
    "ControlDhtPeerDescriptor",
    "ExpertDescriptor",
    "HandleAddressRecord",
    "MatcherCapabilityDescriptor",
    "MIXNET_ROUTING_SCHEMA",
    "MATCHER_CAPABILITY_SCHEMA",
    "HANDLE_ADDRESS_SCHEMA",
    "CONTROL_DHT_PEER_SCHEMA",
    "MixnetRoutingDescriptor",
    "ReachabilityAssistDescriptor",
    "SoftwareIdentityDescriptor",
    "TrustUpdateDescriptor",
    "MixnetControlService",
    "MixnetRouteBinding",
    "MIXNODE_DESCRIPTOR_SCHEMA",
    "MATCH_RESULT_SCHEMA",
    "MatchCandidateDescriptor",
    "MatchResultDescriptor",
    "MixnodeDescriptor",
    "PersistentControlStore",
    "POOL_DESCRIPTOR_SCHEMA",
    "PoolDescriptor",
    "REVIEW_DESCRIPTOR_SCHEMA",
    "ReviewDescriptor",
    "RouteBindingError",
    "SignedControlRecord",
    "RECORD_TYPE_ATTESTATION_RECEIPT",
    "RECORD_TYPE_MIXNET_ROUTING",
    "RECORD_TYPE_REACHABILITY_ASSIST",
    "RECORD_TYPE_SOFTWARE_IDENTITY",
    "RECORD_TYPE_TRUST_UPDATE",
    "TenetName",
    "TenetNameError",
    "TrustReceipt",
    "TRUST_UPDATE_KEY",
    "TOPIC_DESCRIPTOR_SCHEMA",
    "TopicDescriptor",
    "dht_key_bytes",
    "ControlWireMessage",
    "CONTROL_SYNC_PREFIXES",
    "control_get",
    "control_have",
    "control_put",
    "decode_control_message",
    "encode_control_message",
    "is_control_datagram",
    "parse_tenet_name",
    "query_commitment",
    "replication_plan",
    "responsible_nodes",
    "xor_distance",
    "sync_control_from_cluster",
    "KademliaControlOverlay",
    "AttestationReceiptDescriptor",
    "MixnetRoutingDescriptor",
    "ReachabilityAssistDescriptor",
    "SoftwareIdentityDescriptor",
    "TrustUpdateDescriptor",
    "ATTESTATION_RECEIPT_SCHEMA",
    "MIXNET_ROUTING_SCHEMA",
    "REACHABILITY_ASSIST_SCHEMA",
    "SOFTWARE_IDENTITY_SCHEMA",
    "TRUST_UPDATE_SCHEMA",
    "sign_control_record",
    "KademliaControlOverlay",
]


def __getattr__(name: str):
    if name == "KademliaControlOverlay":
        from .kademlia_overlay import KademliaControlOverlay as _Overlay  # lazy, only when the DHT cap is exercised

        return _Overlay
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
