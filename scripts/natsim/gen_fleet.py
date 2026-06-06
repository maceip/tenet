#!/usr/bin/env python3
"""Generate a self-contained relay+expert fleet for a live NAT-simulation test.

No matcher/mailbox/attestation: the cluster carries all node KEM keys, so
`tenet send --config cluster_client.json --directory-snapshot snapshot.json
--relay relay` seals directly to the expert and routes via the relay. NAT'd
clients are handled by the relay return-session; the expert is public-via-relay.

Emits three role clusters sharing the same keys, because the runtime binds to
identity.host (EC2 boxes don't hold their public IP locally):
  - cluster_relay.json   relay binds 0.0.0.0:RELAY_PORT ; expert at 127.0.0.1:EXPERT_PORT
  - cluster_expert.json  expert binds 127.0.0.1:EXPERT_PORT ; relay at 127.0.0.1:RELAY_PORT
  - cluster_client.json  relay dialled at PUBLIC_HOST:RELAY_PORT ; expert at 127.0.0.1:EXPERT_PORT

Usage: gen_fleet.py OUTDIR PUBLIC_RELAY_HOST RELAY_PORT EXPERT_PORT

See top-of-file comment for the relationship to the modern sim/ framework.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from tenet.packet.OutfoxParams import OutfoxParams
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.experts.directory import PublicManifestDirectory, PeerObservation
from tenet.handles import OpaqueHandleIssuer

PACKET = {"payload_size": 2048, "routing_size": 16, "max_hops": 5}


def _cluster(relay_host, relay_port, expert_host, expert_port, rpk, rsk, epk, esk,
             client_host="0.0.0.0", client_port=0):
    # Modern default: nodes declare capabilities so the unified WireNodeRuntime
    # starts the real Kademlia control overlay (when control_dht is present) and
    # participates correctly in the signed control record system.
    # The relay here acts as a mixnode + control_dht participant for the quick
    # NAT test fleet.
    return {
        "params": PACKET,
        "client": {"host": client_host, "port": client_port},
        "nodes": {
            "relay": {
                "host": relay_host,
                "port": relay_port,
                "kem_pk": rpk,
                "kem_sk": rsk,
                "role": "relay",
                "capabilities": ["mixnode", "control_dht"],
            },
            "expert-art": {
                "host": expert_host,
                "port": expert_port,
                "kem_pk": epk,
                "kem_sk": esk,
                "role": "expert",
                "capabilities": ["expert", "mixnode"],
            },
        },
    }


def main() -> int:
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    public_host = sys.argv[2]
    relay_port = int(sys.argv[3])
    expert_port = int(sys.argv[4])

    params = OutfoxParams(payload_size=2048, routing_size=16, max_hops=5)
    rpk, rsk = (b.hex() for b in params.kem.keygen())
    epk, esk = (b.hex() for b in params.kem.keygen())

    def w(name, relay_host, expert_host):
        (out / name).write_text(json.dumps(
            _cluster(relay_host, relay_port, expert_host, expert_port, rpk, rsk, epk, esk),
            indent=2), encoding="utf-8")

    w("cluster_relay.json", "0.0.0.0", "127.0.0.1")
    w("cluster_expert.json", "127.0.0.1", "127.0.0.1")
    w("cluster_client.json", public_host, "127.0.0.1")

    corpus = out / "corpus" / "expert-art"
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / "notes.md").write_text(
        "Claude Monet pioneered Impressionism: broken color, visible brushstrokes, "
        "plein-air light studies, the Water Lilies and Rouen Cathedral series.\n",
        encoding="utf-8",
    )
    manifest = build_memory_index(IndexConfig(peer_id="expert-art", roots=(str(corpus),))).manifest
    handle_record = OpaqueHandleIssuer(b"natsim-handle-secret-v1").record(
        peer_id="expert-art", manifest_digest=manifest.index_digest,
        mailbox_id="mailbox-art", now=1000.0,
    )
    directory = PublicManifestDirectory.from_manifests(
        (manifest,),
        (PeerObservation(peer_id="expert-art", p50_latency_ms=70, completion_rate=0.99),),
        source="natsim-directory",
    )
    directory.snapshot(generated_at="2026-06-06T00:00:00+00:00").with_handle_records(
        {"expert-art": handle_record.to_public_dict()}
    ).save(out / "snapshot.json")

    print(f"public_host={public_host} relay_port={relay_port} expert_port={expert_port} handle={handle_record.handle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
