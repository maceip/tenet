#!/usr/bin/env python3
"""Verify README protocol invariants through a two-user shrimping journey.

Bob (expert, home laptop): joins, publishes shrimping expertise via matcher
manifest path, idles behind an opaque handle + REACH registration.

Alice (asker, home laptop): discovers shrimping experts through the matcher
(privacy boundary), resolves substrate via control/DHT, routes only through
opaque handles over the reachability capability.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tenet.config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig
from tenet.experts.client import run_client_once
from tenet.experts.directory import PublicManifestDirectory
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.experts.expert_route import PeerObservation
from tenet.experts.matcher import PLAIN_MATCHER_V1, PlainEnclavePlaneDiscoveryProvider, PlainMailbox, PlainMatcher
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.handles import OpaqueHandleIssuer, is_opaque_handle
from tenet.mixnet.control import (
    ClientAdvertisement,
    CapabilityDescriptor,
    ExpertDescriptor,
    MixnetControlService,
    PoolDescriptor,
    sign_control_record,
)
from tenet.mixnet.control.advertisement import CAPABILITY_ANSWER, CAPABILITY_REACHABILITY_ASSIST
from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.mixnet.peer_address import PeerAddressRelay, UdpEndpoint
from tenet.protocol_invariants import SUBSTRATE_CAPABILITIES, validate_advertised_capability
from tests.helpers import write_process_wire_cluster


def _shrimping_directory(tmp: Path) -> PublicManifestDirectory:
    bob_root = tmp / "bob_shrimp_corpus"
    bob_root.mkdir()
    (bob_root / "shrimping.md").write_text(
        "Shrimping nets bait tides estuary harvest crustacean trawl dock Gulf Coast season.",
        encoding="utf-8",
    )
    manifest = build_memory_index(IndexConfig(peer_id="bob_home", roots=(str(bob_root),))).manifest
    return PublicManifestDirectory.from_manifests(
        (manifest,),
        (PeerObservation(peer_id="bob_home", p50_latency_ms=90, completion_rate=0.98),),
        source="bob-shrimping-expert",
    )


def _assert_invariant(name: str, ok: bool, detail: str = "") -> None:
    if not ok:
        raise AssertionError(f"INVARIANT FAIL [{name}]: {detail}")


def main() -> int:
    os.environ.setdefault("POR_CLIENT_REQUEST_REPEATS", "1")
    os.environ.setdefault("POR_STREAM_CHUNK_REPEATS", "1")
    os.environ.setdefault("POR_STREAM_DONE_REPEATS", "1")

    checks: list[tuple[str, bool, str]] = []

    with tempfile.TemporaryDirectory(prefix="tenet-shrimp-verify-") as tmpdir:
        tmp = Path(tmpdir)
        config_path, _raw, node_ids = write_process_wire_cluster(tmp, node_count=3)
        cluster = ClusterConfig.load(config_path)

        # --- Bob's shrimping manifest (matcher-side, not public routeable expertise) ---
        directory = _shrimping_directory(tmp)
        bob_record = directory.records[0]
        bob_handle = OpaqueHandleIssuer(b"bob-shrimping-handle-secret").record(
            peer_id="bob_home",
            manifest_digest=bob_record.manifest.index_digest,
            mailbox_id="mailbox-shrimp",
            now=time.time(),
        )
        _assert_invariant(
            "handles are opaque",
            is_opaque_handle(bob_handle.handle),
            bob_handle.handle,
        )

        # --- Substrate capability ads (Bob is a client too; no routeable expertise on DHT) ---
        try:
            validate_advertised_capability(kind=CAPABILITY_ANSWER, pools=())
            validate_advertised_capability(kind=CAPABILITY_REACHABILITY_ASSIST, pools=())
            bad = False
            try:
                validate_advertised_capability(kind=CAPABILITY_ANSWER, pools=("shrimping.expert~tenet",))
            except Exception:
                bad = True
            _assert_invariant("substrate-only client ads", bad, "expertise pools must not be advertised")
        except Exception as exc:
            raise AssertionError(f"substrate capability validation: {exc}") from exc

        bob_ad = ClientAdvertisement(
            client_id="bob_home",
            code_identity={"build": "sim-laptop"},
            capabilities=(
                CapabilityDescriptor(kind=CAPABILITY_ANSWER, capability_id="bob-answer"),
                CapabilityDescriptor(kind=CAPABILITY_REACHABILITY_ASSIST, capability_id="bob-reach"),
            ),
        )
        checks.append(("clients advertise substrate only", "shrimping" not in json.dumps(bob_ad.to_dict()).lower(), ""))

        # --- Control/DHT: pool descriptor is substrate routing metadata, not expertise ---
        signing_key = SigningKey.generate()
        verify_keys = {"root": signing_key.verify_key.encode().hex()}
        control = MixnetControlService(network_id="shrimp-net", verify_keys=verify_keys)
        pool = PoolDescriptor.from_name("shrimping.expert~tenet", topic_tags=("shrimping", "fishing"))
        control.put_signed(
            sign_control_record(
                control.make_unsigned_pool_descriptor(pool, seq=1),
                signing_key_hex=signing_key.encode().hex(),
                key_id="root",
            )
        )
        expert_desc = ExpertDescriptor(
            expert_id="bob_home",
            pools=("shrimping.expert~tenet",),
            manifest_ref=f"manifest/{bob_record.manifest.index_digest}",
            topic_refs=("topic/shrimping/descriptor",),
        )
        control.put_signed(
            sign_control_record(
                control.make_unsigned_expert_descriptor(expert_desc, seq=1),
                signing_key_hex=signing_key.encode().hex(),
                key_id="root",
            )
        )
        checks.append(("DHT has signed pool/expert control records", control.pool_descriptor(pool.name) == pool, ""))

        # --- Matcher discovers expertise behind privacy boundary (opaque handle only) ---
        matcher = PlainMatcher.from_records(
            directory.records,
            {"bob_home": bob_handle},
            top_k=3,
        )
        match_result = matcher.discover(
            __import__("tenet.experts.directory", fromlist=["DiscoveryRequest"]).DiscoveryRequest(
                intent=__import__("tenet.experts.expert_route", fromlist=["RouteIntent"]).RouteIntent(
                    prompt="How do I rig a shrimp net for inshore fishing?",
                    requested_expertise="shrimping",
                ),
                mode=PLAIN_MATCHER_V1,
            )
        )
        matched_handles = {c.manifest.peer_id for c in match_result.candidates}
        checks.append(
            (
                "matcher returns opaque handle not publisher id",
                any(is_opaque_handle(c.route_handle) for c in match_result.candidates),
                f"candidates={matched_handles}",
            )
        )
        checks.append(
            (
                "matcher selected shrimping expert",
                bob_handle.handle in {c.route_handle for c in match_result.candidates},
                "",
            )
        )

        # --- REACH registration + mailbox (handle connects matching to routing) ---
        relay_node = cluster.node("relay1")
        bob_node = cluster.node("expert_art")  # wire cluster reuses expert_art slot for bob
        relay_secret = b"shrimping-reach-relay-secret!!"
        relay = PeerAddressRelay(
            relay_id="relay1",
            relay_endpoint=UdpEndpoint(relay_node.host, relay_node.port),
            secret=relay_secret,
        )
        challenge = relay.request_registration(
            peer_id=bob_handle.handle,
            observed_endpoint=UdpEndpoint(bob_node.host, bob_node.port),
            now=time.time(),
        )
        peer_address = relay.confirm_registration(challenge).to_public_dict()
        mailbox = PlainMailbox()
        mailbox.add(
            record=bob_handle,
            routing_kem_pk_hex=bob_node.kem_pk_hex,
            peer_address=peer_address,
        )
        discovery_provider = PlainEnclavePlaneDiscoveryProvider(matcher, mailbox)

        # --- Live nodes: Bob idles as expert; relay forwards by handle ---
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay_sock.bind((relay_node.host, relay_node.port))
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bob_sock.bind((bob_node.host, bob_node.port))
        alice_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        alice_sock.bind((cluster.client.host, cluster.client.port))
        alice_sock.settimeout(0.5)

        stop = threading.Event()
        seen_prompts: list[str] = []
        seen_expertise: list[str] = []

        def bob_reply_handler(envelope, node_id):
            seen_prompts.append(envelope.prompt_text())
            seen_expertise.append(envelope.intent_descriptor.get("requested_expertise") or "")
            return [f"{node_id}: enriched with local shrimping context — tides, bait, net rigging."]

        relay_rt = WireNodeRuntime(cluster, "relay1")
        bob_rt = WireNodeRuntime(
            cluster,
            "expert_art",
            reply_handler=bob_reply_handler,
        )
        reach = SupernodeDaemon(relay_rt, relay_secret=relay_secret)
        relay_rt.on_reach_control = reach._handle_reach
        relay_rt.on_opaque_forward = reach._handle_opaque
        bob_addr = (bob_node.host, bob_node.port)
        challenge = reach.relay.request_registration(
            peer_id=bob_handle.handle,
            observed_endpoint=UdpEndpoint(*bob_addr),
            now=time.time(),
        )
        reach.relay.confirm_registration(challenge)
        reach.forwarder.register_peer(bob_handle.handle, bob_addr)

        threads = (
            threading.Thread(target=relay_rt.serve_on_socket, args=(relay_sock,), kwargs={"stop": stop}, daemon=True),
            threading.Thread(target=bob_rt.serve_on_socket, args=(bob_sock,), kwargs={"stop": stop}, daemon=True),
        )
        for t in threads:
            t.start()
        time.sleep(0.3)

        try:
            # Alice queries shrimping pool and sends enrichment prompt
            result = run_client_once(
                cluster=cluster,
                discovery_provider=discovery_provider,
                prompt="Please enrich this: what bait works best for inshore shrimping at dawn?",
                requested_expertise="shrimping",
                service_name="shrimping.expert~tenet",
                control_service=control,
                expert_mode_config=ExpertModeConfig(discovery_mode=PLAIN_MATCHER_V1, min_pool_size=1),
                peer_address_config=PeerAddressConfig(enabled=True),
                trusted_reachability_relays=(
                    TrustedReachabilityRelayConfig(
                        relay_id="relay1",
                        host=relay_node.host,
                        port=relay_node.port,
                        verify_key=relay_secret.hex(),
                    ),
                ),
                timeout=5.0,
                client_sock=alice_sock,
            )
        finally:
            stop.set()
            for sock in (relay_sock, bob_sock, alice_sock):
                sock.close()
            for t in threads:
                t.join(timeout=2.0)

        checks.append(("alice did not use frontier fallback", not result.fallback_used, result.client_logs))
        checks.append(("alice selected bob opaque handle", result.selected_handle == bob_handle.handle, result.selected_handle or ""))
        checks.append(("route target is opaque handle", is_opaque_handle(result.selected_handle or ""), ""))
        checks.append(("bob received prompt", len(seen_prompts) == 1, str(seen_prompts)))
        checks.append(("bob saw shrimping expertise tag", seen_expertise == ["shrimping"], str(seen_expertise)))
        checks.append(("expert enriched response returned", "shrimping context" in result.response_text, result.response_text))
        checks.append(("traffic routed via REACH relay path", "relay1" in result.client_logs, ""))
        checks.append(("only handles in send path", "expert_art" not in result.client_logs.split("forward_path=")[-1] if "forward_path=" in result.client_logs else True, ""))

    print("Protocol invariant verification — Bob/Alice shrimping journey\n")
    failed = 0
    for name, ok, detail in checks:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failed += 1

    print(f"\nSubstrate capabilities enforced: {sorted(SUBSTRATE_CAPABILITIES)}")
    if failed:
        print(f"\n{failed} check(s) failed.")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
