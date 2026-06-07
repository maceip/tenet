#!/usr/bin/env python3
"""Persistent Berlin EXPERT + relay node (one process).

Run this in one window/machine, then run berlin_ask.py in another. Real
two-process tenet mixnet — the asker's sealed Outfox packet crosses actual
sockets to a separate process (and a separate machine if you set the hosts).

  # two processes, one box (loopback):
  .venv/bin/python scripts/demo/berlin_serve.py

  # second machine (expert box) — bind its LAN IP so the asker can reach it:
  RELAY_HOST=192.168.1.20 EXPERT_HOST=192.168.1.20 .venv/bin/python scripts/demo/berlin_serve.py

Shares state with the asker via $TENET_NET_DIR (default /tmp/tenet-net):
cluster.json (ports+keys) and askpack.json (handle + reachable peer address).
Set ANTHROPIC_API_KEY for the live expert; otherwise a real captured answer.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

import berlin_pick as bp  # noqa: E402
from tenet.config import (  # noqa: E402
    DEFAULT_PAYLOAD_SIZE,
    DEFAULT_ROUTING_SIZE,
    ClusterConfig,
    LoggingConfig,
)
from tenet.edges.cli.supernode import SupernodeDaemon  # noqa: E402
from tenet.handles import OpaqueHandleIssuer  # noqa: E402
from tenet.mixnet.node_runtime import WireNodeRuntime  # noqa: E402
from tenet.mixnet.peer_address import PeerAddressRelay, UdpEndpoint  # noqa: E402
from tenet.packet.OutfoxParams import OutfoxParams  # noqa: E402

SHARE = Path(os.environ.get("TENET_NET_DIR", "/tmp/tenet-net"))
RELAY_HOST = os.environ.get("RELAY_HOST", "127.0.0.1")
EXPERT_HOST = os.environ.get("EXPERT_HOST", "127.0.0.1")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "0"))   # 0 = ephemeral (no port conflicts)
EXPERT_PORT = int(os.environ.get("EXPERT_PORT", "0"))
ASKER_HOST = os.environ.get("ASKER_HOST", "127.0.0.1")


def main() -> int:
    SHARE.mkdir(parents=True, exist_ok=True)
    for stale in ("relay-store.json", "expert-store.json"):
        (SHARE / stale).unlink(missing_ok=True)
    api_key = bp.load_anthropic_key()
    model = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

    # Bind sockets FIRST on (default ephemeral) ports — eliminates the fixed-port
    # "Address already in use" crash on re-runs / stale processes.
    rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    esock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    esock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        rsock.bind((RELAY_HOST, RELAY_PORT))
        esock.bind((EXPERT_HOST, EXPERT_PORT))
    except OSError as exc:
        print(f"[serve] could not bind ({exc}). A berlin_serve may already be running — "
              f"run:  pkill -f berlin_serve  and retry.")
        return 2
    relay_port = rsock.getsockname()[1]
    expert_port = esock.getsockname()[1]

    # cluster with the ACTUAL bound ports so the asker can find us
    params = OutfoxParams(payload_size=DEFAULT_PAYLOAD_SIZE, routing_size=DEFAULT_ROUTING_SIZE, max_hops=5)
    nodes = {}
    for nid, host, port in ((bp.RELAY_ID, RELAY_HOST, relay_port), (bp.EXPERT_ID, EXPERT_HOST, expert_port)):
        pk, sk = params.kem.keygen()
        nodes[nid] = {"host": host, "port": port, "kem_pk": pk.hex(), "kem_sk": sk.hex(),
                      "role": "relay" if nid == bp.RELAY_ID else "expert"}
    raw = {"params": {"payload_size": DEFAULT_PAYLOAD_SIZE, "routing_size": DEFAULT_ROUTING_SIZE, "max_hops": 5},
           "client": {"host": ASKER_HOST, "port": 0}, "nodes": nodes}
    (SHARE / "cluster.json").write_text(json.dumps(raw), encoding="utf-8")
    cluster = ClusterConfig.load(SHARE / "cluster.json")

    bootstrap_path, _sk = bp.runtime_bootstrap(cluster, SHARE)
    directory = bp.build_directory(SHARE)
    record = next(it for it in directory.records if it.peer_id == bp.EXPERT_ID)
    # The manifest digest is non-deterministic per build, so serialize THIS one for
    # the asker (load, don't recompute) along with the handle that's bound to it.
    directory.snapshot().with_supernodes(
        [{"node_id": bp.RELAY_ID, "endpoint": {"host": RELAY_HOST, "port": relay_port}}]
    ).save(SHARE / "directory.json")

    handle_record = OpaqueHandleIssuer(bp.HANDLE_SECRET).record(
        peer_id=bp.EXPERT_ID, manifest_digest=record.manifest.index_digest,
        mailbox_id="mailbox-berlin", now=1000.0)
    par = PeerAddressRelay(relay_id=bp.RELAY_ID, relay_endpoint=UdpEndpoint(RELAY_HOST, relay_port),
                           secret=bp.REACH_SECRET)
    challenge = par.request_registration(peer_id=handle_record.handle,
                                         observed_endpoint=UdpEndpoint(EXPERT_HOST, expert_port), now=time.time())
    peer_address = par.confirm_registration(challenge).to_public_dict()
    (SHARE / "askpack.json").write_text(json.dumps({
        "handle": handle_record.handle,
        "manifest_digest": record.manifest.index_digest,
        "kem_pk_hex": cluster.node(bp.EXPERT_ID).kem_pk_hex,
        "peer_address": peer_address,
        "relay_host": RELAY_HOST, "relay_port": relay_port}), encoding="utf-8")

    stop = threading.Event()
    quiet = LoggingConfig(level="silent")
    relay_rt = WireNodeRuntime(cluster, bp.RELAY_ID, control_bootstrap_path=str(bootstrap_path),
                               control_store_path=str(SHARE / "relay-store.json"),
                               control_replication_factor=2, logging=quiet)
    expert_rt = WireNodeRuntime(cluster, bp.EXPERT_ID, control_bootstrap_path=str(bootstrap_path),
                                control_store_path=str(SHARE / "expert-store.json"),
                                control_replication_factor=2, logging=quiet,
                                reply_handler=bp.make_berlin_reply_handler(api_key, model))
    sup = SupernodeDaemon(relay_rt, relay_secret=bp.REACH_SECRET, advertise_host=RELAY_HOST)
    sup.attach_socket(rsock)
    sup.forwarder.register_peer(handle_record.handle, (EXPERT_HOST, expert_port))

    threads = [
        threading.Thread(target=relay_rt.serve_on_socket, args=(rsock,), kwargs={"stop": stop}, daemon=True),
        threading.Thread(target=expert_rt.serve_on_socket, args=(esock,), kwargs={"stop": stop}, daemon=True),
    ]
    for t in threads:
        t.start()

    print(f"[serve] relay  {RELAY_HOST}:{relay_port}")
    print(f"[serve] expert {EXPERT_HOST}:{expert_port}  (LLM={'claude:' + model if api_key else 'captured answer'})")
    print(f"[serve] askpack → {SHARE / 'askpack.json'}")
    print(f"[serve] READY. In another window/machine run:")
    print(f"        TENET_NET_DIR={SHARE} .venv/bin/python scripts/demo/berlin_ask.py")
    print("[serve] Ctrl-C to stop.")

    def _stop(*_a):
        stop.set()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    try:
        while not stop.is_set():
            time.sleep(0.5)
    finally:
        for rt in (expert_rt, relay_rt):
            ov = getattr(rt, "_kademlia_overlay", None)
            if ov is not None:
                try:
                    ov.stop()
                except Exception:
                    pass
        for t in threads:
            t.join(timeout=2.0)
        for s in (rsock, esock):
            s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
