#!/usr/bin/env python3
"""Asker process — routes a real question over the mixnet to the Berlin expert
running in a SEPARATE process (berlin_serve.py), possibly on another machine.

  # after starting berlin_serve.py:
  .venv/bin/python scripts/demo/berlin_ask.py
  .venv/bin/python scripts/demo/berlin_ask.py --prompt "best berlin neighbourhood for nightlife?"

Reads $TENET_NET_DIR/{cluster.json,askpack.json} written by berlin_serve.py and
deterministically rebuilds the discovery provider (same handle, same corpus),
then sends a real sealed Outfox packet → relay → the expert process.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

import berlin_pick as bp  # noqa: E402
from tenet.config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig  # noqa: E402
from tenet.experts.client import run_client_once  # noqa: E402
from tenet.experts.expert_mode import ExpertModeConfig  # noqa: E402
from tenet.experts.directory import load_public_snapshot_directory  # noqa: E402
from tenet.experts.matcher import (  # noqa: E402
    PLAIN_MATCHER_V1,
    PlainEnclavePlaneDiscoveryProvider,
    PlainMailbox,
    PlainMatcher,
)
from tenet.handles import OpaqueHandleIssuer  # noqa: E402

RED = "\033[38;2;229;53;43m"
GREEN = "\033[38;2;90;209;122m"
GREY = "\033[38;2;130;130;130m"
B = "\033[1m"
R = "\033[0m"

SHARE = Path(os.environ.get("TENET_NET_DIR", "/tmp/tenet-net"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="get me an airbnb in berlin — i don't want to deal with it")
    ap.add_argument("--expertise", default="berlin-neighbourhoods")
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args()
    os.environ.setdefault("POR_CLIENT_REQUEST_REPEATS", "1")
    os.environ.setdefault("POR_STREAM_CHUNK_REPEATS", "1")
    os.environ.setdefault("POR_STREAM_DONE_REPEATS", "1")

    cfg = SHARE / "cluster.json"
    pack_path = SHARE / "askpack.json"
    if not cfg.is_file() or not pack_path.is_file():
        print(f"{RED}[ask] no expert node found in {SHARE}.{R}")
        print(f"{GREY}      start it first:  .venv/bin/python scripts/demo/berlin_serve.py{R}")
        return 2

    cluster = ClusterConfig.load(cfg)
    pack = json.loads(pack_path.read_text(encoding="utf-8"))

    # Load the directory the server serialized (the manifest digest is non-deterministic
    # per build, so we LOAD it) and rebuild the handle bound to that exact digest.
    directory = load_public_snapshot_directory(SHARE / "directory.json")
    handle_record = OpaqueHandleIssuer(bp.HANDLE_SECRET).record(
        peer_id=bp.EXPERT_ID, manifest_digest=pack["manifest_digest"],
        mailbox_id="mailbox-berlin", now=1000.0)
    if handle_record.handle != pack["handle"]:
        print(f"{RED}[ask] handle mismatch — serve/ask out of sync{R}")
        return 3

    mailbox = PlainMailbox()
    mailbox.add(record=handle_record,
                routing_kem_pk_hex=pack["kem_pk_hex"],
                peer_address=pack["peer_address"])
    matcher = PlainMatcher.from_records(directory.records, {bp.EXPERT_ID: handle_record}, top_k=1)
    provider = PlainEnclavePlaneDiscoveryProvider(matcher, mailbox)

    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.bind((cluster.client.host, 0))  # ephemeral: relay replies to our source port
    csock.settimeout(0.5)

    print(f"{GREY}[ask]{R} → relay {B}{pack['relay_host']}:{pack['relay_port']}{R}  "
          f"{GREY}(separate process){R}")
    print(f"{GREY}[ask]{R} $ {B}{args.prompt}{R}\n")

    try:
        result = run_client_once(
            cluster=cluster, discovery_provider=provider, prompt=args.prompt,
            requested_expertise=args.expertise, timeout=args.timeout, random_seed=1,
            expert_mode_config=ExpertModeConfig(discovery_mode=PLAIN_MATCHER_V1, min_pool_size=1),
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=(TrustedReachabilityRelayConfig(
                relay_id=bp.RELAY_ID, host=pack["relay_host"], port=pack["relay_port"],
                verify_key=bp.REACH_SECRET.hex()),),
            client_sock=csock)
    finally:
        csock.close()

    ok = result.selected_handle == pack["handle"] and not result.fallback_used
    mark = f"{GREEN}✓{R}" if ok else f"{RED}✗{R}"
    print(f"{mark} {GREY}routed cross-process · matched{R} {result.selected_handle[:14]}…  "
          f"{GREY}fallback{R} {result.fallback_used}")
    print(f"\n{RED}{B}=== BERLIN EXPERT (over the mixnet, separate process) ==={R}")
    print(result.response_text)
    print(f"{RED}{B}========================================================={R}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
