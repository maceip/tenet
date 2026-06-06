#!/usr/bin/env python3
"""
LEGACY QUICK EXPERT+REACH LAUNCHER (see note in gen_fleet.py).

For modern simulation, containerized fleets (deploy/Dockerfile.node), and
exercising the real Kademlia control overlay + mixnet data plane across sites,
use the `sim/` framework.

This helper continues to work for quick single-relay NAT reach tests and uses
the current WireNodeRuntime.
"""
from __future__ import annotations

import socket
import sys
import time

from tenet.config import ClusterConfig
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.llm.provider import make_reply_handler
from tenet.mixnet.reach_wire import REACH_CHALLENGE, decode_reach_datagram, encode_confirm, encode_register


def main() -> int:
    cluster = ClusterConfig.load(sys.argv[1])
    node_id = sys.argv[2]
    relay_addr = (sys.argv[3], int(sys.argv[4]))

    runtime = WireNodeRuntime(cluster, node_id, role="expert", reply_handler=make_reply_handler())
    node = cluster.node(node_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((node.host, node.port))
    sock.settimeout(0.5)

    cookie = None
    deadline = time.time() + 12.0
    sock.sendto(encode_register(node_id), relay_addr)
    while time.time() < deadline and cookie is None:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            sock.sendto(encode_register(node_id), relay_addr)
            continue
        if data[:1] == REACH_CHALLENGE:
            cookie = decode_reach_datagram(data).cookie
    if cookie is None:
        print(f"REACH register FAILED for {node_id} -> {relay_addr}", flush=True)
        return 1
    sock.sendto(encode_confirm(node_id, cookie), relay_addr)
    print(f"expert {node_id} REACH-registered with relay {relay_addr}", flush=True)
    sock.settimeout(None)
    runtime.serve_on_socket(sock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
