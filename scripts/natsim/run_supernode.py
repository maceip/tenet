#!/usr/bin/env python3
"""
LEGACY QUICK REACH RELAY LAUNCHER (see note in gen_fleet.py).

For modern multi-site simulation with the real control DHT (Kademlia), netem,
capabilities, and the full node runtime, use `python -m sim` (see sim/README.md).

This helper still works for fast single-relay NAT experiments and already uses
the current WireNodeRuntime + SupernodeDaemon.
"""
from __future__ import annotations

import socket
import sys

from tenet.config import ClusterConfig
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.edges.cli.supernode import SupernodeDaemon


def main() -> int:
    cluster = ClusterConfig.load(sys.argv[1])
    node_id = sys.argv[2]
    advertise = sys.argv[3]
    secret = (sys.argv[4].encode("utf-8") + b"0" * 32)[:32]

    runtime = WireNodeRuntime(cluster, node_id, role="relay")
    node = cluster.node(node_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((node.host, node.port))
    daemon = SupernodeDaemon(runtime, relay_secret=secret, advertise_host=advertise)
    daemon.attach_socket(sock)
    print(f"supernode {node_id} bound {node.host}:{node.port} advertise={advertise}", flush=True)
    runtime.serve_on_socket(sock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
