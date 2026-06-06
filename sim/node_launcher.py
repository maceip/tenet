"""Standalone launcher for nodes inside the simulator container image.

This is a single-file copy of the essential logic from sim/node_entry.py so that
the node image does not need to COPY the entire sim/ tree (which has been
triggering mysterious builder checksum errors on some Docker/Orb setups).

It does the same thing: load a ClusterConfig slice, start WireNodeRuntime for
the given node_id (respecting capabilities declared in the cluster so that
CAPABILITY_CONTROL_DHT nodes bring up the real KademliaControlOverlay), and
serve.

It is deliberately minimal and does not pull in the full sim package.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import threading
from pathlib import Path
from typing import Any

from tenet.config import ClusterConfig, LoggingConfig
from tenet.mixnet.node_runtime import WireNodeRuntime


def _load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _maybe_load_verify_keys(p: str | None) -> dict[str, str] | None:
    if not p:
        return None
    raw = _load_json(p)
    if "verify_keys" in raw and isinstance(raw["verify_keys"], dict):
        return {str(k): str(v) for k, v in raw["verify_keys"].items()}
    return {str(k): str(v) for k, v in raw.items()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Tenet simulator node launcher (standalone)")
    ap.add_argument("--node-id", required=True)
    ap.add_argument("--config", required=True, help="ClusterConfig JSON (or wrapper with 'cluster')")
    ap.add_argument("--role", default=None)
    ap.add_argument("--control-store-path", default=None)
    ap.add_argument("--control-verify-keys", default=None)
    ap.add_argument("--control-bootstrap-path", default=None)
    ap.add_argument("--control-anti-entropy-interval-seconds", type=float, default=0.0)
    ap.add_argument("--control-replication-factor", type=int, default=5)
    args = ap.parse_args(argv)

    node_id = args.node_id
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        return 2

    raw = _load_json(cfg_path)
    if "cluster" in raw and isinstance(raw["cluster"], dict):
        cluster = ClusterConfig.from_dict(raw["cluster"])
    else:
        cluster = ClusterConfig.from_dict(raw)

    verify_keys = _maybe_load_verify_keys(args.control_verify_keys)
    bootstrap_path = args.control_bootstrap_path

    logging = LoggingConfig()

    runtime = WireNodeRuntime(
        cluster,
        node_id,
        role=args.role,
        logging=logging,
        control_store_path=args.control_store_path,
        control_bootstrap_path=bootstrap_path if (bootstrap_path and Path(bootstrap_path).exists()) else None,
        control_verify_keys=verify_keys,
        control_anti_entropy_interval_seconds=args.control_anti_entropy_interval_seconds,
        control_replication_factor=args.control_replication_factor,
    )

    node = cluster.node(node_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_host = node.host or "0.0.0.0"
    sock.bind((bind_host, node.port))
    print(f"[sim.node_launcher] {node_id} bound {bind_host}:{node.port} caps={runtime.capabilities}", flush=True)

    stop = threading.Event()

    def _handle(_signum, _frame):
        stop.set()

    try:
        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
    except Exception:
        pass

    try:
        runtime.serve_on_socket(sock, stop=stop)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
