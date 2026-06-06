"""Thin launcher used inside simulator node containers (and for manual container runs).

Usage (inside the image):
    python -m sim.node_entry \
        --node-id dht-home-1 \
        --config /etc/tenet/node-config.json \
        --control-store-path /var/lib/tenet/control \
        --role any

The config is a (possibly partial) ClusterConfig JSON. The node_id must exist in it.
Capabilities declared in the ClusterNodeConfig control whether the real Kademlia
control overlay is started (CAPABILITY_CONTROL_DHT), whether expert paths are
enabled, etc.

This module deliberately stays small — it just wires the real WireNodeRuntime
the same way the natsim/ scripts and the edge CLIs do, plus the modern control
service parameters the simulator cares about (store, verify keys, bootstrap,
anti-entropy).
"""

from __future__ import annotations

import argparse
import json
import os
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
    # Accept either {"root": "hex..."} or {"verify_keys": {...}}
    if "verify_keys" in raw and isinstance(raw["verify_keys"], dict):
        return {str(k): str(v) for k, v in raw["verify_keys"].items()}
    return {str(k): str(v) for k, v in raw.items()}


def _maybe_load_bootstrap_records(p: str | None) -> list[dict[str, Any]] | None:
    if not p:
        return None
    raw = _load_json(p)
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and "records" in raw:
        return raw["records"]
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Tenet simulator node entrypoint")
    ap.add_argument("--node-id", required=True, help="Node id inside the cluster config")
    ap.add_argument("--config", required=True, help="Path to node (or site) ClusterConfig JSON")
    ap.add_argument("--role", default=None, help="Override role (mixnode|relay|expert|any)")
    ap.add_argument("--control-store-path", default=None, help="Enable PersistentControlStore at this path")
    ap.add_argument("--control-verify-keys", default=None, help="JSON file with verify key id -> hex")
    ap.add_argument("--control-bootstrap-path", default=None, help="JSON file with initial signed control records")
    ap.add_argument("--control-anti-entropy-interval-seconds", type=float, default=0.0)
    ap.add_argument("--control-replication-factor", type=int, default=5)
    args = ap.parse_args(argv)

    node_id = args.node_id
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        return 2

    raw = _load_json(cfg_path)
    # The simulator may give us a full ClusterConfig or a {"cluster": ...} wrapper.
    if "cluster" in raw and isinstance(raw["cluster"], dict):
        cluster = ClusterConfig.from_dict(raw["cluster"])
    else:
        cluster = ClusterConfig.from_dict(raw)

    verify_keys = _maybe_load_verify_keys(args.control_verify_keys)
    bootstrap_path = args.control_bootstrap_path

    # If bootstrap records were provided inline (sim convenience), write a temp file
    # the ControlBootstrap loader can consume. For v0 we just pass the path if given.
    # (The real ControlBootstrap path is a signed bootstrap blob; the sim may also
    # just rely on the nodes self-publishing after start.)
    if bootstrap_path and not Path(bootstrap_path).exists():
        print(f"warning: bootstrap path does not exist: {bootstrap_path}", file=sys.stderr)

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
    # Bind the main mixnet socket (UDP). The runtime will start the Kademlia
    # overlay on (port+1) internally if the node has CAPABILITY_CONTROL_DHT.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_host = node.host or "0.0.0.0"
    sock.bind((bind_host, node.port))
    print(f"[sim.node_entry] {node_id} bound {bind_host}:{node.port} caps={runtime.capabilities}", flush=True)

    stop = threading.Event()

    def _handle_sig(*_):
        stop.set()

    try:
        import signal
        signal.signal(signal.SIGTERM, _handle_sig)
        signal.signal(signal.SIGINT, _handle_sig)
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
