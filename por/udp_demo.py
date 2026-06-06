"""Local UDP demo for P-OR Expert Mode.

**HARNESS ONLY — not production wire.**

This module uses JSON/base64 UDP frames for orchestration convenience.
Production daemons use canonical binary wire (``por.wire_frame``) via
``por relay`` / ``por expert`` / ``por run``.

Use this for local smoke tests and trace inspection. Do not build
production features on top of this module.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from sphinxmix.OutfoxParams import OutfoxParams

from .client import run_client_once
from .config import ClusterConfig, DEFAULT_PAYLOAD_SIZE, DEFAULT_ROUTING_SIZE
from .directory import PublicManifestDirectory
from .expert_mode import ExpertModeConfig, prepare_expert_mode_request
from .expert_route import PeerObservation, RouteIntent
from .memory_index import IndexConfig, build_memory_index
from .node_runtime import (
    WireNodeRuntime,
)
from .provider import stream_frontier_reply


@dataclass(frozen=True)
class DemoResult:
    selected_peer_id: str
    degraded_anonymity: bool
    fallback_used: bool
    response_text: str
    node_logs: str
    client_logs: str


def run_demo(node_count: int = 4, timeout: float = 8.0) -> DemoResult:
    if node_count < 3 or node_count > 5:
        raise ValueError("demo supports 3-5 local node processes")

    with tempfile.TemporaryDirectory(prefix="por-udp-demo-") as tmp:
        tmp_path = Path(tmp)
        params = OutfoxParams(payload_size=DEFAULT_PAYLOAD_SIZE, routing_size=DEFAULT_ROUTING_SIZE, max_hops=5)
        node_ids = _node_ids(node_count)
        ports = _reserve_ports(len(node_ids) + 1)
        client_addr = ("127.0.0.1", ports[-1])

        nodes = {}
        for node_id, port in zip(node_ids, ports[:-1]):
            pk, sk = params.kem.keygen()
            role = "expert" if node_id.startswith("expert") else "relay"
            nodes[node_id] = {
                "host": "127.0.0.1",
                "port": port,
                "kem_pk": pk.hex(),
                "kem_sk": sk.hex(),
                "role": role,
            }

        harness = {
            "params": {
                "payload_size": DEFAULT_PAYLOAD_SIZE,
                "routing_size": DEFAULT_ROUTING_SIZE,
                "max_hops": 5,
            },
            "client": {"host": client_addr[0], "port": client_addr[1]},
            "nodes": nodes,
        }
        config_path = tmp_path / "demo_config.json"
        config_path.write_text(json.dumps(harness, sort_keys=True, indent=2), encoding="utf-8")

        procs = _start_nodes(config_path, node_ids)
        try:
            time.sleep(0.35)
            selected_peer_id, degraded, fallback_used, prompt, expertise, prepared = _plan_demo_route(tmp_path)
            if selected_peer_id not in nodes:
                response_text = "".join(stream_frontier_reply(prompt, "no selected expert peer"))
                client_logs = (
                    "client event=expert_plan selected=none degraded_anonymity=false "
                    "fallback_used=true"
                )
                return DemoResult(
                    selected_peer_id="",
                    degraded_anonymity=degraded,
                    fallback_used=True,
                    response_text=response_text,
                    node_logs="",
                    client_logs=client_logs,
                )

            relay_path = [nid for nid in node_ids if nid.startswith("relay")][:2]
            directory = _demo_directory(tmp_path)
            cluster = ClusterConfig.load(config_path)
            client_result = run_client_once(
                cluster=cluster,
                discovery_provider=directory,
                prompt=prompt,
                requested_expertise=expertise,
                relay_path=tuple(relay_path),
                timeout=timeout,
                expert_mode_config=ExpertModeConfig(min_pool_size=3, allow_degraded_pool=True),
                random_seed=3,
            )
            response_text = client_result.response_text
            client_logs = client_result.client_logs
        finally:
            _shutdown_nodes(harness, node_ids)
            node_logs = _collect_node_logs(procs)

    return DemoResult(
        selected_peer_id=selected_peer_id,
        degraded_anonymity=degraded,
        fallback_used=fallback_used,
        response_text=response_text,
        node_logs=node_logs,
        client_logs=client_logs,
    )


def node_main(config_path: str, node_id: str) -> int:
    cluster = ClusterConfig.load(config_path)
    runtime = WireNodeRuntime(cluster, node_id, role="any")
    return runtime.serve_forever()


def _demo_directory(tmp_path: Path) -> PublicManifestDirectory:
    art_root = tmp_path / "expert_art_memory"
    sys_root = tmp_path / "expert_sys_memory"
    art_root.mkdir(exist_ok=True)
    sys_root.mkdir(exist_ok=True)
    (art_root / "impressionism.md").write_text(
        "Monet Degas Renoir Impressionism Paris Salon color light brushwork modern painting.",
        encoding="utf-8",
    )
    (sys_root / "systems.md").write_text(
        "QUIC UDP congestion control packet loss stream transport scheduler.",
        encoding="utf-8",
    )
    art_manifest = build_memory_index(IndexConfig(peer_id="expert_art", roots=(str(art_root),))).manifest
    sys_manifest = build_memory_index(IndexConfig(peer_id="expert_sys", roots=(str(sys_root),))).manifest
    prompt = "What did Monet change about modern painting?"
    expertise = "Impressionist art history"
    directory = PublicManifestDirectory.from_manifests(
        (art_manifest, sys_manifest),
        (
            PeerObservation(peer_id="expert_art", p50_latency_ms=80, completion_rate=0.99),
            PeerObservation(peer_id="expert_sys", p50_latency_ms=60, completion_rate=0.99),
        ),
        source="udp-demo",
    )
    return directory


def _plan_demo_route(tmp_path: Path):
    prompt = "What did Monet change about modern painting?"
    expertise = "Impressionist art history"
    directory = _demo_directory(tmp_path)
    prepared = prepare_expert_mode_request(
        RouteIntent(
            prompt=prompt,
            requested_expertise=expertise,
            random_seed=3,
        ),
        directory,
        ExpertModeConfig(min_pool_size=3, allow_degraded_pool=True),
    )
    fallback = prepare_expert_mode_request(
        RouteIntent(
            prompt="Explain basalt petrology",
            requested_expertise="basalt petrology",
            fallback_provider="frontier",
        ),
        directory,
    )
    plan = prepared.plan
    print(
        f"demo event=expert_selection use_expert={str(plan.use_expert).lower()} "
        f"selected={plan.selected_peer_id} degraded={str(plan.pool.degraded_anonymity).lower()} "
        f"pool_size={len(plan.pool.candidates)}",
        flush=True,
    )
    print(
        f"demo event=fallback_case use_expert={str(fallback.use_expert).lower()} "
        f"fallback_provider={fallback.plan.fallback_provider} reason={fallback.plan.reason!r}",
        flush=True,
    )
    return (
        plan.selected_peer_id or "",
        plan.pool.degraded_anonymity,
        not plan.use_expert,
        prompt,
        expertise,
        prepared,
    )


def _node_ids(node_count: int) -> list[str]:
    base = ["relay1", "relay2", "expert_art", "expert_sys", "relay3"]
    return base[:node_count]


def _daemon_argv(node_id: str) -> list[str]:
    subcommand = "expert" if node_id.startswith("expert") else "relay"
    return ["-m", "por", subcommand, "--config"]


def _reserve_ports(count: int) -> list[int]:
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def _start_nodes(config_path: Path, node_ids: Sequence[str]) -> list[subprocess.Popen]:
    procs = []
    for node_id in node_ids:
        procs.append(
            subprocess.Popen(
                [sys.executable, *_daemon_argv(node_id), str(config_path), "--node-id", node_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
    return procs


def _shutdown_nodes(harness: dict, node_ids: Sequence[str]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    frame = json.dumps({"kind": "shutdown"}).encode("utf-8")
    for node_id in node_ids:
        node = harness["nodes"][node_id]
        sock.sendto(frame, (node["host"], node["port"]))
    sock.close()


def _collect_node_logs(procs: Sequence[subprocess.Popen]) -> str:
    chunks = []
    for proc in procs:
        try:
            out, _ = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            out, _ = proc.communicate(timeout=2.0)
        chunks.append(out)
    return "".join(chunks)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local UDP P-OR demo.")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    node = sub.add_parser("node")
    node.add_argument("--config", required=True)
    node.add_argument("--node-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.cmd == "node":
        return node_main(args.config, args.node_id)

    result = run_demo()
    print("demo event=response_begin")
    print(result.response_text)
    print("demo event=response_end")
    print("demo event=client_logs_begin")
    print(result.client_logs)
    print("demo event=client_logs_end")
    print("demo event=node_logs_begin")
    print(result.node_logs, end="")
    print("demo event=node_logs_end")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
