"""Host realization for the simulator (local-only mode on one machine).

Launches real WireNodeRuntime instances as separate python processes (via the
standalone node launcher). This exercises the production code paths for:

- capabilities (control_dht, expert, mixnode, etc.)
- KademliaControlOverlay (real DHT for signed control records, network-scoped
  keys, mesh-ready, republish, size bounds)
- MixnetControlService, planner, WireNodeRuntime serve_on_socket
- the full Scenario model: logical sites + links (netem profiles), node
  placement, TEE modeling (none/mock/nitro), persist flags

All nodes for the "local" sites share one ClusterConfig (so DHT participants
see each other as peers and bootstrap/replicate regardless of which logical
site they are placed in). The logical site placement is used for netem profile
recording and for future workload/chaos logic that wants to simulate
cross-site conditions.

The parent CLI process does not own the UDP sockets or threads; the child
processes do. This makes `sim status`, `sim logs`, and `sim down` work after
the `up` command returns (real long-lived processes + on-disk session + logs).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tenet.config import ClusterConfig
from tenet.packet.OutfoxParams import OutfoxParams

from ..model import Scenario


def _reserve_udp() -> tuple[socket.socket, str, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    host, port = s.getsockname()
    return s, host, port


@dataclass
class HostDevHandle:
    scenario: Scenario
    site: str  # "local-host" for the aggregate local realization
    nodes: dict[str, dict] = field(default_factory=dict)  # nid -> {"pid", "log", "addr", "dht_port", "site"}
    netem_profiles: dict[tuple[str, str], dict] = field(default_factory=dict)
    cfg_dir: Path | None = None


class HostDevRunner:
    """Real-process host runner for local sim mode."""

    def bring_up(self, sc: Scenario, *, netem: bool = True, wait: bool = True) -> HostDevHandle:
        # All nodes belonging to sites that are realized locally in this run.
        # (For a pure host local-only run this is every node in the scenario.)
        local_nodes = [
            n for n in sc.nodes
            if (s := sc.sites.get(n.placement)) and s.runner in ("local-docker", "host", "host-dev")
        ]
        if not local_nodes:
            return HostDevHandle(sc, "local-host", cfg_dir=None)

        params = OutfoxParams(
            payload_size=int(sc.mixnet.get("payload_size", 2048)),
            routing_size=int(sc.mixnet.get("routing_size", 16)),
            max_hops=int(sc.mixnet.get("max_hops", 5)),
        )

        nodes_cfg: dict[str, Any] = {}
        # Pre-pick free ports so the cluster tells every child exactly what to bind.
        # Close the reservation socket immediately so the child can bind it.
        for idx, np in enumerate(local_nodes):
            s, _, port = _reserve_udp()
            s.close()
            nodes_cfg[np.id] = {
                "host": "127.0.0.1",
                "port": port,
                "kem_pk": "",
                "kem_sk": "",
                "role": np.role or ("expert" if "expert" in np.capabilities else "relay"),
                "capabilities": list(np.capabilities),
            }

        # KEM material (same as docker path and tests).
        for nid, nd in nodes_cfg.items():
            pk, sk = params.kem.keygen()
            nd["kem_pk"] = pk.hex()
            nd["kem_sk"] = sk.hex()

        client_port = 61000 + len(local_nodes) * 2 + 17
        raw = {
            "params": {
                "payload_size": params.payload_size,
                "routing_size": params.routing_size,
                "max_hops": params.max_hops,
            },
            "client": {"host": "127.0.0.1", "port": client_port},
            "nodes": nodes_cfg,
            "network_id": sc.network_id,
        }
        cluster = ClusterConfig.from_dict(raw)

        cfg_dir = Path(
            __import__("tempfile").mkdtemp(prefix=f"tenet-sim-host-{sc.network_id}-")
        )
        (cfg_dir / "cluster.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")
        (cfg_dir / "logs").mkdir(exist_ok=True)
        (cfg_dir / "pids").mkdir(exist_ok=True)
        (cfg_dir / "stores").mkdir(exist_ok=True)

        root = Path(__file__).resolve().parents[2]
        launcher = root / "sim" / "node_launcher.py"

        node_infos: dict[str, dict] = {}
        for np in local_nodes:
            nid = np.id
            log_path = cfg_dir / "logs" / f"{nid}.log"
            pid_path = cfg_dir / "pids" / f"{nid}.pid"
            store_path = cfg_dir / "stores" / nid if getattr(np, "persist", False) else None
            if store_path:
                store_path.mkdir(parents=True, exist_ok=True)

            cmd = [
                sys.executable,
                str(launcher),
                "--node-id",
                nid,
                "--config",
                str(cfg_dir / "cluster.json"),
            ]
            if store_path:
                cmd += ["--control-store-path", str(store_path)]

            env = os.environ.copy()
            env["PYTHONPATH"] = str(root) + (":" + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else "")

            with open(log_path, "w", encoding="utf-8") as lf:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(root),
                    env=env,
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

            with open(pid_path, "w", encoding="utf-8") as pf:
                pf.write(str(proc.pid))

            port = nodes_cfg[nid]["port"]
            node_infos[nid] = {
                "pid": proc.pid,
                "log": str(log_path),
                "addr": f"127.0.0.1:{port}",
                "dht_port": port + 1 if "control_dht" in np.capabilities else None,
                "site": np.placement,
            }

        # Record netem profiles between every pair of logical sites (for status and workloads).
        profiles: dict[tuple[str, str], dict] = {}
        for a in sc.site_names:
            for b in sc.site_names:
                if a >= b:
                    continue
                ln = sc.link_profile(a, b)
                if ln:
                    profiles[(a, b)] = {
                        "latency_ms": ln.latency_ms,
                        "loss_percent": ln.loss_percent,
                        "jitter_ms": ln.jitter_ms,
                    }

        h = HostDevHandle(
            scenario=sc,
            site="local-host",
            nodes=node_infos,
            netem_profiles=profiles,
            cfg_dir=cfg_dir,
        )

        if wait:
            # Give the real processes time to bind and for control_dht nodes to
            # start their Kademlia overlays and do initial bootstrap/contact exchange.
            time.sleep(1.0)

        return h

    def status(self, h: HostDevHandle) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for nid, info in h.nodes.items():
            pid = info.get("pid")
            alive = False
            if pid is not None:
                try:
                    os.kill(pid, 0)
                    alive = True
                except Exception:
                    alive = False
            out[nid] = {
                "alive": alive,
                "addr": info.get("addr"),
                "dht": bool(info.get("dht_port")),
                "dht_port": info.get("dht_port"),
                "site": info.get("site"),
            }
        out["_netem"] = {f"{a}->{b}": p for (a, b), p in h.netem_profiles.items()}
        if h.cfg_dir:
            out["_cfg_dir"] = str(h.cfg_dir)
        return out

    def logs(self, h: HostDevHandle, node_id: str, *, follow: bool = False, tail: int = 50) -> None:
        info = h.nodes.get(node_id)
        if not info:
            print(f"no such node {node_id}")
            return
        log_path = Path(info["log"])
        if not log_path.exists():
            print(f"log not present yet: {log_path}")
            return
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-tail:]
            for line in lines:
                print(line)
        except Exception as e:
            print("error reading log:", e)
        if follow:
            print(f"(follow with: tail -f {log_path})")

    def apply_netem(self, h: HostDevHandle) -> None:
        print("netem profiles (modeled for this local realization):")
        for (a, b), p in h.netem_profiles.items():
            print(f"  {a} <-> {b}: {p}")

    def down(self, h: HostDevHandle, *, clean: bool = False) -> None:
        for nid, info in h.nodes.items():
            pid = info.get("pid")
            if pid:
                try:
                    os.kill(pid, 15)
                    time.sleep(0.05)
                    os.kill(pid, 9)
                except Exception:
                    pass
        if clean and h.cfg_dir:
            try:
                import shutil
                shutil.rmtree(h.cfg_dir, ignore_errors=True)
            except Exception:
                pass
