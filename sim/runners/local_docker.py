"""Local Docker runner for the Tenet mixnet+DHT simulator (Mode 1 and as a building block).

This runner:
- Creates (or reuses) a user-defined Docker network for the scenario.
- For each logical node assigned to a local-docker site, starts a container
  running the real WireNodeRuntime (via deploy/Dockerfile.node + node-entry).
- Writes per-node ClusterConfig "views" and control bootstrap material into a
  host temp dir that is bind-mounted into the container at /etc/tenet.
- After containers are up, can apply netem (via docker exec + tc inside the
  container, which has iproute2 and runs with --cap-add=NET_ADMIN).

The same logical scenario can later target ssh-docker sites with almost no
changes — only the "how do I launch a container on that site" differs.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tenet.config import ClusterConfig, ClusterNodeConfig
from tenet.packet.OutfoxParams import OutfoxParams

from ..model import NodePlacement, Scenario, Site


def _run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        capture_output=capture,
    )


def _docker(args: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return _run(["docker", *args], check=check, capture=capture)


@dataclass
class LocalDockerHandle:
    """Opaque handle returned by bring_up for later status/logs/down/netem."""
    scenario: Scenario
    network: str
    containers: dict[str, str]  # node_id -> container_name
    cfg_root: Path  # host path containing per-node/ subdirs with their configs


class LocalDockerRunner:
    def __init__(self, image: str = "tenet-node:dev", network_prefix: str = "tenet-sim"):
        self.image = image
        self.network_prefix = network_prefix

    def _ensure_image(self, *, rebuild: bool = False) -> None:
        # Check if image already exists.
        try:
            _docker(["image", "inspect", self.image], check=True, capture=True)
            if not rebuild:
                return
        except subprocess.CalledProcessError:
            pass

        # Controlled temp context build (robust across .dockerignore / partial contexts).
        # This mirrors the pattern in scripts/build-client-sim-image.sh.
        here = Path(__file__).resolve()
        root = here.parents[2]
        dockerfile_src = root / "deploy" / "Dockerfile.node"
        entry_src = root / "deploy" / "node-entry.sh"
        if not dockerfile_src.exists():
            raise RuntimeError(f"Cannot auto-build: {dockerfile_src} not found")

        import shutil
        import tempfile

        with tempfile.TemporaryDirectory(prefix="tenet-node-build-") as td:
            tdp = Path(td)
            (tdp / "deploy").mkdir()
            shutil.copy2(dockerfile_src, tdp / "deploy" / "Dockerfile.node")
            shutil.copy2(entry_src, tdp / "deploy" / "node-entry.sh")
            shutil.copy2(root / "pyproject.toml", tdp / "pyproject.toml")
            if (root / "uv.lock").exists():
                shutil.copy2(root / "uv.lock", tdp / "uv.lock")
            # Copy only the package source the image needs (tenet).
            shutil.copytree(root / "tenet", tdp / "tenet")
            # Only the standalone launcher under sim/ (never the full sim/ tree).
            # This avoids builder checksum bugs seen on some Docker setups (OrbStack)
            # when a broad COPY sim/ was present in the context during repeated sim dev builds.
            (tdp / "sim").mkdir(parents=True, exist_ok=True)
            launcher_src = root / "sim" / "node_launcher.py"
            if launcher_src.exists():
                shutil.copy2(launcher_src, tdp / "sim" / "node_launcher.py")

            print(f"[local-docker] building {self.image} from controlled context ...", flush=True)
            _run(
                [
                    "docker",
                    "build",
                    "-t",
                    self.image,
                    "-f",
                    str(tdp / "deploy" / "Dockerfile.node"),
                    str(tdp),
                ],
                check=True,
            )

    def _ensure_network(self, name: str) -> None:
        # Create if missing (idempotent).
        res = _docker(["network", "ls", "--format", "{{.Name}}"], capture=True)
        nets = set(res.stdout.strip().splitlines())
        if name not in nets:
            _docker(["network", "create", "--driver", "bridge", name])

    def _container_name(self, node_id: str) -> str:
        # Stable, docker-friendly name.
        safe = node_id.replace("_", "-").replace("/", "-")
        return f"tenet-{safe}"

    def _gen_cluster_view_for_local(
        self,
        sc: Scenario,
        nodes_in_realization: list[NodePlacement],
        internal_base_port: int = 51000,
    ) -> tuple[ClusterConfig, dict[str, int]]:
        """Create a ClusterConfig where 'host' for container-to-container is the container name.

        All these nodes will be on the *same* docker network for this realization
        (even if they are in different *logical* sites for netem purposes).
        """
        params = OutfoxParams(
            payload_size=int(sc.mixnet.get("payload_size", 2048)),
            routing_size=int(sc.mixnet.get("routing_size", 16)),
            max_hops=int(sc.mixnet.get("max_hops", 5)),
        )
        nodes: dict[str, Any] = {}
        port_map: dict[str, int] = {}
        for idx, np in enumerate(nodes_in_realization):
            port = internal_base_port + idx * 2  # leave room for dht (port+1)
            cname = self._container_name(np.id)
            # Use container name as host so Docker DNS works inside the network.
            # Bind on 0.0.0.0 inside the container.
            nodes[np.id] = {
                "host": "0.0.0.0",
                "port": port,
                "kem_pk": "",  # filled below
                "kem_sk": "",
                "role": np.role or ("expert" if "expert" in np.capabilities else "relay"),
                "capabilities": list(np.capabilities),
            }
            port_map[np.id] = port

        # Generate KEM material (same as tests/helpers and natsim/gen_fleet).
        for nid, nd in nodes.items():
            pk, sk = params.kem.keygen()
            nd["kem_pk"] = pk.hex()
            nd["kem_sk"] = sk.hex()

        # A client port (not really used for infra nodes, but ClusterConfig wants one).
        client_port = internal_base_port + len(nodes_in_realization) * 2 + 7
        raw = {
            "params": {
                "payload_size": params.payload_size,
                "routing_size": params.routing_size,
                "max_hops": params.max_hops,
            },
            "client": {"host": "127.0.0.1", "port": client_port},
            "nodes": nodes,
            "network_id": sc.network_id,
        }
        cluster = ClusterConfig.from_dict(raw)
        return cluster, port_map

    def bring_up(
        self,
        sc: Scenario,
        *,
        netem: bool = True,
        wait: bool = True,
        rebuild_image: bool = False,
    ) -> LocalDockerHandle:
        """Bring up all nodes whose sites use the local-docker runner."""
        self._ensure_image(rebuild=rebuild_image)

        # Which nodes are realized locally in this invocation?
        local_nodes = [n for n in sc.nodes if sc.sites[n.placement].runner == "local-docker"]
        if not local_nodes:
            raise ValueError("Scenario has no nodes placed on local-docker sites")

        net_name = f"{self.network_prefix}-{sc.network_id}"
        self._ensure_network(net_name)

        # For the first cut we put *all* local-docker nodes (even from different logical sites)
        # onto the same docker network. Netem inside containers creates the "distance".
        cluster, port_map = self._gen_cluster_view_for_local(sc, local_nodes)

        # Temp dir on host with per-node config trees.
        tmp = Path(tempfile.mkdtemp(prefix="tenet-sim-"))
        (tmp / "common").mkdir(exist_ok=True)

        # Write a single shared cluster view (nodes can have the full view for local sim;
        # in real multi-site we would emit per-site subsets with external addresses).
        common_cluster_path = tmp / "common" / "cluster.json"
        common_cluster_path.write_text(json.dumps(cluster.to_dict(), indent=2), encoding="utf-8")

        containers: dict[str, str] = {}
        for np in local_nodes:
            cname = self._container_name(np.id)
            node_dir = tmp / np.id
            node_dir.mkdir(parents=True, exist_ok=True)

            # Per-node config (for now just point at the common view; future: site-filtered view).
            node_cfg = {"cluster": cluster.to_dict()}
            (node_dir / "node-config.json").write_text(json.dumps(node_cfg, indent=2), encoding="utf-8")

            # If the node has seeds (e.g. pool), write a tiny bootstrap hint file.
            # For v0 the node_entry + runtime will self-publish via the DHT once mesh-ready.
            # We still write it for future use by ControlBootstrap or manual injection.
            if np.seeds:
                (node_dir / "seeds.json").write_text(json.dumps({"seeds": np.seeds}, indent=2), encoding="utf-8")

            env = [
                "-e",
                f"TENET_NODE_ID={np.id}",
                "-e",
                f"TENET_ROLE={np.role or ('expert' if 'expert' in np.capabilities else 'relay')}",
            ]
            if np.persist:
                env += ["-e", "TENET_CONTROL_STORE=1"]

            caps = ["--cap-add=NET_ADMIN"]
            if np.persist:
                vol = f"tenet-sim-{sc.network_id}-{np.id}-ctl"
                # Create the volume if it doesn't exist (idempotent).
                _docker(["volume", "create", vol], check=False)
                caps += ["-v", f"{vol}:/var/lib/tenet/control"]

            # Mount the per-node config dir at /etc/tenet
            mounts = [
                "-v",
                f"{node_dir}:/etc/tenet:ro",
            ]

            # For fast dev iteration on the *same* machine, also mount the live source
            # so the container can `uv pip install -e /host-src` at entry.
            # The Dockerfile.node + node-entry.sh already support /host-src.
            root = Path(__file__).resolve().parents[2]
            mounts += ["-v", f"{root}:/host-src:ro"]

            # Run (detached). We do not publish ports for pure local-docker container-to-container.
            # (If you want to reach from the host, add -p or use host networking.)
            run_cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                cname,
                "--network",
                net_name,
                *caps,
                *env,
                *mounts,
                self.image,
                "serve",
            ]
            _docker(run_cmd)
            containers[np.id] = cname

        handle = LocalDockerHandle(
            scenario=sc,
            network=net_name,
            containers=containers,
            cfg_root=tmp,
        )

        if netem:
            self.apply_netem(handle)

        if wait:
            # Give the containers a moment to start their serve loops and (for dht nodes)
            # complete their internal mesh-ready bootstrap. The runtime already waits
            # for mesh before republishing, so a short sleep + a later "wait for records"
            # in workloads is usually enough.
            time.sleep(1.5)

        return handle

    def apply_netem(self, h: LocalDockerHandle) -> None:
        """Apply (or re-apply) netem inside each container based on its logical site.

        v0: simple global netem on eth0 using the "worst" link from this container's
        site to any other site that has containers in this realization. This already
        gives differentiated conditions between "home" and "faraway" groups.

        A later version will do destination-IP specific filters using the actual
        container IPs of the peer sites.
        """
        sc = h.scenario
        # Group containers by their logical site.
        site_of: dict[str, str] = {}
        for n in sc.nodes:
            if n.id in h.containers:
                site_of[n.id] = n.placement

        # For each container, pick a representative profile (max latency/loss among
        # links from its site to any other site that has nodes here).
        for nid, cname in h.containers.items():
            mysite = site_of.get(nid, "")
            prof = None
            for other in set(site_of.values()):
                if other == mysite:
                    continue
                ln = sc.link_profile(mysite, other)
                if ln is None:
                    continue
                if prof is None or (ln.latency_ms or 0) > (prof.latency_ms or 0):
                    prof = ln
            if prof is None:
                # No cross-site link for this site in the current realization; nothing to do.
                continue

            delay = f"{int(prof.latency_ms)}ms" if prof.latency_ms else "0ms"
            loss = f"{prof.loss_percent}%" if prof.loss_percent else "0%"
            jitter = f"{int(prof.jitter_ms)}ms" if prof.jitter_ms else ""

            # Clear existing qdisc (best effort), then add a simple root netem.
            # This affects *all* egress from the container.
            cmds = [
                "tc qdisc del dev eth0 root || true",
                f'tc qdisc add dev eth0 root netem delay {delay} {f"jitter {jitter} " if jitter else ""}loss {loss}',
            ]
            for c in cmds:
                # docker exec may fail if container not fully up yet; be tolerant on first apply
                try:
                    _run(["docker", "exec", cname, "sh", "-c", c], check=False, capture=True)
                except Exception:
                    pass

    def logs(self, h: LocalDockerHandle, node_id: str, *, follow: bool = False, tail: int | None = None) -> None:
        cname = h.containers[node_id]
        cmd = ["docker", "logs"]
        if follow:
            cmd.append("-f")
        if tail is not None:
            cmd += ["--tail", str(tail)]
        cmd.append(cname)
        # Stream to current stdout/stderr
        subprocess.run(cmd, check=False)

    def status(self, h: LocalDockerHandle) -> dict[str, Any]:
        out = {}
        for nid, cname in h.containers.items():
            try:
                res = _docker(
                    ["inspect", "--format", "{{.State.Status}} {{.State.Running}}", cname],
                    capture=True,
                )
                out[nid] = res.stdout.strip()
            except subprocess.CalledProcessError:
                out[nid] = "missing"
        return out

    def down(self, h: LocalDockerHandle, *, remove_volumes: bool = False, remove_net: bool = True) -> None:
        for cname in h.containers.values():
            _docker(["rm", "-f", cname], check=False)
        if remove_volumes:
            # Volumes are named tenet-sim-<netid>-<node>-ctl
            for nid in h.containers:
                vol = f"tenet-sim-{h.scenario.network_id}-{nid}-ctl"
                _docker(["volume", "rm", "-f", vol], check=False)
        if remove_net:
            _docker(["network", "rm", h.network], check=False)
        # Best-effort cleanup of the temp config dir (may be in use on some platforms).
        try:
            # Do not rm -rf here in case the user wants to inspect; caller can decide.
            pass
        except Exception:
            pass
