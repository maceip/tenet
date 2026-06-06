"""Basic ssh-docker runner for the 5-mode simulator (Modes 2-5).

This is a first-cut implementation of the "remote site" surface.

Responsibilities for a site declared with runner: ssh-docker:
- Build (or reuse) the local tenet-node image.
- docker save | ssh <user@host> docker load
- Write per-site ClusterConfig views that use the site's external_host for
  any "public" seed contacts (so other sites can reach the nodes).
- docker run on the remote (with -p for the mixnet and dht ports, or --network host).
- Apply netem on the remote containers via ssh docker exec (same tc rules).
- Support stop / logs / status via ssh docker ...

Assumptions on the remote:
- Docker is installed and the user can run docker (in docker group or root).
- For easy UDP between sites, the machines should be on the same VPN
  (Tailscale, WireGuard, etc.). The scenario's external_host should be the
  VPN IP (or a public IP with the ports open).

This is intentionally not as polished as the local-docker runner; it gives the
required "surface" so that a single scenario file + `sim up` can target mixed
and cloud configurations.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..model import Scenario, Site


def _sh(cmd: str) -> int:
    return subprocess.call(cmd, shell=True)


@dataclass
class SshDockerHandle:
    scenario: Scenario
    site: str
    ssh: str
    containers: dict[str, str]  # node_id -> remote container name
    remote_work_dir: str
    external_host: str | None


class SshDockerRunner:
    """Minimal but usable ssh-docker implementation for the 5 modes."""

    def __init__(self, image: str = "tenet-node:dev"):
        self.image = image

    def _local_build_if_needed(self) -> None:
        # Best effort: if the image doesn't exist locally, try the dedicated script.
        try:
            subprocess.check_call(
                ["docker", "image", "inspect", self.image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except Exception:
            pass
        script = Path(__file__).resolve().parents[2] / "scripts" / "build-node-image.sh"
        if script.exists():
            subprocess.check_call(["bash", str(script)])
        else:
            # Fall back to plain build (may have the same context issues; user can pre-build).
            subprocess.check_call(
                ["docker", "build", "-t", self.image, "-f", "deploy/Dockerfile.node", "."]
            )

    def _ssh(self, ssh: str, remote_cmd: str) -> None:
        full = f"ssh -o StrictHostKeyChecking=accept-new {ssh} {shlex.quote(remote_cmd)}"
        rc = _sh(full)
        if rc != 0:
            raise RuntimeError(f"ssh command failed on {ssh}: {remote_cmd}")

    def _ssh_capture(self, ssh: str, remote_cmd: str) -> str:
        full = f"ssh -o StrictHostKeyChecking=accept-new {ssh} {shlex.quote(remote_cmd)}"
        out = subprocess.check_output(full, shell=True, text=True)
        return out

    def bring_up_site(
        self,
        sc: Scenario,
        site_name: str,
        site: Site,
        *,
        netem: bool = True,
    ) -> SshDockerHandle:
        assert site.runner == "ssh-docker"
        assert site.ssh, "ssh-docker site requires ssh user@host"

        self._local_build_if_needed()

        # Save image and load on remote.
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tf:
            tar_path = tf.name
        try:
            subprocess.check_call(["docker", "save", "-o", tar_path, self.image])
            remote_tar = "/tmp/tenet-node-image.tar"
            _sh(f"cat {tar_path} | ssh -o StrictHostKeyChecking=accept-new {site.ssh} 'cat > {remote_tar}'")
            self._ssh(site.ssh, f"docker load -i {remote_tar}")
        finally:
            Path(tar_path).unlink(missing_ok=True)

        # For this site, generate a ClusterConfig view that advertises the external_host
        # for any nodes that other sites will dial.
        # (Simplified: we give every node in this site the same external_host for its
        # "public" address in the client/remote views. Real impl would do per-node port
        # publishing + external_host:published_port.)
        ext = site.external_host or "127.0.0.1"

        nodes_in_site = [n for n in sc.nodes if n.placement == site_name]
        if not nodes_in_site:
            return SshDockerHandle(sc, site_name, site.ssh, {}, "/tmp", ext)

        # Write a site-local view on the remote.
        # We use a simple layout under ~/tenet-sim-<network_id>/
        remote_dir = f"~/tenet-sim-{sc.network_id}/{site_name}"
        self._ssh(site.ssh, f"mkdir -p {remote_dir}")

        # Minimal cluster slice for this site (binds on 0.0.0.0 inside the remote containers,
        # but the "advertised" host for other sites is the external_host).
        # For v1 we let the sim orchestrator (the caller) have already decided the ports
        # or we pick fixed ones. Here we just use the ports from a generated full cluster
        # and override the "visible" host.
        # To keep it simple, we synthesize a tiny cluster for the nodes in this site.
        from tenet.packet.OutfoxParams import OutfoxParams
        from tenet.config import ClusterConfig

        params = OutfoxParams(
            payload_size=int(sc.mixnet.get("payload_size", 2048)),
            routing_size=int(sc.mixnet.get("routing_size", 16)),
            max_hops=int(sc.mixnet.get("max_hops", 5)),
        )
        nodes: dict[str, Any] = {}
        base_port = 52000
        for i, np in enumerate(nodes_in_site):
            p = base_port + i * 2
            nodes[np.id] = {
                "host": "0.0.0.0",  # bind inside container
                "port": p,
                "kem_pk": "",  # will be filled
                "kem_sk": "",
                "role": np.role or ("expert" if "expert" in np.capabilities else "relay"),
                "capabilities": list(np.capabilities),
            }
        for nid, nd in nodes.items():
            pk, sk = params.kem.keygen()
            nd["kem_pk"] = pk.hex()
            nd["kem_sk"] = sk.hex()

        client_p = base_port + len(nodes_in_site) * 2 + 9
        raw = {
            "params": {"payload_size": params.payload_size, "routing_size": params.routing_size, "max_hops": params.max_hops},
            "client": {"host": "127.0.0.1", "port": client_p},
            "nodes": nodes,
            "network_id": sc.network_id,
        }
        cluster = ClusterConfig.from_dict(raw)

        # Write the config on the remote.
        cfg_json = json.dumps(cluster.to_dict(), indent=2)
        self._ssh(site.ssh, f"cat > {remote_dir}/cluster.json << 'EOC'\n{cfg_json}\nEOC")

        containers: dict[str, str] = {}
        for np in nodes_in_site:
            cname = f"tenet-{np.id}"
            # Run with published ports so the external_host can reach them.
            # We publish the mixnet port and the dht port (mixnet+1).
            node = cluster.node(np.id)
            mix_p = node.port
            dht_p = mix_p + 1
            run = (
                f"docker run -d --name {cname} "
                f"-p {mix_p}:{mix_p}/udp -p {dht_p}:{dht_p}/udp "
                f"--cap-add=NET_ADMIN "
                f"-e TENET_NODE_ID={np.id} "
                f"-e TENET_ROLE={np.role or ('expert' if 'expert' in np.capabilities else 'relay')} "
                f"-v {remote_dir}:/etc/tenet:ro "
                f"{self.image} serve"
            )
            self._ssh(site.ssh, run)
            containers[np.id] = cname

        if netem:
            self.apply_netem_for_site(sc, site_name, site.ssh, containers)

        return SshDockerHandle(sc, site_name, site.ssh, containers, remote_dir, ext)

    def apply_netem_for_site(
        self, sc: Scenario, site_name: str, ssh: str, containers: dict[str, str]
    ) -> None:
        # Same simple global netem as the local runner (max latency to any other realized site).
        for nid, cname in containers.items():
            mysite = site_name
            prof = None
            for other_site in sc.site_names:
                if other_site == mysite:
                    continue
                ln = sc.link_profile(mysite, other_site)
                if ln and (prof is None or (ln.latency_ms or 0) > (prof.latency_ms or 0)):
                    prof = ln
            if not prof:
                continue
            delay = f"{int(prof.latency_ms)}ms" if prof.latency_ms else "0ms"
            loss = f"{prof.loss_percent}%" if prof.loss_percent else "0%"
            jitter = f"{int(prof.jitter_ms)}ms" if prof.jitter_ms else ""
            jitter_clause = f"jitter {jitter} " if jitter else ""
            cmd = (
                f"docker exec {cname} sh -c "
                f"'tc qdisc del dev eth0 root 2>/dev/null || true; "
                f"tc qdisc add dev eth0 root netem delay {delay} {jitter_clause}loss {loss}'"
            )
            _sh(f"ssh -o StrictHostKeyChecking=accept-new {ssh} {shlex.quote(cmd)}")

    def down_site(self, h: SshDockerHandle, *, clean: bool = False) -> None:
        for cname in h.containers.values():
            self._ssh(h.ssh, f"docker rm -f {cname} || true")
        if clean:
            self._ssh(h.ssh, f"rm -rf {h.remote_work_dir} || true")
