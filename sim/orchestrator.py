"""High-level orchestrator.

Dispatches a Scenario to the appropriate runner(s) based on each site's declared
runner (local-docker, ssh-docker, or host realization). Owns session lifecycle
for the sim CLI commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import Scenario, load_scenario
from .runners.host_dev import HostDevHandle, HostDevRunner
from .runners.local_docker import LocalDockerHandle, LocalDockerRunner
from .runners.ssh_docker import SshDockerRunner

import json
from pathlib import Path


@dataclass
class SimSession:
    scenario: Scenario
    local_handle: LocalDockerHandle | None = None
    # Future: per-site handles for ssh-docker, cloud, etc.


class Orchestrator:
    def __init__(self) -> None:
        self._session: SimSession | None = None
        self._local_runner = LocalDockerRunner()
        self._host_runner = HostDevRunner()
        self._ssh_runner = SshDockerRunner()

    def load(self, scenario_path: str | Path) -> Scenario:
        return load_scenario(scenario_path)

    def up(
        self,
        scenario: Scenario | str | Path,
        *,
        netem: bool = True,
        wait: bool = True,
        rebuild: bool = False,
        realization: str | None = None,  # "docker" | "host" | None (auto)
    ) -> SimSession:
        if not isinstance(scenario, Scenario):
            scenario = self.load(scenario)

        # Realize local sites via the chosen realization. ssh-docker sites are
        # handled by the ssh runner (used for true multi-machine modes).
        use_host = realization == "host"
        if realization is None:
            try:
                import subprocess
                subprocess.check_call(
                    ["docker", "image", "inspect", "tenet-node:dev"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                use_host = False
            except Exception:
                use_host = True

        if use_host:
            h = self._host_runner.bring_up(scenario, netem=netem, wait=wait)
            sess = SimSession(scenario=scenario, local_handle=None)
            sess._host_handle = h  # type: ignore[attr-defined]
            self._session = sess
            self._persist_session(sess, scenario if isinstance(scenario, (str, Path)) else None)
            return sess

        h = self._local_runner.bring_up(scenario, netem=netem, wait=wait, rebuild_image=rebuild)
        sess = SimSession(scenario=scenario, local_handle=h)
        self._session = sess
        self._persist_session(sess, scenario if isinstance(scenario, (str, Path)) else None)
        return sess

    def status(self, sess: SimSession | None = None) -> dict[str, Any]:
        sess = sess or self._session
        if sess is None:
            return {"error": "no active session"}
        if getattr(sess, "_host_handle", None) is not None:
            return self._host_runner.status(sess._host_handle)  # type: ignore[attr-defined]
        if sess.local_handle is None:
            return {"error": "no active session"}
        return self._local_runner.status(sess.local_handle)

    def logs(self, node_id: str, *, follow: bool = False, tail: int | None = 50, sess: SimSession | None = None) -> None:
        sess = sess or self._session
        if sess is None:
            print("no active session")
            return
        if getattr(sess, "_host_handle", None) is not None:
            self._host_runner.logs(sess._host_handle, node_id, follow=follow, tail=tail or 50)  # type: ignore[attr-defined]
            return
        if sess.local_handle is None:
            print("no active session")
            return
        self._local_runner.logs(sess.local_handle, node_id, follow=follow, tail=tail)

    def netem_apply(self, sess: SimSession | None = None) -> None:
        sess = sess or self._session
        if sess is None:
            return
        if getattr(sess, "_host_handle", None) is not None:
            self._host_runner.apply_netem(sess._host_handle)  # type: ignore[attr-defined]
            return
        if sess.local_handle is None:
            return
        self._local_runner.apply_netem(sess.local_handle)

    def down(self, *, clean: bool = False, sess: SimSession | None = None) -> None:
        sess = sess or self._session
        if sess is None:
            return
        if getattr(sess, "_host_handle", None) is not None:
            self._host_runner.down(sess._host_handle, clean=clean)  # type: ignore[attr-defined]
            self._session = None
            return
        if sess.local_handle is None:
            return
        self._local_runner.down(sess.local_handle, remove_volumes=clean, remove_net=True)
        self._session = None

    def plan(self, scenario: Scenario | str | Path) -> dict[str, Any]:
        if not isinstance(scenario, Scenario):
            scenario = self.load(scenario)
        realization: dict[str, list[str]] = {}
        for site_name, site in scenario.sites.items():
            nodes_here = [n.id for n in scenario.nodes if n.placement == site_name]
            realization[site_name] = {
                "runner": site.runner,
                "ssh": site.ssh,
                "external_host": site.external_host,
                "tee_mode": site.tee_mode,
                "nodes": nodes_here,
            }
        return {
            "network_id": scenario.network_id,
            "sites": realization,
            "links": [
                {
                    "from": ln.from_site,
                    "to": ln.to_site,
                    "latency_ms": ln.latency_ms,
                    "loss_percent": ln.loss_percent,
                    "jitter_ms": ln.jitter_ms,
                }
                for ln in scenario.links
            ],
            "default_tee_mode": scenario.default_tee_mode,
        }

    def _persist_session(self, sess: SimSession, scenario_path: str | Path | None = None) -> None:
        h = getattr(sess, "_host_handle", None)
        data = {
            "scenario": str(scenario_path) if scenario_path else None,
            "realization": "host" if h is not None else "docker",
        }
        if h is not None:
            data["cfg_dir"] = str(h.cfg_dir) if getattr(h, "cfg_dir", None) else None
            data["nodes"] = getattr(h, "nodes", {})
            data["netem"] = getattr(h, "netem_profiles", {})
        p = Path.cwd() / ".tenet-sim-session.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
