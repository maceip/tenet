"""Lightweight scenario model for the Tenet mixnet+DHT simulator.

No heavy dependencies (no pydantic). YAML/JSON driven, validated lightly.
This is the single source of truth for "what logical network do I want"
independent of where the nodes physically run (local docker, ssh to laptop,
cloud VM, or any mix of the above).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

from tenet.config import CAPABILITY_CONTROL_DHT, CAPABILITY_EXPERT, CAPABILITY_MIXNODE


VALID_RUNNERS = {"local-docker", "ssh-docker"}

DEFAULT_MIXNET = {
    "payload_size": 2048,
    "routing_size": 16,
    "max_hops": 5,
}


@dataclass
class Site:
    name: str
    runner: str = "local-docker"
    # For ssh-docker
    ssh: str | None = None  # e.g. "user@host" or "user@host:port"
    external_host: str | None = None  # IP/hostname that *other* sites use to reach nodes in this site
    # TEE / attestation modeling for modes without real cloud TEE (Nitro etc.).
    # Reasonable options for "lack of cloud-tee":
    #   "none"  - no attestation; experts/matchers run plain (most local/mixed dev sims).
    #   "mock"  - the sim can inject fake AttestationReceiptDescriptor records so
    #             trust/control-plane code paths for TEE claims are still exercised.
    #   "nitro" - this site has (or will have) real Nitro/TEE; the runner is
    #             expected to launch the full bountynet + EIF workload (only
    #             meaningful for certain cloud ssh or future cloud-native runners).
    tee_mode: str = "none"
    # Extra free-form (cloud region, notes, etc.)
    meta: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.runner not in VALID_RUNNERS:
            raise ValueError(f"site {self.name}: unknown runner {self.runner!r}")
        if self.runner == "ssh-docker" and not self.ssh:
            raise ValueError(f"site {self.name}: ssh-docker requires 'ssh' (user@host)")
        if self.tee_mode not in ("none", "mock", "nitro"):
            raise ValueError(f"site {self.name}: tee_mode must be none|mock|nitro")


@dataclass
class Link:
    """Directed or undirected network condition between two sites."""
    from_site: str
    to_site: str
    latency_ms: float = 0.0
    loss_percent: float = 0.0
    jitter_ms: float = 0.0

    def key(self) -> tuple[str, str]:
        # Normalize so (A,B) == (B,A) for lookup purposes.
        a, b = sorted((self.from_site, self.to_site))
        return (a, b)


@dataclass
class NodePlacement:
    id: str
    placement: str  # site name
    capabilities: tuple[str, ...] = (CAPABILITY_MIXNODE, CAPABILITY_CONTROL_DHT)
    role: str | None = None  # mixnode | relay | expert | any (for runtime)
    # Optional: seed some initial control records (e.g. a pool this expert serves).
    # These are *declarative* hints; the sim may turn them into signed records at bootstrap.
    seeds: dict[str, Any] = field(default_factory=dict)
    persist: bool = False  # give this node a docker volume for PersistentControlStore

    def validate(self, known_sites: set[str]) -> None:
        if self.placement not in known_sites:
            raise ValueError(f"node {self.id}: placement site {self.placement!r} not declared")
        # Light capability sanity (real validation happens in tenet.config too).
        bad = [c for c in self.capabilities if not isinstance(c, str)]
        if bad:
            raise ValueError(f"node {self.id}: capabilities must be strings")


@dataclass
class Workload:
    name: str
    type: str  # "mixnet_client" for now
    placement: str  # site to run the client/driver container from
    target: str  # e.g. "pool~demo~tenet" or a stable name / handle
    count: int = 1
    expect_success: bool = True
    timeout_s: float = 30.0


@dataclass
class Scenario:
    network_id: str
    sites: dict[str, Site]
    links: list[Link]
    nodes: list[NodePlacement]
    workloads: list[Workload] = field(default_factory=list)
    mixnet: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_MIXNET))
    # Global default for TEE modeling when individual sites don't specify.
    default_tee_mode: str = "none"

    @property
    def site_names(self) -> set[str]:
        return set(self.sites.keys())

    def link_profile(self, a: str, b: str) -> Link | None:
        """Return the (normalized) profile for traffic from a to b (or b to a)."""
        key = tuple(sorted((a, b)))
        for ln in self.links:
            if ln.key() == key:
                return ln
        return None

    def nodes_in_site(self, site: str) -> list[NodePlacement]:
        return [n for n in self.nodes if n.placement == site]

    def validate(self) -> None:
        if not self.network_id:
            raise ValueError("network_id is required")
        if not self.sites:
            raise ValueError("at least one site is required")
        for s in self.sites.values():
            s.validate()
        known = self.site_names
        for n in self.nodes:
            n.validate(known)
        for w in self.workloads:
            if w.placement not in known:
                raise ValueError(f"workload {w.name}: placement {w.placement!r} unknown")
        # Links may reference undeclared sites (useful for "future" sites); we only warn.
        for ln in self.links:
            for side in (ln.from_site, ln.to_site):
                if side not in known:
                    # Not fatal — allows partial scenarios.
                    pass


def _load_yaml_or_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required to load .yaml scenarios. "
                "Install with: uv add --dev pyyaml   (or pip install pyyaml) "
                "and re-run."
            )
        return yaml.safe_load(text) or {}
    return json.loads(text)


def load_scenario(path: str | Path) -> Scenario:
    p = Path(path)
    raw = _load_yaml_or_json(p)

    # sites
    sites: dict[str, Site] = {}
    for name, sraw in (raw.get("sites") or {}).items():
        sites[name] = Site(
            name=name,
            runner=str(sraw.get("runner", "local-docker")),
            ssh=sraw.get("ssh"),
            external_host=sraw.get("external_host"),
            meta=dict(sraw.get("meta") or {}),
        )

    # links
    links: list[Link] = []
    for lraw in raw.get("links") or []:
        links.append(
            Link(
                from_site=str(lraw["from"]),
                to_site=str(lraw["to"]),
                latency_ms=float(lraw.get("latency_ms", 0)),
                loss_percent=float(lraw.get("loss_percent", 0)),
                jitter_ms=float(lraw.get("jitter_ms", 0)),
            )
        )

    # nodes
    nodes: list[NodePlacement] = []
    for nraw in raw.get("nodes") or []:
        caps = nraw.get("capabilities")
        if caps is None:
            # Sensible default for a core mixnet+dht participant
            caps = [CAPABILITY_MIXNODE, CAPABILITY_CONTROL_DHT]
        nodes.append(
            NodePlacement(
                id=str(nraw["id"]),
                placement=str(nraw["placement"]),
                capabilities=tuple(str(c) for c in caps),
                role=nraw.get("role"),
                seeds=dict(nraw.get("seeds") or {}),
                persist=bool(nraw.get("persist", False)),
            )
        )

    # workloads (optional)
    workloads: list[Workload] = []
    for wraw in raw.get("workloads") or []:
        workloads.append(
            Workload(
                name=str(wraw["name"]),
                type=str(wraw.get("type", "mixnet_client")),
                placement=str(wraw["placement"]),
                target=str(wraw["target"]),
                count=int(wraw.get("count", 1)),
                expect_success=bool(wraw.get("expect_success", True)),
                timeout_s=float(wraw.get("timeout_s", 30)),
            )
        )

    mixnet = dict(DEFAULT_MIXNET)
    mixnet.update(raw.get("mixnet") or {})

    sc = Scenario(
        network_id=str(raw.get("network_id", "sim-default")),
        sites=sites,
        links=links,
        nodes=nodes,
        workloads=workloads,
        mixnet=mixnet,
        default_tee_mode=str(raw.get("default_tee_mode", "none")),
    )
    # Apply default tee_mode to sites that didn't specify one.
    for s in sc.sites.values():
        if not s.tee_mode or s.tee_mode == "none" and sc.default_tee_mode:
            # only override if the site didn't explicitly set something else
            if getattr(s, "_explicit_tee", False) is False:
                s.tee_mode = sc.default_tee_mode
    sc.validate()
    return sc


def scenario_to_dict(sc: Scenario) -> dict[str, Any]:
    """For debugging / dumping effective scenario."""
    return {
        "network_id": sc.network_id,
        "mixnet": sc.mixnet,
        "sites": {
            name: {
                "runner": s.runner,
                "ssh": s.ssh,
                "external_host": s.external_host,
                "meta": s.meta,
            }
            for name, s in sc.sites.items()
        },
        "links": [
            {
                "from": ln.from_site,
                "to": ln.to_site,
                "latency_ms": ln.latency_ms,
                "loss_percent": ln.loss_percent,
                "jitter_ms": ln.jitter_ms,
            }
            for ln in sc.links
        ],
        "nodes": [
            {
                "id": n.id,
                "placement": n.placement,
                "capabilities": list(n.capabilities),
                "role": n.role,
                "persist": n.persist,
            }
            for n in sc.nodes
        ],
        "workloads": [
            {
                "name": w.name,
                "type": w.type,
                "placement": w.placement,
                "target": w.target,
                "count": w.count,
            }
            for w in sc.workloads
        ],
    }
