"""Legacy module name for network-beta topology.

Real nodes, enforced separation, scale via expert list. See STATUS.md item 15.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from tenet.schema import normalize_schema, supports_schema

TOPOLOGY_VERSION = "tenet.gate_b_topology.2026-06"
DEFAULT_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "gate-b-topology.json"


@dataclass(frozen=True)
class RoleHost:
    """SSH-reachable network node."""

    host: str
    ssh_user: str = "ec2-user"
    ssh_key: str | None = None
    port: int | None = None
    node_id: str | None = None

    def validate(self, role: str) -> None:
        if not self.host or self.host in {"local", "127.0.0.1", "localhost"}:
            if role in {"expert", "reach_relay"}:
                raise ValueError(f"{role}.host must be a remote node IP/DNS, not {self.host!r}")
        if self.port is not None and not (1 <= int(self.port) <= 65535):
            raise ValueError(f"{role}.port must be 1..65535")


@dataclass(frozen=True)
class MatcherRole:
    """Attested matcher TEE (parent may share IP with reach relay; expert nodes may not)."""

    url: str
    host: str | None = None
    ssh_user: str = "ec2-user"
    ssh_key: str | None = None

    def validate(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError("matcher.url must be https://")


@dataclass(frozen=True)
class GateBTopology:
    version: str
    reach_relay: RoleHost
    experts: tuple[RoleHost, ...]
    matcher: MatcherRole
    asker_host: str = "local"

    @property
    def expert(self) -> RoleHost:
        """First expert node (compat)."""
        return self.experts[0]

    def validate(self) -> GateBTopology:
        if not supports_schema(self.version, TOPOLOGY_VERSION):
            raise ValueError(f"unsupported topology version: {self.version!r}")
        if not self.experts:
            raise ValueError("topology must include at least one expert node")
        self.reach_relay.validate("reach_relay")
        for index, expert in enumerate(self.experts):
            expert.validate(f"experts[{index}]")
            if expert.host == self.reach_relay.host:
                raise ValueError(
                    f"experts[{index}].host must differ from reach_relay.host "
                    f"({self.reach_relay.host!r}) — run expert clients on separate nodes"
                )
            if self.matcher.host and expert.host == self.matcher.host:
                raise ValueError(
                    f"experts[{index}].host must differ from matcher parent host "
                    f"({self.matcher.host!r})"
                )
        seen = {e.host for e in self.experts}
        if len(seen) != len(self.experts):
            raise ValueError("expert node hosts must be unique")
        self.matcher.validate()
        return self

    def relay_endpoint(self) -> tuple[str, int]:
        return self.reach_relay.host, int(self.reach_relay.port or 4433)

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "GateBTopology":
        roles = raw.get("roles")
        if not isinstance(roles, dict):
            raise ValueError("topology.roles must be an object")

        def _role(name: str) -> dict[str, object]:
            block = roles.get(name)
            if not isinstance(block, dict):
                raise ValueError(f"topology.roles.{name} must be an object")
            return block

        relay_raw = _role("reach_relay")
        matcher_raw = _role("matcher")
        asker_raw = roles.get("asker")
        asker_host = "local"
        if isinstance(asker_raw, dict) and asker_raw.get("host"):
            asker_host = str(asker_raw["host"])

        experts: list[RoleHost] = []
        experts_raw = roles.get("experts")
        if isinstance(experts_raw, list):
            for item in experts_raw:
                if not isinstance(item, dict):
                    raise ValueError("topology.roles.experts[] entries must be objects")
                experts.append(_expert_from_dict(item))
        if not experts:
            experts.append(_expert_from_dict(_role("expert")))

        topo = cls(
            version=normalize_schema(str(raw.get("version", "")), TOPOLOGY_VERSION),
            reach_relay=RoleHost(
                host=str(relay_raw["host"]),
                ssh_user=str(relay_raw.get("ssh_user", "ec2-user")),
                ssh_key=_optional_str(relay_raw.get("ssh_key")),
                port=int(relay_raw["port"]) if relay_raw.get("port") is not None else 4433,
            ),
            experts=tuple(experts),
            matcher=MatcherRole(
                url=str(matcher_raw["url"]),
                host=_optional_str(matcher_raw.get("host")),
                ssh_user=str(matcher_raw.get("ssh_user", "ec2-user")),
                ssh_key=_optional_str(matcher_raw.get("ssh_key")),
            ),
            asker_host=asker_host,
        )
        return topo.validate()

    @classmethod
    def load(cls, path: str | Path | None = None) -> "GateBTopology":
        env_path = os.environ.get("TENET_GATE_B_TOPOLOGY")
        config_path = Path(path) if path is not None else Path(env_path or DEFAULT_TOPOLOGY_PATH)
        if not config_path.is_file():
            raise FileNotFoundError(
                f"gate-B topology not found: {config_path} "
                "(run ./scripts/gate-b/provision-network.sh)"
            )
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("topology file must be a JSON object")
        return cls.from_dict(raw)


def _expert_from_dict(raw: dict[str, object]) -> RoleHost:
    return RoleHost(
        host=str(raw["host"]),
        ssh_user=str(raw.get("ssh_user", "ubuntu")),
        ssh_key=_optional_str(raw.get("ssh_key")),
        node_id=_optional_str(raw.get("node_id")),
    )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
