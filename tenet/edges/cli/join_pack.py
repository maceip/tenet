"""Single-file join pack for askers and experts (public pins only, no secrets)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

JOIN_PACK_SCHEMA = "por.join_pack.v1"
DEFAULT_JOIN_PACK_PATHS = (
    Path("config/join-pack.json"),
    Path("join-pack.json"),
)


def resolve_join_pack_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    for candidate in DEFAULT_JOIN_PACK_PATHS:
        if candidate.is_file():
            return candidate
    return DEFAULT_JOIN_PACK_PATHS[0]


@dataclass(frozen=True)
class JoinPack:
    """Public network pins: attested matcher + trusted reachability relay."""

    matcher: Mapping[str, object]
    reachability_relay: Mapping[str, object]
    directory: Mapping[str, object]
    asker_mailbox_config: Path
    pack_path: Path

    @classmethod
    def load(cls, path: str | Path | None = None) -> "JoinPack":
        pack_path = resolve_join_pack_path(path).resolve()
        raw = json.loads(pack_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("join pack must be a JSON object")
        schema = str(raw.get("schema", ""))
        if schema != JOIN_PACK_SCHEMA:
            raise ValueError(f"unsupported join pack schema: {schema!r}")

        matcher = raw.get("matcher")
        if not isinstance(matcher, dict):
            raise TypeError("matcher must be an object")

        relay = raw.get("reachability_relay")
        if not isinstance(relay, dict):
            raise TypeError("reachability_relay must be an object")

        directory = raw.get("directory")
        if not isinstance(directory, dict):
            raise TypeError("directory must be an object")

        asker = raw.get("asker")
        if not isinstance(asker, dict):
            raise TypeError("asker must be an object")
        mailbox_rel = str(asker.get("mailbox_config", "config/live-mailbox-client.json"))
        mailbox_path = (pack_path.parent / mailbox_rel).resolve()
        if not mailbox_path.is_file():
            raise FileNotFoundError(f"join pack mailbox config missing: {mailbox_path}")

        return cls(
            matcher=matcher,
            reachability_relay=relay,
            directory=directory,
            asker_mailbox_config=mailbox_path,
            pack_path=pack_path,
        )

    def matcher_url(self) -> str:
        return str(self.matcher["url"]).rstrip("/")

    def match_endpoint(self) -> str:
        return str(self.directory.get("match_url", f"{self.matcher_url()}/v1/match"))
