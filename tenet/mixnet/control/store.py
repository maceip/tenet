"""Persistent local store for mixnet control records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from tenet.mixnet.control.records import SignedControlRecord


class PersistentControlStore:
    """Small JSON store for validated signed control records.

    The store is intentionally simple because records are small control-plane
    objects, not arbitrary blobs.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> tuple[SignedControlRecord, ...]:
        if not self.path.is_file():
            return tuple()
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("control store root must be an object")
        records = raw.get("records") or []
        if not isinstance(records, list):
            raise ValueError("control store records must be a list")
        return tuple(
            SignedControlRecord.from_dict(item)
            for item in records
            if isinstance(item, dict)
        )

    def save_all(self, records: Iterable[SignedControlRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        raw = {
            "schema": "tenet.mixnet.control.store.2026-06",
            "records": [record.to_dict() for record in records],
        }
        tmp.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)
