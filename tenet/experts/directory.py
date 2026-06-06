"""Peer discovery surfaces for tenet Expert Mode.

The MVP discovery model is deliberately boring: clients fetch a public snapshot
of peer manifests and rank locally. That avoids sending exact interests to a
live directory. Private discovery can be added later by implementing the same
provider interface and returning the same `DiscoveryResult` shape.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from tenet.experts.expert_route import PeerCandidate, PeerObservation, RouteIntent
from tenet.experts.memory_index import MemoryManifest
from tenet.handles import is_opaque_handle, opaque_handle_record_from_dict
from tenet.schema import normalize_schema, supports_schema


PUBLIC_SNAPSHOT_V1 = "public_snapshot_v1"
PRIVATE_DISCOVERY_V1 = "private_discovery_v1"
DIRECTORY_SNAPSHOT_VERSION = "tenet.directory_snapshot.2026-06"
DEFAULT_SNAPSHOT_FETCH_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_SNAPSHOT_BYTES = 5_000_000


class PrivateDiscoveryUnavailable(RuntimeError):
    """Raised when a caller asks for private discovery without a provider."""


class DirectorySnapshotFormatError(ValueError):
    """Raised when a public directory snapshot cannot be parsed safely."""


class DirectorySnapshotFetchError(RuntimeError):
    """Raised when a public directory snapshot cannot be fetched."""


@dataclass(frozen=True)
class PeerRecord:
    """Directory record for one service/expert peer."""

    manifest: MemoryManifest
    observation: PeerObservation | None = None
    descriptor: dict[str, object] | None = None
    handle: dict[str, object] | None = None

    @property
    def peer_id(self) -> str:
        return self.manifest.peer_id

    def route_handle(self, *, now: float | None = None) -> str | None:
        if self.handle is None:
            return None
        try:
            record = opaque_handle_record_from_dict(self.handle)
        except (TypeError, ValueError):
            return None
        if record.is_expired(now):
            return None
        if not is_opaque_handle(record.handle):
            return None
        return record.handle

    def candidate(self, *, now: float | None = None) -> PeerCandidate | None:
        if self.observation and self.observation.peer_id != self.peer_id:
            raise ValueError("observation peer_id must match manifest peer_id")
        handle = self.route_handle(now=now)
        if handle is None:
            return None
        return PeerCandidate(
            self.manifest,
            self.observation,
            route_handle=handle,
            publisher_id=self.peer_id,
        )


@dataclass(frozen=True)
class DiscoveryRequest:
    """Request for candidates before route scoring.

    Public snapshot discovery intentionally ignores the exact prompt and returns
    a snapshot for local ranking. Private discovery providers may use the intent
    cryptographically, but they should still return a candidate pool.
    """

    intent: RouteIntent
    mode: str = PUBLIC_SNAPSHOT_V1
    max_records: int | None = None


@dataclass(frozen=True)
class DiscoveryResult:
    candidates: tuple[PeerCandidate, ...]
    mode: str
    snapshot_size: int
    exact_query_sent: bool
    private_query_used: bool
    generated_at: str
    note: str


class DiscoveryProvider(Protocol):
    def discover(self, request: DiscoveryRequest) -> DiscoveryResult:
        """Return candidates for local Expert Mode planning."""


@dataclass(frozen=True)
class DirectorySnapshot:
    """Serializable public peer snapshot.

    This is not private discovery. It is a signed-or-served-later JSON-friendly
    list of public manifests that clients can rank locally without sending an
    exact prompt interest to the directory.
    """

    records: tuple[PeerRecord, ...]
    generated_at: str
    source: str = "snapshot"
    supernodes: tuple[dict[str, object], ...] = ()
    version: str = DIRECTORY_SNAPSHOT_VERSION

    @classmethod
    def from_directory(
        cls,
        directory: "PublicManifestDirectory",
        generated_at: str | None = None,
    ) -> "DirectorySnapshot":
        return cls(
            records=directory.records,
            generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
            source=directory.source,
        )

    @classmethod
    def from_json(cls, data: str) -> "DirectorySnapshot":
        try:
            raw = json.loads(data)
        except json.JSONDecodeError as exc:
            raise DirectorySnapshotFormatError(f"invalid directory snapshot JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise DirectorySnapshotFormatError("directory snapshot root must be an object")
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DirectorySnapshot":
        version = raw.get("version")
        if not supports_schema(str(version), DIRECTORY_SNAPSHOT_VERSION):
            raise DirectorySnapshotFormatError(
                f"unsupported directory snapshot version: {version!r}"
            )
        version = normalize_schema(str(version), DIRECTORY_SNAPSHOT_VERSION)

        generated_at = raw.get("generated_at")
        if not isinstance(generated_at, str) or not generated_at:
            raise DirectorySnapshotFormatError("directory snapshot requires generated_at")

        source = raw.get("source", "snapshot")
        if not isinstance(source, str):
            raise DirectorySnapshotFormatError("directory snapshot source must be a string")

        raw_records = raw.get("records")
        if not isinstance(raw_records, list):
            raise DirectorySnapshotFormatError("directory snapshot records must be a list")

        records = tuple(_peer_record_from_dict(item) for item in raw_records)
        supernodes_raw = raw.get("supernodes", [])
        if supernodes_raw is None:
            supernodes_raw = []
        if not isinstance(supernodes_raw, list):
            raise DirectorySnapshotFormatError("directory snapshot supernodes must be a list")
        supernodes = tuple(_supernode_record_from_dict(item) for item in supernodes_raw)
        return cls(
            records=records,
            generated_at=generated_at,
            source=source,
            supernodes=supernodes,
            version=version,
        )

    @classmethod
    def load(cls, path: str | Path) -> "DirectorySnapshot":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version": self.version,
            "generated_at": self.generated_at,
            "source": self.source,
            "records": [_peer_record_to_dict(record) for record in self.records],
        }
        if self.supernodes:
            data["supernodes"] = [dict(record) for record in self.supernodes]
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json() + "\n", encoding="utf-8")

    def directory(self) -> "PublicManifestDirectory":
        return PublicManifestDirectory(records=self.records, source=self.source)

    def with_supernodes(self, supernodes: Sequence[dict[str, object]]) -> "DirectorySnapshot":
        merged = {str(record.get("node_id", "")): dict(record) for record in self.supernodes}
        for record in supernodes:
            node_id = str(record.get("node_id", ""))
            if node_id:
                merged[node_id] = dict(record)
        return DirectorySnapshot(
            records=self.records,
            generated_at=self.generated_at,
            source=self.source,
            supernodes=tuple(merged.values()),
            version=self.version,
        )

    def with_handle_records(
        self,
        handle_records: Mapping[str, dict[str, object]],
    ) -> "DirectorySnapshot":
        records = []
        for record in self.records:
            handle = handle_records.get(record.peer_id, record.handle)
            records.append(
                PeerRecord(
                    manifest=record.manifest,
                    observation=record.observation,
                    descriptor=record.descriptor,
                    handle=dict(handle) if handle is not None else None,
                )
            )
        return DirectorySnapshot(
            records=tuple(records),
            generated_at=self.generated_at,
            source=self.source,
            supernodes=self.supernodes,
            version=self.version,
        )


@dataclass(frozen=True)
class PublicManifestDirectory:
    """In-memory public directory snapshot for MVP discovery."""

    records: tuple[PeerRecord, ...]
    source: str = "local"

    @classmethod
    def from_manifests(
        cls,
        manifests: Sequence[MemoryManifest],
        observations: Sequence[PeerObservation] | None = None,
        source: str = "local",
    ) -> "PublicManifestDirectory":
        obs_by_peer = {obs.peer_id: obs for obs in observations or ()}
        return cls(
            records=tuple(
                PeerRecord(manifest=manifest, observation=obs_by_peer.get(manifest.peer_id))
                for manifest in manifests
            ),
            source=source,
        )

    @classmethod
    def from_snapshot(cls, snapshot: DirectorySnapshot) -> "PublicManifestDirectory":
        return cls(records=snapshot.records, source=snapshot.source)

    @classmethod
    def from_snapshot_file(cls, path: str | Path) -> "PublicManifestDirectory":
        return cls.from_snapshot(DirectorySnapshot.load(path))

    def snapshot(self, generated_at: str | None = None) -> DirectorySnapshot:
        return DirectorySnapshot.from_directory(self, generated_at=generated_at)

    def save_snapshot(self, path: str | Path, generated_at: str | None = None) -> None:
        self.snapshot(generated_at=generated_at).save(path)

    def handle_records(self) -> dict[str, dict[str, object]]:
        return {
            record.peer_id: dict(record.handle)
            for record in self.records
            if record.handle is not None
        }

    def routing_kem_pk_hex(self, _handle: str) -> str | None:
        # Public snapshots may carry manifests and handle records, but they are
        # not a mailbox. Product routing key lookup must go through handle
        # resolution, not public descriptor material keyed by peer_id.
        return None

    def discover(self, request: DiscoveryRequest) -> DiscoveryResult:
        if request.mode != PUBLIC_SNAPSHOT_V1:
            raise PrivateDiscoveryUnavailable(
                f"{request.mode} is not configured; only {PUBLIC_SNAPSHOT_V1} is available"
            )

        candidates = tuple(
            candidate
            for record in self.records
            for candidate in (record.candidate(),)
            if candidate is not None
        )
        note = (
            "public snapshot returned handle-bearing records for local ranking; "
            "prompt and exact interest were not sent to the directory"
        )
        if request.max_records is not None:
            note += "; max_records ignored so public discovery does not truncate before scoring"

        return DiscoveryResult(
            candidates=candidates,
            mode=PUBLIC_SNAPSHOT_V1,
            snapshot_size=len(self.records),
            exact_query_sent=False,
            private_query_used=False,
            generated_at=datetime.now(timezone.utc).isoformat(),
            note=note,
        )


def load_records_from_snapshot_file(path: str | Path) -> tuple[PeerRecord, ...]:
    """Load public peer records from a JSON snapshot file."""
    return DirectorySnapshot.load(path).records


def load_directory_snapshot(
    source: str | Path,
    *,
    timeout: float = DEFAULT_SNAPSHOT_FETCH_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
) -> DirectorySnapshot:
    """Load a public directory snapshot from a file path or HTTP(S) URL."""

    if _is_http_source(source):
        return DirectorySnapshot.from_json(
            _read_http_snapshot(str(source), timeout=timeout, max_bytes=max_bytes)
        )
    return DirectorySnapshot.load(source)


def load_public_snapshot_directory(
    source: str | Path,
    *,
    timeout: float = DEFAULT_SNAPSHOT_FETCH_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
) -> PublicManifestDirectory:
    """Load a public snapshot provider from a file path or HTTP(S) URL."""

    return PublicManifestDirectory.from_snapshot(
        load_directory_snapshot(source, timeout=timeout, max_bytes=max_bytes)
    )


def _is_http_source(source: str | Path) -> bool:
    if isinstance(source, Path):
        return False
    return urlparse(str(source)).scheme in {"http", "https"}


def _read_http_snapshot(url: str, *, timeout: float, max_bytes: int) -> str:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise DirectorySnapshotFetchError(f"directory snapshot HTTP status {status}")
            data = response.read(max_bytes + 1)
    except HTTPError as exc:
        raise DirectorySnapshotFetchError(f"directory snapshot HTTP status {exc.code}") from exc
    except URLError as exc:
        raise DirectorySnapshotFetchError(f"directory snapshot fetch failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise DirectorySnapshotFetchError("directory snapshot fetch timed out") from exc
    if len(data) > max_bytes:
        raise DirectorySnapshotFetchError("directory snapshot exceeds max_bytes")
    return data.decode("utf-8")


def _peer_record_to_dict(record: PeerRecord) -> dict[str, Any]:
    data: dict[str, Any] = {
        "manifest": json.loads(record.manifest.to_json()),
    }
    if record.observation is not None:
        data["observation"] = asdict(record.observation)
    if record.descriptor is not None:
        data["descriptor"] = record.descriptor
    if record.handle is not None:
        data["handle"] = record.handle
    return data


def _peer_record_from_dict(raw: object) -> PeerRecord:
    if not isinstance(raw, dict):
        raise DirectorySnapshotFormatError("directory snapshot record must be an object")

    manifest_raw = raw.get("manifest")
    if not isinstance(manifest_raw, dict):
        raise DirectorySnapshotFormatError("directory snapshot record requires manifest object")
    try:
        manifest = MemoryManifest.from_json(json.dumps(manifest_raw))
    except (KeyError, TypeError, ValueError) as exc:
        raise DirectorySnapshotFormatError("record manifest is invalid") from exc

    observation = None
    observation_raw = raw.get("observation")
    if observation_raw is not None:
        if not isinstance(observation_raw, dict):
            raise DirectorySnapshotFormatError("record observation must be an object")
        observation = _peer_observation_from_dict(observation_raw)

    descriptor = raw.get("descriptor")
    if descriptor is not None and not isinstance(descriptor, dict):
        raise DirectorySnapshotFormatError("record descriptor must be an object")
    if "peer_address" in raw:
        raise DirectorySnapshotFormatError("record peer_address is not an asker-facing field")
    handle = raw.get("handle")
    if handle is not None and not isinstance(handle, dict):
        raise DirectorySnapshotFormatError("record handle must be an object")

    record = PeerRecord(
        manifest=manifest,
        observation=observation,
        descriptor=descriptor,
        handle=handle,
    )
    if record.observation and record.observation.peer_id != record.peer_id:
        exc = ValueError("observation peer_id must match manifest peer_id")
        raise DirectorySnapshotFormatError(str(exc)) from exc
    return record


def _supernode_record_from_dict(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise DirectorySnapshotFormatError("directory snapshot supernode must be an object")
    node_id = raw.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        raise DirectorySnapshotFormatError("directory snapshot supernode requires node_id")
    endpoint = raw.get("endpoint")
    if not isinstance(endpoint, dict):
        raise DirectorySnapshotFormatError("directory snapshot supernode requires endpoint")
    host = endpoint.get("host")
    port = endpoint.get("port")
    if not isinstance(host, str) or not host:
        raise DirectorySnapshotFormatError("directory snapshot supernode endpoint requires host")
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise DirectorySnapshotFormatError("directory snapshot supernode endpoint port must be 0..65535")
    return dict(raw)


def _peer_observation_from_dict(raw: dict[str, Any]) -> PeerObservation:
    try:
        return PeerObservation(
            peer_id=str(raw["peer_id"]),
            p50_latency_ms=float(raw.get("p50_latency_ms", 500.0)),
            p95_latency_ms=float(raw.get("p95_latency_ms", 1500.0)),
            uptime=float(raw.get("uptime", 1.0)),
            completion_rate=float(raw.get("completion_rate", 1.0)),
            price_units=float(raw.get("price_units", 0.0)),
        )
    except KeyError as exc:
        raise DirectorySnapshotFormatError("record observation requires peer_id") from exc
