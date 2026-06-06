"""Generic attested enclave host (EnclaveRuntime).

The host terminates attested TLS, parses the ARC credential, and dispatches a
**route table** of JSON and SSE endpoints. It knows nothing about what those
routes *do* — a workload (e.g. the experts ``MatchWorkload`` in
``tenet.experts.match_workload``) registers its routes. This is the Set B host/tenant
split: the matcher is a tenant running on the host, not the host itself.

Wire is unchanged: the route names, JSON shapes, healthz schema, and SSE framing
are exactly what the deployed clients and the live EIF speak.
"""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler
from typing import Callable, Iterable, Mapping
from urllib.request import Request, urlopen

from tenet.enclave.arc import NoopArcCredential, noop_arc_credential_from_dict
from tenet.enclave.attested_transport import EnclaveAttestationError, build_pinned_opener


DEFAULT_ENCLAVE_PLANE_TIMEOUT_SECONDS = 8.0

# A JSON route maps a parsed request dict to a response dict. A stream route maps
# a parsed request dict to an iterable of raw packets (the host SSE-frames each).
JsonRoute = Callable[[Mapping[str, object]], Mapping[str, object]]
StreamRoute = Callable[[Mapping[str, object]], Iterable[bytes]]


class AttestedEnclaveClient:
    """TLS-pinned JSON/SSE client core for any enclave workload.

    Speaks no workload vocabulary: it posts JSON and streams SSE, attaching the
    ARC credential. A workload client (e.g. ``MatchWorkloadClient``) subclasses
    this and adds endpoint-specific methods.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = DEFAULT_ENCLAVE_PLANE_TIMEOUT_SECONDS,
        arc_credential: NoopArcCredential | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.arc_credential = arc_credential or NoopArcCredential.issue()
        self._opener = None
        self.tls_pin: str | None = None

    def set_tls_pin(self, spki_hex: str) -> None:
        """Pin every subsequent connection's TLS SPKI to ``spki_hex`` (item 5).

        Called by ``AttestedEnclavePlaneClient`` after attestation. Pinning is
        only meaningful over TLS; refuse (fail closed) to pin a plaintext
        ``http://`` transport rather than give a false sense of protection.
        """
        if not self.base_url.lower().startswith("https://"):
            raise EnclaveAttestationError(
                f"cannot pin SPKI on a non-TLS transport: {self.base_url}"
            )
        self.tls_pin = spki_hex
        self._opener = build_pinned_opener(spki_hex)

    def _open(self, req, *, timeout: float):
        if self._opener is not None:
            return self._opener.open(req, timeout=timeout)
        return urlopen(req, timeout=timeout)

    def post_json(self, path: str, body: Mapping[str, object]) -> dict[str, object]:
        payload = {**body, "arc_credential": self.arc_credential.to_public_dict()}
        req = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with self._open(req, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_sse(self, path: str, body: Mapping[str, object], *, timeout: float) -> Iterable[bytes]:
        payload = {**body, "arc_credential": self.arc_credential.to_public_dict()}
        req = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        )

        def packets() -> Iterable[bytes]:
            with self._open(req, timeout=timeout + 1.0) as response:
                for line in response:
                    if not line.startswith(b"data: "):
                        continue
                    yield base64.b64decode(line[6:].strip())

        return packets()


def make_enclave_handler(
    routes: Mapping[str, JsonRoute],
    stream_routes: Mapping[str, StreamRoute] | None = None,
) -> Callable[..., BaseHTTPRequestHandler]:
    """Build an HTTP handler dispatching a workload's route table.

    ``routes`` return a JSON dict; ``stream_routes`` return raw packets the host
    SSE-frames as ``data: <b64>\\n\\n``. The host validates the ARC credential on
    every POST and answers ``/healthz`` itself.
    """
    stream_routes = dict(stream_routes or {})

    class Handler(BaseHTTPRequestHandler):
        server_version = "por-plain-enclave-plane/0.1"

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send_json({"ok": True, "schema": "tenet.plain_enclave_plane.health.2026-06"})
                return
            self.send_error(404)

        def do_POST(self) -> None:
            try:
                raw = self._read_json()
                noop_arc_credential_from_dict(_dict_field(raw, "arc_credential"))
                if self.path in routes:
                    self._send_json(dict(routes[self.path](raw)))
                    return
                if self.path in stream_routes:
                    self._stream(stream_routes[self.path], raw)
                    return
            except (KeyError, TypeError, ValueError) as exc:
                self.send_error(400, str(exc))
                return
            self.send_error(404)

        def _stream(self, route, raw: dict[str, object]) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            for packet in route(raw):
                line = b"data: " + base64.b64encode(packet) + b"\n\n"
                try:
                    self.wfile.write(line)
                    self.wfile.flush()
                except BrokenPipeError:
                    break

        def _read_json(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("request body must be an object")
            return raw

        def _send_json(self, body: dict[str, object]) -> None:
            data = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format, *_args) -> None:
            return

    return Handler


def _dict_field(raw: dict[str, object], key: str) -> dict[str, object]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value
