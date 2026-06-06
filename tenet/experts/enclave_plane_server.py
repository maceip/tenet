"""Standalone server entry point for the enclave plane.

Runs the matcher + mailbox HTTP service (``tenet.enclave.enclave_plane`` handler) as a
deployable workload — e.g. the run-cards Stage-1 process behind attested TLS,
bound to loopback. This is the plain stand-in workload; obliviousness hardening
(full hardware obliviousness per item 6) happens inside the same boxes later (wire-then-harden).

The matcher is built from a public directory snapshot (manifests + opaque handle
records). The mailbox resolution data (handle -> reachability + routing key) is
*not* in the public snapshot by design (item 1), so it is loaded separately from a
private mailbox file that only the enclave holds.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Mapping, Sequence

from tenet.config import PeerAddressConfig, TrustedReachabilityRelayConfig
from tenet.experts.directory import load_public_snapshot_directory
from tenet.experts.match_workload import make_plain_enclave_plane_handler
from tenet.handles import opaque_handle_record_from_dict
from tenet.schema import supports_schema
from tenet.experts.matcher import (
    PlainEnclavePlaneDiscoveryProvider,
    PlainMailbox,
    PlainMailboxDelivery,
    PlainMatcher,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9384
MAILBOX_FILE_VERSION = "tenet.enclave_mailbox_file.2026-06"


def serve_enclave_plane(
    provider: PlainEnclavePlaneDiscoveryProvider,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> ThreadingHTTPServer:
    """Bind an HTTP server for the provider and return it (caller drives serve).

    Port 0 selects an ephemeral port; read it back from ``server.server_address``.
    The caller owns the lifecycle (``serve_forever`` / ``shutdown``).
    """
    return ThreadingHTTPServer((host, port), make_plain_enclave_plane_handler(provider))


def build_provider_from_files(
    *,
    snapshot: str | Path,
    mailbox: str | Path,
    top_k: int = 20,
) -> PlainEnclavePlaneDiscoveryProvider:
    """Build a matcher (from a public snapshot) + mailbox (from a private file)."""
    directory = load_public_snapshot_directory(str(snapshot))
    handle_records = {
        peer_id: opaque_handle_record_from_dict(raw)
        for peer_id, raw in directory.handle_records().items()
    }
    matcher = PlainMatcher.from_records(directory.records, handle_records, top_k=top_k)

    raw = json.loads(Path(mailbox).read_text(encoding="utf-8"))
    if not supports_schema(str(raw.get("version", "")), MAILBOX_FILE_VERSION):
        raise ValueError(f"unsupported mailbox file version: {raw.get('version')!r}")
    box = PlainMailbox()
    for entry in raw.get("entries", ()):
        box.add(
            record=opaque_handle_record_from_dict(entry["record"]),
            routing_kem_pk_hex=str(entry["routing_kem_pk_hex"]),
            peer_address=entry["peer_address"],
        )
    delivery = _mailbox_delivery_from_mailbox_file(raw, box)
    return PlainEnclavePlaneDiscoveryProvider(matcher, box, delivery)


def _trusted_relays_from_mailbox_raw(
    raw: Mapping[str, object],
) -> tuple[TrustedReachabilityRelayConfig, ...]:
    relays_raw = raw.get("trusted_reachability_relays")
    if isinstance(relays_raw, list) and relays_raw:
        relays = []
        for item in relays_raw:
            if not isinstance(item, dict):
                raise TypeError("trusted_reachability_relays entries must be objects")
            relays.append(TrustedReachabilityRelayConfig.from_dict(item))
        return tuple(relays)
    if relays_raw not in (None, []):
        raise TypeError("trusted_reachability_relays must be an array")
    relay_id = os.environ.get("POR_TRUSTED_RELAY_ID", "reach-beta-1")
    host = os.environ.get("POR_TRUSTED_RELAY_HOST", "")
    port = int(os.environ.get("POR_TRUSTED_RELAY_PORT", "4433"))
    verify_key = os.environ.get("POR_TRUSTED_RELAY_VERIFY_KEY_HEX", "")
    if host and verify_key:
        return (
            TrustedReachabilityRelayConfig(
                relay_id=relay_id,
                host=host,
                port=port,
                verify_key=verify_key,
            ),
        )
    return ()


def _mailbox_delivery_from_mailbox_file(
    raw: Mapping[str, object],
    mailbox: PlainMailbox,
) -> PlainMailboxDelivery | None:
    trusted = _trusted_relays_from_mailbox_raw(raw)
    if not trusted:
        return None
    mailbox_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mailbox_sock.bind(("0.0.0.0", 0))
    return PlainMailboxDelivery(
        mailbox,
        mailbox_sock=mailbox_sock,
        peer_address_config=PeerAddressConfig(enabled=True),
        trusted_reachability_relays=trusted,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the plain enclave-plane workload.")
    parser.add_argument("--snapshot", required=True, help="public directory snapshot (URL or path)")
    parser.add_argument("--mailbox", required=True, help="private mailbox resolution file (JSON)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--top-k", type=int, default=20)
    args = parser.parse_args(argv)

    provider = build_provider_from_files(
        snapshot=args.snapshot, mailbox=args.mailbox, top_k=args.top_k
    )
    server = serve_enclave_plane(provider, host=args.host, port=args.port)
    bound = server.server_address
    print(f"enclave-plane workload serving on http://{bound[0]}:{bound[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
