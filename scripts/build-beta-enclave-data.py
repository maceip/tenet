#!/usr/bin/env python3
"""Build TEE snapshot + mailbox JSON for the current beta path (items 12–14)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tenet.experts.directory import DIRECTORY_SNAPSHOT_VERSION, PeerRecord
from tenet.experts.enclave_plane_server import MAILBOX_FILE_VERSION
from tenet.handles import (
    OPAQUE_HANDLE_RECORD_VERSION,
    OpaqueHandle,
    OpaqueHandleIssuer,
    OpaqueHandleRecord,
)
from tenet.experts.memory_index import MemoryManifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True, help="Expert corpus directory")
    parser.add_argument("--peer-id", default="", help="Manifest peer_id (defaults to basename)")
    parser.add_argument("--handle-secret-hex", required=True)
    parser.add_argument("--handle-token", default="")
    parser.add_argument("--routing-kem-pk-hex", required=True)
    parser.add_argument("--peer-address-json", required=True)
    parser.add_argument("--out-dir", default="deploy/data/beta")
    args = parser.parse_args()

    from tenet.experts.memory_index import IndexConfig, build_memory_index

    peer_id = args.peer_id or Path(args.corpus).name
    built = build_memory_index(IndexConfig(peer_id=peer_id, roots=(args.corpus,)))
    manifest = built.manifest
    issuer = OpaqueHandleIssuer(bytes.fromhex(args.handle_secret_hex))
    if args.handle_token:
        OpaqueHandle(args.handle_token)
        issued_at = time.time()
        unsigned = OpaqueHandleRecord(
            version=OPAQUE_HANDLE_RECORD_VERSION,
            handle=args.handle_token,
            mailbox_id="mailbox-beta",
            issued_at=issued_at,
            expires_at=issued_at
            + int(os.environ.get("POR_HANDLE_TTL_SECONDS", "86400")),
            signature="",
        )
        record = OpaqueHandleRecord(
            **{**asdict(unsigned), "signature": issuer._record_signature(unsigned)}
        )
    else:
        record = issuer.record(
            peer_id=peer_id,
            manifest_digest=manifest.index_digest,
            mailbox_id="mailbox-beta",
            ttl_seconds=int(os.environ.get("POR_HANDLE_TTL_SECONDS", "86400")),
        )
    peer_addr = json.loads(Path(args.peer_address_json).read_text(encoding="utf-8"))

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    snapshot = {
        "version": DIRECTORY_SNAPSHOT_VERSION,
        "generated_at": manifest.created_at,
        "records": [
            {
                "manifest": asdict(manifest),
                "handle": record.to_public_dict(),
            }
        ],
    }
    (out / "snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")

    relay_id = os.environ.get("REACH_RELAY_ID", "reach-beta-1")
    relay_host = os.environ.get("REACH_RELAY_HOST", "")
    relay_port = int(os.environ.get("REACH_RELAY_PORT", "4433"))
    relay_verify = os.environ.get("RELAY_VERIFY_KEY_HEX", "")
    mailbox = {
        "version": MAILBOX_FILE_VERSION,
        "entries": [
            {
                "record": record.to_public_dict(),
                "routing_kem_pk_hex": args.routing_kem_pk_hex,
                "peer_address": peer_addr,
            }
        ],
    }
    if relay_host and relay_verify:
        mailbox["trusted_reachability_relays"] = [
            {
                "relay_id": relay_id,
                "host": relay_host,
                "port": relay_port,
                "verify_key": relay_verify,
            }
        ]
    (out / "mailbox.json").write_text(json.dumps(mailbox, indent=2) + "\n", encoding="utf-8")
    token = record.handle.token if hasattr(record.handle, "token") else record.handle
    print(f"[beta-data] peer_id={peer_id} handle={token}")
    print(f"[beta-data] wrote {out}/snapshot.json {out}/mailbox.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
