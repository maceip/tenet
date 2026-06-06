#!/usr/bin/env python3
"""One-shot beta artifacts: handle, expert config, snapshot, mailbox."""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict
from pathlib import Path

from tenet.experts.directory import DIRECTORY_SNAPSHOT_VERSION
from tenet.experts.enclave_plane_server import MAILBOX_FILE_VERSION
from tenet.handles import OpaqueHandleIssuer
from tenet.experts.memory_index import IndexConfig, build_memory_index


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--handle-secret-hex", required=True)
    parser.add_argument("--routing-kem-pk-hex", required=True)
    parser.add_argument("--peer-address-json", required=True)
    parser.add_argument("--expert-config", default="config/expert-laptop.json")
    parser.add_argument("--out-dir", default="deploy/data/beta")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    built = build_memory_index(
        IndexConfig(
            peer_id="expert",
            roots=(args.corpus,),
            created_at_iso="2026-06-04T00:00:00+00:00",
        )
    )
    manifest = built.manifest
    issuer = OpaqueHandleIssuer(bytes.fromhex(args.handle_secret_hex))
    record = issuer.record(
        peer_id="expert",
        manifest_digest=manifest.index_digest,
        mailbox_id="mailbox-beta",
    )
    handle = record.handle if isinstance(record.handle, str) else record.handle.token
    peer_addr = json.loads(Path(args.peer_address_json).read_text(encoding="utf-8"))

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "version": DIRECTORY_SNAPSHOT_VERSION,
        "generated_at": manifest.created_at,
        "records": [{"manifest": asdict(manifest), "handle": record.to_public_dict()}],
    }
    (out / "snapshot.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
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
    (out / "mailbox.json").write_text(json.dumps(mailbox, indent=2), encoding="utf-8")

    cfg_path = root / args.expert_config
    text = cfg_path.read_text(encoding="utf-8")
    text = re.sub(r'"REPLACE_WITH_OPAQUE_HANDLE"', f'"{handle}"', text)
    text = re.sub(r'"h[0-9a-f]{16}"', f'"{handle}"', text, count=0)
    # Only replace node_id / default_node_id / peer_id fields that look like handles
    for key in ("default_node_id", "node_id", "peer_id"):
        text = re.sub(
            rf'("{key}": )"h[0-9a-f]{{16}}"',
            rf'\1"{handle}"',
            text,
        )
    # Replace daemon map key
    text = re.sub(
        r'"daemons": \{\s*"[^"]+":',
        f'"daemons": {{\n    "{handle}":',
        text,
        count=1,
    )
    cfg_path.write_text(text, encoding="utf-8")
    print(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
