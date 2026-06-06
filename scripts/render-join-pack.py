#!/usr/bin/env python3
"""Render config/join-pack.json from live enclave + mailbox client configs."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
JOIN_PACK_SCHEMA = "por.join_pack.v1"


def _relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def main() -> int:
    enclave_path = Path(
        sys.argv[1] if len(sys.argv) > 1 else ROOT / "config" / "live-enclave.json"
    )
    mailbox_path = Path(
        sys.argv[2] if len(sys.argv) > 2 else ROOT / "config" / "live-mailbox-client.json"
    )
    out_path = Path(sys.argv[3] if len(sys.argv) > 3 else ROOT / "config" / "join-pack.json")

    enclave = json.loads(enclave_path.read_text(encoding="utf-8"))
    mailbox = json.loads(mailbox_path.read_text(encoding="utf-8"))

    url = str(enclave["url"]).rstrip("/")
    value_x = str(enclave["approved_value_x"][0])
    host = urlparse(url).hostname or ""
    expected_host = f"{value_x[:12]}.aeon.site"
    if host != expected_host:
        raise SystemExit(
            f"live enclave URL host {host!r} does not match Value X prefix {expected_host!r}"
        )
    relays = mailbox.get("trusted_reachability_relays") or []
    if not relays:
        raise SystemExit("mailbox config has no trusted_reachability_relays")
    relay = relays[0]
    nodes = mailbox.get("nodes") or {}
    relay_id = str(relay["relay_id"])
    node = nodes.get(relay_id) or {}

    pack = {
        "schema": JOIN_PACK_SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "matcher": {
            "schema": enclave.get("schema", "por.live_enclave.v1"),
            "url": url + "/",
            "approved_value_x": enclave["approved_value_x"],
            "tls_spki_hash": enclave["tls_spki_hash"],
            "require_spki_pin": enclave.get("require_spki_pin", True),
            "aw_bin": enclave.get("aw_bin", "aw"),
            "attested_workload_sha": enclave.get("attested_workload_sha"),
        },
        "reachability_relay": {
            "relay_id": relay_id,
            "host": relay["host"],
            "port": relay["port"],
            "verify_key": relay["verify_key"],
            "kem_pk": node.get("kem_pk", ""),
        },
        "directory": {
            "mode": "attested_matcher",
            "match_url": f"{url}/v1/match",
            "deliver_url": f"{url}/v1/deliver",
            "note": (
                "Beta joiners do not fetch a separate public directory snapshot URL. "
                "Manifests are baked into the Nitro EIF; discovery is POST /v1/match "
                "over attested TLS."
            ),
        },
        "asker": {
            "mailbox_config": _relative_path(mailbox_path, out_path.parent),
        },
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
    print(f"[join-pack] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
