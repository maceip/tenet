#!/usr/bin/env python3
"""Publish half of the unified trust-update rail.

Sign a release into a ``trust-update.json`` bundle: a ``software_identity``
(version + build_ref + canonical code_hash) and a ``trust_update``
(approved_code_hashes = every released binary's sha256), both signed with the
join-pack-root key. Clients fetch + verify this against the join-pack
``update_roots`` and check their own hash — see ``tenet/trust_gate.py``.

Run in the release job AFTER SHA256SUMS exists:

  TENET_JOIN_PACK_SIGNING_KEY_HEX=<ed25519 seed hex> \
  python scripts/sign_release_trust_update.py \
      --shasums release/SHA256SUMS --version v0.1.2 \
      --build-ref "v0.1.2 · run 123" \
      --base-url https://github.com/maceip/tenet/releases/latest/download \
      --out release/trust-update.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tenet.mixnet.control.descriptors import (  # noqa: E402
    SoftwareIdentityDescriptor,
    TrustUpdateDescriptor,
)
from tenet.mixnet.control.records import (  # noqa: E402
    RECORD_TYPE_SOFTWARE_IDENTITY,
    RECORD_TYPE_TRUST_UPDATE,
    ControlRecord,
    sign_control_record,
)
from tenet.trust_gate import TRUST_BUNDLE_SCHEMA  # noqa: E402

NETWORK_ID = "default"
TTL_SECONDS = 365 * 24 * 3600  # records live a year; re-signed every release


def _parse_shasums(path: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            mapping[parts[-1].lstrip("*")] = parts[0]
    return mapping


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--shasums", required=True, help="SHA256SUMS file from the release job")
    ap.add_argument("--version", required=True, help="release version / tag")
    ap.add_argument("--build-ref", default="", help="git tag + CI run (transparency stamp)")
    ap.add_argument("--base-url", default="", help="release download base URL")
    ap.add_argument("--also-approve", action="append", default=[],
                    help="extra code hash to keep approved (rolling window). Repeatable.")
    ap.add_argument("--require", action="store_true",
                    help="mark this bundle required (clients fail closed on unknown code)")
    ap.add_argument("--key-id", default="join-pack-root")
    ap.add_argument("--out", default="trust-update.json")
    args = ap.parse_args(argv)

    key_hex = os.environ.get("TENET_JOIN_PACK_SIGNING_KEY_HEX", "").strip()
    if not key_hex:
        print("Set TENET_JOIN_PACK_SIGNING_KEY_HEX (ed25519 seed hex) to sign.", file=sys.stderr)
        return 2

    shas = _parse_shasums(args.shasums)
    # ignore the checksums file itself if it appears
    code_hashes = sorted({h for name, h in shas.items() if not name.endswith("SHA256SUMS")}
                         | set(args.also_approve))
    if not code_hashes:
        print(f"no code hashes found in {args.shasums}", file=sys.stderr)
        return 2

    now = time.time()
    canonical = shas.get("tenet-linux-x86_64") or code_hashes[0]
    software = SoftwareIdentityDescriptor(
        identity_id="tenet", code_hash=canonical, version=args.version,
        build_ref=args.build_ref or args.version)
    trust = TrustUpdateDescriptor(
        update_id=f"release/{args.version}", issuer=args.key_id, policy="release",
        approved_code_hashes=tuple(code_hashes))

    def _signed(desc, record_type) -> dict:
        record = ControlRecord(
            network_id=NETWORK_ID, key=desc.key, record_type=record_type,
            seq=int(now), issued_at=now, expires_at=now + TTL_SECONDS,
            value=desc.to_dict())
        return sign_control_record(record, signing_key_hex=key_hex, key_id=args.key_id).to_dict()

    bundle = {
        "schema": TRUST_BUNDLE_SCHEMA,
        "version": args.version,
        "base_url": args.base_url,
        "required": bool(args.require),
        "software_identity": _signed(software, RECORD_TYPE_SOFTWARE_IDENTITY),
        "trust_update": _signed(trust, RECORD_TYPE_TRUST_UPDATE),
    }
    Path(args.out).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"wrote {args.out} · {len(code_hashes)} approved hash(es) · version {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
