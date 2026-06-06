#!/usr/bin/env python3
"""Print signed peer_address JSON for a REACH-registered peer (run on relay host)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--node-id")
    parser.add_argument("--peer-id", required=True)
    parser.add_argument(
        "--export-dir",
        default=os.environ.get("POR_REACH_EXPORT_DIR", "/tmp/por-reach-records"),
    )
    args = parser.parse_args()

    path = Path(args.export_dir) / (quote(args.peer_id, safe="") + ".json")
    if not path.exists():
        print(
            f"peer {args.peer_id!r} not exported by running relay at {path}",
            file=sys.stderr,
        )
        return 1
    raw = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(raw, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
