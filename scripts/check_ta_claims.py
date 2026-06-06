#!/usr/bin/env python3
"""TA-3 guard: fail if tracked docs oversell streaming return privacy.

Usage:
  python3 scripts/check_ta_claims.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tenet.packet.ta_claims import (
    TA_CLAIM_SCAN_PATHS,
    missing_scan_paths,
    scan_files_for_forbidden_claims,
)


def main() -> int:
    missing = missing_scan_paths(ROOT, TA_CLAIM_SCAN_PATHS)
    if missing:
        print("TA-3 scan paths missing:")
        for path in missing:
            print(f"  {path}")
        return 1

    violations = scan_files_for_forbidden_claims(ROOT, TA_CLAIM_SCAN_PATHS)
    if not violations:
        print(f"TA-3 OK: scanned {len(TA_CLAIM_SCAN_PATHS)} paths")
        return 0

    print("TA-3 violations (overselling streaming return):")
    for path, bad in violations:
        print(f"  {path}: {', '.join(bad)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
