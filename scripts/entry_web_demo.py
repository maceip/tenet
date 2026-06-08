#!/usr/bin/env python3
"""Minimal entry for the offline website demo binary (no mixnet stack)."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    from tenet.edges.cli.serve import run_serve

    parser = argparse.ArgumentParser(
        prog="tenet-web",
        description="Offline HTTP bridge for the tenet website xterm demo (networking disabled).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--path", default="/v1/expert")
    parser.add_argument("--status-path", default="/v1/status")
    args = parser.parse_args(argv)
    return run_serve(
        offline=True,
        host=args.host,
        port=args.port,
        path=args.path,
        status_path=args.status_path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
