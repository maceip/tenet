#!/usr/bin/env python3
"""Materialize Alpha network experts from agent session logs."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from tenet.experts.alpha_experts import materialize_alpha_population, write_alpha_population


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Alpha expert population from agent logs")
    parser.add_argument(
        "--log-root",
        action="append",
        default=[],
        help="Extra roots to scan (default: ~/.cursor/projects)",
    )
    parser.add_argument(
        "--transcript",
        action="append",
        default=[],
        help="Explicit .jsonl transcript file",
    )
    parser.add_argument("--corpus-out", default="data/alpha/corpus")
    parser.add_argument("--out", default="config/alpha-population.json")
    parser.add_argument("--min-experts", type=int, default=1)
    parser.add_argument("--max-transcripts", type=int, default=50)
    parser.add_argument("--no-synthetic", action="store_true")
    parser.add_argument("--write-groups", action="store_true", help="Also write data/alpha/groups.json")
    args = parser.parse_args()

    population = materialize_alpha_population(
        log_roots=args.log_root or None,
        corpus_out=args.corpus_out,
        min_experts=args.min_experts,
        max_transcripts=args.max_transcripts,
        include_synthetic=not args.no_synthetic,
        extra_transcript_paths=args.transcript,
    )
    out = write_alpha_population(population, ROOT / args.out)
    print(f"[alpha] wrote {out} experts={len(population.experts)}", file=sys.stderr)

    if args.write_groups:
        groups_path = ROOT / "data/alpha/groups.json"
        groups_path.parent.mkdir(parents=True, exist_ok=True)
        groups_path.write_text(
            population.population_index(min_group_size=1).to_json() + "\n",
            encoding="utf-8",
        )
        print(f"[alpha] wrote {groups_path}", file=sys.stderr)

    print(json.dumps({"experts": [e.expert_id for e in population.experts]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
