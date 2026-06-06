"""CLI for the Tenet mixnet + DHT simulator.

Usage examples:
    uv run python -m sim up sim/scenarios/all-local-docker-small.yaml --netem --wait
    uv run python -m sim status
    uv run python -m sim logs dht-home-1 --follow
    uv run python -m sim netem-apply
    uv run python -m sim down --clean
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .orchestrator import Orchestrator


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sim", description="Tenet mixnet + DHT simulator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # up
    p_up = sub.add_parser("up", help="Bring up a scenario (local-docker sites for now)")
    p_up.add_argument("scenario", help="Path to scenario YAML/JSON")
    p_up.add_argument("--netem", action="store_true", help="Apply netem profiles after launch")
    p_up.add_argument("--wait", action="store_true", help="Wait briefly for containers to be ready")
    p_up.add_argument("--rebuild", action="store_true", help="Force rebuild of the node image")
    p_up.add_argument("--realization", choices=["docker", "host"], default=None,
                      help="Force 'docker' (real containers) or 'host' (real python processes on this machine). Default=auto.")

    # status
    sub.add_parser("status", help="Show container status for the active session")

    # logs
    p_logs = sub.add_parser("logs", help="Show logs for a node")
    p_logs.add_argument("node_id")
    p_logs.add_argument("-f", "--follow", action="store_true")
    p_logs.add_argument("--tail", type=int, default=100)

    # netem
    sub.add_parser("netem-apply", help="Re-apply netem inside running containers (after manual tc clear, or to change profiles)")

    # down
    p_down = sub.add_parser("down", help="Stop and remove containers for the active session")
    p_down.add_argument("--clean", action="store_true", help="Also remove named volumes (persisted control stores)")

    # plan (no side effects; shows placement, runners, links, etc.)
    p_plan = sub.add_parser("plan", help="Show what the scenario would do (placement, runners, netem) without launching anything")
    p_plan.add_argument("scenario", help="Path to scenario YAML/JSON")

    # (Future) run-workload, chaos, etc. are stubbed for now.

    args = ap.parse_args(argv)
    orch = Orchestrator()

    if args.cmd == "up":
        sess = orch.up(
            args.scenario,
            netem=args.netem,
            wait=args.wait,
            rebuild=args.rebuild,
            realization=getattr(args, "realization", None),
        )
        print("UP complete.")
        st = orch.status(sess)
        print("Nodes:", st)

        # Thick verification for local host runs: exercise the real Kademlia
        # overlays launched in the child processes for nodes placed in different
        # logical sites. We bootstrap short-lived probe overlays to the dht ports
        # of two control_dht nodes (from different sites in the scenario) and
        # confirm a value stored via one peer is retrievable via the other.
        h = getattr(sess, "_host_handle", None)
        if h is not None:
            try:
                import asyncio
                from tenet.mixnet.control import KademliaControlOverlay

                net_id = sess.scenario.network_id
                dht_infos = [(nid, i) for nid, i in h.nodes.items() if i.get("dht_port")]
                if len(dht_infos) >= 2:
                    def site_of(x):
                        return h.nodes.get(x[0], {}).get("site", "")
                    dht_infos.sort(key=lambda x: (site_of(x) != "home", site_of(x)))
                    n1, i1 = dht_infos[0]
                    n2, i2 = dht_infos[-1]
                    p1 = i1["dht_port"]
                    p2 = i2["dht_port"]

                    o1 = KademliaControlOverlay("probe-mesh-1", listen_port=0, network_id=net_id)
                    o1.start(bootstrap=[("127.0.0.1", p1)])
                    o1.wait_for_mesh(2.5)
                    key = f"sim-mesh-{int(time.time())}"
                    val = "from-site-a-to-b"
                    fut = asyncio.run_coroutine_threadsafe(o1.server.set(key, val), o1._loop)
                    fut.result(5)

                    o2 = KademliaControlOverlay("probe-mesh-2", listen_port=0, network_id=net_id)
                    o2.start(bootstrap=[("127.0.0.1", p2)])
                    o2.wait_for_mesh(2.5)
                    fut = asyncio.run_coroutine_threadsafe(o2.server.get(key), o2._loop)
                    got = fut.result(5)
                    o1.stop()
                    o2.stop()
                    ok = (got == val)
                    print("MESH CHECK:", "PASS (value replicated between dht nodes from different logical sites via real Kademlia)" if ok else "got different value")
                else:
                    print("MESH CHECK: only one dht node in scenario; skipping cross-site replication demo")
            except Exception as e:
                print("MESH CHECK: (non-fatal)", e)

        print("Use: python -m sim status | logs <node> | down")
        return 0

    if args.cmd == "status":
        st = orch.status()
        if isinstance(st, dict) and st.get("error") == "no active session":
            # Fallback to persisted session for host runs (so status works after `up` exits)
            p = Path.cwd() / ".tenet-sim-session.json"
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                print("session:", data.get("scenario"))
                print("realization:", data.get("realization"))
                nodes = data.get("nodes", {})
                for nid, info in sorted(nodes.items()):
                    print(f"{nid}: {info}")
                net = data.get("netem", {})
                if net:
                    print("_netem:", net)
                return 0
        for k, v in sorted(st.items()):
            print(f"{k}: {v}")
        return 0

    if args.cmd == "logs":
        # Try in-memory first; if no session, fall back to persisted log path for host.
        p = Path.cwd() / ".tenet-sim-session.json"
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            nodes = data.get("nodes", {})
            info = nodes.get(args.node_id)
            if info and info.get("log"):
                logp = Path(info["log"])
                tailn = args.tail or 100
                if logp.exists():
                    lines = logp.read_text(encoding="utf-8", errors="replace").splitlines()[-tailn:]
                    for line in lines:
                        print(line)
                    if args.follow:
                        print("(follow: tail -f", logp, ")")
                    return 0
        orch.logs(args.node_id, follow=args.follow, tail=args.tail)
        return 0

    if args.cmd == "netem-apply":
        orch.netem_apply()
        print("netem re-applied")
        return 0

    if args.cmd == "down":
        # If we have a persisted host session, handle down directly so it works
        # after the `up` process has exited (real processes, not threads in the cli proc).
        p = Path.cwd() / ".tenet-sim-session.json"
        handled = False
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("realization") == "host":
                import os, time, shutil
                nodes = data.get("nodes", {})
                for nid, info in nodes.items():
                    pid = info.get("pid")
                    if pid:
                        try:
                            os.kill(pid, 15)
                            time.sleep(0.05)
                            os.kill(pid, 9)
                        except Exception:
                            pass
                if args.clean:
                    cd = data.get("cfg_dir")
                    if cd:
                        shutil.rmtree(cd, ignore_errors=True)
                try:
                    p.unlink()
                except Exception:
                    pass
                print("DOWN complete.")
                handled = True
        if not handled:
            orch.down(clean=args.clean)
            print("DOWN complete.")
        return 0

    if args.cmd == "plan":
        plan = orch.plan(args.scenario)
        import json

        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    print("unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
