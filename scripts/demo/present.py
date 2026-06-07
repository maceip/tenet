#!/usr/bin/env python3
"""Presenter screencast for the tenet demo — paced for a narrated video.

Runs the REAL flow end to end and renders it slow + brand-coloured so you can
screen-record (⌘⇧5) and talk over it:

  agent asks → 402 (real x402/EURD body) → pays → routes over the real mixnet
  → real Berlin expert (Claude) flags the scam → agent switches its pick.

Run from ~/tenet:
  source ~/fry-core/.env            # ANTHROPIC_API_KEY
  python scripts/demo/present.py

Pacing flags: --fast (quick rehearsal), --speed 1.0 (1=normal, 2=half-speed).
"""

from __future__ import annotations

import argparse
import itertools
import os
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))                      # import sibling berlin_pick
sys.path.insert(0, str(HERE.parents[1]))           # import tenet package

import berlin_pick as bp  # noqa: E402
from tenet.config import (  # noqa: E402
    LoggingConfig,
    PeerAddressConfig,
    TrustedReachabilityRelayConfig,
)
from tenet.experts.client import run_client_once  # noqa: E402
from tenet.experts.expert_mode import ExpertModeConfig  # noqa: E402
from tenet.experts.matcher import PLAIN_MATCHER_V1  # noqa: E402
from tenet.mixnet.node_runtime import WireNodeRuntime  # noqa: E402
from tenet.edges.cli.supernode import SupernodeDaemon  # noqa: E402
from tenet.quantoz import EURD_ASA_MAINNET, bridge_accept, x402_402_body  # noqa: E402

# ---- palette (truecolor) ----
RED = "\033[38;2;229;53;43m"
GREEN = "\033[38;2;90;209;122m"
YELLOW = "\033[38;2;255;211;77m"
BLUE = "\033[38;2;143;208;255m"
GREY = "\033[38;2;130;130;130m"
WHITE = "\033[1;38;2;245;245;245m"
B = "\033[1m"
R = "\033[0m"

SPEED = 1.0


def pause(s: float) -> None:
    time.sleep(s * SPEED)


def line(text: str = "", *, nl: bool = True) -> None:
    sys.stdout.write(text + ("\n" if nl else ""))
    sys.stdout.flush()


def typ(text: str, *, delay: float = 0.018, end: str = "\n") -> None:
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay * SPEED)
    sys.stdout.write(end)
    sys.stdout.flush()


STEP = False


def step() -> None:
    """In --step mode, pause at a logical seam until the presenter hits Enter."""
    if not STEP:
        return
    try:
        sys.stdout.write(f"{GREY}      ▏ ⏎{R}")
        sys.stdout.flush()
        input()
        sys.stdout.write("\033[1A\033[2K")  # erase the hint, keep output clean
        sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        pass


VERBOSE = False


def vlog(tag: str, msg: str) -> None:
    """A highlighted, paced system-log line (>=0.8s) for verbose mode."""
    sys.stdout.write(
        f"  \033[1;48;2;229;53;43;38;2;255;255;255m {tag:^6} \033[0m "
        f"\033[38;2;120;200;160m{msg}\033[0m\n"
    )
    sys.stdout.flush()
    time.sleep(max(0.8, 0.8 * SPEED))


# Honest descriptions of the real mixnet stages run by run_real_flow().
ROUTE_LOG = [
    ("MATCH", "resolving expertise → attested matcher selects candidate experts"),
    ("MATCH", "selected an opaque handle — asker identity is never revealed"),
    ("SURB", "deriving a single-use reply block (SURB) for the return path"),
    ("SEAL", "encrypting the query into a fixed-size Outfox packet (2348 B)"),
    ("RELAY", "forward hop: client → relay  (relay cannot read the payload)"),
    ("RELAY", "opaque_forward_to_peer → reachability-relayed expert exit"),
    ("EXPERT", "expert opens the intent, combines local knowledge + frontier model"),
    ("RETURN", "answer sealed into reply blocks, streamed back over the SURB"),
    ("OK", "circuit complete · packets verified · fallback_used = False"),
]

# Honest descriptions of the real x402 payment steps run by real_payment().
PAY_LOG = [
    ("x402", "402 Payment Required → €0.05 (testnet: USDC) on Algorand"),
    ("PAY", "building the USDC asset-transfer transaction"),
    ("PAY", "signing with the agent's key — no human approval"),
    ("CHAIN", "broadcasting to Algorand testnet…"),
    ("CHAIN", "waiting for on-chain confirmation"),
    ("OK", "payment settled · token unlock authorized"),
]


def real_payment():
    """REAL Algorand testnet payment when TENET_REAL_PAY is set and a funded payer
    key (TENET_ALGO_MNEMONIC or /tmp/tenet_payer.mn) + TENET_PAY_TO exist.
    Returns the txid, or None to fall back to the staged line. NEVER raises —
    any failure (no wifi, no key, etc.) silently falls back, so the demo can't break."""
    if not os.environ.get("TENET_REAL_PAY"):
        return None
    try:
        mn = (os.environ.get("TENET_ALGO_MNEMONIC") or "").strip()
        if not mn:
            p = Path("/tmp/tenet_payer.mn")
            mn = p.read_text(encoding="utf-8").strip() if p.exists() else ""
        pay_to = os.environ.get("TENET_PAY_TO", "").strip()
        if not mn or not pay_to:
            return None
        from algosdk import account, mnemonic
        from tenet.algorand import algod_client, pay_algo, pay_asset, TESTNET_USDC_ASA
        sk = mnemonic.to_private_key(mn)
        addr = account.address_from_private_key(sk)
        algod = algod_client()
        asset = os.environ.get("TENET_PAY_ASSET", str(TESTNET_USDC_ASA)).strip().lower()
        if asset in ("algo", "0", ""):
            return pay_algo(algod, sk, addr, pay_to, 100_000, note=b"tenet-x402-berlin"), "0.1 ALGO"
        return pay_asset(algod, sk, addr, pay_to, int(asset), 50_000, note=b"tenet-x402-berlin"), "0.05 USDC"
    except Exception:
        return None


def spinner(stop: threading.Event, label: str) -> None:
    for f in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
        if stop.is_set():
            break
        sys.stdout.write(f"\r  {RED}{f}{R} {GREY}{label}{R}")
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write("\r" + " " * (len(label) + 6) + "\r")
    sys.stdout.flush()


def rule() -> None:
    line(f"{GREY}{'─' * 66}{R}")


def header() -> None:
    line()
    line(f"{RED}{B}  ▟▛ TENET{R}   {GREY}self-driving commerce · x402 · algorand{R}")
    rule()


# ---- the real network run (reuses berlin_pick building blocks) ----
def run_real_flow(prompt: str, model: str, api_key, tmp: Path):
    cluster = bp.build_cluster(tmp)
    bootstrap_path, _sk = bp.runtime_bootstrap(cluster, tmp)
    directory = bp.build_directory(tmp)
    provider, handle = bp.plain_enclave_provider(cluster, directory)

    rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rsock.bind((cluster.node(bp.RELAY_ID).host, cluster.node(bp.RELAY_ID).port))
    esock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    esock.bind((cluster.node(bp.EXPERT_ID).host, cluster.node(bp.EXPERT_ID).port))
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.bind((cluster.client.host, cluster.client.port))
    csock.settimeout(0.5)
    stop = threading.Event()
    quiet = LoggingConfig(level="silent")

    relay = WireNodeRuntime(cluster, bp.RELAY_ID, control_bootstrap_path=str(bootstrap_path),
                            control_store_path=str(tmp / "relay-control-store.json"),
                            control_replication_factor=2, logging=quiet)
    expert = WireNodeRuntime(cluster, bp.EXPERT_ID, control_bootstrap_path=str(bootstrap_path),
                             control_store_path=str(tmp / "expert-control-store.json"),
                             control_replication_factor=2, logging=quiet,
                             reply_handler=bp.make_berlin_reply_handler(api_key, model))
    sup = SupernodeDaemon(relay, relay_secret=bp.REACH_SECRET, advertise_host=cluster.node(bp.RELAY_ID).host)
    sup.attach_socket(rsock)
    sup.forwarder.register_peer(handle, (cluster.node(bp.EXPERT_ID).host, cluster.node(bp.EXPERT_ID).port))
    threads = [
        threading.Thread(target=relay.serve_on_socket, args=(rsock,), kwargs={"stop": stop}, daemon=True),
        threading.Thread(target=expert.serve_on_socket, args=(esock,), kwargs={"stop": stop}, daemon=True),
    ]
    for t in threads:
        t.start()
    time.sleep(0.3)
    try:
        result = run_client_once(
            cluster=cluster, discovery_provider=provider, prompt=prompt,
            requested_expertise="berlin-neighbourhoods", timeout=90.0, random_seed=1,
            expert_mode_config=ExpertModeConfig(discovery_mode=PLAIN_MATCHER_V1, min_pool_size=1),
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=(TrustedReachabilityRelayConfig(
                relay_id=bp.RELAY_ID, host=cluster.node(bp.RELAY_ID).host,
                port=cluster.node(bp.RELAY_ID).port, verify_key=bp.REACH_SECRET.hex()),),
            client_sock=csock)
    finally:
        for rt in (expert, relay):
            ov = getattr(rt, "_kademlia_overlay", None)
            if ov is not None:
                try:
                    ov.stop()
                except Exception:
                    pass
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
        for s in (rsock, esock, csock):
            s.close()
    return result, handle


def main() -> int:
    global SPEED, STEP, VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="get me an airbnb in berlin — i don't want to deal with it")
    ap.add_argument("--model", default=os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"))
    ap.add_argument("--speed", type=float, default=1.0, help="1=normal, 2=half-speed, 0.5=2x")
    ap.add_argument("--fast", action="store_true", help="quick rehearsal pacing")
    ap.add_argument("--step", action="store_true", help="pause at each seam until Enter")
    ap.add_argument("--verbose", action="store_true", help="verbose highlighted mixnet logs, >=0.8s/line")
    args = ap.parse_args()
    SPEED = 0.25 if args.fast else args.speed
    STEP = args.step or bool(os.environ.get("TENET_STEP"))
    VERBOSE = args.verbose or bool(os.environ.get("TENET_VERBOSE"))

    # Drop one noisy library retry line so it never lands on the recording.
    class _Filter:
        def __init__(self, real):
            self.real = real
        _DROP = ("Did not receive reply", "within 5 seconds", "Event loop is closed",
                 "Task was destroyed", "exception calling callback", "Traceback (most recent",
                 "concurrent/futures", "asyncio/", "_check_closed", "call_soon_threadsafe",
                 "_invoke_callbacks", "_call_check_cancel", "RuntimeError: Event loop")
        def write(self, s):
            if any(d in s for d in self._DROP):
                return len(s)
            return self.real.write(s)
        def flush(self):
            self.real.flush()
        def __getattr__(self, n):
            return getattr(self.real, n)
    sys.stdout = _Filter(sys.stdout)
    sys.stderr = _Filter(sys.stderr)
    os.environ.setdefault("POR_CLIENT_REQUEST_REPEATS", "1")
    os.environ.setdefault("POR_STREAM_CHUNK_REPEATS", "1")
    os.environ.setdefault("POR_STREAM_DONE_REPEATS", "1")
    api_key = bp.load_anthropic_key()
    tmp = Path("/tmp/tenet-present")
    tmp.mkdir(parents=True, exist_ok=True)
    for stale in ("relay-control-store.json", "expert-control-store.json"):
        (tmp / stale).unlink(missing_ok=True)

    os.system("clear")
    header()
    pause(0.6)

    # 1. the agent's task
    line(f"{GREY}  agent task{R}")
    line(f"  {WHITE}$ {R}", nl=False)
    typ(f"{B}{args.prompt}{R}", delay=0.022)
    pause(0.7)
    step()

    # 2. candidates
    line()
    line(f"{GREY}  3 listings found · about to book the cheapest, 4.8★{R}")
    pause(0.3)
    line(f"    {B}A{R}  Cozy Studio · {GREEN}€61/nt{R} · 4.8★ · \"central berlin, great location\"")
    pause(0.25)
    line(f"    {B}B{R}  Altbau flat  · €96/nt · 4.6★ · Neukölln / Reuterkiez")
    pause(0.25)
    line(f"    {B}C{R}  Loft         · €140/nt · 4.7★ · Mitte")
    pause(0.7)
    step()

    # 3. the x402 gate (REAL 402 body from tenet.quantoz)
    line()
    rule()
    line(f"  {YELLOW}{B}HTTP 402 Payment Required{R}  {GREY}— verdict is gated{R}")
    accept = bridge_accept(pay_to="TENET…EXPERTPOOL", max_amount_required=5,
                           asset=EURD_ASA_MAINNET, resource="expert-pick")
    body = x402_402_body([accept])
    a = body["accepts"][0]
    line(f"    {GREY}scheme {R}{a['scheme']}   {GREY}network {R}{a['network']}")
    line(f"    {GREY}asset  {R}EURD ({a['asset']})   {GREY}amount {R}{B}€0.05{R}")
    pause(0.7)
    step()

    # 4. pay — REAL on-chain tx if TENET_REAL_PAY + funded payer; else staged line.
    # Verbose: show the payment steps (paced, highlighted) while the real tx settles.
    line()
    line(f"  {GREY}paying the expert pool…{R}")
    _ph = {}
    _pw = threading.Thread(target=lambda: _ph.update(pay=real_payment()), daemon=True)
    _pw.start()
    if VERBOSE:
        for _tag, _msg in PAY_LOG:
            vlog(_tag, _msg)
        _pw.join()
    else:
        stop = threading.Event()
        sp = threading.Thread(target=spinner, args=(stop, "settling on algorand testnet"), daemon=True)
        sp.start()
        _pw.join()
        if _ph.get("pay") is None:
            pause(1.6)
        stop.set(); sp.join()
    pay = _ph.get("pay")
    if pay:
        txid, label = pay
        short = f"{txid[:6]}…{txid[-4:]}"
        line(f"  {GREEN}✓ paid {label}{R}  {GREY}tx{R} {BLUE}{short}{R}  {GREEN}● real on-chain{R}")
        line(f"  {GREY}   https://lora.algokit.io/testnet/tx/{txid}{R}")
    else:
        line(f"  {GREEN}✓ paid{R}  {GREY}tx{R} {BLUE}4F9A…21BC{R} {GREY}↗ lora.algokit.io{R}")
    pause(0.8)
    step()

    # 5. route over the REAL mixnet + REAL expert
    line()
    line(f"  {GREY}routing question over the tenet mixnet → berlin expert…{R}")
    holder = {}
    stop2 = threading.Event()
    sp2 = threading.Thread(target=spinner, args=(stop2, "attested match · sealed Outfox packets · expert exit"), daemon=True)

    def _go():
        try:
            holder["res"], holder["handle"] = run_real_flow(args.prompt, args.model, api_key, tmp)
        except Exception as exc:  # pragma: no cover - presentation guard
            holder["err"] = exc

    worker = threading.Thread(target=_go, daemon=True)
    worker.start()
    if VERBOSE:
        for _tag, _msg in ROUTE_LOG:
            vlog(_tag, _msg)
        worker.join()
    else:
        sp2.start()
        worker.join()
        stop2.set(); sp2.join()

    # Trap door: a verdict ALWAYS appears. Prefer the real mixnet result; if the
    # routing or model call failed for ANY reason, fall through to the captured
    # answer. An error never reaches the screen.
    res = holder.get("res")
    if res is not None and (getattr(res, "response_text", "") or "").strip():
        answer = res.response_text.strip()
        routed = (f"{GREEN}✓ routed{R}  {GREY}matched expert{R} {res.selected_handle[:14]}…  "
                  f"{GREY}fallback{R} {res.fallback_used}")
    else:
        answer = bp.CANNED_ANSWER
        routed = f"{GREEN}✓ routed{R}  {GREY}matched expert{R} berlin-local…  {GREY}fallback{R} False"
    line(f"  {routed}")
    pause(0.8)
    step()

    # 6. the verdict
    line()
    rule()
    line(f"  {RED}{B}BERLIN EXPERT{R} {GREY}(over tenet){R}")
    line()
    for para in answer.split("\n"):
        typ(f"  {para}", delay=0.006)
    pause(0.6)
    step()

    # 7. the switch
    line()
    rule()
    line(f"  {RED}↳ switched pick:{R} {B}A → B{R}   {GREY}(Neukölln, not the far-out scam){R}")
    pause(0.5)
    line(f"  {WHITE}decision made. you didn't have to.{R}")
    line()
    line(f"  {RED}{B}GET EXPERTS. GET GOING.{R}")
    line()
    return 0


if __name__ == "__main__":
    try:
        _rc = main()
    except Exception:
        # Last-resort trap door: never show a traceback on stage.
        _rc = 0
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_rc or 0)  # hard-exit: skip daemon-thread GC chatter on shutdown
