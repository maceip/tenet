"""Default ``tenet`` experience — run the binary with no arguments.

    $ tenet

Connects to the bootstrap matcher pinned in the join-pack, opens a minimal
asker prompt, and — if this machine is directly reachable — promotes itself to
also offer relay (a dumb NAT forwarder) for other clients.

Role model (see README protocol invariants): everyone is a client. "Relay" is a
*capability* a reachable client opts into, not a separate role. Reachability is
detected with the existing UPnP/NAT-PMP module (``tenet.mixnet.upnp``): a
successful public port mapping is the promotion trigger; otherwise we stay a
pure asker behind the bootstrap relay.

Wire-then-harden status:
  - asker prompt loop:           REAL (same path as ``tenet ask``)
  - reachability detection:      REAL (UPnP/NAT-PMP port mapping + external IP)
  - relay promotion decision:    REAL (acquires the public endpoint to advertise)
  - relay control-DHT join:      SEAM — bringing up a live supernode runtime that
                                 advertises into the join-pack control plane is
                                 the next hardening step (see _promote_to_relay).
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

# brand-light palette (truecolor), only used on a real TTY
_R = "\033[0m"
_RED = "\033[38;2;229;53;43m"
_GRN = "\033[38;2;90;209;122m"
_GRY = "\033[38;2;130;130;130m"
_WHT = "\033[1;38;2;245;245;245m"
_B = "\033[1m"


def _color_ok() -> bool:
    return (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )


def _c(code: str, text: str) -> str:
    return f"{code}{text}{_R}" if _color_ok() else text


def detect_reachability(internal_port: int = 0) -> dict:
    """Probe direct reachability with UPnP/NAT-PMP. Never raises.

    Returns ``{reachable, endpoint, method, detail}``. A successful public port
    mapping means inbound traffic can reach us directly — the cue to promote to
    relay and advertise ``endpoint``. Failure means we're behind NAT.
    """
    try:
        from tenet.mixnet.upnp import try_port_mapping
    except Exception as exc:  # pragma: no cover - import guard
        return {"reachable": False, "endpoint": None, "method": None,
                "detail": f"upnp module unavailable: {exc}"}
    try:
        res = try_port_mapping(internal_port or 0)
    except Exception as exc:  # pragma: no cover - defensive
        return {"reachable": False, "endpoint": None, "method": None,
                "detail": f"probe error: {exc}"}
    if res.success and res.mapping is not None:
        m = res.mapping
        return {
            "reachable": True,
            "endpoint": f"{m.external_ip or '?'}:{m.external_port}",
            "method": m.method,
            "detail": "public port mapping acquired",
        }
    return {"reachable": False, "endpoint": None, "method": None,
            "detail": res.error or "no NAT mapping (behind NAT)"}


def _promote_to_relay(pack, verdict: dict, log) -> None:
    """A directly-reachable client opts into the relay capability.

    The public endpoint to advertise has already been acquired (UPnP/NAT-PMP).
    Standing up a live supernode runtime that registers ``reachability_relay``
    into the join-pack control plane (``run_supernode_cluster`` needs a
    DaemonConfig synthesized from ``pack.control_bootstrap`` + the mapped
    endpoint + a generated relay identity) is the hardening step; until then we
    surface the relay-ready endpoint without joining the live control DHT.
    """
    endpoint = verdict.get("endpoint")
    log(f"directly reachable at {endpoint} via {verdict.get('method')} "
        f"→ eligible to relay for NATed clients")
    # HARDEN: from tenet.edges.cli.supernode import run_supernode_cluster
    #   daemon = synthesize_supernode_daemon(pack, endpoint, relay_secret)
    #   threading.Thread(target=run_supernode_cluster, args=(daemon, por),
    #                    daemon=True).start()
    log("relay capability staged (live control-DHT advertisement is the next step)")


def _ask_once(pack, prompt: str, *, timeout: float = 120.0) -> dict:
    """Route one prompt to the bootstrap matcher — same path as ``tenet ask``."""
    from tenet.experts.live_client import LiveMailboxClientConfig, send_live_enclave_summary
    from tenet.experts.live_enclave import LiveEnclaveConfig

    enclave = LiveEnclaveConfig.from_dict(pack.matcher)
    mailbox = LiveMailboxClientConfig.load(pack.asker_mailbox_config)
    return send_live_enclave_summary(
        enclave,
        mailbox,
        prompt=prompt,
        timeout=timeout,
        control_service=pack.to_control_service(),
    )


def _run_query(pack, prompt: str, timeout: float) -> int:
    try:
        result = _ask_once(pack, prompt, timeout=timeout)
    except Exception as exc:  # pragma: no cover - network/runtime guard
        print(_c(_RED, f"  ! query failed: {exc}"))
        return 1
    print("  " + (result.get("response_text") or "").strip())
    return 0 if result.get("ok") else 1


def run_default_client(
    join_pack_path: str | Path | None = None,
    *,
    prompt: str | None = None,
    enable_relay: bool = True,
    timeout: float = 120.0,
) -> int:
    """No-args entry point: connect to the bootstrap matcher and ask.

    Interactive on a TTY (prompt loop); one-shot with ``prompt=...`` or piped
    stdin. Concurrently probes reachability and auto-promotes to relay when the
    machine is directly reachable (unless ``enable_relay`` is False).
    """
    from tenet.edges.cli.join_pack import JoinPack, resolve_join_pack_path

    pack_path = resolve_join_pack_path(join_pack_path)
    if not pack_path.is_file():
        print(
            f"tenet: no join-pack at {pack_path}.\n"
            "      Place config/join-pack.json (or pass --join-pack PATH) to connect.",
            file=sys.stderr,
        )
        return 2
    try:
        pack = JoinPack.load(pack_path)
    except Exception as exc:
        print(f"tenet: could not load join-pack: {exc}", file=sys.stderr)
        return 2

    host = urlparse(pack.matcher_url()).hostname or pack.matcher_url()
    print(_c(_RED + _B, "  ▟▛ tenet") + "  " + _c(_GRY, f"connected · matcher {host}"))

    # Reachability + relay promotion run in the background so the prompt is instant.
    def _probe() -> None:
        port = int(os.environ.get("TENET_RELAY_PORT", "0") or 0)
        v = detect_reachability(port)
        if v["reachable"]:
            print(_c(_GRN, f"  ◆ directly reachable: {v['endpoint']} ({v['method']})"))
            if enable_relay:
                _promote_to_relay(pack, v, lambda m: print(_c(_GRY, f"  relay · {m}")))
            else:
                print(_c(_GRY, "  relay · auto-promotion disabled (--no-relay)"))
        else:
            print(_c(_GRY, f"  ○ behind NAT ({v['detail']}) → asker only, via bootstrap relay"))

    probe = threading.Thread(target=_probe, daemon=True)
    probe.start()

    # One-shot: explicit prompt, or piped stdin with no TTY.
    if prompt is not None:
        probe.join(timeout=6.0)
        return _run_query(pack, prompt, timeout)
    if not sys.stdin.isatty():
        probe.join(timeout=6.0)
        print(_c(_GRY, "  (no prompt; status only — pass --prompt or run in a terminal to ask)"))
        return 0

    # Interactive asker TUI.
    print(_c(_GRY, "  ask anything · Ctrl-D or /quit to exit"))
    rc = 0
    while True:
        try:
            line = input(_c(_RED, "tenet › ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return rc
        if not line:
            continue
        if line in ("/quit", "/exit", "/q"):
            return rc
        rc = _run_query(pack, line, timeout)
