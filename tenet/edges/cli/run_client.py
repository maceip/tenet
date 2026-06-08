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


def _reserve_udp_port() -> int:
    """Pick a free UDP port for the relay bind (and the UPnP mapping)."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def _build_supernode_daemon(pack, pack_path, *, internal_port: int, public_ip: str, tmpdir: str):
    """Synthesize a 2026-06 supernode daemon config from the join-pack.

    A reachable client becomes a real relay: a fresh KEM identity + relay
    secret, bound to ``internal_port``, advertising ``public_ip``, and carrying
    the join-pack's control bootstrap verbatim so it joins the same control
    plane the askers trust. Returns ``(daemon, por_config, node_id)``.
    """
    import json
    import os
    from pathlib import Path as _Path

    from tenet.config import load_config
    from tenet.packet.OutfoxParams import OutfoxParams

    params = OutfoxParams(payload_size=2048, routing_size=16, max_hops=5)
    pk, sk = params.kem.keygen()
    node_id = "relay-" + os.urandom(4).hex()
    relay_secret = os.urandom(32).hex()

    # carry the live control bootstrap verbatim (raw block — to_dict() would
    # re-validate signatures, which we leave to the runtime's own loader).
    boot_path = _Path(tmpdir) / "control-bootstrap.json"
    raw_pack = json.loads(_Path(pack_path).read_text(encoding="utf-8"))
    boot_path.write_text(json.dumps(raw_pack["control_bootstrap"]), encoding="utf-8")

    daemon_doc = {
        "version": "tenet.config.2026-06",
        "default_node_id": node_id,
        "daemons": {
            node_id: {
                "role": "relay",
                "node_id": node_id,
                "kem_pk_hex": pk.hex(),
                "kem_sk_hex": sk.hex(),
                "transport": {"kind": "udp", "host": "0.0.0.0", "port": internal_port},
                "packet": {"payload_size": 2048, "routing_size": 16, "max_hops": 5},
                "supernode": {
                    "enabled": True,
                    "public_ip": public_ip,
                    "relay_secret_hex": relay_secret,
                    "advertise_relay": True,
                    "accept_inbound_mix": True,
                },
                "peer_address": {
                    "enabled": True,
                    "heartbeat_interval_seconds": 120,
                    "registration_ttl_seconds": 86400,
                },
                "control": {"bootstrap_path": str(boot_path)},
            }
        },
    }
    cfg_path = _Path(tmpdir) / "relay-daemon.json"
    cfg_path.write_text(json.dumps(daemon_doc), encoding="utf-8")
    por = load_config(str(cfg_path))
    return por.daemon(node_id), por, node_id


def _promote_to_relay(pack, pack_path, verdict: dict, internal_port: int) -> tuple[bool, str]:
    """A directly-reachable client opts into the relay capability and actually
    runs the supernode: advertises ``reachability_relay`` into the control plane
    and forwards opaque traffic for NATed clients (a dumb NAT forwarder).

    Returns ``(serving, detail)``. Prints nothing — the caller reflects state in
    the status header, so nothing races the interactive prompt."""
    import tempfile

    endpoint = verdict.get("endpoint") or ""
    public_ip = endpoint.split(":")[0] if endpoint else "0.0.0.0"
    tmpdir = tempfile.mkdtemp(prefix="tenet-relay-")
    try:
        daemon, por, node_id = _build_supernode_daemon(
            pack, pack_path, internal_port=internal_port, public_ip=public_ip, tmpdir=tmpdir
        )
    except Exception as exc:
        return False, f"relay unavailable: {exc}"

    from tenet.edges.cli.supernode import run_supernode_cluster

    def _serve() -> None:
        try:
            run_supernode_cluster(daemon, por)
        except Exception:  # pragma: no cover - runtime guard
            pass

    t = threading.Thread(target=_serve, daemon=True, name="tenet-relay")
    t.start()
    # If the runtime dies immediately (e.g. control bootstrap can't validate),
    # report failure so the relay light goes red instead of a false green.
    t.join(timeout=1.2)
    if not t.is_alive():
        return False, "relay failed to start (control plane unavailable)"
    return True, f"relaying as {node_id} · advertising {public_ip} for NATed clients"


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
        match_gossip_salt=pack.query_epoch_salt,
        default_pool=pack.default_pool,
        dataset_commitment=pack.dataset_commitment,
    )


def _peek_matcher_host(pack_path: Path) -> str | None:
    """Best-effort matcher host for the header, even if full validation fails."""
    try:
        import json
        raw = json.loads(pack_path.read_text(encoding="utf-8"))
        url = str((raw.get("matcher") or {}).get("url", "")).strip()
        return (urlparse(url).hostname or url) if url else None
    except Exception:
        return None


def _run_query(pack, prompt: str, timeout: float) -> int:
    if pack is None:
        print(_c(_GRY, "  offline: matcher pins unverified — cannot route (need a valid join-pack)"))
        return 1
    try:
        result = _ask_once(pack, prompt, timeout=timeout)
    except Exception as exc:  # pragma: no cover - network/runtime guard
        print(_c(_RED, f"  ! query failed: {exc}"))
        return 1
    print("  " + (result.get("response_text") or "").strip())
    return 0 if result.get("ok") else 1


# ---- toy traffic-light status header ----
# Each light is a 3-lamp cluster (red · yellow · green); one lamp lit per state.
# conn is always shown; relay/expert are hidden until the node takes that role.
_OFF, _S_RED, _S_YEL, _S_GRN = "off", "red", "yellow", "green"
_LAMP_COLOR = {
    "red": "\033[38;2;229;53;43m",
    "yellow": "\033[38;2;255;211;77m",
    "green": "\033[38;2;90;209;122m",
}
_LAMP_DIM = "\033[38;2;64;64;64m"


class _Status:
    """Live client status; mutated by the background probe, read by the header."""

    def __init__(self) -> None:
        self.conn = _OFF      # green=verified · yellow=degraded · red=down
        self.relay = _OFF     # hidden until promoted; yellow=promoting · green=relaying · red=failed
        self.expert = _OFF    # hidden until serving as an expert
        self.build = None     # None | up_to_date | update_available | unknown (trust gate)


def _light(label: str, state: str) -> str:
    if state == _OFF:
        return ""
    if not _color_ok():
        return f"{label}[{ {'red': 'R', 'yellow': 'Y', 'green': 'G'}.get(state, '?') }]"
    lamps = "".join(
        f"{(_LAMP_COLOR[c] if state == c else _LAMP_DIM)}⏺{_R}"
        for c in ("red", "yellow", "green")
    )
    return f"{_GRY}{label}{_R} {lamps}"


def _render_header(status: "_Status") -> str:
    cells = [_c(_RED + _B, "▟▛ tenet"), _light("conn", status.conn)]
    if status.relay != _OFF:
        cells.append(_light("relay", status.relay))
    if status.expert != _OFF:
        cells.append(_light("expert", status.expert))
    line = "  " + "    ".join(c for c in cells if c)
    if status.build == "update_available":
        line += "    " + _c(_LAMP_COLOR["yellow"], "⟳ update available")
    return line


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
    pack = None
    warn = None
    status = _Status()
    detail = {"matcher": "unconfigured", "relay": "probing…", "expert": "not serving",
              "build": "checking…"}
    if pack_path.is_file():
        detail["matcher"] = _peek_matcher_host(pack_path) or detail["matcher"]
        try:
            pack = JoinPack.load(pack_path)
            status.conn = _S_GRN
            detail["matcher"] = urlparse(pack.matcher_url()).hostname or detail["matcher"]
        except Exception as exc:
            warn = f"join-pack pins unverified ({exc})"
            status.conn = _S_YEL
    else:
        warn = f"no join-pack at {pack_path}"
        status.conn = _S_RED

    relay_port = int(os.environ.get("TENET_RELAY_PORT", "0") or 0) or _reserve_udp_port()

    # Reachability + relay promotion run in the background and update `status`
    # SILENTLY (no prints) — so nothing races the prompt. The header reprints
    # each turn and self-updates as the relay light resolves.
    def _probe() -> None:
        forced = os.environ.get("TENET_FORCE_REACHABLE")  # "ip:port" to exercise relay behind NAT
        v = ({"reachable": True, "endpoint": forced, "method": "forced"} if forced
             else detect_reachability(relay_port))
        if not v["reachable"]:
            detail["relay"] = "behind NAT — asker only, via bootstrap relay"
            return
        if pack is None:
            detail["relay"] = "reachable · need a verified join-pack to relay"
            return
        if not enable_relay:
            detail["relay"] = "reachable · relay disabled (--no-relay)"
            return
        status.relay = _S_YEL
        detail["relay"] = f"promoting at {v['endpoint']}…"
        serving, info = _promote_to_relay(pack, pack_path, v, relay_port)
        status.relay = _S_GRN if serving else _S_RED
        detail["relay"] = info

    def _trust_check() -> None:
        # Consume half of the trust-update rail: is our binary an approved build?
        # Best-effort + silent (never races the prompt); soft by default.
        from tenet import _buildinfo
        if pack is None:
            detail["build"] = "join-pack unverified — trust gate skipped"
            status.build = "unknown"
            return
        try:
            from tenet.trust_gate import load_trust_state
            ts = load_trust_state(pack)
        except Exception as exc:  # pragma: no cover - defensive
            detail["build"] = f"trust gate error: {exc}"
            status.build = "unknown"
            return
        status.build = ts.state
        ver = f" · latest {ts.latest_version}" if ts.latest_version else ""
        detail["build"] = (f"{_buildinfo.VERSION} ({_buildinfo.BUILD_REF}) — "
                           f"{ts.state}: {ts.detail}{ver}")
        if ts.required and not ts.ok:
            detail["build"] = "REQUIRED update — " + detail["build"]

    threading.Thread(target=_probe, daemon=True, name="tenet-probe").start()
    threading.Thread(target=_trust_check, daemon=True, name="tenet-trust").start()

    print(_render_header(status))
    if warn:
        print(_c(_GRY, f"  ! {warn} → diagnostic mode (queries disabled)"))

    # One-shot: explicit prompt, or piped stdin with no TTY.
    if prompt is not None:
        return _run_query(pack, prompt, timeout)
    if not sys.stdin.isatty():
        print(_c(_GRY, "  (status only — pass --prompt or run in a terminal to ask)"))
        return 0

    # Interactive asker TUI — header reprinted above each prompt so it stays put.
    print(_c(_GRY, "  ask anything · /status · Ctrl-D or /quit to exit"))
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
        if line == "/status":
            print(_render_header(status))
            print(_c(_GRY, f"    matcher  {detail['matcher']}"))
            print(_c(_GRY, f"    relay    {detail['relay']}"))
            print(_c(_GRY, f"    expert   {detail['expert']}"))
            print(_c(_GRY, f"    build    {detail['build']}"))
            continue
        rc = _run_query(pack, line, timeout)
        print(_render_header(status))
