"""Wire node runtime for P-OR daemons.

**Wire:** canonical binary datagrams via ``por.wire_frame`` (``0x00`` forward,
``0x01`` circuit, ``0x02`` shutdown). This is the only path; the legacy
JSON/base64 framing and the POR1 route-info blob format have been removed.
"""

from __future__ import annotations

import json
import signal
import socket
import time
from os import urandom
from typing import Literal, Sequence

from sphinxmix.OutfoxNode import (
    circuit_packet_create,
    circuit_packet_process,
    outfox_process,
)
from sphinxmix.OutfoxParams import OutfoxParams, derive_circuit_key

from .config import ClusterConfig, LoggingConfig
from .envelope import PromptRequestEnvelope
from .log_events import PorLogEvent, emit_log_event
from .provider import ProviderError, expert_reply_chunks
from .wire_frame import decode_datagram, encode_forward


CIRCUIT_ID_SIZE = 16
KEY_SIZE = 16

NodeRole = Literal["relay", "expert", "any"]


class WireNodeRuntime:
    def __init__(
        self,
        cluster: ClusterConfig,
        node_id: str,
        *,
        role: NodeRole | None = None,
        logging: LoggingConfig | None = None,
    ):
        self.cluster = cluster
        self.node_id = node_id
        self.identity = cluster.node(node_id)
        self.role: NodeRole = role or self.identity.role  # type: ignore[assignment]
        if self.role not in {"relay", "expert", "any"}:
            self.role = "any"
        params = cluster.params
        self.params = OutfoxParams(
            payload_size=params.payload_size,
            routing_size=params.routing_size,
            max_hops=params.max_hops,
        )
        self.sk = bytes.fromhex(self.identity.kem_sk_hex)
        self.pk = bytes.fromhex(self.identity.kem_pk_hex)
        self.circuits: dict[str, dict[str, object]] = {}
        self._harness = cluster.to_harness_dict()
        self._shutdown = False
        self.logging = logging or LoggingConfig()
        self.on_reach_control = None
        self.on_opaque_forward = None
        self.supernode_daemon = None
        self._current_src_addr: tuple[str, int] | None = None

    def install_signal_handlers(self) -> None:
        def _handle(_signum, _frame):
            self._shutdown = True

        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)

    def serve_forever(self) -> int:
        self.install_signal_handlers()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.identity.host, self.identity.port))
        self._log(
            "started",
            fields={
                "wire": "binary",
                "addr": f"{self.identity.host}:{self.identity.port}",
            },
        )
        try:
            return self.serve_on_socket(sock)
        finally:
            sock.close()
            self._log("stopped", fields={"signal": True})

    def serve_on_socket(
        self,
        sock: socket.socket,
        *,
        stop: "object | None" = None,
    ) -> int:
        """Drive the canonical binary receive/dispatch loop on a bound socket.

        Production ``serve_forever`` binds its own socket and delegates here.
        Test harnesses bind a socket once, hold it open, and pass it in — so a
        node never closes a port only to rebind it later (the source of the
        cross-test datagram races). ``stop`` is an optional ``threading.Event``;
        when set, the loop exits without relying on signal handlers.
        """

        sock.settimeout(0.5)

        def _should_stop() -> bool:
            if self._shutdown:
                return True
            return stop is not None and stop.is_set()

        while not _should_stop():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            self._current_src_addr = addr
            self._dispatch_binary(sock, data, addr)
            if self.supernode_daemon is not None:
                self.supernode_daemon.purge_if_due()
        return 0

    def _log(
        self,
        event: str,
        *,
        level: str = "info",
        link_cid: str | None = None,
        fields: dict[str, object] | None = None,
    ) -> None:
        component = f"por-{self.role}" if self.role in {"relay", "expert"} else "por-node"
        emit_log_event(
            PorLogEvent(
                event=event,
                component=component,
                node_id=self.node_id,
                role=self.role,
                level=level,
                link_cid=link_cid,
                fields=fields or {},
            ),
            fmt=self.logging.fmt,
            redact_fields=frozenset(self.logging.redact_fields),
        )

    def _dispatch_binary(self, sock: socket.socket, data: bytes, addr) -> None:
        from .reach_wire import is_reach_datagram

        # Demux order (fixed — I2P SSU2 style):
        # 1. REACH_* control → reachability signaling
        # 2. Outfox 0x00/0x01/0x02 → mix processing
        # 3. Opaque forward → registered peer NAT relay
        # 4. Unknown → drop + log

        if is_reach_datagram(data):
            if self.on_reach_control is not None:
                self.on_reach_control(data, addr)
            else:
                self._log("reach_no_handler", level="warning",
                          fields={"bytes": len(data)})
            return

        kind, a, b = decode_datagram(data, self.params.payload_size)
        if kind == "shutdown":
            self._log("shutdown", fields={"wire": "binary"})
            self._shutdown = True
        elif kind == "forward":
            self._handle_forward_binary(sock, a, b, addr)
        elif kind == "circuit":
            self._handle_circuit_binary(sock, a, addr)
        elif self.on_opaque_forward is not None:
            self.on_opaque_forward(data, addr)
        else:
            self._log(
                "wire_unknown",
                level="warning",
                fields={"wire": "binary", "bytes": len(data)},
            )

    def _handle_forward_binary(
        self,
        sock: socket.socket,
        header: bytes,
        payload: bytes,
        src_addr: tuple[str, int] | None = None,
    ) -> None:
        circuit_installed = {}
        def _on_circuit(inbound_cid, circuit_key, next_hop, outbound_cid, ttl):
            cid_hex = inbound_cid.hex()
            out_hex = outbound_cid.hex()
            nh = next_hop.rstrip(b'\x00').decode('ascii', errors='replace')
            self.circuits[cid_hex] = {
                "key": circuit_key.hex(),
                "outbound_cid": out_hex,
                "next_id": nh,
                "high_watermark": -1,
                "last_active": time.time(),
            }
            circuit_installed["inbound_cid"] = cid_hex
            circuit_installed["return_next"] = nh

        try:
            hop_result = outfox_process(
                self.params, self.sk, self.pk, (header, payload),
                is_last=False, on_circuit=_on_circuit)
        except ValueError as exc:
            self._log("forward_rejected", level="warning", fields={"reason": str(exc)})
            return
        if hop_result is None:
            self._log("forward_expired_or_invalid", level="warning")
            return

        routing_info, _flag, next_packet = hop_result
        next_id = routing_info.rstrip(b'\x00').decode('ascii', errors='replace')
        next_header, next_payload = next_packet
        cid_log = circuit_installed.get("inbound_cid", "")[:8]
        return_next = circuit_installed.get("return_next", "")

        if next_id and next_header:
            self._log(
                "forward_hop",
                link_cid=cid_log,
                fields={
                    "next": next_id,
                    "return_next": return_next,
                    "prompt_visible": False,
                },
            )
            self._send_binary(
                sock,
                next_id,
                encode_forward(next_header, next_payload),
                src_addr=src_addr,
            )
            return

        if self.role == "relay":
            self._log("forward_exit_disallowed", level="warning")
            return

        final_result = outfox_process(
            self.params, self.sk, self.pk, (header, payload),
            is_last=True, on_circuit=_on_circuit)
        if final_result is None:
            self._log("exit_rejected", level="warning")
            return

        _routing, _flag, msg, _surb_info = final_result
        envelope = PromptRequestEnvelope.from_json(msg)
        prompt = envelope.prompt_text()
        expertise = envelope.intent_descriptor.get("requested_expertise") or "auto"
        degraded = bool(envelope.intent_descriptor.get("degraded_anonymity"))
        exit_cid = circuit_installed.get("inbound_cid", "")
        exit_entry = self.circuits.get(exit_cid)
        if exit_entry is None:
            self._log("exit_missing_circuit", level="warning", link_cid=exit_cid[:8])
            return
        exit_key = bytes.fromhex(exit_entry["key"])
        exit_outbound = bytes.fromhex(exit_entry["outbound_cid"])
        return_next = exit_entry["next_id"]

        self._log(
            "expert_exit",
            link_cid=exit_cid[:8],
            fields={
                "selected": True,
                "prompt_visible": True,
                "expertise": expertise,
                "return_next": return_next,
                "degraded": degraded,
            },
        )
        try:
            chunks = expert_reply_chunks(envelope, self.node_id)
        except ProviderError as exc:
            self._log(
                "provider_error",
                level="error",
                fields={"reason": str(exc), "retryable": exc.retryable, "status": exc.status},
            )
            chunks = [f"[provider_error] peer={self.node_id} message={exc}"]

        for seq, chunk in enumerate(chunks):
            plain = json.dumps({"seq": seq, "data": chunk, "done": False}).encode("utf-8")
            pkt = circuit_packet_create(self.params, exit_outbound, seq, plain, [exit_key])
            self._send_binary(sock, return_next, pkt, src_addr=src_addr)
            time.sleep(0.05)

        done = json.dumps({"seq": len(chunks), "data": "", "done": True}).encode("utf-8")
        pkt = circuit_packet_create(self.params, exit_outbound, len(chunks), done, [exit_key])
        self._send_binary(sock, return_next, pkt, src_addr=src_addr)

    def _handle_circuit_binary(
        self,
        sock: socket.socket,
        packet: bytes,
        src_addr: tuple[str, int] | None = None,
    ) -> None:
        inbound_cid = packet[1:17].hex()
        nonce = int.from_bytes(packet[17:25], "big")
        entry = self.circuits.get(inbound_cid)
        if entry is None:
            self._log("circuit_missing", level="warning", link_cid=inbound_cid[:8])
            return
        if nonce <= int(entry.get("high_watermark", -1)):
            self._log("circuit_replay", level="warning", link_cid=inbound_cid[:8])
            return
        entry["high_watermark"] = nonce

        key = bytes.fromhex(entry["key"])
        outbound_cid = bytes.fromhex(entry["outbound_cid"])
        next_id = entry["next_id"]
        processed = circuit_packet_process(self.params, key, packet, outbound_link_cid=outbound_cid)
        if processed is None:
            self._log("circuit_malformed", level="warning", link_cid=inbound_cid[:8])
            return
        _, _, forwarded = processed
        self._log(
            "circuit_hop",
            link_cid=inbound_cid[:8],
            fields={"next": next_id, "payload_visible": False},
        )
        self._send_binary(sock, next_id, forwarded, src_addr=src_addr)

    def _send_binary(
        self,
        sock: socket.socket,
        target_id: str,
        data: bytes,
        *,
        src_addr: tuple[str, int] | None = None,
    ) -> None:
        if target_id == "client":
            target = self.cluster.client
            sock.sendto(data, (target.host, target.port))
            return
        sn = self.supernode_daemon
        if sn is not None:
            peer_addr = sn.forwarder.lookup_peer_addr(target_id)
            if peer_addr is not None:
                client_addr = src_addr or self._current_src_addr
                if client_addr is not None:
                    sn.forward_to_peer(target_id, data, client_addr)
                else:
                    sock.sendto(data, peer_addr)
                return
        target = self.cluster.node(target_id)
        sock.sendto(data, (target.host, target.port))

def build_native_forward_plan(forward_path: Sequence[str] | list[str] | tuple[str, ...]):
    """Build route-info and circuit setup for process-wire clients.

    The visible routing field carries only the next forward hop. Return circuit
    state is carried in Outfox circuit setup fields and installed by relay
    callbacks.
    """

    if not forward_path:
        raise ValueError("forward_path is required")

    n = len(forward_path)
    client_inbound = urandom(CIRCUIT_ID_SIZE)
    inbound_cids = [urandom(CIRCUIT_ID_SIZE) for _ in range(n)]
    outbound_cids = [client_inbound] + inbound_cids[:-1]
    seeds = [urandom(KEY_SIZE) for _ in range(n)]
    keys = [derive_circuit_key(seeds[i], inbound_cids[i]) for i in range(n)]

    route_infos: list[bytes] = []
    circuit_setup: list[dict[str, object]] = []
    for index, _node_id in enumerate(forward_path):
        next_forward = forward_path[index + 1] if index + 1 < n else ""
        return_next = "client" if index == 0 else forward_path[index - 1]
        route_infos.append(next_forward.encode("ascii"))
        circuit_setup.append(
            {
                "inbound_link_cid": inbound_cids[index],
                "key_seed": seeds[index],
                "next_hop": return_next.encode("ascii"),
                "outbound_link_cid": outbound_cids[index],
                "ttl": 120,
            }
        )

    return route_infos, circuit_setup, list(reversed(keys))
