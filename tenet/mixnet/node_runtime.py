"""Wire node runtime for tenet daemons.

**Wire:** canonical binary datagrams via ``tenet.mixnet.wire_frame`` (``0x00`` forward,
``0x01`` circuit, ``0x02`` shutdown). This is the only path; the legacy
JSON/base64 framing and the POR1 route-info blob format have been removed.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from os import urandom
from typing import Callable, Literal, Sequence

from tenet.packet.OutfoxNode import (
    circuit_packet_create,
    circuit_packet_process,
    outfox_process,
)
from tenet.packet.OutfoxParams import OutfoxParams, derive_circuit_key

from tenet.config import ClusterConfig, LoggingConfig
from tenet.envelope import PromptRequestEnvelope
from tenet.log_events import PorLogEvent, emit_log_event
from tenet.mixnet.wire_frame import decode_datagram, encode_forward


# How an expert node turns a request into answer chunks. The mixnet does not
# know *how* answers are produced (LLM, local index, anything) — a capability
# injects this. Keeping it out of the substrate is Seam A: the relay/expert
# runtime must run with no provider/LLM code present.
ReplyHandler = Callable[[PromptRequestEnvelope, str], Sequence[str]]


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
        reply_handler: ReplyHandler | None = None,
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
        if not self.identity.kem_sk_hex:
            raise ValueError(f"{node_id} requires kem_sk_hex to run as a daemon")
        self.sk = bytes.fromhex(self.identity.kem_sk_hex)
        self.pk = bytes.fromhex(self.identity.kem_pk_hex)
        self.circuits: dict[str, dict[str, object]] = {}
        self._shutdown = False
        self.logging = logging or LoggingConfig()
        self._reply_handler = reply_handler
        self.on_reach_control = None
        self.on_opaque_forward = None
        self.supernode_daemon = None
        self._current_src_addr: tuple[str, int] | None = None
        self._response_cache: dict[str, dict[str, object]] = {}
        workers = max(1, int(os.environ.get("POR_EXPERT_WORKERS", "4")))
        self._expert_executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=f"por-{self.node_id}-expert",
        )
        self._state_lock = threading.RLock()
        self._response_inflight: set[str] = set()

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
        Tests can bind a socket once, hold it open, and pass it in — so a
        node never closes a port only to rebind it later (the source of the
        cross-test datagram races). ``stop`` is an optional ``threading.Event``;
        when set, the loop exits without relying on signal handlers.
        """

        if self.supernode_daemon is not None:
            self.supernode_daemon.attach_socket(sock)
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
        component = f"tenet-{self.role}" if self.role in {"relay", "expert"} else "tenet-node"
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
        from tenet.mixnet.reach_wire import is_reach_datagram

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
            key_hex = circuit_key.hex()
            out_hex = outbound_cid.hex()
            nh = next_hop.rstrip(b'\x00').decode('ascii', errors='replace')
            existing = self.circuits.get(cid_hex)
            if (
                existing is not None
                and existing.get("key") == key_hex
                and existing.get("outbound_cid") == out_hex
                and existing.get("next_id") == nh
            ):
                existing["last_active"] = time.time()
                circuit_installed["duplicate"] = True
            else:
                self.circuits[cid_hex] = {
                    "key": key_hex,
                    "outbound_cid": out_hex,
                    "next_id": nh,
                    "high_watermark": -1,
                    "last_active": time.time(),
                }
            circuit_installed["inbound_cid"] = cid_hex
            circuit_installed["outbound_cid"] = out_hex
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
                return_session=str(circuit_installed.get("outbound_cid", "")) or None,
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

        with self._state_lock:
            cached = self._response_cache.get(exit_cid)
            if cached is not None:
                chunks = [str(chunk) for chunk in cached.get("chunks", ())]
                start_nonce = int(cached.get("next_nonce", 0))
                cached["next_nonce"] = start_nonce + self._response_packet_count(chunks)
                cached["last_active"] = time.time()
            else:
                chunks = []
                start_nonce = 0
        if cached is not None:
            self._log(
                "expert_exit_duplicate",
                link_cid=exit_cid[:8],
                fields={"return_next": return_next, "cached_chunks": len(chunks)},
            )
            self._expert_executor.submit(
                self._send_response_chunks,
                sock,
                chunks,
                exit_key,
                exit_outbound,
                return_next,
                src_addr=src_addr,
                link_cid=exit_cid[:8],
                start_nonce=start_nonce,
                replay=True,
            )
            return
        with self._state_lock:
            if exit_cid in self._response_inflight:
                self._log(
                    "expert_exit_duplicate_inflight",
                    link_cid=exit_cid[:8],
                    fields={"return_next": return_next},
                )
                return
            self._response_inflight.add(exit_cid)

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
        self._expert_executor.submit(
            self._process_expert_exit_response,
            sock,
            envelope,
            exit_key,
            exit_outbound,
            return_next,
            src_addr,
            exit_cid,
        )
        return

    def _reply(self, envelope: PromptRequestEnvelope) -> Sequence[str]:
        """Produce answer chunks via the injected handler (Seam A).

        The substrate has no opinion on *how* answers are made; a capability
        injects ``reply_handler``. Handler error types (e.g. ``ProviderError``)
        are read structurally so the mixnet need not import them.
        """
        if self._reply_handler is None:
            self._log("reply_no_handler", level="error", fields={"peer": self.node_id})
            return [f"[provider_error] peer={self.node_id} message=no reply handler configured"]
        try:
            return self._reply_handler(envelope, self.node_id)
        except Exception as exc:
            self._log(
                "provider_error",
                level="error",
                fields={
                    "reason": str(exc),
                    "retryable": getattr(exc, "retryable", None),
                    "status": getattr(exc, "status", None),
                },
            )
            return [f"[provider_error] peer={self.node_id} message={exc}"]

    def _process_expert_exit_response(
        self,
        sock: socket.socket,
        envelope: PromptRequestEnvelope,
        exit_key: bytes,
        exit_outbound: bytes,
        return_next: str,
        src_addr: tuple[str, int] | None,
        exit_cid: str,
    ) -> None:
        chunks = self._reply(envelope)

        try:
            next_nonce = self._send_response_chunks(
                sock,
                chunks,
                exit_key,
                exit_outbound,
                return_next,
                src_addr=src_addr,
                link_cid=exit_cid[:8],
            )
            self._cache_response_chunks(exit_cid, chunks, next_nonce)
        finally:
            with self._state_lock:
                self._response_inflight.discard(exit_cid)

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

        # If this is the exit (no next_id or next_id is empty) and we get a
        # circuit packet, check if the decrypted content is a new prompt envelope
        # for circuit reuse (multi-turn conversation).
        if self.role == "expert" and (not next_id or next_id == "client"):
            from tenet.packet.OutfoxNode import circuit_packet_decrypt
            plain = circuit_packet_decrypt(self.params, key, packet)
            if plain is not None:
                try:
                    envelope = PromptRequestEnvelope.from_json(plain)
                    self._log("circuit_reuse_prompt", link_cid=inbound_cid[:8],
                              fields={"prompt_visible": True})
                    exit_key = key
                    exit_outbound = outbound_cid
                    self._handle_circuit_prompt(
                        sock, envelope, exit_key, exit_outbound, next_id or "client",
                        src_addr=src_addr)
                    return
                except (ValueError, KeyError):
                    pass

        self._log(
            "circuit_hop",
            link_cid=inbound_cid[:8],
            fields={"next": next_id, "payload_visible": False},
        )
        self._send_binary(sock, next_id, forwarded, src_addr=src_addr)

    def _handle_circuit_prompt(self, sock, envelope, exit_key, exit_outbound_bytes,
                                return_next, *, src_addr=None):
        """Process a follow-up prompt received via circuit reuse."""
        self._expert_executor.submit(
            self._process_circuit_prompt_response,
            sock,
            envelope,
            exit_key,
            exit_outbound_bytes,
            return_next,
            src_addr,
        )

    def _process_circuit_prompt_response(
        self,
        sock: socket.socket,
        envelope: PromptRequestEnvelope,
        exit_key: bytes,
        exit_outbound_bytes: bytes,
        return_next: str,
        src_addr: tuple[str, int] | None,
    ) -> None:
        chunks = self._reply(envelope)

        self._send_response_chunks(
            sock,
            chunks,
            exit_key,
            exit_outbound_bytes,
            return_next,
            src_addr=src_addr,
        )

    def _send_response_chunks(
        self,
        sock: socket.socket,
        chunks: Sequence[str],
        exit_key: bytes,
        exit_outbound: bytes,
        return_next: str,
        *,
        src_addr=None,
        link_cid: str | None = None,
        start_nonce: int = 0,
        replay: bool = False,
    ) -> int:
        chunk_repeats = max(1, int(os.environ.get("POR_STREAM_CHUNK_REPEATS", "3")))
        nonce = start_nonce
        for seq, chunk in enumerate(chunks):
            plain = json.dumps({"seq": seq, "data": chunk, "done": False}).encode("utf-8")
            for repeat in range(chunk_repeats):
                pkt = circuit_packet_create(self.params, exit_outbound, nonce, plain, [exit_key])
                self._send_binary(sock, return_next, pkt, src_addr=src_addr)
                nonce += 1
                if repeat < chunk_repeats - 1:
                    time.sleep(0.02)
            time.sleep(0.05)

        done = json.dumps({"seq": len(chunks), "data": "", "done": True}).encode("utf-8")
        done_repeats = max(1, int(os.environ.get("POR_STREAM_DONE_REPEATS", "4")))
        for repeat in range(done_repeats):
            pkt = circuit_packet_create(self.params, exit_outbound, nonce, done, [exit_key])
            self._send_binary(sock, return_next, pkt, src_addr=src_addr)
            nonce += 1
            if repeat < done_repeats - 1:
                time.sleep(0.05)
        self._log(
            "stream_return_sent",
            link_cid=link_cid,
            fields={
                "chunks": len(chunks),
                "chunk_repeats": chunk_repeats,
                "done_repeats": done_repeats,
                "packets": nonce - start_nonce,
                "start_nonce": start_nonce,
                "replay": replay,
            },
        )
        return nonce

    @staticmethod
    def _response_packet_count(chunks: Sequence[str]) -> int:
        chunk_repeats = max(1, int(os.environ.get("POR_STREAM_CHUNK_REPEATS", "3")))
        done_repeats = max(1, int(os.environ.get("POR_STREAM_DONE_REPEATS", "4")))
        return (len(chunks) * chunk_repeats) + done_repeats

    def _cache_response_chunks(
        self,
        exit_cid: str,
        chunks: Sequence[str],
        next_nonce: int,
    ) -> None:
        now = time.time()
        ttl = max(1, int(os.environ.get("POR_RESPONSE_CACHE_TTL", "300")))
        with self._state_lock:
            for cid, cached in list(self._response_cache.items()):
                last_active = float(cached.get("last_active", cached.get("created", now)))
                if now - last_active > ttl:
                    self._response_cache.pop(cid, None)
            self._response_cache[exit_cid] = {
                "chunks": tuple(chunks),
                "next_nonce": next_nonce,
                "created": now,
                "last_active": now,
            }
            max_entries = max(1, int(os.environ.get("POR_RESPONSE_CACHE_MAX", "256")))
            while len(self._response_cache) > max_entries:
                oldest = min(
                    self._response_cache,
                    key=lambda cid: float(
                        self._response_cache[cid].get(
                            "last_active",
                            self._response_cache[cid].get("created", now),
                        )
                    ),
                )
                self._response_cache.pop(oldest, None)

    def _send_binary(
        self,
        sock: socket.socket,
        target_id: str,
        data: bytes,
        *,
        src_addr: tuple[str, int] | None = None,
        return_session: str | None = None,
    ) -> None:
        sn = self.supernode_daemon
        if target_id == "client":
            if sn is not None and src_addr is not None:
                if sn.forward_return_from_peer(data, src_addr):
                    return
            target = self.cluster.client
            sock.sendto(data, (target.host, target.port))
            return
        if sn is not None:
            peer_addr = sn.forwarder.lookup_peer_addr(target_id)
            if peer_addr is not None:
                client_addr = src_addr or self._current_src_addr
                if client_addr is not None:
                    sn.forward_to_peer(
                        target_id,
                        data,
                        client_addr,
                        return_session=return_session,
                    )
                else:
                    sock.sendto(data, peer_addr)
                return
        if self.role == "expert" and src_addr is not None:
            sock.sendto(data, src_addr)
            return
        # Relay must discover next hop via REACH forwarding table, not static config.
        # Fall back to cluster config ONLY for the client return address (which the
        # relay legitimately knows from the forward packet's source).
        if target_id == "client":
            target = self.cluster.client
            sock.sendto(data, (target.host, target.port))
            return
        try:
            target = self.cluster.node(target_id)
            sock.sendto(data, (target.host, target.port))
        except (KeyError, AttributeError):
            self._log("send_no_route", level="warning",
                      fields={"target": target_id})

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
