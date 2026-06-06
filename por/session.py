"""Persistent client session — hold circuit state across multiple prompts.

Instead of a full Outfox forward pass per prompt, a session reuses the
established circuit for follow-up messages. The first prompt does the
full KEM + AEAD + circuit setup. Subsequent prompts on the same session
send through the existing circuit — one AES-CTR op per hop, no KEM.

Usage:
    session = ClientSession(cluster, forward_path, discovery_provider)
    session.connect(first_envelope)  # full Outfox forward, installs circuits
    response1 = session.send(first_envelope)
    response2 = session.send(second_envelope)  # reuses circuit
    session.close()
"""

from __future__ import annotations

import json
import socket
import time
from typing import Callable, Sequence

from sphinxmix.OutfoxClient import packet_create
from sphinxmix.OutfoxNode import circuit_packet_create, circuit_packet_decrypt
from sphinxmix.OutfoxParams import OutfoxParams

from .config import ClusterConfig
from .directory import DiscoveryProvider
from .envelope import PromptRequestEnvelope
from .node_runtime import build_native_forward_plan
from .wire_frame import encode_forward, decode_datagram


class ClientSession:
    """Persistent circuit session across multiple prompts.

    First call to send() does the full Outfox forward to establish circuits.
    Subsequent calls reuse the circuit — just AES-CTR encrypt the new
    prompt and stream it through the existing return path.
    """

    def __init__(
        self,
        cluster: ClusterConfig,
        forward_path: Sequence[str],
        discovery_provider: DiscoveryProvider | None = None,
        *,
        dial_addr: tuple[str, int] | None = None,
        timeout: float = 8.0,
    ):
        self.cluster = cluster
        self.forward_path = tuple(forward_path)
        self.discovery_provider = discovery_provider
        self.params = OutfoxParams(**cluster.params.outfox_kwargs())
        self.timeout = timeout

        if dial_addr:
            self._dial_addr = dial_addr
        else:
            first = cluster.node(forward_path[0])
            self._dial_addr = (first.host, first.port)

        self._client_addr = (cluster.client.host, cluster.client.port)
        self._sock: socket.socket | None = None
        self._send_sock: socket.socket | None = None
        self._circuit_keys: list[bytes] | None = None
        self._circuit_nonce = 0
        self._established = False
        self._prompts_sent = 0

    @property
    def established(self) -> bool:
        return self._established

    @property
    def prompts_sent(self) -> int:
        return self._prompts_sent

    def connect(self) -> None:
        """Bind sockets. Call before first send()."""
        if self._sock is not None:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(self._client_addr)
        self._sock.settimeout(0.5)
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(
        self,
        envelope: PromptRequestEnvelope,
        *,
        on_chunk: Callable[[dict], None] | None = None,
    ) -> str:
        """Send a prompt and return the streamed response text.

        First call establishes the circuit via full Outfox forward.
        Subsequent calls reuse the circuit.
        """
        if self._sock is None:
            self.connect()

        if not self._established:
            return self._send_first(envelope, on_chunk=on_chunk)
        return self._send_reuse(envelope, on_chunk=on_chunk)

    def close(self) -> None:
        """Release sockets and circuit state."""
        if self._sock:
            self._sock.close()
            self._sock = None
        if self._send_sock:
            self._send_sock.close()
            self._send_sock = None
        self._circuit_keys = None
        self._established = False

    def _send_first(self, envelope, *, on_chunk=None) -> str:
        """Full Outfox forward — establishes circuit state at relays."""
        route_infos, circuit_setup, client_peel_keys = build_native_forward_plan(
            self.forward_path)

        kem_keys = self._kem_keys()
        header, payload = packet_create(
            self.params, route_infos, kem_keys,
            envelope.to_json().encode("utf-8"),
            circuit_setup=circuit_setup,
        )

        self._send_sock.sendto(encode_forward(header, payload), self._dial_addr)
        self._circuit_keys = client_peel_keys
        self._established = True
        self._prompts_sent += 1

        return self._receive_stream(on_chunk=on_chunk)

    def _send_reuse(self, envelope, *, on_chunk=None) -> str:
        """Reuse existing circuit — just circuit packet, no KEM."""
        if self._circuit_keys is None:
            raise RuntimeError("No circuit established")

        # Send the prompt as a circuit packet through the existing circuit
        self._circuit_nonce += 1
        prompt_data = envelope.to_json().encode("utf-8")
        # Use the exit key (last in peel order = first in circuit_keys reversed)
        exit_key = self._circuit_keys[-1]
        # For reuse, we create a circuit packet from client side
        # The exit knows the circuit key and can decrypt
        pkt = circuit_packet_create(
            self.params,
            b'\x00' * 16,  # link_cid — exit will match by circuit state
            self._circuit_nonce,
            prompt_data,
            [exit_key],
        )
        self._send_sock.sendto(pkt, self._dial_addr)
        self._prompts_sent += 1

        return self._receive_stream(on_chunk=on_chunk)

    def _receive_stream(self, *, on_chunk=None) -> str:
        """Wait for circuit packet stream and return assembled text."""
        chunks = []
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                data, _ = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            kind, body, _ = decode_datagram(data, self.params.payload_size)
            if kind != "circuit":
                continue
            plain = circuit_packet_decrypt(self.params, self._circuit_keys, body)
            if plain is None:
                continue
            chunk = json.loads(plain.decode("utf-8"))
            if on_chunk:
                on_chunk(chunk)
            if chunk.get("done"):
                break
            chunks.append(chunk["data"])
        else:
            raise TimeoutError("session timed out waiting for response")
        return "".join(chunks)

    def _kem_keys(self) -> list[bytes]:
        keys = []
        for nid in self.forward_path:
            try:
                node = self.cluster.node(nid)
                keys.append(bytes.fromhex(node.kem_pk_hex))
            except (KeyError, AttributeError):
                if self.discovery_provider:
                    from .directory import DirectorySnapshot
                    for rec in self.discovery_provider.discover(None).candidates:
                        if rec.manifest.peer_id == nid:
                            desc = getattr(rec, 'descriptor', None)
                            if desc and 'kem_pk' in desc:
                                keys.append(bytes.fromhex(desc['kem_pk']))
                                break
                    else:
                        raise ValueError(f"No KEM key for {nid}")
                else:
                    raise ValueError(f"No KEM key for {nid}")
        return keys
