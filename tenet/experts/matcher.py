"""Plain matcher/mailbox linkage for the enclave-plane wire shape.

This is intentionally a stand-in implementation. It proves the wire-shape
interfaces with ordinary Python objects while keeping the transport unchanged:
the matcher returns opaque handles, and only the mailbox resolves those handles
to reachability records and routing keys.
"""

from __future__ import annotations

import hmac
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Iterator, Mapping, Sequence

from tenet.config import PeerAddressConfig, TrustedReachabilityRelayConfig
from tenet.experts.cover import cover_candidate
from tenet.experts.directory import DiscoveryRequest, DiscoveryResult, PeerRecord
from tenet.experts.expert_route import PeerCandidate
from tenet.handles import (
    HandleResolution,
    OpaqueHandle,
    OpaqueHandleIssuer,
    OpaqueHandleRecord,
)
from tenet.experts.memory_index import MemoryManifest, score_manifest
from tenet.experts.oblivious import DUMMY_INDEX, ct_select, oblivious_top_k
from tenet.mixnet.peer_address import ROUTE_RELAY, build_dial_plan, peer_address_record_from_dict
from tenet.mixnet.transport_dial import DialTarget, resolve_dial_target


PLAIN_MATCHER_V1 = "plain_matcher_v1"


@dataclass(frozen=True)
class MatcherEntry:
    handle: OpaqueHandle
    candidate: PeerCandidate


class PlainMatcher:
    """Query-to-top-K handle matcher using existing public manifest scores."""

    def __init__(
        self,
        entries: Sequence[MatcherEntry],
        *,
        top_k: int = 20,
        pad_with_covers: bool = True,
        cover_key: bytes | None = None,
    ) -> None:
        if top_k <= 0:
            raise ValueError("top_k must be positive")
        self.entries = tuple(entries)
        self.top_k = top_k
        # Item 6: pad the result to a constant K with cover candidates so the
        # operator cannot read the real-match count off the response. The
        # cover_key seeds the (per-response-nonce'd) cover handles; a fresh
        # random key per matcher is fine since covers need only be unlinkable.
        self.pad_with_covers = pad_with_covers
        self.cover_key = cover_key or os.urandom(32)

    @classmethod
    def from_records(
        cls,
        records: Sequence[PeerRecord],
        handles: Mapping[str, OpaqueHandle | OpaqueHandleRecord],
        *,
        top_k: int = 20,
    ) -> "PlainMatcher":
        entries = []
        for record in records:
            handle = handles.get(record.peer_id)
            if handle is None:
                continue
            opaque = (
                OpaqueHandle(handle.handle)
                if isinstance(handle, OpaqueHandleRecord)
                else handle
            )
            entries.append(
                MatcherEntry(
                    handle=opaque,
                    candidate=PeerCandidate(
                        _manifest_with_handle(record.manifest, opaque),
                        _observation_with_handle(record.observation, opaque),
                        route_handle=opaque.token,
                        publisher_id=record.peer_id,
                    ),
                )
            )
        return cls(entries, top_k=top_k)

    def discover(self, request: DiscoveryRequest) -> DiscoveryResult:
        if request.mode != PLAIN_MATCHER_V1:
            raise ValueError(f"unsupported matcher mode: {request.mode!r}")

        query = request.intent.query_text()
        limit = self.top_k
        if request.max_records is not None:
            limit = min(limit, request.max_records)

        # Oblivious selection: score every entry (no data-dependent skip/sort),
        # then pick top-K via a uniform-access primitive (tenet.experts.oblivious). The
        # selection access pattern no longer depends on which entry matched.
        scores = [score_manifest(entry.candidate.manifest, query) for entry in self.entries]
        selected = oblivious_top_k(scores, limit) if limit > 0 else []
        candidates = self._assemble(selected)
        return DiscoveryResult(
            candidates=candidates,
            mode=PLAIN_MATCHER_V1,
            snapshot_size=len(self.entries),
            exact_query_sent=True,
            private_query_used=False,
            generated_at=datetime.now(timezone.utc).isoformat(),
            note=(
                "oblivious top-K selection (uniform access pattern); output-count "
                "hidden by cover-handle padding to constant K; hardware-CT/ORAM "
                "and exact byte-length normalisation are the in-TEE port"
            ),
        )

    def _assemble(self, selected: Sequence[int]) -> tuple[PeerCandidate, ...]:
        """Turn selected indices into candidates.

        With ``pad_with_covers`` (item 6): every empty (``DUMMY_INDEX``) slot becomes
        a cover candidate, so the result is always exactly ``len(selected)``
        candidates and the real-match count never shows in the response. Without
        it (legacy/plain wire), empty slots are simply dropped.
        """
        if not self.pad_with_covers:
            return tuple(
                self.entries[i].candidate for i in selected if i != DUMMY_INDEX
            )
        # A per-response nonce makes cover handles unlinkable across calls.
        nonce = os.urandom(16)
        template = self.entries[0].candidate.manifest if self.entries else None
        out: list[PeerCandidate] = []
        for slot, i in enumerate(selected):
            if i != DUMMY_INDEX:
                out.append(self.entries[i].candidate)
            elif template is not None:
                out.append(cover_candidate(template, self.cover_key, nonce, slot))
            # No entries at all => nothing to template a cover from; emit nothing.
        return tuple(out)


@dataclass(frozen=True)
class MailboxEntry:
    record: OpaqueHandleRecord
    routing_kem_pk_hex: str
    peer_address: dict[str, object]


class PlainMailbox:
    """Mailbox-side handle resolver.

    This object is the only plain stand-in component that knows how an opaque handle
    maps to a reachability record and routing key.
    """

    def __init__(self, entries: Sequence[MailboxEntry] = ()) -> None:
        self._entries = {entry.record.handle: entry for entry in entries}

    def add(
        self,
        *,
        record: OpaqueHandleRecord,
        routing_kem_pk_hex: str,
        peer_address: Mapping[str, object],
    ) -> None:
        if peer_address.get("peer_id") != record.handle:
            raise ValueError("mailbox peer_address record must be issued to the handle")
        bytes.fromhex(routing_kem_pk_hex)
        self._entries[record.handle] = MailboxEntry(
            record=record,
            routing_kem_pk_hex=routing_kem_pk_hex,
            peer_address=dict(peer_address),
        )

    def resolve_handle(
        self, handle: str, *, on_access: Callable[[str], None] | None = None
    ) -> HandleResolution | None:
        # Oblivious scan: touch every stored entry in a fixed (insertion) order
        # regardless of which handle is requested, so the access pattern does not
        # reveal the target. Handle comparison is constant-time and the matching
        # entry is chosen via constant-time select. (Hardware-CT/ORAM is the
        # in-TEE port; this is the algorithm + access-pattern invariance.)
        found = False
        found_kem: str | None = None
        found_addr: dict | None = None
        for stored_handle, entry in self._entries.items():
            if on_access is not None:
                on_access(stored_handle)
            match = hmac.compare_digest(stored_handle, handle)
            found = ct_select(match, True, found)
            found_kem = ct_select(match, entry.routing_kem_pk_hex, found_kem)
            found_addr = ct_select(match, entry.peer_address, found_addr)
        if not found:
            return None
        return HandleResolution(
            handle=handle,
            routing_kem_pk_hex=found_kem,
            peer_address=dict(found_addr),
        )

    def routing_kem_pk_hex(self, handle: str) -> str | None:
        entry = self.resolve_handle(handle)
        if entry is None:
            return None
        return entry.routing_kem_pk_hex

    def to_json(self) -> str:
        data = {
            "version": "tenet.plain_mailbox.2026-06",
            "handles": sorted(self._entries),
        }
        return json.dumps(data, sort_keys=True, indent=2)


class PlainMailboxDelivery:
    """Plain mailbox transport for the committed wire shape.

    This is not the hardened oblivious mailbox. It sends sealed Outfox bytes
    from a mailbox-owned UDP socket to a reachability relay and yields sealed
    return datagrams back to the client code for decryption.
    """

    def __init__(
        self,
        mailbox: PlainMailbox,
        *,
        mailbox_sock: socket.socket,
        per_request_sockets: bool = True,
        bind_host: str | None = None,
        peer_address_config: PeerAddressConfig | None = None,
        trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig] = (),
        dev_allow_untrusted_reachability_relays: bool = False,
    ) -> None:
        self.mailbox = mailbox
        self.mailbox_sock = mailbox_sock
        self.per_request_sockets = per_request_sockets
        self.bind_host = bind_host or self._socket_bind_host(mailbox_sock)
        self._shared_socket_lock = threading.Lock()
        self.peer_address_config = peer_address_config or PeerAddressConfig(enabled=True)
        self.trusted_reachability_relays = tuple(trusted_reachability_relays)
        self.dev_allow_untrusted_reachability_relays = dev_allow_untrusted_reachability_relays

    def relay_path_for_handle(self, handle: str) -> tuple[str, ...]:
        dial_target = self._dial_target(handle)
        if dial_target.route_kind != ROUTE_RELAY:
            return tuple()
        if not dial_target.relay_id:
            raise ValueError("mailbox delivery requires a reachability assist route id")
        return (dial_target.relay_id,)

    def deliver_to_handle(
        self,
        handle: str,
        datagram: bytes,
        *,
        timeout: float,
    ) -> Iterator[bytes]:
        dial_target = self._dial_target(handle)
        sock, owns_socket = self._delivery_socket()

        def packets() -> Iterator[bytes]:
            lock = None if owns_socket else self._shared_socket_lock
            if lock is not None:
                lock.acquire()
            try:
                sock.settimeout(0.5)
                sock.sendto(datagram, (dial_target.host, dial_target.port))
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        data, _addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    yield data
            finally:
                if owns_socket:
                    sock.close()
                if lock is not None:
                    lock.release()

        return packets()

    def _delivery_socket(self) -> tuple[socket.socket, bool]:
        if not self.per_request_sockets:
            return self.mailbox_sock, False
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.bind_host, 0))
        return sock, True

    @staticmethod
    def _socket_bind_host(sock: socket.socket) -> str:
        try:
            host = str(sock.getsockname()[0])
        except OSError:
            return "0.0.0.0"
        return host or "0.0.0.0"

    def _dial_target(self, handle: str) -> DialTarget:
        resolution = self.mailbox.resolve_handle(handle)
        if resolution is None:
            raise ValueError("handle_unresolved")
        record = peer_address_record_from_dict(dict(resolution.peer_address))
        plan = build_dial_plan(
            record,
            allow_direct=self.peer_address_config.allow_direct,
            prefer_direct=self.peer_address_config.prefer_direct,
        )
        dial_target = resolve_dial_target(
            plan,
            self.trusted_reachability_relays,
            dev_allow_untrusted_reachability_relays=self.dev_allow_untrusted_reachability_relays,
        )
        if dial_target is None:
            raise ValueError("mailbox_no_trusted_dial_target")
        return dial_target


class PlainEnclavePlaneDiscoveryProvider:
    """DiscoveryProvider facade linking plain matcher and plain mailbox."""

    def __init__(
        self,
        matcher: PlainMatcher,
        mailbox: PlainMailbox,
        delivery: PlainMailboxDelivery | None = None,
    ) -> None:
        self.matcher = matcher
        self.mailbox = mailbox
        self.delivery = delivery

    def discover(self, request: DiscoveryRequest) -> DiscoveryResult:
        return self.matcher.discover(request)

    @property
    def mailbox_delivery_enabled(self) -> bool:
        return self.delivery is not None

    def resolve_handle(self, handle: str) -> HandleResolution | None:
        return self.mailbox.resolve_handle(handle)

    def routing_kem_pk_hex(self, handle: str) -> str | None:
        return self.mailbox.routing_kem_pk_hex(handle)

    def relay_path_for_handle(self, handle: str) -> tuple[str, ...]:
        if self.delivery is None:
            resolution = self.mailbox.resolve_handle(handle)
            if resolution is None:
                raise ValueError("handle_unresolved")
            record = peer_address_record_from_dict(dict(resolution.peer_address))
            plan = build_dial_plan(record)
            if plan.primary is None:
                raise ValueError("mailbox_no_delivery_path")
            if plan.primary.kind != ROUTE_RELAY:
                return tuple()
            if not plan.primary.relay_id:
                raise ValueError("mailbox_no_reachability_assist_path")
            return (plan.primary.relay_id,)
        return self.delivery.relay_path_for_handle(handle)

    def deliver_to_handle(
        self,
        handle: str,
        datagram: bytes,
        *,
        timeout: float,
    ) -> Iterator[bytes]:
        if self.delivery is None:
            raise ValueError("mailbox_delivery_disabled")
        return self.delivery.deliver_to_handle(handle, datagram, timeout=timeout)


def _manifest_with_handle(manifest: MemoryManifest, handle: OpaqueHandle) -> MemoryManifest:
    return replace(manifest, peer_id=handle.token)


def _observation_with_handle(observation, handle: OpaqueHandle):
    if observation is None:
        return None
    return replace(observation, peer_id=handle.token)
