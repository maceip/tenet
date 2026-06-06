"""Real Kademlia DHT overlay for Tenet signed control records.

This replaces the previous in-memory "pseudo-DHT" (global xor sort over a
static peer list) with a library-backed Kademlia implementation that provides
the required mechanics for scale:

- routing table with k-buckets
- iterative node/value lookups (not a single sort of everything)
- peer discovery and liveness (periodic refresh / ping)
- churn handling and routing table maintenance
- replication factor (k) and provider storage for record keys
- refresh intervals and anti-entropy (internal to the server)
- bootstrap from known contacts with recovery
- bounded fanout (alpha concurrency, k-closest)

Application records (pools, experts, names, match results, trust updates, ...)
are still required to be signed, sequence-numbered, expiring, network-scoped,
and free of direct dial information. The DHT only carries the canonical
signed record bytes (or their JSON form); all validation, seq checks, and
expiry enforcement remain in the MixnetControlService / record validator.

The mixnet data plane is unchanged. This overlay is *only* for control-plane
discovery and replication of signed records. Client request traffic still
resolves via control records to a mixnet forward plan and never obtains raw
endpoints from here.

Kademlia traffic uses its own UDP port (main_port + 1 by default in the
integrating runtime) so it does not interfere with the mixnet wire format or
our custom TCTL control messages (which continue to be used for fast local
sync/gossip and as a secondary propagation path).
"""

from __future__ import annotations

import asyncio
import json
import threading
from hashlib import sha256
from typing import Sequence

from kademlia.network import Server

from tenet.mixnet.control.records import (
    MAX_SIGNED_CONTROL_RECORD_BYTES,
    SignedControlRecord,
    signed_record_to_dht_bytes,
)


class KademliaControlOverlay:
    """Background Kademlia node that stores and retrieves signed control records.

    Usage in a daemon:

        overlay = KademliaControlOverlay(node_id, listen_port=main_port + 1)
        overlay.start(bootstrap=[("10.0.0.5", 7001 + 1), ...])
        ...
        overlay.publish(record_key, signed_record)
        got = overlay.fetch(record_key)
        if got is not None:
            service.put_signed(got)   # re-validates

    The publish uses Kademlia set() which performs the iterative lookup for the
    k closest nodes for that key and replicates the value. fetch() performs an
    iterative get. Both survive the original bootstrap nodes disappearing as
    long as the k-bucket/routing information has enough live contacts and some
    replica holders for the key are reachable.
    """

    def __init__(
        self,
        local_node_label: str,
        *,
        listen_host: str = "0.0.0.0",
        listen_port: int,
        network_id: str | None = None,
    ) -> None:
        self.local_node_label = str(local_node_label)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.network_id = network_id  # used to scope DHT keys per network (fix eclipse)
        self.server: Server | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._mesh_ready = threading.Event()  # set after listen + (optional) bootstrap; publishes wait for this to avoid "no neighbors" sets
        self._pending_lock = threading.Lock()
        self._pending_publishes: list[tuple[str, SignedControlRecord]] = []

    async def _serve(self, bootstrap: Sequence[tuple[str, int]]) -> None:
        # Each node gets its own storage (in-memory is fine; records are also
        # persisted by the control service's PersistentControlStore when the
        # node has the capability and a store_path).
        self.server = Server()
        await self.server.listen(self.listen_port, self.listen_host)
        self._ready.set()
        # NOTE: we intentionally do NOT flush publishes here. We wait until
        # after bootstrap (if any) so that the first server.set() calls see a
        # populated routing table instead of "no known neighbors".
        if bootstrap:
            # bootstrap() performs FIND_NODE against the given contacts and
            # populates the routing table. Real iterative behavior (and safe
            # replication on publish) starts here.
            await self.server.bootstrap(list(bootstrap))
        # Now we have (or had no need for) initial neighbors. Safe to publish
        # with expectation of replication to k-closest.
        self._mesh_ready.set()
        self._flush_pending()
        # Idle until asked to stop. The Server's internal refresh loops keep
        # buckets and replicas alive.
        while not self._stop.is_set():
            await asyncio.sleep(0.5)

    def start(self, bootstrap: Sequence[tuple[str, int]] = ()) -> None:
        """Launch the Kademlia server in a daemon thread with its own event loop."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def _runner() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._serve(bootstrap))
            finally:
                try:
                    if self.server is not None:
                        self.server.stop()
                except Exception:
                    pass
                try:
                    self._mesh_ready.clear()
                except Exception:
                    pass
                self._loop.close()

        self._thread = threading.Thread(
            target=_runner,
            name=f"tenet-kad-{self.local_node_label}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal shutdown and wait briefly for the thread."""
        self._stop.set()
        if self._loop is not None:
            # Wake the sleep loop.
            self._loop.call_soon_threadsafe(lambda: None)
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._ready.clear()
        self._mesh_ready.clear()

    def wait_for_mesh(self, timeout: float = 5.0) -> bool:
        """Block (with timeout) until this overlay has completed listen and its
        initial bootstrap (if bootstrap contacts were supplied to start()).

        Returns True if the mesh became ready within the timeout. Callers that
        want their publishes to have a good chance of replicating on first try
        (instead of being queued until the internal bootstrap settles) should
        call this after start() and before the first wave of publish() calls.
        """
        return self._mesh_ready.wait(timeout=timeout)

    def _derive_dht_key(self, record_key: str) -> str:
        """Return the network-scoped storage key for Kademlia.

        This prevents one network from occupying slots that belong to another
        (e.g. pool/foo from netA must not shadow pool/foo for netB).
        """
        if not self.network_id:
            return record_key
        return sha256(
            b"tenet-control-dht-v1\x00"
            + self.network_id.encode("utf-8")
            + b"\x00"
            + record_key.encode("utf-8")
        ).hexdigest()

    def _flush_pending(self) -> None:
        with self._pending_lock:
            if not self._pending_publishes:
                return
            pend = self._pending_publishes
            self._pending_publishes = []
        for rec_key, srec in pend:
            try:
                self.publish(rec_key, srec)
            except Exception:
                pass

    def publish(self, key: str, signed: SignedControlRecord) -> None:
        """Best-effort publish of a signed record.

        The value stored in Kademlia is the canonical to_dict() form under a
        network-scoped key. Callers must still validate on retrieval.
        """
        # Size bound (fix 7): reject oversized before we ever call into Kademlia set.
        try:
            blob = signed_record_to_dht_bytes(signed)
            if len(blob) > MAX_SIGNED_CONTROL_RECORD_BYTES:
                return  # drop; do not store in DHT
        except Exception:
            return

        if self.server is None or self._loop is None or not self._mesh_ready.is_set():
            # Queue while the mesh is not ready (post-bootstrap). This prevents
            # publishing via server.set() when there are no known neighbors yet,
            # which would cause the value to be stored only locally (or dropped)
            # instead of replicated. The pending items are flushed once
            # _serve completes its bootstrap step and sets _mesh_ready.
            if self._thread and self._thread.is_alive():
                with self._pending_lock:
                    self._pending_publishes.append((key, signed))
            return

        self._flush_pending()

        dht_key = self._derive_dht_key(key)  # network-scoped to prevent cross-net eclipse (fix 1)

        async def _do_set() -> None:
            if self.server is None:
                return
            await self.server.set(dht_key, blob.decode("utf-8"))  # lib accepts str or bytes; keep consistent

        try:
            asyncio.run_coroutine_threadsafe(_do_set(), self._loop)
        except Exception:
            # Fire-and-forget; a later refresh or explicit re-publish will retry.
            pass

    def fetch(self, key: str, timeout: float = 4.0) -> SignedControlRecord | None:
        """Perform an iterative Kademlia GET for the key and return a parsed
        SignedControlRecord (or None on miss/timeout/error).

        The returned object has *not* been signature-validated against any
        particular roots; the caller (usually MixnetControlService) must call
        .validate(...) with its verify_keys before trusting/ingesting it.
        Size is checked after retrieval to avoid accepting huge blobs from the DHT.
        """
        if self.server is None or self._loop is None:
            return None

        dht_key = self._derive_dht_key(key)

        async def _do_get() -> str | None:
            if self.server is None:
                return None
            return await self.server.get(dht_key)

        try:
            fut = asyncio.run_coroutine_threadsafe(_do_get(), self._loop)
            raw = fut.result(timeout=timeout)
        except Exception:
            return None
        if not raw:
            return None
        try:
            data = raw if isinstance(raw, (bytes, bytearray)) else raw.encode("utf-8")
            if len(data) > MAX_SIGNED_CONTROL_RECORD_BYTES:
                return None  # oversized from DHT; reject (fix 7)
            return SignedControlRecord.from_dict(json.loads(data))
        except Exception:
            return None

    def control_wire_contacts(
        self,
        *,
        limit: int = 20,
        timeout: float = 1.0,
    ) -> tuple[tuple[str, tuple[str, int]], ...]:
        """Return live peers learned by Kademlia as control-wire contacts.

        Signed control records still do not contain host/port material. This
        method reads the library routing table at runtime and derives the Tenet
        control-wire port from the local convention that Kademlia listens on
        ``control_port + 1``. The peer id returned here is the Kademlia node id
        hex, suitable for logging/deduping but not as route truth.
        """

        if self.server is None or self._loop is None or not self._mesh_ready.is_set():
            return tuple()

        async def _do_contacts() -> tuple[tuple[str, tuple[str, int]], ...]:
            server = self.server
            if server is None:
                return tuple()
            protocol = getattr(server, "protocol", None)
            router = getattr(protocol, "router", None)
            buckets = tuple(getattr(router, "buckets", ()) or ())
            contacts: list[tuple[str, tuple[str, int]]] = []
            local = getattr(server, "node", None)
            seen: set[tuple[str, int]] = set()
            for bucket in buckets:
                get_nodes = getattr(bucket, "get_nodes", None)
                if not callable(get_nodes):
                    continue
                for node in get_nodes():
                    host = str(getattr(node, "ip", "") or "")
                    dht_port = int(getattr(node, "port", 0) or 0)
                    if not host or dht_port <= 1:
                        continue
                    if local is not None and node.same_home_as(local):
                        continue
                    control_port = dht_port - 1
                    addr = (host, control_port)
                    if addr in seen:
                        continue
                    seen.add(addr)
                    node_id = getattr(node, "id", b"")
                    if isinstance(node_id, (bytes, bytearray)):
                        label = node_id.hex()
                    else:
                        label = str(getattr(node, "long_id", node_id))
                    contacts.append((f"kad:{label}", addr))
            contacts.sort(key=lambda item: (item[1][0], item[1][1], item[0]))
            return tuple(contacts[: max(0, int(limit))])

        try:
            fut = asyncio.run_coroutine_threadsafe(_do_contacts(), self._loop)
            return fut.result(timeout=timeout)
        except Exception:
            return tuple()

    @property
    def is_running(self) -> bool:
        return bool(self.server is not None and self._thread and self._thread.is_alive())

    @property
    def is_mesh_ready(self) -> bool:
        """True once listen has completed and any initial bootstrap supplied to
        start() has finished (routing table has had a chance to learn neighbors).
        publish() will only perform replicating Kademlia sets after this is true.
        """
        return self._mesh_ready.is_set()
