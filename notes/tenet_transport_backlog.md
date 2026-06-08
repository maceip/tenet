# tenet Transport Backlog

Status: local QUIC/H3 harness exists; production QUIC daemon and peer
address/NAT work remain backlog.
Priority: the QUIC harness is MVP evidence, but production peer transport is
not complete.

This note captures the Freehold-inspired peer address work so it is not lost,
and records the local QUIC transport slice now used by the tenet harness.

## Freehold Review Snapshot

Reviewed locally from `maceip/freehold`, including the most recent 50 commits
as of 2026-05-30. Relevant commits include:

- `7727fb9` learn NAT-mapped port from reverse path for symmetric NAT support
- `0e6d89f` open NAT mapping for relay data port
- `57d0ddb` rewrite NAT docs for full SNAT+DNAT relay architecture
- `953c1d1` add forward-path SNAT so reverse XDP relay works
- `666e305` NAT port spray plus bidirectional XDP relay fallback
- `21c343f` tune heartbeat, registration TTL, and DNS TTL
- `cb57683` add WebTransport support to h3-proxy
- `6c37e05` add DemuxSocket for shared Engine/Quinn UDP socket
- `29d50f5` add relay-assisted NAT hole punching
- `990d7fb` add WebSocket over HTTP/3

The important conclusion is not "hole punching works." Freehold's reliable
path is inline relay forwarding. A direct UDP address is an optimization when a
NAT happens to permit it.

## What To Borrow

Useful Freehold primitives for tenet:

- UDP registration plus challenge/confirm before advertising a peer address.
- Short TTL registration state with heartbeats as NAT keepalives.
- Observed address/port learning from the reverse path.
- Shared UDP socket demux so control messages and QUIC traffic can use one
  bound port.
- QUIC/H3/WebTransport support for browser and mobile clients.
- Relay-assisted direct path attempts as an optional optimization.
- Always-available inline relay fallback.
- Dual-path advertisements: a guaranteed relay path plus optional direct path.
- NAT diagnostics as local hints, not as correctness assumptions.

Freehold's current timing constants are useful starting numbers, not protocol
requirements:

```text
heartbeat_interval   90 seconds
registration_ttl     270 seconds
dns_ttl              810 seconds
```

## NAT Traversal Strategy (decided)

Follow libtorrent/qBittorrent. Same sequence, same logic, no novel research:

1. **UPnP/NAT-PMP** — try to get a port mapping from the router (~2 seconds)
2. If that works, advertise the public endpoint in `PeerAddressRecord`
3. If not, register with a supernode relay (inline opaque forward)
4. If relay is unavailable, fail closed (no spray-and-pray, no hole punch as correctness path)

UPnP lease renewal aligns with the heartbeat interval (90s). If renewal
fails (router rebooted, network changed), the peer address record drops
the direct endpoint and falls back to relay-only. Clients seamlessly
switch via `build_dial_plan()` fallbacks.

This is not novel. libtorrent has 15 years of battle-tested NAT traversal
doing exactly this. Every fancy scheme (ICE, STUN/TURN, WebRTC) converges
to the same pattern — try the obvious thing, fall back to relay.

Hole punching (BEP 55 equivalent) is explicitly deferred. Most residential
users are behind symmetric NAT or CGNAT where hole punching is impossible.
REACH/relay is a first-class reachability capability for bootstrap, NAT, and
policy fallback; it should not become the only steady-state routing concept.

## What Not To Borrow As A Requirement

Do not make these tenet requirements:

- A central relay server operated by one party.
- BGP, anycast, XDP, eBPF, root privileges, or kernel packet rewriting.
- Public DNS, ACME, or browser-trusted public hostnames.
- Non-inline hole punching as the reliable path.
- Stable raw home endpoints for experts or users by default.

tenet may later have high-performance relay operators, but the protocol should
also work with ordinary peer relays in user space.

## tenet Adaptation

Add a handle-address layer underneath matcher discovery and above raw transport.
It should describe which address to dial for an opaque handle without changing
Outfox packet bytes. Durable peer/client IDs may sign or publish records, but
they are not route targets.

Candidate peer address record:

```text
PeerAddressRecord {
  handle                   opaque route target, not a public expertise id
  publisher_id             durable signing/publishing identity, not routeable
  relay_candidates          relay addresses to dial first
  observed_udp_endpoints    optional direct UDP addresses, policy-controlled
  nat_hints                 optional diagnostics only
  supported_transports      quic_datagram | webtransport | h3_websocket
  ttl
  address_policy            expose_direct_endpoint? stable_relay_only?
  signature
}
```

Candidate contact flow:

```text
1. Peer registers with one or more address relays.
2. Each assist relay keeps a short-TTL endpoint mapping.
3. Matcher/handle resolver returns a signed handle-address record.
4. Dialer builds a dial plan from relay addresses and optional direct hints.
5. Dialer may try direct QUIC only when policy allows it.
6. Dialer falls back to inline relay immediately.
7. tenet packets ride inside the chosen QUIC/WebTransport path unchanged.
```

The peer address layer is about getting UDP/QUIC packets between peers. It
should not parse prompts, memory claims, expertise labels, provider metadata,
or return-circuit contents.

## Wire Impact

No immediate relay-wire change is needed.

Current tenet packet types stay as-is:

```text
0x00 forward Outfox packet
0x01 return circuit packet
0x02 reserved teardown/control
```

Peer address records and registration messages are control-plane transport
metadata. They may later become a separate packet family or QUIC control stream,
but they should not be mixed into Outfox headers or circuit packets.

Possible future transport control messages:

```text
REACH_REGISTER
REACH_CHALLENGE
REACH_CONFIRM
REACH_HEARTBEAT
REACH_NEIGHBORS
REACH_PUNCH_HINT
REACH_CONTACT_PLAN
```

These messages should be authenticated and TTL-bound. They are not anonymity
proofs and must not be marketed as such.

## Privacy Constraints

Peer address publishing must not become an expert-targeting oracle.

Default posture:

- Advertise relay handles first.
- Expose direct endpoints only by explicit peer policy.
- Prefer short-lived peer address records.
- Avoid globally stable endpoint records for rare expertise pools.
- Keep "direct path available" separate from "selected expert identity."

If only a tiny expert pool exists, directory and route planning should surface a
degraded-anonymity warning. Peer address routing cannot fix a small anonymity
set.

## Implemented Skeleton

`tenet.mixnet.peer_address` now implements the detached control-plane skeleton:

- `PeerAddressRelay` for register/challenge/confirm and heartbeat refresh.
- `PeerAddressRecord` for short-lived relay/direct peer address metadata.
- `build_dial_plan()` for relay-first dialing with optional direct hints.
- Privacy policy gates so direct UDP endpoints are not exposed by default.
- `tenet.config` supports `client.trusted_reachability_relays`.
- `tenet.experts.directory` can serve signed `peer_address` records beside existing expert
  manifests and `supernodes[]`.
- `tenet.experts.client` verifies peer-address record signatures and rejects untrusted
  relay IDs before any peer-address route can influence a send. This does not
  change packet bytes or transport IO.

`tenet.mixnet.quic_transport` now implements the first local QUIC/H3 transport slice:

- QUIC DATAGRAM send/receive over localhost using `aioquic`.
- Bidirectional DATAGRAM behavior: either peer can send DATAGRAM frames on the
  same QUIC connection.
- In-memory QUIC session-ticket capture and reuse hooks.
- Minimal HTTP/3 Extended CONNECT path with `:protocol = websocket` for
  WebSocket-style byte streams.
- Localhost certificate generation for process demos.
- TLS verification is on by default; localhost demos explicitly disable it for
  generated certs with `dev_allow_insecure_tls=True`.
- Client receive queues are bounded by default.

The removed QUIC demo previously fed Expert Mode harness traffic through
QUIC/H3 between separate local node processes:

- Client builds the real Layer 7 prompt envelope.
- Forward frames traverse relay1 -> relay2 -> selected expert over QUIC.
- The selected expert emitted harness chunks back through the relay-additive
  return circuit over QUIC.
- Logs show each relay only sees hop/circuit state, while the selected expert
  sees the visible prompt.

The current carrier for harness tenet frames is HTTP/3 Extended CONNECT over
QUIC, not QUIC DATAGRAM. `DEFAULT_MAX_DATAGRAM_FRAME_SIZE` is intentionally
MTU-sized for DATAGRAM tests and control messages. Full Outfox/circuit frames
must use the H3 stream carrier unless a future packet profile adds explicit
DATAGRAM fragmentation.

## Deferred Work Items

**Sequencing:** items 1–5 below are **Milestone D (transport/NAT)**. Relay-path
planning is wired; direct dialing and daemon UDP-loop changes remain deferred
until a transport owner takes them.

1. Add persistent peer connections to the production daemon.
2. Add a local UDP registration/heartbeat test between peer processes.
3. Add a user-space inline relay fallback path.
4. Add optional direct QUIC attempt with fast fallback to inline relay.
5. Revisit Freehold's DemuxSocket pattern when the daemon uses one UDP socket
   for peer-address control plus QUIC packet traffic.

This should stay below the current MVP items: migrating process harnesses to
per-hop link CIDs, turning the local harnesses into a daemon shape, Layer 7
expert routing, frontier fallback, and traceable degraded-anonymity reporting.
