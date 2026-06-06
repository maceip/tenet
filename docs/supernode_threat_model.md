# Supernode Reachability — Threat Model & Constraints

Status: **conditionally approved** (coordination/security review, 2026-05-30).
Reviewer: architecture coordination (Composer agent — same party that wrote the
gate). **D2–D4 may proceed.** **D5 (bundled defaults) remains blocked** until
D3 + D4 + security regression tests land.

## Review outcome (2026-05-30)

**Approved for continued implementation:**

- Reachability supernode as **bootstrap infrastructure** with **documented trust**
  (not anonymity-neutral).
- `PeerAddressRelay` challenge/confirm + TTL (already implemented).
- `SupernodeForwarder` as **registry only** today; D2 must add opaque byte relay.

**Conditions on D2 (daemon forward loop):**

1. Forward path must not import `envelope`, `provider`, `expert_route`, or call
   `outfox_process` / `PromptRequestEnvelope` — only move UDP datagram bytes and
   optional type-byte demux to `WireNodeRuntime` vs peer table.
2. Add **rate limits** on registration (per source IP + per peer_id) before any
   public deployment.
3. Log **metadata only** (peer_id, bytes, event) — never payload hex/dumps on
   reachability path.

**Conditions on D3/D4 (before D5):**

4. Client verifies `PeerAddressRecord.signature` before dial (landed in the
   client dial planner; current harness uses HMAC signatures).
5. Directory `PeerAddressRecord` per expert — not just `supernodes[]` ads
   (landed in directory snapshots).
6. `trusted_reachability_relays` in client config — no dial of unsigned or
   unlisted supernodes (landed; dev override exists for tests only).

**Demux decision (closed for MVP):**

Use **one UDP bind** on the supernode. Demux order:

1. `REACH_*` control datagrams → `PeerAddressRelay` (registration/heartbeat).
2. Otherwise → if destination is this node's mix identity, hand to `WireNodeRuntime`.
3. Otherwise → opaque forward to registered peer NAT mapping (D2).

Log `supernode_role=reachability|mix` at debug. Document in operator docs that
**mix + reachability on one public IP increases correlation** (constraint 2).

**Not approved yet:**

- Shipped default supernodes without named operator trust text (D5).
- Automated directory self-registration without operator approval.
- Direct UDP / hole punch as correctness path.

## What a supernode is

A supernode is a regular P-OR node (same binary) with a **public IP** that
also forwards UDP packets for registered peers who cannot accept inbound
connections (NAT'd experts).

The supernode is a **reachability relay only**. It forwards opaque encrypted
bytes. It does not decrypt, parse, or inspect Outfox packets, circuit packets,
prompts, envelopes, or provider metadata.

## What a supernode is NOT

- Not a mix node (no batching, delay, or cover traffic at the relay layer)
- Not confidentiality-neutral — bootstrap reachability relays are **trusted for
  metadata** (timing, IPs, session linking), not for reading payloads
- Not a NAT hole-punching server (no STUN/TURN/ICE)
- Not an eBPF/XDP accelerator (user-space UDP only)

## Threat model

### Adversary capabilities

| Adversary | Can see | Cannot see |
|---|---|---|
| Supernode operator | Source IP of both client and expert, packet timing, packet sizes | Packet contents (encrypted), prompt text, expert identity beyond peer_id |
| Network observer (same LAN as supernode) | All of the above | Same |
| Client | Supernode IP, expert's peer_id from directory | Expert's real IP (behind NAT, via supernode) |
| Expert | Supernode IP, nothing about client | Client IP (supernode is the visible source) |

### What the supernode CAN correlate

**This is the critical risk:**

1. **Client ↔ Expert timing**: The supernode sees a forward packet arrive from
   client IP A, and immediately forwards it to expert IP B. The temporal
   correlation is trivial. This is inherent to inline forwarding without mixing
   delays.

2. **Session linking**: All packets for the same registered peer go through the
   same supernode. The supernode can count packets, measure session duration,
   and link forward + return traffic for the same session.

3. **Reachability + mix on same IP**: If a supernode also serves as an Outfox
   relay hop on the mix path AND as the reachability forwarder, the supernode
   sees both the mix-layer traffic and the forwarded traffic. This makes
   correlation strictly easier than if they were separate roles on separate IPs.

### What the supernode CANNOT do

1. **Read prompts or responses** — all traffic is Outfox-encrypted or circuit-encrypted
2. **Modify traffic undetected** — AEAD on forward path, magic check on return
3. **Impersonate the expert** — needs expert's KEM secret key
4. **Learn which frontier model is called** — provider selection is inside the encrypted envelope

## Constraints (security team mandated)

1. **Reachability relay is opaque** — `SupernodeForwarder` must NEVER parse
   packet contents beyond the type byte (0x00/0x01) needed for forwarding.

2. **Separate reachability from mix role** — document that running reachability
   relay + mix relay on the same public IP creates a correlation surface. MVP
   may allow it with a warning; production should separate.

3. **Client dials trusted relay endpoints only** — the client config or
   directory must specify which supernodes to trust. No auto-discovery of
   random supernodes.

4. **Directory embeds signed PeerAddressRecord** — the record must be signed
   by the supernode's key. Client verifies before dialing.

5. **Registration requires challenge-response** — already implemented in
   `PeerAddressRelay`. Prevents spoofed registrations.

6. **Heartbeat TTL enforced** — expired peers become unreachable. Already
   implemented.

## Explicitly deferred

- **Automated directory registration** — supernodes registering themselves in
  the public directory without operator approval
- **Direct UDP** — client connecting directly to expert's NAT'd address via
  hole-punching. Relay-first is the correctness path.
- **Mixing reachability traffic** — adding batching/delay at the supernode
  forwarding layer (would add latency, not in scope for MVP)
- **Multiple supernodes per expert** — failover between supernodes

## Open decision (pick before D2 daemon)

**Demux:** ~~open~~ **Closed for MVP** — see Review outcome above (one UDP bind,
three-way demux: REACH control → mix runtime → opaque NAT forward).

## Implementation order (per security team)

0. Threat model doc — **conditionally approved** (2026-05-30)
1. Opaque inline forward — **lookup table landed**; daemon receive→forward loop is **D2 (unblocked)**
2. Client dial to trusted relay endpoints — **D3 partial** (target resolution
   landed; socket IO still waits for Transport D2/D3)
3. Directory embeds signed PeerAddressRecord — **D4 landed**
4. Bootstrap defaults — **D5 blocked** until 2–3 + item 5
5. Security regression tests — required before D5
