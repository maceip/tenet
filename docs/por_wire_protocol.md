# P-OR Full Wire Map

Status: target relay wire map plus current Python prototype notes. This is not
a claim that every harness emits final canonical bytes today.
Scope: bytes that cross peer, relay, exit, and client boundaries.

This document separates three things that are easy to blur:

- Relay wire: Outfox forward packets and symmetric circuit packets.
- Layer 7 payload: JSON request envelopes and discovery records carried by or
  used before relay packets.
- Demo transport glue: localhost JSON/base64 frames used by `por.udp_demo` and
  `por.quic_demo`.

## 0. Current Constants

Defined in `sphinxmix.OutfoxParams` unless noted.

```text
KEM ciphertext size        32 bytes   current KEM: X25519
KEM public key size        32 bytes
KEM secret key size        32 bytes
Header AEAD                ChaCha20-Poly1305
Header AEAD tag            16 bytes
Header AEAD nonce          12 zero bytes, safe only because header key is per-hop
Payload SE                 LIONESS over AES-128-CTR
Circuit stream cipher      AES-128-CTR
Circuit key size           16 bytes
Payload key size K         16 bytes
Timestamp                  8 bytes, unsigned BE milliseconds
Flag                       1 byte bitfield
Default routing_size R     16 bytes
Default payload_size P     1024 bytes
Default max_hops           5
Default circuit TTL        120 seconds
Circuit packet magic       "POR2" = 0x504f5232
Forward packet type        0x00, canonical prefix, legacy optional
Circuit packet type        0x01
```

The UDP demo uses `payload_size=2048` and `routing_size=80` so it can carry a
larger demo route instruction. That is not the core default.

## 1. Target Relay Flow

This is the intended relay flow for the production daemon and final process
harnesses:

```text
1. Client obtains discovery snapshot or private discovery result.
2. Client ranks candidates locally and chooses selected expert/exit peer.
3. Client builds a Layer 7 PromptRequestEnvelope as JSON bytes.
4. Client builds an Outfox forward packet to relay...relay...expert.
5. Circuit setup fields in each hop install return circuit state.
6. Relays forward by decrypting only their hop header and one payload layer.
7. Expert receives the Layer 7 envelope and streams response chunks.
8. Streaming chunks return as fixed-size circuit packets.
9. Client decrypts circuit packets and reconstructs the response stream.
```

Prompt hiding, provider-call proof, settlement, and private discovery are not
relay-wire fields. They are endpoint or directory extensions.

Late-stage UDP/QUIC peer address work is tracked separately in
`docs/por_transport_backlog.md`. It should not change these packet bytes until
the core relay wire and hybrid return path are stable.

Current implementation boundary:

| Surface | Boundary | Provider/response | Return CID shape |
| --- | --- | --- | --- |
| `sphinxmix` / `MixnetSim` | in-process packet/sim code | simulated or caller-provided | per-hop link CIDs in packet/sim paths |
| `por.udp_demo` | localhost UDP JSON/base64 harness | harness response | older single visible circuit ID |
| `por.quic_demo` | localhost QUIC/H3 JSON/base64 harness | harness response | older single visible circuit ID |
| production daemon/gateway | not implemented | not implemented | target wire in this document |

## 2. Transport Frame

### 2.1 Canonical Relay Datagram

Target QUIC/UDP should carry one raw P-OR packet per datagram or QUIC message:

```text
offset  size              field
0       1                 packet_type
1       variable          packet_body
```

`packet_type`:

```text
0x00    forward Outfox packet
0x01    return circuit packet
0x02    reserved teardown/control
```

### 2.2 Forward Compatibility

Current `packet_create()` returns `(header, payload)` without the `0x00` prefix.
`MixNode.process_packet()` accepts both:

```text
legacy forward body       header || payload
canonical forward frame   0x00 || header || payload
```

For either form, `payload_size` is profile-known, so:

```text
header_len = total_forward_body_len - payload_size
header     = body[0:header_len]
payload    = body[header_len:]
```

### 2.3 Demo-Only UDP Frames

`por.udp_demo` uses JSON/base64 over localhost UDP and `por.quic_demo` carries
the same frame shape over HTTP/3 Extended CONNECT on QUIC:

```json
{"kind":"forward","header":"...base64...","payload":"...base64..."}
{"kind":"circuit","seq":1,"packet":"...base64..."}
{"kind":"shutdown"}
```

That is harness glue only. It is not the relay wire.

QUIC DATAGRAM is implemented in `por.quic_transport`, but the default DATAGRAM
payload limit is MTU-sized and the current fixed-size demo frames exceed it.
The local QUIC harness therefore uses the H3 stream carrier for full
frames. These are separate connection profiles: DATAGRAM uses
`por-quic-datagram-v1`; H3 Extended CONNECT uses `h3`.

## 3. Forward Outfox Packet

A forward packet body is:

```text
header || payload
```

or canonically:

```text
0x00 || header || payload
```

The header is nested, one layer per hop. The payload is fixed-size and wrapped
by every hop using the payload key derived for that hop.

## 4. Forward Header Layer

For hop `i`, the visible layer is:

```text
offset  size              field
0       32                kem_ciphertext_i
32      variable          aead_ciphertext_i
end-16  16                aead_tag_i
```

The AEAD key is derived from the per-hop KEM shared secret:

```text
shared_key = KEM.decapsulate(kem_ciphertext_i, hop_secret_key)
material   = HKDF-SHA256(shared_key, len=32+K, info=kem_ciphertext_i || hop_public_key)
s_h        = material[0:32]       header AEAD key
s_p        = material[32:32+K]    payload SE key
```

The AEAD plaintext is:

```text
offset              size             field
0                   R                routing_info
R                   8                timestamp_ms_be
R+8                 1                flags
R+9                 optional         circuit_setup fields, if flags & 0x02
after setup         variable         next_inner_header, empty for final hop
```

Header AEAD uses ChaCha20-Poly1305 with an all-zero nonce. That is acceptable
only because `s_h` is fresh per hop/layer.

## 5. Forward Flags

```text
bit 0 / 0x01        dummy packet
bit 1 / 0x02        circuit setup fields present

0x00                real packet, no circuit setup
0x01                dummy packet, no circuit setup
0x02                real packet, circuit setup
0x03                dummy packet, circuit setup
```

Relays must preserve and report the flag to the local node logic, but relays
must not parse Layer 7 prompt contents.

## 6. Circuit Setup Fields In Forward Header

Present immediately after `flags` when `flags & 0x02`.

```text
offset  size              field
0       16                inbound_link_cid
16      16                key_seed
32      R                 return_next_hop
32+R    16                outbound_link_cid
48+R    2                 ttl_seconds_be
```

`inbound_link_cid` is the cleartext lookup key this hop expects in bytes 1-16
of circuit packets it receives on the return path.

`outbound_link_cid` is the value this hop writes into bytes 1-16 before
forwarding the circuit packet toward the client.

For adjacent return hops `U -> V`, `U.outbound_link_cid` must equal
`V.inbound_link_cid`. Non-adjacent hops must not share link CIDs.

Relay key derivation:

```text
circuit_key = HKDF-SHA256(
  ikm  = key_seed,
  salt = inbound_link_cid,
  info = "circuit_v2",
  len  = 16
)
```

The relay stores:

```text
inbound_link_cid -> {
  key: circuit_key,
  next_hop: return_next_hop,
  outbound_link_cid: outbound_link_cid,
  high_watermark: 0,
  last_active: now,
  ttl: ttl_seconds
}
```

Current table limits in `CircuitTable`:

```text
max_entries       1024
eviction          LRU oldest last_active
default TTL       120 seconds
nonce policy      accept only nonce > high_watermark
```

## 7. Header Size Formula

Let:

```text
R     routing_size
CT    KEM ciphertext size = 32
TAG   AEAD tag size = 16
META  timestamp + flag = 9
CIRC  0 without circuit setup, or 16 + 16 + R + 16 + 2 with circuit setup
```

Innermost header:

```text
CT + R + META + CIRC + TAG
```

Each outer header:

```text
CT + R + META + CIRC + inner_header_len + TAG
```

The implementation exposes this as:

```python
OutfoxParams.header_sizes(num_hops, circuit_setup=False | True)
```

## 8. Forward Payload

Before per-hop SE wrapping, the payload plaintext is:

```text
offset                  size                field
0                       K                   zero_prefix, all 0x00
K                       2                   surb_len_be
K+2                     params.surb_size    surb_field, zero padded
K+2+params.surb_size    variable            Layer 7 message bytes
...                     1                   pad delimiter 0x7f
...                     rest                pad bytes 0xff
```

`zero_prefix` is the exit-side payload tagging check. If it is not all zero
after all payload layers are removed, the exit rejects the packet.

The message bytes are usually `PromptRequestEnvelope.to_json().encode("utf-8")`.

Payload encryption order on the forward path:

```text
payload = pad_to_payload_size(inner_payload)
for hop from exit back to guard:
    payload = LIONESS_SE_Enc(s_p_hop, payload)
```

Relay processing:

```text
1. Peel one header layer with KEM + AEAD.
2. Validate timestamp freshness.
3. Install circuit state if flags & 0x02.
4. payload = LIONESS_SE_Dec(s_p_hop, payload)
5. Forward next_inner_header || payload to next hop.
```

## 9. SURB Single-Shot Reply Format

SURBs are still supported for short replies, errors, and setup confirmations.

`surb_create()` returns:

```text
surb      = (surb_header, surb_key)
idsurb    = innermost header bytes
sksurb    = per-hop payload keys for client recovery
```

Embedded SURB bytes in a forward payload:

```text
surb_len_be      2 bytes
surb_bytes       surb_header || surb_key
padding          zeroes until params.surb_size is filled
```

Receiver creates a SURB reply with:

```text
header = surb_header
inner  = zero_prefix(K) || 0x0000 || zeroed_surb_field || reply_message || padding
payload = LIONESS_SE_Enc(surb_key, pad(inner))
```

Reply relays process it as normal forward packets. Client identifies the reply
by checking whether the final header suffix matches `idsurb`, then recovers via
`surb_recover()`.

SURB is not the streaming path. Streaming uses circuit packets.

## 10. Circuit Return Packet

Circuit packets are fixed-size and begin with packet type `0x01`.

```text
offset  size              field
0       1                 type = 0x01
1       16                link_cid
17      8                 nonce_be
25      P-25              encrypted_region
```

The encrypted region plaintext is:

```text
offset  size              field
0       2                 inner_len_be
2       4                 magic "POR2"
6       inner_len         token_data
6+N     rest              random padding
```

Maximum token data per circuit packet:

```text
payload_size - 1 - 16 - 8 - 2 - 4
= payload_size - 31
```

For default `payload_size=1024`, max token data is 993 bytes.

The AES-CTR IV for every circuit layer is:

```text
iv = nonce_be || 8 zero bytes
```

`link_cid` is hop-local. On link `U -> V`, sender `U` writes
`V.inbound_link_cid`. Receiver `V` looks up `CircuitTable[link_cid]`.

`nonce` is transmitted in cleartext. It must be unique and strictly increasing
per circuit key. Gaps are allowed. Repeats and regressions are dropped.

## 11. Circuit Return Encryption

P-OR uses relay-additive return for streaming. The exit only knows its local
exit circuit key and the first relay's inbound link CID. It must not receive
relay-layer keys in the Layer 7 envelope.

The exit creates:

```text
packet = 0x01 || first_relay_inbound_link_cid || nonce ||
         AES-CTR(exit_key, nonce, framed_token)
```

Each relay looks up `link_cid`, applies AES-CTR with its local circuit key, and
rewrites bytes 1-16 to `outbound_link_cid` while forwarding toward the client.
Because AES-CTR is XOR-based and self-inverse, this adds that relay's layer to
the encrypted region.

For return path:

```text
Exit -> Relay B -> Relay A -> Client
```

packet evolution is:

```text
Exit:    [0x01 | B.inbound      | nonce | C0 = AES-CTR(exit_key, nonce, inner)]
Relay B: [0x01 | A.inbound      | nonce | C1 = AES-CTR(key_B,    nonce, C0)]
Relay A: [0x01 | client.inbound | nonce | C2 = AES-CTR(key_A,    nonce, C1)]
Client:  inner = AES-CTR(exit_key, nonce,
                  AES-CTR(key_B, nonce,
                    AES-CTR(key_A, nonce, C2)))
```

The client decrypts layers in the opposite order they were added:

```text
[client_side_relay_key, ..., exit_side_relay_key, exit_key]
```

For `Exit -> Relay B -> Relay A -> Client`, the client peel order is:

```text
[key_A, key_B, exit_key]
```

This keeps return keys local to each hop and matches the forward setup rule:
each hop installs only its own
`inbound_link_cid -> circuit_key -> next_hop -> outbound_link_cid` state.

Compatibility note: `circuit_packet_create()` can technically accept multiple
keys. Target daemon code should call it with `[exit_key]` and let relays add
their own layers in transit.

## 12. Circuit Keepalive

Keepalive is a circuit packet whose decrypted `inner_len` is zero:

```text
inner_len = 0
magic     = "POR2"
token     = empty
padding   = random
```

It increments the same nonce counter and is indistinguishable from an empty
token packet before decryption.

## 13. Circuit Error Handling

Relay behavior:

```text
unknown link_cid          drop
expired link_cid          drop
nonce <= high_watermark   drop
malformed packet          drop
```

Client behavior:

```text
unknown client link_cid   ignore
nonce <= watermark        ignore
magic mismatch            corruption_count += 1
success                   corruption_count = 0
3 consecutive corruptions delete logical circuit and require re-establish
```

State loss at a relay currently drops the circuit packet. Self-healing random
replacement exists as `circuit_self_heal()`, but it is not a complete wire
control flow for lost circuit table state.

## 14. Layer 7 Prompt Request Envelope

The Layer 7 request is UTF-8 compact JSON carried as the forward payload message
bytes. Relays do not parse it.

Current schema from `por.envelope.PromptRequestEnvelope`:

```json
{
  "version": "por.app.v1",
  "request_id": "hex-or-uuidlike string",
  "selected_peer_id": "expert peer id or null",
  "mode": "visible_prompt_v1",
  "provider_request": {
    "provider": "expert_peer",
    "selected_peer_id": "peer id",
    "fallback_provider": "frontier",
    "stream": true
  },
  "intent_descriptor": {
    "requested_expertise": "string or null",
    "prompt_sha256": "sha256 hex",
    "discovery_mode": "public_snapshot_v1",
    "candidate_pool_size": 3,
    "degraded_anonymity": false,
    "pool_tier": "strong"
  },
  "prompt_payload": {
    "content_type": "text/plain",
    "encoding": "utf-8",
    "text": "plaintext prompt in base mode"
  },
  "return_descriptor": {
    "mode": "hybrid_return_path_v2",
    "stream": true,
    "ta_claim": "encrypted_relay_chain",
    "ta_claim_detail": "circuit_return_path",
    "ta_not": ["not_gpa_resistant", "not_mixnet_streaming", "not_path_wide_cover"],
    "return_profile": "relay_additive_v1"
  },
  "proof_requirements": ["none"],
  "client_extensions": ["public_snapshot_v1", "hybrid_return_path_v2"],
  "privacy_warnings": []
}
```

`mode="confidential_prompt_v1"` is reserved. In that mode `prompt_payload.text`
should not be present, but the exact encrypted payload shape is not implemented
yet.

## 15. Directory And Expert Discovery Wire

The MVP directory is an in-memory public snapshot, not a relay packet.
If serialized for an API, the safe shape is:

```json
{
  "mode": "public_snapshot_v1",
  "generated_at": "ISO-8601 timestamp",
  "records": [
    {
      "manifest": "MemoryManifest JSON",
      "observation": {
        "peer_id": "peer id",
        "p50_latency_ms": 80.0,
        "p95_latency_ms": 1500.0,
        "uptime": 1.0,
        "completion_rate": 0.99,
        "price_units": 0.0
      },
      "descriptor": {}
    }
  ]
}
```

Public discovery must not truncate before local scoring. In the current
orchestrator, `discovery_max_records` is ignored for `public_snapshot_v1` and a
warning is emitted.

Private discovery is represented by the same provider interface, but no PSI/PIR
wire is implemented yet.

## 16. MemoryManifest Discovery Payload

`MemoryManifest` is public metadata, not relay wire. It intentionally excludes
raw text and source paths.

Core fields:

```json
{
  "version": "por.memory_manifest.v1",
  "peer_id": "peer id",
  "created_at": "ISO-8601 timestamp",
  "roots": ["opaque root id"],
  "file_count": 10,
  "byte_count": 12345,
  "chunk_count": 42,
  "token_count": 9000,
  "file_types": {".md": 3, ".txt": 7},
  "top_terms": [["monet", 12], ["impressionism", 9]],
  "corpus_root": "merkle root hex",
  "index_digest": "manifest digest hex",
  "privacy": {
    "raw_text_published": false,
    "sources_in_manifest": false,
    "public_terms": true
  }
}
```

This proves deterministic corpus fit only. It is not proof of expertise or
answer quality.

## 17. Optional Signed Payload

`packet_create_signed()` wraps a message before putting it in the forward
payload:

```text
sig_len_be      2 bytes
signature       sig_len bytes, ML-DSA-65
sender_id       caller supplied bytes
receiver_id     caller supplied bytes
timestamp       8 bytes BE milliseconds
message         remaining bytes
```

The signature covers:

```text
sender_id || receiver_id || timestamp || message
```

This is optional application integrity, not relay routing integrity.

## 18. What Each Party Sees

Guard/middle relay:

```text
visible: previous transport address, next hop after decrypt, routing_info,
         timestamp, flags, hop-local link CIDs, return_next/ttl, packet size
hidden:  prompt, selected expertise, provider request, response text
```

Expert/exit peer:

```text
visible: its incoming relay, Layer 7 envelope, prompt in visible_prompt_v1,
         return descriptor, selected provider metadata
hidden:  client network address, full relay path unless exposed by extensions
```

Client:

```text
visible: discovery snapshot/result, selected peer id, relay path it chose,
         logical circuit state, client inbound link CID, and decryption keys
```

Directory/matcher:

```text
public snapshot mode: sees no exact query, just publishes records
future private mode: should return equivalent candidate records without
                     exposing exact interest
```

## 19. Current Review Flags

These are not blockers for documenting the wire, but reviewers should decide
them before a production daemon is treated as stable:

1. Forward packet type prefix is only partially migrated. Canonical is `0x00`,
   but `packet_create()` still returns legacy `(header, payload)`.
2. Per-hop link CIDs are the target wire. The packet/sim paths implement this,
   but the UDP/QUIC process harnesses still use a single visible `circuit_id`;
   `HYBRID_RETURN_PATH_SPEC.txt` tracks that remaining migration as Phase 2.6.
3. `routing_info` is opaque in the core. The UDP demo's `POR1` route-info
   layout is demo-only and should not become accidental production wire.
4. Raw QUIC DATAGRAM support exists, but current QUIC harness frames ride over
   HTTP/3 Extended CONNECT on QUIC. Persistent peer connections, daemon
   authentication, and cross-hop flow-control policy are still
   transport-daemon work.
5. Prompt hiding and provider-call proof are extension slots only. They do not
   change relay packet bytes unless a future extension explicitly negotiates a
   new envelope mode.
