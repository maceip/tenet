# P-OR Layer 7 Architecture

This note captures the recovered product vision for P-OR and separates it from
the lower-level Sphinx/Outfox packet work already present in this repository.

## Core Product Shape

P-OR is not a general-purpose Tor replacement. It is a prompt-routing network.
The network should route HTTP-style LLM prompt requests to peers that can serve
as API-credit exits, memory holders, tools/agents, or domain specialists while
hiding the requester's network identity from the servicing peer.

The base mode assumes the prompt and response are visible to the servicing peer.
Prompt confidentiality from the exit peer, and proof that the peer actually
called an upstream LLM provider, are protocol extensions.

## Layer Split

### Data Plane

The data plane should stay dumb and fast:

- Outfox/Sphinx-style packet processing.
- Per-hop routing metadata.
- Optional relay-visible circuit setup for fast symmetric return streams.
- Fixed-size packet framing, timestamps, flags, and replay checks.

Relays should not parse prompts, agent capabilities, model names, memory claims,
or payment/proof semantics.

### Layer 7 Control Plane

The product control plane decides where a prompt should go before the onion
packet is built. The repository has an MVP slice of this layer now; the full
gateway/session/extension layer is still incomplete.

It is responsible for:

- Capability discovery: which peers can call which LLM providers and models.
- Expertise discovery: which peers claim domain or agent competence.
- Memory discovery: which peers hold a relevant memory cache or session state.
- Claim validation: lightweight challenge/response, signed descriptors, or
  future proof-of-retrievability checks.
- Route planning: choose a servicing peer plus relay path policy.
- Session continuity: issue opaque tokens for repeated access to the same
  memory or agent without exposing user identity.
- Extension negotiation: decide whether this request requires prompt hiding,
  transcript proof, settlement proof, or plain visible-prompt mode.

This layer can start centralized or in-memory for a prototype, but it should be
defined behind interfaces that can later back onto a DHT or other decentralized
directory.

## Important Correction From Earlier Design Notes

Intermediate relays should not inspect prompts for intent-based routing. That
would couple application semantics into the packet router and expand metadata
exposure.

The safer shape is:

1. The client asks a Layer 7 directory or matcher for candidate peers.
2. The matcher returns signed or otherwise authenticated peer descriptors.
3. The client chooses a peer and builds an onion path to that peer.
4. The relays process only routing/circuit metadata.
5. The selected servicing peer sees the Layer 7 request envelope.

## Application Envelope

The payload delivered to the servicing peer should use an explicit versioned
application envelope. A practical first schema:

```text
por.app.v1
  request_id
  session_token?             opaque continuity token
  mode                       visible_prompt | confidential_prompt
  provider_request           target provider/model/api shape
  intent_descriptor          topic, task type, tool needs, latency budget
  memory_selector?           cache/session/topic selector
  prompt_payload             plaintext in base mode; encrypted in extension mode
  return_descriptor          SURB or circuit setup reference
  proof_requirements?        none | tls_transcript | future variants
  payment_terms?             optional settlement policy
  client_extensions          supported extension identifiers
```

This envelope is Layer 7 payload. It does not need to change the outer
Outfox/Sphinx packet format.

## What Does Require Lower-Layer Changes

The fast hybrid return path is not just Layer 7. If relays are expected to store
short-lived circuit entries and process token packets without a KEM on every
packet, each relay must receive relay-visible setup material during the request
phase.

That implies a relay control message or expanded per-hop encrypted routing
metadata containing:

- hop-local inbound/outbound link identifiers
- symmetric return key or derivation seed
- return next-hop/routing direction
- expiry/TTL
- packet counter or nonce policy

This is separate from the application envelope. It belongs to the P-OR routing
protocol because relays must understand it.

This is a required P-OR milestone, not an optional optimization. The repository
now contains simulator support and local UDP/QUIC wire harnesses for this idea,
but the process demos still use the older single visible circuit ID shape rather
than the final per-hop link-CID wire. Treat them as harnesses until that is
migrated.

Minimum completion criteria:

- Request setup installs return-circuit state at each relay on the selected
  reply path.
- Return token packets use a compact circuit packet format rather than a full
  Outfox/SURB packet per chunk.
- Relays process return packets through the circuit table and symmetric cipher.
- Hop-local link IDs, TTL, counters/nonces, teardown, and missing-state behavior
  are specified and tested.
- The HTTP/SSE gateway streams response chunks through this return circuit
  instead of buffering the full provider response.
- Tests prove both the happy path and state-loss/self-healing behavior.

## Extensions

### Prompt Hiding

Prompt hiding from the servicing peer is an endpoint extension, not a relay
feature. Candidate mechanisms include mpTLS/MPC authorization, split request
construction, or a future confidential-fetch protocol. Relays should only carry
opaque bytes.

### Proof Of Execution

Proof that a servicing peer called an upstream LLM provider is also an endpoint
extension. Candidate mechanisms include TLS transcript proofs or zkTLS-style
receipts. The proof should be returned in the Layer 7 response envelope.

### Expertise And Memory Claims

Expertise and memory should be expressed in signed descriptors and validated by
the matcher/client before routing. They should not be embedded in every relay
packet header.

Initial descriptors can be simple:

```text
peer_descriptor
  peer_id
  provider_capabilities
  model_capabilities
  expertise_tags
  memory_roots
  latency_region
  public_keys
  expiry
  signature
```

Later versions can add challenge/response proofs for memory ownership or cache
coverage.

## Memory-Fit MVP

The first implemented primitive is deterministic memory fit, not expertise.
Peers can run a read-only sidecar indexer over whatever local memory system they
already use. They do not need to change their agent, RAG database, transcript
folder, or provider workflow.

The sidecar emits a `MemoryManifest` with:

- corpus size statistics
- file type counts
- top public terms, unless disabled
- a Merkle commitment root over local chunks
- a manifest digest
- privacy metadata stating that raw text and source paths are not published

The raw chunks stay local. The matcher can score public manifests against a
query, and a peer can locally retrieve top matching chunks without publishing
snippets. Inclusion proofs can show that a chunk commitment was part of the
indexed corpus, but this does not prove expertise, usefulness, or quality.

This MVP is intentionally spam-vulnerable: a peer can inflate apparent coverage
by indexing junk. That is acceptable for the first milestone because the system
is only measuring corpus fit plus operational facts such as latency, uptime, and
completion rate. Quality and anti-spam signals need later marketplace/reputation
work.

## Routing Selection Implications

Memory-fit routing changes the network stack. P-OR cannot be a purely random
Tor-style circuit selector once the product goal is "find a peer whose local
memory/index fits this prompt." The client needs a servicing-peer candidate
before it builds the onion path.

The dangerous naive design is:

```text
client asks directory for exact rare tag or exact peer
directory returns one peer
client builds circuit directly to that peer
```

That turns the directory into a targeting oracle and can make rare memories,
rare topics, or rare peers easy to probe.

Required shape:

- The client should rank candidates locally from a directory snapshot whenever
  possible, instead of sending precise interest queries to a live directory.
- Matching should produce a candidate pool, not a single mandatory peer.
- Normal routing should choose from the pool with randomness/weighting.
- Rare tags or undersized pools should degrade to broader buckets or fail
  closed unless the user has an explicit continuity token.
- Direct peer targeting should be a separate capability-gated mode, not the
  default marketplace path.
- Relay path selection remains independent from servicing-peer selection.
- Relays still see only routing/circuit metadata, not the memory-fit reason.

For the MVP this means the networking stack needs an explicit route-planning
stage:

```text
prompt -> local manifest ranking -> candidate pool -> chosen service peer
       -> relay path selection -> packet/circuit construction
```

Later privacy improvements can replace directory snapshots with private
information retrieval, gossip snapshots, or other query-hiding directory
mechanisms. The first implementation can stay simple, but it must not pretend
that capability-based routing is the same as random relay selection.

## Expert Mode MVP

The product surface can be as small as a checkbox:

```text
Expert Mode: try to route this prompt through a peer with relevant memory.
Fallback: if no useful match is found, use the normal frontier provider path.
```

The detached application-layer planner should expose one basic operation:

```text
plan_expert_route(prompt, requested_expertise?, manifests, observations)
```

It returns:

- whether to use an expert peer
- the selected servicing peer ID
- the candidate pool
- whether destination anonymity is degraded because the pool is small
- the fallback provider
- scoring reasons

The planner is intentionally not a router. It does not select relay hops, build
packets, contact peers, or call LLM providers. It produces a route decision that
the routing layer can later consume.

The repository also includes local UDP and QUIC wire harnesses. They run
separate node processes over localhost sockets, select an Expert Mode peer from
memory manifests, route a prompt envelope to that peer, and stream a harness
response over a symmetric return circuit. They are socket/process harnesses, not
production daemons and not real provider integrations.

Threat-model target for a real multi-hop P-OR route with correct crypto and
non-local deployment:

- protects user network identity from the expert
- protects expert network identity from the user
- reduces relay-side linkage
- does not claim global passive adversary resistance
- does not hide self-identifying prompt contents in visible-prompt mode
- allows small expert pools with explicit degraded destination anonymity
  semantics

The localhost demos are plumbing evidence. They do not, by themselves, prove
the deployed privacy claims above.

## Current Repository Status

The repository contains:

- `sphinxmix`: packet crypto, Outfox forward processing, SURB replies, circuit
  packet helpers, and the in-process `MixnetSim`.
- `por/envelope.py`: versioned prompt request envelope.
- `por/directory.py`: public snapshot discovery interface and JSON snapshot
  loader/saver.
- `por/expert_route.py` and `por/expert_mode.py`: memory-fit planning and
  request preparation.
- `por/memory_index.py`: deterministic memory manifest sidecar.
- `por/config.py`: shared daemon/config schema.
- `por/log_events.py`: structured log event helper.
- `por/udp_demo.py` and `por/quic_demo.py`: local process/socket wire harnesses.

Still missing or incomplete:

- Production daemon wiring with persistent peer connections.
- Migration of process demos to the final per-hop link-CID return wire.
- Real provider/LLM integration in the UDP/QUIC harnesses.
- Prompt hiding and proof-of-execution extensions.
- A gateway that maps HTTP/SSE provider traffic into envelopes and back.

The existing `sphinxmix` package should remain the lower-level packet/routing
library; the `por` package is the application/control-plane layer above it.
