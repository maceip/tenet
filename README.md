# tenet

tenet is an expert network: ask a question once, route it to the person or
agent whose knowledge best matches it, and return an answer over sealed
transport. The product direction is a human-scale mixture of experts where
useful expertise can be discovered, reached, and eventually compensated; this
repository currently implements the routing, attestation, reachability, and CLI
runtime foundations for that network. Payments and payouts are not implemented
in the current runtime.

> **Current live status, queue, pins, and operations:** [`STATUS.md`](STATUS.md)
> is the source of truth. Archived design docs live under
> `~/fat/tenet-archive/docs/`.

## Protocol Invariants

- All nodes are clients.
- Clients advertise substrate capabilities, not routeable expertise.
- DHT discovers substrate and signed opaque/control records.
- Matcher discovers expertise behind a privacy boundary.
- Handles connect matching to routing.
- Only handles route traffic.
- Routing chooses among reachable capabilities.
- REACH/relay is one capability, not the center.

## Why It Exists

Most AI products ask one model every question. tenet treats expertise as a
network instead: each participant can publish a statistical manifest of what
they know, receive matching questions privately, and answer with their own local
context plus a frontier model.

For askers, this means better specialist answers without manually finding the
right expert. For experts, it means their knowledge can become reachable by the
network without publishing their files or opening a public port. For operators,
it gives a concrete path from today's live expert-routing network toward a
market where useful answers can be rewarded.

## Product Shape

- **Ask once.** `tenet ask` submits a prompt to the live network.
- **Match privately.** The attested matcher selects candidate experts from
  manifests baked into the Nitro enclave workload. Signed cached matcher
  results may be gossiped and reused so the TEE is an authority, not a
  throughput bottleneck. Project/root signatures still bootstrap software,
  trust-policy, and update authority.
- **Route sealed traffic.** The question travels through the mixnet and
  reachability relay substrate; relays forward bytes without reading them. This
  is sealed transport today, not a standalone anonymity guarantee.
- **Answer from local knowledge.** The selected expert opens the request,
  combines local context with a model, and streams the answer back.
- **Compensation later.** Payout UI and ledger integration are deliberately
  excluded until there is a real payment contract.

## Architecture

| Layer | Current Package | Role |
|-------|-----------------|------|
| Packet | `tenet.packet` | Sphinx/Outfox packet primitives |
| Base | `tenet.config`, `tenet.envelope`, `tenet.handles`, `tenet.log_events` | Shared types and compatibility schemas |
| Mixnet | `tenet.mixnet` | Relay runtime, wire frames, QUIC, REACH, peer address control |
| Enclave | `tenet.enclave` | Attested host, ARC, SPKI-pinned transport |
| Experts | `tenet.experts` | Matching, manifests, routing, live client/expert flows |
| Edges | `tenet.edges.cli` | CLI, daemon entrypoints, dashboard, local HTTP/SSE edge |

Some on-disk schemas still use `por.*.v1` names for compatibility with deployed
configs, live pins, and persisted manifests. Treat those as wire/schema
identifiers, not the product or package name.

## Quick Start

```bash
pip install -r requirements.txt
make smoke
python3 -m tenet --help
```

### Ask The Live Network

There is no separate public directory URL for beta joiners. The current live
network uses an attested matcher at `POST /v1/match`; public pins live in
[`config/join-pack.json`](config/join-pack.json) and
[`config/live-enclave.json`](config/live-enclave.json).

```bash
./scripts/render-join-pack.sh
python3 -m tenet ask --prompt "In one sentence, name one Monet painting technique."
```

For the current operator dashboard:

```bash
python3 -m tenet status --plain
python3 -m tenet status --render-options
```

Ops-only attestation tools:

```bash
python3 -m tenet enclave check
python3 -m tenet enclave match --prompt "Tell me about Monet"
python3 -m tenet enclave send --prompt "What is impressionism in painting?"
```

## Run An Expert

```bash
./scripts/expert-onboard.sh /path/to/your/corpus
# then start the printed tenet run command; export peer_address; rebuild TEE data
```

Experts publish a manifest, register reachability through the relay when behind
NAT, and answer matching questions through the same `tenet` binary. Public
control/DHT state carries substrate capabilities and signed opaque records; it
must not advertise routeable expertise directly.

## Project Layout

```
tenet/
  packet/          Packet format and cryptographic routing primitives
  mixnet/          Relay/runtime transports and REACH control plane
  enclave/         Attested enclave host and transport trust
  experts/         Matching, manifests, expert routing, live network clients
  edges/cli/       User CLI, daemon entrypoints, status dashboard
config/            Live pins, join packs, templates, client configs
deploy/            Nitro, relay, and network deployment helpers
scripts/           Build, smoke, packaging, and live-ops helpers
tests/             Unit, integration, layering, and live-gated tests
notes/             Design notes that still matter during the transition
oblivious-core/    Rust oblivious top-k extension
```

## Build A Release Binary

```bash
python3 scripts/build_binary.py
# dist/tenet-<platform>
```

If an `aw` binary is available, the build embeds it for one-file attestation
checks; otherwise the built binary requires `aw` on `PATH`.

## Testing

See [`STATUS.md`](STATUS.md) for which commands count as live-network proof.

```bash
make smoke
./scripts/verify-live.sh
pytest -q
```

`pytest` proves local behavior; it is not a substitute for `tenet enclave
check|match|send` or `tenet ask` against the pinned live network.
