# tenet — the expert network

**tenet routes a question to the peer most likely to answer it well.**

Most LLM setups ask one model, working from training data, every question.
tenet does something different: it treats a network of participants — each with
their own indexed knowledge and domain focus — as a routing surface. When you
ask a question, tenet finds the peers whose local knowledge actually matches it,
sends the question to one of them, and streams the answer back.

The premise is plain: for a specialized question, the right specialist's
indexed library beats a general model guessing from memory. A structural
engineer's reference shelf answers a load-bearing question better than a generic
completion. A wine importer's tasting notes know more about a region than a
chat model does. tenet is the routing layer that connects the question to that
knowledge.

This is an **expert-routing network** — not a chain, not a token, and not a
verification scheme. There is nothing to mine and nothing to stake. The unit of
value is a good answer.

## Why run a node

If you run a node, your own questions become routable to every other expert on
the network — and in exchange, your indexed knowledge becomes reachable by
others when it's the best match. The more specialized what you contribute, the
more specialized what you can reach.

Participation is designed to be low-commitment and low-exposure:

- **You don't expose your prompts.** A question travels a multi-hop encrypted
  path; each relay on the path learns only the hop before and after it, never
  who asked or who answered.
- **Relays can't read traffic.** Only the chosen expert peer can open the
  question; every relay in between forwards sealed bytes.
- **You don't publish your files.** A node advertises a *manifest* — statistical
  summaries and commitments describing *what it knows*, never raw documents or
  paths.
- **You don't need an open port.** A home node reaches the network through a
  reachability relay; it never needs an inbound listener or a pasted IP address.

## How it works

1. Your client indexes local knowledge (documents, notes, corpora) into a
   **manifest** that describes your expertise without revealing its contents.
2. You register on the network as an **expert peer**.
3. When someone's question matches your manifest, the network routes it to you
   over an encrypted, multi-hop path.
4. Your node answers using your local knowledge together with a frontier model,
   producing a domain-specific reply.
5. The answer streams back to the asker over a return path keyed so only they
   can read it.

## Architecture

tenet is built from a small set of constructs. Each is described in full under
[`docs/`](docs/); this is the map.

| Construct | Role |
|-----------|------|
| **Client** | Indexes local knowledge, asks questions, and receives streamed answers. The same program everyone runs. |
| **Expert peer** | A node selected to answer because its manifest matches the question. Combines local knowledge with a frontier model at the edge. |
| **Manifest** | A privacy-preserving summary of a peer's knowledge — statistical features and commitments, published to the directory so the network can match questions to expertise without seeing the underlying corpus. |
| **Directory** | A signed, public snapshot of who is on the network and what they claim to know. Clients pull it to plan a route; it carries no secrets. |
| **Reachability relay** | A publicly reachable node that lets peers behind home routers participate without an inbound port. It forwards sealed bytes to a registered peer's current address and never inspects them. |
| **Encrypted path** | The multi-hop forward route a question travels. Layered so each relay peels exactly one layer — enough to learn the next hop, and nothing more. |
| **Return circuit** | The symmetric path the answer takes back, keyed so intermediate nodes forward opaque bytes and only the asker can read the result. |

**One program, two postures.** Everyone runs the same client. A participant with
a public address can be *promoted* by config into a reachability relay (a
"supernode") that helps others connect. There is no separate gateway build and
no second node type — capability comes from configuration, not from a different
binary.

**Where the boundaries sit.** Routing and reachability operate *below* the layer
that can read a question and *above* the raw transport. Relays move sealed
bytes; only the selected expert peer ever sees prompt content. These boundaries
are enforced in the runtime and covered by the test suite.

Full technical detail — the layered packet format, the wire protocol, the
reachability/forwarding model, and the relay threat model — lives in
[`docs/`](docs/):

- [`docs/por_layer7_architecture.md`](docs/por_layer7_architecture.md) — application-layer design
- [`docs/por_wire_protocol.md`](docs/por_wire_protocol.md) — on-the-wire packet and control formats
- [`docs/supernode_threat_model.md`](docs/supernode_threat_model.md) — reachability-relay threat model

## Quick start

> The CLI and package are currently named `por`; a rename to `tenet` is in
> progress and gated on the last reachability / persistent-connection work.

```bash
pip install -r requirements.txt

# Run the test suite
pytest -q

# Expert-routing demo (simulated, no network)
python3 scripts/demo.py

# Wire demo over real UDP sockets (separate node processes)
python3 -m por.udp_demo demo

# Unified client
python3 -m por --help
python3 -m por run --config client.json

# Answer with a real model at the expert edge
POR_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... python3 -m por.udp_demo demo
```

### Home client

The product path is `python3 -m por run --config client.json`. A home client
needs no inbound listener and never pastes an expert's address into config: it
loads a signed directory snapshot, verifies the selected expert's reachability
record, and dials a trusted reachability relay.

```json
{
  "node_id": "client-home",
  "role": "client",
  "client": {
    "directory_snapshot": "https://directory.example/snapshot",
    "trusted_reachability_relays": [
      {
        "relay_id": "bootstrap-1",
        "host": "203.0.113.10",
        "port": 4433,
        "verify_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
      }
    ],
    "local_http": {
      "enabled": true,
      "bind": {"host": "127.0.0.1", "port": 8766},
      "path": "/v1/expert"
    }
  },
  "peer_address": {"enabled": true}
}
```

A reachability relay is the same program promoted with `supernode` flags; see
[`examples/`](examples/) for a paired client + relay config.

## Project layout

```
por/                 Client, expert, and relay runtime (the product)
por/daemon/          Node entry points
tests/               Test suite (durable harness in tests/harness.py)
scripts/             Demos and the release-binary builder
docs/                Full technical detail
examples/            Ready-to-run config pairs
```

## Building a release binary

A node ships as a single self-contained executable — download one file and run
it. Binaries are built per-platform with PyInstaller:

```bash
python3 scripts/build_binary.py        # writes dist/por-<platform>-<arch>
./dist/por-macos-arm64 --help
```

CI (`.github/workflows/build-binaries.yml`) builds binaries for Windows, macOS,
and Linux x86-64; an experimental Android job tracks the mobile target.

## Status

tenet is pre-1.0. The expert-routing, directory, encrypted-path, and
reachability-relay layers work and are tested. The remaining work before the
`tenet` rename is automatic home-router traversal and persistent connections.

## Testing

```bash
pytest -m product       # end-to-end acceptance paths
pytest -m integration   # threaded / multi-process runtime checks
pytest -m crypto        # low-level packet-format regressions
pytest --cov=por        # coverage (floor enforced in pytest.ini)
```

## License

LGPL v3. Built on packet-format work by Ian Goldberg and George Danezis (UCL);
see [`docs/`](docs/) for academic references.
