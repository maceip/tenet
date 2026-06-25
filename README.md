# tenet

> **Built on a confidential-compute platform** — runs inside a cloud TEE via [attested-workload](https://github.com/maceip/attested-workload) with portable receipts in [unified-quote](https://github.com/maceip/unified-quote) format. Platform: [cvm-agent](https://github.com/maceip/cvm-agent) · [attestation-service](https://github.com/maceip/attestation-service) · [unified-quote](https://github.com/maceip/unified-quote) · [attested-workload](https://github.com/maceip/attested-workload).


> *An invisible college you reach through hardware you're not allowed to look
> inside. Knowledge moves; people disappear.*

tenet is private infrastructure for buying judgment. Before an agent spends your
money — or you make a call you can't take back — it pays a reputation-staked
human expert to tell it which option to actually trust, and it does so over a
network that is structurally incapable of keeping a logbook of who asked what,
or who answered.

## The expert network

tenet is **an open mixture-of-experts where the experts are sovereign human
nodes with private knowledge, the gate is a privacy-preserving oblivious
matcher, and a frontier model acts as the floor.**

That is a deliberate edit of a mental model you already have. Standard
mixture-of-experts has three parts; tenet keeps the shape and subverts each one:

- **The experts.** Not trained feed-forward blocks inside one neural network —
  independent, decentralized nodes, each guarding private local data. A real
  person or machine with a corpus that never leaves their box.
- **The gating network.** Not a learned softmax layer — an oblivious
  cryptographic similarity search over *public manifests*. The gate scores
  whether a query fits a node's corpus without learning the query or the corpus.
- **The fallback.** Not degraded logit outputs — an absolute performance floor
  held up by a frontier model.

Be honest about where the analogy ends, because someone will point it out
otherwise: real MoE optimizes a differentiable gate alongside its components
through joint training. **This is separate machines that share zero weights —
the gate is a search, not a neural layer.** The framing is an intuitive
conceptual model, not an exact mathematical definition.

### The frontier floor

> *You can route around the giant, but you can never route below it.*

The network is a sovereign layer of human expertise trading data in the
shadows — but beneath the entire infrastructure sits an inescapable, silent
machine intelligence holding up the baseline. A match can be lossy; that is
fine. If no human expert fits a query, the frontier model answers, so quality
never falls through the floor. The underground believes it is the whole
ecosystem; it is actually suspended over an AI foundation that catches every
mistake.

### How a question moves

1. A client loads a **join-pack** (matcher attestation pins + control
   bootstrap) and asks a question.
2. The **matcher** scores the query against public manifests behind a privacy
   boundary and returns **opaque handles** — never identities.
3. The question routes over the **mixnet** to the selected expert. Relays
   forward sealed bytes without reading them.
4. The **expert** opens the request, combines its private corpus with a model,
   and streams a tier-marked answer back along a return path.
5. If no expert fits, the **frontier floor** answers.

The separation of duties is the whole point. **The matcher generates the token
but cannot reverse it to an identity; the relay handles the data but cannot read
the token's destination.** No single component holds the translation key. The
component that evaluates semantic similarity only emits an unresolvable,
ephemeral handle; the routing infrastructure delivers data using that handle but
lacks the context to reverse-engineer who asked or who answered.

## How experts get paid

Experts are paid in **stablecoin over [x402](https://x402.org)**. An expert's
judgment is gated behind `HTTP 402 Payment Required`. Before the agent acts:

1. It receives the `402` with on-chain payment requirements.
2. It signs and broadcasts a real on-chain stablecoin payment — no human in the
   loop.
3. The settlement is verified on-chain, then **blind-signed** into a single-use
   rate-limit token: **pay → verify on-chain → blind-sign → spend once.**

The economics are simple: judgment is the product. Clicking "book" is one boring
API call; not getting scammed is what you pay a stranger five cents for.

Payment is built for **deniability over secrecy** — conversations architected to
be *unprovable*, not merely hidden. Because the rate-limit token is blind-signed
and the route targets are opaque handles, nobody can demonstrate that a given
exchange happened — including the people who ran the wires. Information transfers
safely because the system itself is structurally incapable of keeping a logbook.

## Security axioms

These are not features; they are invariants the architecture refuses to
violate.

### The Network Invariant

> *Security level is a property of the network at a point in time, never of the
> user.*

A user-facing security toggle is a fragmentation engine. The moment you ship an
opt-in privacy feature, the users who activate it self-segregate into a smaller,
highly distinguishable sub-population. By trying to become "more secure," they
separate themselves from the crowd and become *easier* to target. Anonymity
requires uniform volume; a toggle evicts you from the collective cover set. So
tenet has no privacy switch — the security level is network-wide, always.

### The Temporal Invariant

> *Migration flips the network; it never forks the users.*

Systems fail when they run two trust planes concurrently and let users pick a
path per request. The only stable architecture is temporal: **exactly one trust
model is operational for the entire network at any single microsecond.** The
future decentralized substrate (the mixnet, the control-plane DHT) remains a
dormant substrate and an engineering migration path — never an active second
plane running parallel to the current one. Migration flips everyone at once.

### The Trust-Relocation Reality

> *A TEE is trust-relocation, not anonymity — and it fails correlated and
> catastrophic.*

Confidential computing (SGX/TDX, Nitro) does not erase the need for trust; it
moves the trust boundary from the human operator to the silicon manufacturer's
supply chain. Because of that centralization, the risk profile changes shape: a
single structural hardware exploit does not degrade privacy gracefully — it
de-anonymizes the entire user base simultaneously, in one correlated event.
tenet uses trusted hardware where it earns its keep (private matching, sealed
routing), names the trade-off plainly, and treats the enclave as an authority,
not an unquestioned root.

The tension is the design, not a bug in it: tenet uses highly locked-down,
proprietary silicon to construct a completely open, untraceable human
communications network.

## Building it: wire first, harden after

> *Build the wire with plain stand-ins, then harden the boxes without rewiring.*

To ship a high-assurance system without getting trapped in cryptographic
implementation before the architecture is proven, separate **topology** from
**cryptographic hardening**. Build the end-to-end data flow first with plain
components — plain processes, simple lookups, open routing maps — until the
structural pipeline is fully validated and green in the test harness. Then swap
components for their secure equivalents one at a time, *without ever altering the
transport layout*:

```
HTTP stand-ins → attestation → SPKI pinning → oblivious matching → TEE
```

That sequence is exactly how this repo grew, and it is why the wire shape is
stable while the boxes on it keep getting harder.

## What's implemented

- **Mixnet routing** — `tenet.mixnet`: relay runtime, wire frames, QUIC,
  sealed Sphinx/Outfox packets, SURB return paths. Relays forward bytes without
  reading them.
- **Attested matcher** — `tenet.experts`: selects candidate experts from
  manifests behind a privacy boundary; signed results can be gossiped/reused,
  with outage fallback so the TEE is an authority, not a bottleneck.
- **Oblivious selection** — `tenet/experts/oblivious.py` with a constant-time
  Rust core (`oblivious-core/`) so the in-TEE access pattern is data-independent.
- **Reachability relay** — experts behind NAT register reachability and receive
  matched questions without opening a public port.
- **Expert flow** — the selected expert opens the request, combines local
  context with a model, and streams the answer back, tier-marked to the asker.
- **Expertise proxy** — corpus ingest → matcher manifest → reply-time RAG
  enrichment. See [`docs/expertise-proxy.md`](docs/expertise-proxy.md).
- **x402 payment rail** — `tenet/x402.py`, `tenet/x402_http.py`,
  `tenet/quantoz.py`, `tenet/blind_rsa.py`, `tenet/rate_token.py`: on-chain
  stablecoin settlement plus a blind-signed, single-use rate-limit token (pay →
  verify on-chain → blind-sign → spend once).
- **CLI runtime** — `tenet.edges.cli`: ask, run an expert, status dashboard,
  enclave attestation checks, and a local HTTP/SSE bridge (`tenet serve`).

### Protocol invariants

- All nodes are clients.
- Clients advertise substrate capabilities, not routeable expertise.
- The DHT discovers substrate and signed opaque/control records.
- The matcher discovers expertise behind a privacy boundary.
- Handles connect matching to routing; only handles route traffic.
- Routing chooses among reachable capabilities.
- REACH/relay is one capability, not the center.

## What's tested

The full asker → mixnet → expert → payment stack runs offline under pytest, no
live network required:

```bash
make smoke
pytest -q
```

| Area | Tests cover |
|------|-------------|
| Mixnet / runtime | relay runtime + capability integration, end-to-end packet routing (`fallback_used=False`) |
| Matcher | resolver, signed-result gossip fallback, matcher-outage fallback |
| Experts | expert pick, pick server, execution honesty, reputation weighting |
| Payment | x402 + x402-HTTP (incl. underpaid-rejection), stablecoin verify, blind-RSA issuance, single-use rate-token / nullifier |
| Reachability / control | reachability resolver, control records + policy, capability guard (incl. adversarial) |

## Architecture

| Layer | Package | Role |
|-------|---------|------|
| Packet  | `tenet.packet`    | Sphinx/Outfox packet primitives |
| Mixnet  | `tenet.mixnet`    | Relay runtime, wire frames, QUIC, REACH |
| Enclave | `tenet.enclave`   | Attested host, ARC, SPKI-pinned transport |
| Experts | `tenet.experts`   | Matching, manifests, routing, live flows |
| Edges   | `tenet.edges.cli` | CLI, daemon, dashboard, local HTTP/SSE edge |

Production discovery (control plane + REACH + match gossip) is described in
[`docs/network-discovery.md`](docs/network-discovery.md).

Some on-disk schemas keep `por.*.v1` names for compatibility with deployed
configs — treat those as wire identifiers, not the product name.

## Install the client (Linux / macOS / Windows)

Pre-built single-file binaries for the `tenet` CLI are produced by the
[`build-binaries`](.github/workflows/build-binaries.yml) workflow on every push
and attached to [GitHub Releases](https://github.com/maceip/tenet/releases).

### Fastest path

**macOS (Apple Silicon) / Linux**

```bash
curl -L -o /usr/local/bin/tenet \
  "https://github.com/maceip/tenet/releases/latest/download/tenet-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')-$(uname -m | sed 's/x86_64/x86_64/;s/arm64/arm64/;s/aarch64/arm64/')" \
  && chmod +x /usr/local/bin/tenet
tenet --help
```

Intel Macs: use `pipx install git+https://github.com/maceip/tenet.git` or build
from source (`python3 scripts/build_binary.py --name tenet`). CI ships
`tenet-macos-arm64` only.

**Windows** — download `tenet-windows-x86_64.exe` from the latest Release, rename
to `tenet.exe`, and put it on `PATH`.

**No global install**

```bash
pipx install git+https://github.com/maceip/tenet.git
# or: uv tool install git+https://github.com/maceip/tenet.git
```

### Homebrew (non-cask CLI)

```bash
brew install --formula https://raw.githubusercontent.com/maceip/tenet/master/homebrew/Formula/tenet.rb
# or: brew tap maceip/tenet https://github.com/maceip/tenet && brew install tenet
```

### From source (this repo)

```bash
git clone https://github.com/maceip/tenet.git ~/tenet && cd ~/tenet
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
tenet --help
make smoke
```

Build a release binary locally: `python3 scripts/build_binary.py --name tenet`
→ `dist/tenet-<platform>`.

Needs Python 3.13 (auto-bootstrapped on first run) and, for live model answers,
`ANTHROPIC_API_KEY`.