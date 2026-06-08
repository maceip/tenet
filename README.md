# tenet

**Self-driving commerce.** Before your agent spends your money, it pays a
reputation-staked expert — in stablecoin over [x402](https://x402.org) on
Algorand — to tell it which option to actually trust.

## What we showed in the demo

A Claude-Code agent is told *"get me an Airbnb in Berlin — I don't want to deal
with it."* It finds the cheapest listing, hesitates, dials its model up from
`fast` to `EXPERT`, and asks a live Berlin local which one to book. That answer
is gated behind `402 Payment Required`: the agent **signs and broadcasts a real
Algorand testnet payment** (no human approval), routes the question over the
**real tenet mixnet** to the expert, and **switches its pick** when the expert
flags a scam listing.

```bash
# one box, split screen: asker (left) | expert (right)
./scripts/demo/split.sh

# rehearse offline (staged payment, no chain):
TENET_SIM_ONLY=1 ./scripts/demo/split.sh
```

Needs Python 3.13 (auto-bootstrapped on first run) and `ANTHROPIC_API_KEY`.
Single pane: `python scripts/demo/present.py`. Walkthrough: [`demo.md`](demo.md).
Site: <https://public.computer/tenet>.

**Real in the demo:** the mixnet routing, the expert's live model answer, and
the on-chain payment — 0.05 testnet USDC standing in for EURD (EURD is
mainnet-only; identical transfer, asset id swaps for prod), agent-signed, with a
real txid you can open on the explorer.
**Staged:** the listings and the A→B switch line are scripted for a tight demo,
and payment/answer are sequential — paying isn't yet cryptographically bound to
unlocking the answer.

## Install the client (Linux / macOS / Windows)

Pre-built single-file binaries for the `tenet` CLI are produced by the
[`build-binaries`](.github/workflows/build-binaries.yml) workflow on every push
and attached to [GitHub Releases](https://github.com/maceip/tenet/releases).

### Fastest path for a demo machine

**macOS (Apple Silicon or Intel) / Linux**

```bash
curl -L -o /usr/local/bin/tenet \
  "https://github.com/maceip/tenet/releases/latest/download/tenet-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')-$(uname -m | sed 's/x86_64/x86_64/;s/arm64/arm64/;s/aarch64/arm64/')" \
  && chmod +x /usr/local/bin/tenet
tenet --help
```

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
./scripts/demo/run-safe.sh          # resilient demo cascade
./scripts/demo/split.sh             # split-pane asker | expert
```

Build a release binary locally: `python3 scripts/build_binary.py --name tenet`
→ `dist/tenet-<platform>`.

## What's implemented

- **Mixnet routing** — `tenet.mixnet`: relay runtime, wire frames, QUIC,
  sealed Sphinx/Outfox packets, SURB return paths. Relays forward bytes without
  reading them.
- **Attested matcher** — `tenet.experts`: selects candidate experts from
  manifests behind a privacy boundary; signed results can be gossiped/reused,
  with outage fallback so the TEE is an authority, not a bottleneck.
- **Reachability relay** — experts behind NAT register reachability and receive
  matched questions without opening a public port.
- **Expert flow** — the selected expert opens the request, combines local
  context with a model, and streams the answer back, tier-marked to the asker.
- **x402 payment rail** — `tenet/x402.py`, `tenet/x402_http.py`,
  `tenet/quantoz.py` (EURD), `tenet/blind_rsa.py`, `tenet/rate_token.py`: real
  Algorand testnet settlement plus a blind-signed, single-use rate-limit token
  (pay → verify on-chain → blind-sign → spend once). Standalone end-to-end in
  [`scripts/x402_algorand_demo.py`](scripts/x402_algorand_demo.py).
- **CLI runtime** — `tenet.edges.cli`: ask, run an expert, status dashboard,
  enclave attestation checks.

### Protocol invariants

- All nodes are clients.
- Clients advertise substrate capabilities, not routeable expertise.
- The DHT discovers substrate and signed opaque/control records.
- The matcher discovers expertise behind a privacy boundary.
- Handles connect matching to routing; only handles route traffic.
- Routing chooses among reachable capabilities.
- REACH/relay is one capability, not the center.

## What's tested

`215 passed in ~18s` — the full asker → mixnet → expert → payment stack, no live
network required:

```bash
make smoke
pytest -q
```

| Area | Tests cover |
|------|-------------|
| Mixnet / runtime | relay runtime + capability integration, end-to-end packet routing (`fallback_used=False`) |
| Matcher | resolver, signed-result gossip fallback, matcher-outage fallback |
| Experts | expert pick, pick server, execution honesty, reputation weighting |
| Payment | x402 + x402-HTTP (incl. underpaid-rejection), EURD verify, blind-RSA issuance, single-use rate-token / nullifier |
| Reachability / control | reachability resolver, control records + policy, capability guard (incl. adversarial) |

## Architecture

| Layer | Package | Role |
|-------|---------|------|
| Packet  | `tenet.packet`    | Sphinx/Outfox packet primitives |
| Mixnet  | `tenet.mixnet`    | Relay runtime, wire frames, QUIC, REACH |
| Enclave | `tenet.enclave`   | Attested host, ARC, SPKI-pinned transport |
| Experts | `tenet.experts`   | Matching, manifests, routing, live flows |
| Edges   | `tenet.edges.cli` | CLI, daemon, dashboard, local HTTP/SSE edge |

Some on-disk schemas keep `por.*.v1` names for compatibility with deployed
configs — treat those as wire identifiers, not the product name.
