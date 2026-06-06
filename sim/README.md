# Tenet Mixnet + DHT Simulator (`sim/`)

This is the flexible, realistic simulator for the **core Tenet mixnet (Sphinx/Outfox data plane) + Kademlia control overlay (signed control records for discovery, routing, pools, experts, trust, reachability, etc.)**.

It is designed so the **exact same logical Tenet network** (nodes + capabilities + policies) can be realized in any of these physical environments without changing the scenario:

1. **All-local — Docker only** (one dev machine, pure containers).
2. **Mixed local + second machine** (e.g. your laptop + a colleague's laptop; each runs some number of nodes).
3. **Cloud only** (all nodes in VPS/containers across one or more cloud providers/regions).
4. **Cloud + local** (some nodes on your laptop in Docker, others in cloud).
5. **Cloud + mixed local** (cloud nodes + nodes spread across 2+ physical laptops/machines).

The simulator exercises the **real production code paths**:
- `WireNodeRuntime` + `serve_on_socket`.
- `KademliaControlOverlay` (real library-backed iterative DHT for signed control records, network-scoped keys, size bounds, mesh-ready publish, etc.).
- `MixnetControlService` (validation, persistent store, local cache + DHT fallback, gossip/anti-entropy).
- New control record families (mixnet routing descriptors, reachability assists, pools/experts, trust updates, attestation receipts, ...).
- `planner` + mixnet forward plans (no direct endpoints in production paths).
- Capabilities (a node only gets `CAPABILITY_CONTROL_DHT` if declared; only those nodes run the overlay on `port+1`).
- Churn, partitions, and realistic cross-site conditions (latency, loss, jitter) via netem.

Static full-cluster knowledge (`ClusterConfig`) is used only for **wire identity bootstrap** (KEM keys for the mixnet layer) and **initial local bind addresses**. After start, nodes discover and route using **signed control records over the real Kademlia overlay + wire gossip**, exactly as in production.

## Core Concepts

- **Scenario**: A YAML/JSON file describing the *logical* Tenet network you want to simulate.
  - `network_id`
  - `sites`: named locations (e.g. `home-docker`, `laptop2`, `cloud-us-east`, `cloud-eu`). Each site has a runner type and (for remote) connection info.
  - `links`: inter-site network conditions (`latency_ms`, `loss_percent`, `jitter_ms`).
  - `nodes`: logical nodes with `id`, `placement` (which site), `capabilities` (e.g. `["control_dht", "mixnode"]`), optional role hints, and initial descriptor seeds if desired.
  - `workloads`: optional client-like drivers placed in sites that exercise name resolution → control lookup (DHT) → planner → mixnet send/return.

- **Placement & Sites**: The same node list can be placed differently across runs. A 9-node fleet (3 control_dht + 4 mix relays + 2 experts) can be:
  - All in one `local` site (pure Docker on your laptop).
  - 5 on `laptop-home` (Docker), 4 on `laptop-office` (Docker via SSH).
  - 3 in cloud site A, 3 in cloud site B, 3 local Docker.

- **Runners** (how a site is realized):
  - `local-docker`: `docker run` (or compose under the hood) on the machine where you invoke the sim. Supports multiple logical "sites" within one physical Docker (different container groups + netem between them).
  - `ssh-docker`: Push image + configs over SSH, `docker run` on the remote (laptop or cloud VM). Assumes the remote has Docker + inbound UDP reachable (or all participants share a VPN like Tailscale/WireGuard for easy UDP between sites).
  - Future/optional: direct cloud provider drivers (AWS ECS/Fargate, GCP Cloud Run + UDP, raw EC2 with Docker, etc.). The SSH path already covers "I manually spun up these VPS instances".

- **Netem / Realism**: After containers are up, the orchestrator (or per-container entry) installs `tc` (netem) rules inside containers so that traffic to nodes in other sites experiences the declared latency/loss/jitter. Rules are destination-aware (based on the known IPs/containers of the peer site). You can dynamically re-apply during a run for chaos (partition two sites, add 200ms, random loss burst, etc.).

- **Bootstrap & Control Plane**:
  - The sim generates per-node wire identities (KEM for mixnet) and, for nodes that will publish control records, signing material.
  - It produces minimal per-site "bootstrap views" (ClusterConfig slices for local binds + a few seed contacts for Kademlia within/between sites that have public reachability).
  - Nodes with `control_dht` start the real Kademlia overlay.
  - Initial descriptors (mixnode routing, pools, etc.) can be pre-published or let the nodes themselves advertise on start.
  - The real protocols (Kademlia iterative lookup + replication, anti-entropy, gossip) do the rest. The sim waits for "mesh ready" and record visibility across sites before declaring the control plane healthy.

- **Data Plane**: Client workloads (or manual `tenet send` against a generated client view) go through the planner (control record resolution) to a mixnet forward plan and actual Sphinx/Outfox packets. No direct endpoint shortcuts.

- **Persistence**: Optional per-node `control_store_path` inside the container (volume) so restart tests exercise "persisted records are republished to DHT after attach + mesh-ready".

- **Observability**: `sim logs <node>`, `sim exec <node> -- bash`, structured logs from the runtimes, optional central log shipper (stdout is captured).

## The 5 Modes — How They Map

1. **All-local — Docker only**
   - One machine, Docker daemon.
   - Scenario declares multiple logical sites (or a single site).
   - All containers on one or more user-defined Docker networks.
   - Netem applied inside containers for "cross-site" conditions even though everything is local. This is surprisingly effective for latency/loss/jitter and partition testing.

2. **Mixed local + second machine (2 laptops)**
   - Scenario has `home` (local-docker) and `office` (ssh-docker with `ssh: user@office-laptop`).
   - Central sim (on home) builds the image, `docker save | ssh office docker load`.
   - Launches the assigned subset of containers on each.
   - For UDP between laptops: either open the published mixnet+dht ports on each laptop's firewall, or (strongly recommended) both laptops join the same Tailscale/WireGuard mesh and use those IPs as the "external" addresses for seeds/advertisements. Netem still applies at each end for the declared link characteristics.

3. **Cloud only**
   - All sites are `ssh-docker` (or future cloud-native runners) pointing at your cloud VMs (or a single VM running multiple containers representing multiple "regions").
   - Or use Docker on a beefy cloud instance with logical sites + netem to simulate multi-region without paying for many VMs.
   - Real cloud multi-region: put nodes in different providers/regions, connect them via public IPs or a transit VPN, declare realistic inter-site latencies (e.g. 30-80ms US<->EU, 150ms+ trans-Pacific).

4. **Cloud + local**
   - Some nodes in `local-docker` site on your laptop.
   - Others in `cloud-us` (ssh-docker to an AWS/GCP instance).
   - VPN between your laptop and the cloud instance makes cross-site UDP trivial; netem on both ends enforces the declared conditions.

5. **Cloud + mixed local**
   - Combines (2) and (4): laptop1 (local), laptop2 (ssh), plus 1-2 cloud sites.

## Prerequisites

- Docker (for any docker runner).
- For remote sites: passwordless SSH (or agent) to the target machines + Docker on them. The remote user must be able to `docker run` (in the `docker` group or root).
- For cross-machine UDP: either direct public reachability + port publishing, **or** (preferred for dev) a simple VPN mesh (Tailscale is 2 minutes to set up and works great for this).
- `python` + the tenet source (the sim is part of the repo; run via `uv run python -m sim ...` during development).
- On container hosts that will apply netem: the node image includes `iproute2`. Containers are started with `--cap-add=NET_ADMIN` (or `--privileged` for sim convenience).

## Quick Start (All-Local Docker, Mode 1)

```bash
# From repo root (assumes uv env or system python with the package importable)
uv run python -m sim up sim/scenarios/all-local-docker-small.yaml --netem --wait

# Watch progress
uv run python -m sim status
uv run python -m sim logs dht-1 --follow

# Run a workload (client in one site talks to an expert/pool via real control + mixnet)
uv run python -m sim run-workload --scenario sim/scenarios/all-local-docker-small.yaml --from-site home --name "pool~demo~tenet"

# Induce chaos (partition two logical sites for 20s)
uv run python -m sim chaos partition home cloudsim --loss 100 --duration 20

# Restore and tear down
uv run python -m sim down
```

See `sim/scenarios/all-local-docker-small.yaml` for a minimal fleet that includes multiple `control_dht` nodes placed in different logical sites, mixnodes, and an expert, plus a client workload definition.

## Scenario File Shape (Sketch)

```yaml
network_id: "sim-net-2026-06"
mixnet:
  payload_size: 2048
  routing_size: 16
  max_hops: 5

sites:
  home:
    runner: local-docker
    # docker_network: tenet-sim  (orchestrator can create)
  office:
    runner: ssh-docker
    ssh: "alice@10.0.0.42"
    external_host: "100.64.0.42"   # Tailscale or public IP that other sites use to reach this site's published ports
  cloud-us:
    runner: ssh-docker
    ssh: "ubuntu@ec2-...compute.amazonaws.com"
    external_host: "203.0.113.10"

links:
  - from: home
    to: office
    latency_ms: 12
    loss_percent: 0.2
    jitter_ms: 3
  - from: home
    to: cloud-us
    latency_ms: 45
    loss_percent: 0.1
  - from: office
    to: cloud-us
    latency_ms: 55
    loss_percent: 0.3

nodes:
  - id: dht-1
    placement: home
    capabilities: [control_dht, mixnode]
  - id: dht-2
    placement: office
    capabilities: [control_dht, mixnode]
  - id: relay-1
    placement: home
    capabilities: [mixnode]
  - id: relay-2
    placement: cloud-us
    capabilities: [mixnode]
  - id: expert-demo
    placement: office
    capabilities: [expert, mixnode]
    # optional: initial pool/expert descriptor seeds can be declared here

workloads:
  - name: basic-mixnet
    type: mixnet_client
    placement: home
    target: "pool~demo~tenet"   # resolved via control records + planner
    count: 5
    expect_success: true
```

The orchestrator materializes:
- A master set of KEM identities + (where needed) control signing keys.
- Per-site "local view" ClusterConfig JSONs (bind addresses appropriate to the realization, e.g. 0.0.0.0 inside container, client port for workloads).
- For remote sites, the external_host is used in any seed contacts or when generating "client view" configs that point at the reachable address.
- Persistent volume per node if `persist: true`.
- The declared capabilities flow into the ClusterNodeConfig so the runtime starts Kademlia only where intended.

## Netem & Chaos

- On `up --netem` (or `sim netem apply`), for every container the sim execs a small setup that:
  - Clears existing qdiscs.
  - For each peer site, adds a filter/class that matches destination IPs belonging to that site's containers and applies the link profile (delay + loss + jitter).
- `sim chaos partition A B --duration 30s` temporarily sets 100% loss (or a high loss value) on the A<->B link(s) from the affected containers, then restores the scenario-declared profile.
- Other primitives: `jitter-burst`, `kill -s SIGKILL <node or site-fraction>`, `restart`, `slow-start` (temporarily high latency on new nodes).

## Persistence & Restart Tests (Core Contract)

Because the simulator launches real nodes with optional `control_store_path` (Docker volume), you can:
- Bring up a scenario.
- Let records propagate (DHT + gossip).
- Stop a subset of nodes (or whole sites).
- Restart them (same persistent volume).
- Assert (via `sim` helper or manual) that they republish their local truth into the DHT after mesh-ready, and that other live nodes can still fetch via iterative lookup (the exact "bootstrap_contract" and "dht_contract" behaviors).

## Multi-Machine Tips

- Use Tailscale (or equivalent) on all participating machines (laptops + cloud VMs). It gives stable, NAT-friendly IPs and UDP that just works.
- In the scenario, set `external_host` on each site to the Tailscale (or other VPN) IP of that machine (or a load-balancer / specific published port on the host if not using host networking).
- The orchestrator will tell nodes their "public" seed contacts using those externals where appropriate.
- Netem is still applied locally at each end for the declared characteristics (so you can simulate "cloud-us to home is 45ms even if Tailscale RTT is actually 12ms").

## Development vs. "Release" Images

- During active work: the `up` command (or a helper script) can build a temp context from the current tree (similar to `build-client-sim-image.sh`) and tag it `tenet-node:dev`. Remote machines get this image via `docker save | ssh`.
- For repeated/cloud runs: pre-build a tagged image, push to a registry both sides can pull, or `docker save` to a tarball you distribute.

The node image includes a small entrypoint that:
- Mounts or receives (via env/volume) the node's identity + local cluster view + any bootstrap records.
- Optionally initializes a PersistentControlStore.
- Instantiates `WireNodeRuntime(..., control_store_path=..., control_verify_keys=...)`.
- Binds the socket(s) and calls `serve_on_socket` (or the reach/expert wrappers when role requires).
- On startup for control_dht nodes, waits for mesh-ready internally (the runtime already does the right sequencing) before heavy publish.

## Relation to Existing "natsim", Client-Sim, Gate-b / Live, and EC2 Scripts

All of the following are considered **outdated / legacy** relative to the current architecture (unified WireNodeRuntime, real Kademlia control overlay for signed records, capabilities, pyproject.toml + uv packaging, and the 5-mode simulator):

- `scripts/natsim/` — retained only for very quick single-relay NAT reach experiments. It has been lightly updated to emit capabilities. For anything more realistic (multi-site, netem, restart contracts, full control-plane DHT replication, mixed laptop/cloud, etc.) use `sim/`.
- `deploy/client-sim/` + `scripts/build-client-sim-image.sh` — specialized end-user asker image (Claude Code + `tenet ask`). The infrastructure node image is now `deploy/Dockerfile.node`.
- `scripts/gate-b/`, `scripts/deploy-gate-b-live.sh`, `scripts/deploy-network-clients.sh`, various `deploy-*.sh`, `run-*.sh`, and EC2 provisioning helpers — these rsync + launch on live Nitro/EC2 instances for specific beta/gate-b live paths. They have been annotated and given better packaging steps (uv / -e .) so they continue to work, but new simulation or containerized fleet work should go through `sim/` + `Dockerfile.node`.

The authoritative way to stand up realistic mixnet + control DHT environments that match the five deployment modes is the new `sim/` framework (see the top of this README and the scenario examples).

## Status & Roadmap

- [ ] Core local-docker MVP + netem + basic CLI + one example scenario (exercises control_dht + mixnet roundtrip).
- [ ] SSH runner + image distribution for true 2+ machine and cloud scenarios.
- [ ] Workload driver + assertions.
- [ ] Chaos primitives + "partition + recover + verify DHT still works" example.
- [ ] Optional cloud provider shims (or just excellent docs + SSH path).
- [ ] Packaging: `uv` run experience, optional `tenet-sim` entrypoint.

Contributions and scenario PRs welcome. The goal is that any claim about "the mixnet + DHT works across networks, survives churn, republishes on restart, etc." can be demonstrated in a reproducible simulator run that matches one of the 5 deployment shapes above.

## Running the Simulator (Dev)

```bash
# List scenarios
uv run python -m sim list-scenarios

# Bring up (builds image as needed, creates net, launches, applies netem, waits for basic mesh)
uv run python -m sim up sim/scenarios/all-local-docker-small.yaml --netem

# Inspect
uv run python -m sim status
uv run python -m sim logs --all | head -100

# Teardown (stops + removes containers + volumes if --clean)
uv run python -m sim down --clean
```

See the individual scenario files for per-scenario notes and expected behavior.
