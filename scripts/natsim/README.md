# scripts/natsim/ — Legacy Quick NAT Simulation Helpers

**Status: Legacy / retained for convenience.**

These three scripts (`gen_fleet.py`, `run_supernode.py`, `run_expert_reach.py`) let you quickly generate three tiny ClusterConfig files + a directory snapshot and launch a relay + expert over a REACH supernode for manual NAT reachability smoke tests.

They have been lightly refreshed (headers + capabilities in generated clusters) but are **not** the modern path.

## Modern replacement

Use the new simulator for anything that needs:

- Real Kademlia control overlay (iterative lookup, replication, network-scoped keys, mesh-ready publish, republish of persisted records after restart, size bounds).
- Capabilities (`control_dht`, `mixnode`, `expert`...) controlling runtime behavior.
- Multi-site logical topologies with realistic netem (latency/loss/jitter) between sites.
- The five deployment modes (all-local-docker, 2-laptop mixed, cloud-only, cloud+local, cloud+mixed-local).
- Workloads, chaos (partition, kill, jitter burst), persistence testing, etc.

See:

- `sim/README.md`
- `sim/scenarios/all-local-docker-small.yaml` (and the two-laptops / cloud skeletons)
- `deploy/Dockerfile.node` (the current container image for nodes)
- `python -m sim plan ...` / `up` / `logs` / `chaos` ...

## When you might still use natsim/

- You want three static JSON files in 2 seconds for a one-off manual test.
- You are debugging REACH return path behavior in isolation from the full control plane.
- You need something that runs without Docker or the sim dependencies.

In all other cases, prefer the new `sim/` framework.

The natsim helpers already use the current `WireNodeRuntime`, so they will benefit from the modern control record / DHT / planner changes even in their limited scope.
