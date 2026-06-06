# Demo And Harness Inventory

This repository has several demo surfaces. They are **not equivalent** and
**none of them is the production wire path**.

**Production wire:** `por relay` / `por expert` / `por run` using canonical
binary datagrams (`por.wire_frame`: `0x00` forward, `0x01` circuit, `0x02`
shutdown). See `por/daemon/` and `por/node_runtime.py`.

| Entry point | What it is | Wire | Provider |
| --- | --- | --- | --- |
| `scripts/demo.py` | Terminal UX simulation | No sockets; `MixnetSim` | Harness reply |
| `python3 -m por.udp_demo demo` | Local UDP harness | JSON/base64 UDP (harness-only) | Harness or real (`POR_PROVIDER`) |
| `python3 -m por.quic_demo demo` | Local QUIC harness | JSON/base64 over H3 (harness-only) | Harness reply |
| `scripts/sim_mixnet_*.py` | In-process simulator | No sockets; `MixnetSim` | Optional real LLM |
| `por relay --config` | **Production** relay daemon | Binary `0x00`/`0x01`/`0x02` | N/A (relay) |
| `por expert --config` | **Production** expert daemon | Binary `0x00`/`0x01`/`0x02` | `POR_PROVIDER` |

**Rule:** new features target `por/daemon/` + binary wire. Demos are for
trace inspection and smoke tests only.
