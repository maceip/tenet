#!/usr/bin/env python3
"""P-OR Expert Mode UX simulation.

This script is intentionally not a wire demo:

- no UDP or QUIC sockets
- no separate relay processes
- no real LLM/provider call
- no production wire claim

It uses the real memory-fit planner, request envelope, and MixnetSim crypto
path so the terminal UX can be exercised without pretending to be the product
network. Use ``python3 -m por.udp_demo demo`` or ``python3 -m por.quic_demo
demo`` when you need packets crossing process/socket boundaries.
"""

from __future__ import annotations

import time
from os import urandom

from por.directory import PublicManifestDirectory
from por.envelope import PromptRequestEnvelope
from por.expert_mode import prepare_expert_mode_request
from por.expert_route import PeerObservation, RouteIntent
from por.memory_index import MemoryManifest
from sphinxmix.mixnet import MixnetSim


def _manifest(peer_id, byte_count, chunk_count, file_types, terms):
    return MemoryManifest(
        version="1",
        peer_id=peer_id,
        created_at="2026-05-30T00:00:00Z",
        roots=("root",),
        file_count=sum(file_types.values()),
        byte_count=byte_count,
        chunk_count=chunk_count,
        token_count=chunk_count * 200,
        file_types=file_types,
        top_terms=tuple((term, 100) for term in terms),
        corpus_root=urandom(32).hex(),
        index_digest=urandom(32).hex(),
        privacy={"raw_text_published": False},
    )


EXPERTS = {
    "expert_construction": {
        "name": "BuilderBot (peer 7f3a)",
        "manifest": _manifest(
            "expert_construction",
            48_000_000,
            12_400,
            {"pdf": 890, "txt": 3200, "md": 420},
            (
                "construction",
                "structural",
                "load-bearing",
                "concrete",
                "rebar",
                "foundation",
                "permit",
            ),
        ),
    },
    "expert_art": {
        "name": "ArtisanMind (peer 2b91)",
        "manifest": _manifest(
            "expert_art",
            92_000_000,
            28_000,
            {"pdf": 2100, "txt": 8400, "md": 1200},
            (
                "art",
                "painting",
                "impressionism",
                "monet",
                "renoir",
                "brushwork",
                "light",
                "color",
            ),
        ),
    },
    "expert_cooking": {
        "name": "ChefNode (peer 9e44)",
        "manifest": _manifest(
            "expert_cooking",
            31_000_000,
            9_800,
            {"pdf": 450, "txt": 5200, "md": 890},
            (
                "cooking",
                "roast",
                "baking",
                "recipe",
                "maillard",
                "fermentation",
                "potato",
            ),
        ),
    },
}


def dim(s):
    return f"\033[2m{s}\033[0m"


def bold(s):
    return f"\033[1m{s}\033[0m"


def green(s):
    return f"\033[32m{s}\033[0m"


def cyan(s):
    return f"\033[36m{s}\033[0m"


def yellow(s):
    return f"\033[33m{s}\033[0m"


def _directory():
    observations = tuple(
        PeerObservation(
            peer_id=peer_id,
            p50_latency_ms=120 + index * 40,
            uptime=0.96,
            completion_rate=0.99,
        )
        for index, peer_id in enumerate(EXPERTS)
    )
    return PublicManifestDirectory.from_manifests(
        [entry["manifest"] for entry in EXPERTS.values()],
        observations,
        source="ux-sim",
    )


def _harness_expert_reply(prompt: str, peer_id: str, manifest: MemoryManifest) -> str:
    terms = ", ".join(term for term, _count in manifest.top_terms[:4])
    return (
        f"[ux-sim expert_reply] peer={peer_id} prompt_len={len(prompt)} "
        f"chunks={manifest.chunk_count} top_terms={terms} "
        "llm_called=no raw_text_available=no"
    )


def _frontier_fallback(prompt: str, reason: str | None) -> str:
    return (
        f"[ux-sim frontier_fallback] prompt_len={len(prompt)} "
        f"expert_used=no reason={reason or 'no expert selected'}"
    )


def run_demo():
    print()
    print(bold("  P-OR Expert Mode UX Simulation"))
    print(dim("  not a UDP/QUIC wire demo; no real provider call"))
    print(dim("  ─────────────────────────────────────────"))
    print()

    print(f"  [{green('x')}] Expert Mode")
    print()

    prompt = input(f"  {bold('>')} ")
    if not prompt.strip():
        prompt = "What did Monet change about modern painting?"
        print(f"  {dim(f'(using default: {prompt})')}")

    print()
    print(dim("  planning from public memory snapshot..."))
    time.sleep(0.2)

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt=prompt, min_pool_size=3, allow_degraded_pool=True, random_seed=42),
        _directory(),
    )

    trace = prepared.trace
    if not prepared.use_expert or prepared.envelope is None:
        print(dim("  no useful expert match; using simulated frontier fallback"))
        print(dim(f"  reason: {trace.fallback_reason}"))
        print()
        print(f"  {bold('Fallback:')}")
        print(f"    {_frontier_fallback(prompt, trace.fallback_reason)}")
        return

    selected_peer_id = prepared.plan.selected_peer_id
    selected = EXPERTS[selected_peer_id]
    print(f"  selected: {cyan(selected['name'])}")
    print(dim(f"  pool: {trace.pool_tier} ({trace.candidate_count} candidates)"))
    for warning in trace.warnings:
        print(yellow(f"  warning: {warning}"))
    print()

    print(dim("  routing envelope through MixnetSim..."))
    time.sleep(0.2)

    sim = MixnetSim(num_nodes=6, payload_size=4096)
    client = sim.create_client(b"demo_client___")
    fwd_path = sim.node_ids()[:4]

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path,
        [],
        prepared.envelope.to_json().encode("utf-8"),
    )

    t0 = time.time()
    result = sim.route_forward(fwd_path, header, payload)
    t_fwd = (time.time() - t0) * 1000
    if result is None:
        print("  MixnetSim routing failed")
        return

    _routing, _flag, msg, _surb_info = result
    delivered = PromptRequestEnvelope.from_json(msg)
    stream, _ = sim.create_circuit_stream(fwd_path, client_inbound)
    reply = _harness_expert_reply(
        delivered.prompt_text(),
        selected_peer_id,
        selected["manifest"],
    )
    chunks = [reply[i:i + 40] for i in range(0, len(reply), 40)]

    t0 = time.time()
    decrypted_chunks = []
    for chunk in chunks:
        packet = sim.stream_token(fwd_path, stream, chunk.encode("utf-8"))
        if packet:
            dec = client.decrypt_circuit(packet)
            if dec:
                decrypted_chunks.append(dec.decode("utf-8"))
    t_stream = (time.time() - t0) * 1000

    print(dim(f"  sim forward: {len(fwd_path)} hops, {t_fwd:.1f}ms"))
    print(dim(f"  sim return: {len(chunks)} circuit packets, {t_stream:.1f}ms"))
    print()
    print(f"  {bold('Harness reply:')}")
    print(f"    {''.join(decrypted_chunks)}")
    print()


if __name__ == "__main__":
    try:
        run_demo()
    except (KeyboardInterrupt, EOFError):
        print()
