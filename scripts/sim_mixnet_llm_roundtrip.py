"""In-process MixnetSim + local LLM round-trip harness.

Requires a local LLM server at 127.0.0.1:8000 (Anthropic-compatible API).
No UDP/QUIC sockets or separate relay processes are used here.
"""

import json
import time
from urllib.request import Request, urlopen

from sphinxmix.mixnet import MixnetSim
from sphinxmix.OutfoxParams import FLAG_REAL
from sphinxmix.OutfoxClient import surb_use

API = "http://127.0.0.1:8000/v1/messages"
NUM_NODES = 6
FWD_HOPS = 3
RPLY_HOPS = 3


def run_sim_mixnet_llm_roundtrip():
    sim = MixnetSim(num_nodes=NUM_NODES, payload_size=32768)
    client = sim.create_client(b"user_client___")
    fwd_path = sim.node_ids()[:FWD_HOPS]
    rply_relays = sim.node_ids()[FWD_HOPS:FWD_HOPS + RPLY_HOPS]

    prompt = "Reply with exactly one word: hello"
    request_body = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 32,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    print(f"[client] payload: {len(request_body)} bytes")

    # Forward through mixnet
    t0 = time.time()
    header, pl = client.create_repliable(fwd_path, rply_relays, request_body)
    t_create = time.time() - t0

    t0 = time.time()
    result = sim.route_forward(fwd_path, header, pl)
    t_fwd = time.time() - t0
    assert result is not None, "Forward routing failed"

    routing, flag, msg, surb_info = result
    assert flag == FLAG_REAL
    assert surb_info is not None
    assert msg == request_body, "Payload corrupted in transit"

    print(f"[mixnet] forward: {FWD_HOPS} hops, {t_fwd*1000:.1f}ms")

    # Exit node calls LLM with the decrypted payload
    t0 = time.time()
    req = Request(API, data=msg, method="POST", headers={
        "Content-Type": "application/json",
        "x-api-key": "none",
        "anthropic-version": "2023-06-01",
    })
    resp = urlopen(req, timeout=30)
    resp_body = resp.read()
    t_api = time.time() - t0

    print(f"[exit] LLM: {resp.status} ({len(resp_body)} bytes, {t_api*1000:.0f}ms)")

    # Reply through mixnet
    surb_header, surb_key = surb_info
    reply_header, reply_payload = surb_use(
        sim.params, (surb_header, surb_key), resp_body)

    t0 = time.time()
    reply_header, reply_payload = sim.route_reply(
        rply_relays, reply_header, reply_payload)
    t_rply = time.time() - t0
    assert reply_header is not None, "Reply routing failed"

    print(f"[mixnet] reply: {RPLY_HOPS} hops, {t_rply*1000:.1f}ms")

    # Client decrypts — verify bytes survived the round trip
    decrypted = client.receive_reply(reply_header, reply_payload)
    assert decrypted is not None, "Reply decryption failed"
    assert decrypted == resp_body, "Response corrupted in return path"

    print()
    print(f"  create:   {t_create*1000:6.1f}ms")
    print(f"  forward:  {t_fwd*1000:6.1f}ms  ({FWD_HOPS} hops)")
    print(f"  LLM:      {t_api*1000:6.0f}ms")
    print(f"  reply:    {t_rply*1000:6.1f}ms  ({RPLY_HOPS} hops)")
    print(f"  total:    {(t_create+t_fwd+t_api+t_rply)*1000:6.0f}ms")
    print()
    print(f"  payload integrity: request ✓  response ✓")
    print(f"  hops processed: {sim.stats()['forward']}")


if __name__ == "__main__":
    run_sim_mixnet_llm_roundtrip()
