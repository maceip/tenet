"""In-process packet crypto/routing tests."""

from http.server import BaseHTTPRequestHandler
import json
import struct
from tests.mixnet_test_network import MixnetTestNetwork, Client, CircuitCorrupted
from tests.harness import mixnet_harness
from tenet.packet.OutfoxParams import (
    FLAG_REAL, FLAG_DUMMY, verify_payload, generate_signing_keypair,
)
from tenet.packet.OutfoxClient import surb_use, surb_check, surb_recover


def test_forward_through_test_nodes():
    """Forward packet through 5 in-process test nodes."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    path = sim.node_ids()[:5]
    header, payload = client.create_forward(path, b"hello mixnet")

    result = sim.route_forward(path, header, payload)
    assert result is not None
    routing, flag, msg, surb_info = result
    assert msg == b"hello mixnet"
    assert flag == FLAG_REAL
    assert surb_info is None

    print("[PASS] Forward: 5-hop delivery through MixnetTestNetwork.")


def test_repliable_round_trip():
    """Full repliable flow: forward → exit → reply → sender decrypts."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:4]
    rply_relays = sim.node_ids()[4:7]

    header, payload = client.create_repliable(
        fwd_path, rply_relays, b"please reply")

    result = sim.route_forward(fwd_path, header, payload)
    assert result is not None
    routing, flag, msg, surb_info = result
    assert msg == b"please reply"
    assert surb_info is not None

    surb_header, surb_key = surb_info

    reply_header, reply_payload = surb_use(
        sim.params, (surb_header, surb_key), b"here is your reply")

    reply_header, reply_payload = sim.route_reply(
        rply_relays, reply_header, reply_payload)
    assert reply_header is not None

    received = client.receive_reply(reply_header, reply_payload)
    assert received == b"here is your reply"

    print("[PASS] Repliable: full round-trip forward + reply through MixnetTestNetwork.")


def test_signed_message():
    """Forward packet with ML-DSA-65 signature verified at exit."""
    sim = MixnetTestNetwork(num_nodes=8, payload_size=4096)
    client = sim.create_client(b"alice")

    path = sim.node_ids()[:3]
    receiver_id = b"bob_id_endpoint"
    header, payload = client.create_signed(
        path, receiver_id, b"signed prompt")

    result = sim.route_forward(path, header, payload)
    assert result is not None
    routing, flag, msg, _ = result

    sig_len = struct.unpack(">H", msg[:2])[0]
    signature = msg[2:2 + sig_len]
    signed_content = msg[2 + sig_len:]

    assert verify_payload(client.sign_pk, signed_content, signature)
    assert b"signed prompt" in signed_content
    assert client.client_id in signed_content
    assert receiver_id in signed_content

    print("[PASS] Signed: ML-DSA-65 signature verified at exit node.")


def test_dummy_traffic():
    """Dummy packets are processed identically but flagged."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    path = sim.node_ids()[:3]

    real_h, real_p = client.create_forward(path, b"real message")
    dummy_h, dummy_p = client.create_dummy(path)

    real_result = sim.route_forward(path, real_h, real_p)
    dummy_result = sim.route_forward(path, dummy_h, dummy_p)

    assert real_result is not None
    assert dummy_result is not None

    _, real_flag, _, _ = real_result
    _, dummy_flag, _, _ = dummy_result
    assert real_flag == FLAG_REAL
    assert dummy_flag == FLAG_DUMMY

    print("[PASS] Dummy: real and dummy packets processed identically, flags differ.")


def test_multiple_clients():
    """Multiple clients routing through the same network simultaneously."""
    sim = MixnetTestNetwork(num_nodes=8)
    alice = sim.create_client(b"alice")
    bob = sim.create_client(b"bob__")
    carol = sim.create_client(b"carol")

    path = sim.node_ids()[:4]
    msgs = [
        (alice, b"alice's message"),
        (bob, b"bob's message"),
        (carol, b"carol's message"),
    ]

    for client, msg in msgs:
        h, p = client.create_forward(path, msg)
        result = sim.route_forward(path, h, p)
        assert result is not None
        _, _, received, _ = result
        assert received == msg

    stats = sim.stats()
    assert stats["forward"] == 4 * 3

    print(f"[PASS] Multi-client: 3 clients, {stats['forward']} hops total.")


def test_tampered_header_rejected():
    """Tampered header fails AEAD at the first honest node."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    path = sim.node_ids()[:3]
    header, payload = client.create_forward(path, b"test")

    tampered = bytearray(header)
    tampered[40] ^= 0xFF

    try:
        sim.route_forward(path, bytes(tampered), payload)
        assert False, "Should have failed"
    except ValueError:
        pass

    print("[PASS] Tampered header: AEAD rejection at first hop.")


def test_tagged_payload_rejected():
    """Tagged payload detected at exit via zero-padding check."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    path = sim.node_ids()[:3]
    header, payload = client.create_forward(path, b"secret")

    tagged = bytearray(payload)
    tagged[50] ^= 0xFF

    result = sim.route_forward(path, header, bytes(tagged))
    assert result is None

    print("[PASS] Tagged payload: PRP destroys contents, exit rejects.")


def test_circuit_table():
    """Circuit key table: store, lookup, expiry."""
    from tests.mixnet_test_network import CircuitTable

    table = CircuitTable(ttl=1)
    cid = b"circuit_id_12345"
    key = b"symmetric_key!!!"

    table.store(cid, key, next_hop=b"next_node_id____", outbound_cid=b"outbound_cid____")
    entry = table.lookup(cid)
    assert entry is not None
    assert entry["key"] == key
    assert entry["next_hop"] == b"next_node_id____"
    assert entry["outbound_cid"] == b"outbound_cid____"
    assert entry["high_watermark"] == 0
    assert table.size() == 1

    assert table.check_nonce(cid, 1)
    assert not table.check_nonce(cid, 1)
    assert not table.check_nonce(cid, 0)
    assert table.check_nonce(cid, 2)

    import time
    time.sleep(1.1)
    assert table.lookup(cid) is None
    assert table.size() == 0

    table2 = CircuitTable(ttl=60, max_entries=2)
    table2.store(b"cid_1___________", b"key1____________")
    table2.store(b"cid_2___________", b"key2____________")
    table2.store(b"cid_3___________", b"key3____________")
    assert table2.size() == 2
    assert table2.lookup(b"cid_1___________") is None

    print("[PASS] Circuit table: store, lookup, TTL expiry, nonce check, LRU.")


def test_exit_node_discovery():
    """Clients find exit nodes by provider capability."""
    providers = {
        3: [{"name": "anthropic", "models": ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"]}],
        5: [{"name": "anthropic", "models": ["claude-sonnet-4-20250514"]},
            {"name": "openai", "models": ["gpt-4o"]}],
        7: [{"name": "openai", "models": ["gpt-4o", "gpt-4o-mini"]}],
    }
    sim = MixnetTestNetwork(num_nodes=8, node_providers=providers)
    client = sim.create_client(b"alice")

    # Find Anthropic exit nodes
    anthropic_exits = sim.pki.find_exit_nodes(provider="anthropic")
    assert len(anthropic_exits) == 2
    assert sim.node_ids()[3] in anthropic_exits
    assert sim.node_ids()[5] in anthropic_exits

    # Find OpenAI exit nodes
    openai_exits = sim.pki.find_exit_nodes(provider="openai")
    assert len(openai_exits) == 2
    assert sim.node_ids()[5] in openai_exits
    assert sim.node_ids()[7] in openai_exits

    # Find by specific model
    haiku_exits = sim.pki.find_exit_nodes(provider="anthropic", model="claude-haiku-4-5-20251001")
    assert len(haiku_exits) == 1
    assert sim.node_ids()[3] in haiku_exits

    # No exit for unknown provider
    assert sim.pki.find_exit_nodes(provider="deepseek") == []

    print("[PASS] Exit discovery: find nodes by provider and model.")


def test_capability_based_routing():
    """Client auto-selects path based on desired provider."""
    providers = {
        4: [{"name": "anthropic", "models": ["claude-sonnet-4-20250514"]}],
        6: [{"name": "openai", "models": ["gpt-4o"]}],
    }
    sim = MixnetTestNetwork(num_nodes=8, node_providers=providers)
    client = sim.create_client(b"alice")

    # Select path for Anthropic — exit must be node 4
    path = client.select_path(provider="anthropic", num_hops=3)
    assert path[-1] == sim.node_ids()[4]
    assert len(path) == 3

    # Select path for OpenAI — exit must be node 6
    path = client.select_path(provider="openai", num_hops=3)
    assert path[-1] == sim.node_ids()[6]
    assert len(path) == 3

    # Route a message through the auto-selected path
    path = client.select_path(provider="anthropic", num_hops=3)
    header, payload = client.create_forward(path, b"test prompt")
    result = sim.route_forward(path, header, payload)
    assert result is not None
    _, _, msg, _ = result
    assert msg == b"test prompt"

    # No provider available
    try:
        client.select_path(provider="nonexistent")
        assert False
    except ValueError:
        pass

    print("[PASS] Capability routing: auto-select exit by provider, route works.")


def test_exit_with_api_call():
    """Exit node selected by capability makes the actual LLM call."""
    from urllib.request import Request, urlopen

    with mixnet_harness() as net:
        api_server = net.serve_http(_anthropic_test_handler())
        api_base = f"http://127.0.0.1:{api_server.server_address[1]}"
        providers = {
            2: [{"name": "anthropic", "models": ["claude-sonnet-4-20250514"],
                 "api_base": api_base}],
        }
        sim = MixnetTestNetwork(num_nodes=6, payload_size=32768, node_providers=providers)
        client = sim.create_client(b"alice")

        path = client.select_path(provider="anthropic", num_hops=3)
        request_body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "say ok"}],
        }).encode()

        fwd_path = path
        rply_relays = [nid for nid in sim.node_ids() if nid not in path][:2]
        header, payload = client.create_repliable(fwd_path, rply_relays, request_body)

        result = sim.route_forward(fwd_path, header, payload)
        assert result is not None
        routing, flag, msg, surb_info = result
        assert msg == request_body

        exit_node = sim.nodes[path[-1]]
        api_base = exit_node.providers[0]["api_base"]
        req = Request(api_base + "/v1/messages", data=msg, method="POST", headers={
            "Content-Type": "application/json",
            "x-api-key": "none",
            "anthropic-version": "2023-06-01",
        })
        resp = urlopen(req, timeout=30)
        resp_body = resp.read()
        assert resp.status == 200

        surb_header, surb_key = surb_info
        from tenet.packet.OutfoxClient import surb_use
        reply_header, reply_payload = surb_use(sim.params, (surb_header, surb_key), resp_body)
        reply_header, reply_payload = sim.route_reply(rply_relays, reply_header, reply_payload)
        decrypted = client.receive_reply(reply_header, reply_payload)
        assert decrypted == resp_body

    print(f"[PASS] Exit with API: capability-selected exit called LLM, response verified.")


def _anthropic_test_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/messages":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            request_body = json.loads(self.rfile.read(length))
            body = json.dumps(
                {
                    "id": "msg-test-local",
                    "type": "message",
                    "role": "assistant",
                    "model": request_body["model"],
                    "content": [{"type": "text", "text": "ok"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    return Handler


def test_network_stats():
    """Node statistics are tracked correctly."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    path = sim.node_ids()[:4]
    for _ in range(10):
        h, p = client.create_forward(path, b"msg")
        sim.route_forward(path, h, p)

    stats = sim.stats()
    assert stats["forward"] == 40

    print(f"[PASS] Stats: {stats['forward']} forward hops across 10 messages.")


# ═══════════════════════════════════════════════════════════════════
# Phase 2: Circuit setup + streaming return path
# ═══════════════════════════════════════════════════════════════════


def test_circuit_install_on_forward():
    """Forward packet with circuit setup installs state at each relay."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:4]
    rply_relays = sim.node_ids()[4:7]

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"setup circuits")

    result = sim.route_forward(fwd_path, header, payload)
    assert result is not None
    routing, flag, msg, surb_info = result
    assert msg == b"setup circuits"

    all_inbound_cids = set()
    for nid in fwd_path:
        node = sim.nodes[nid]
        assert node.circuits.size() == 1, f"Circuit not installed at {nid!r}"
        inbound_cid = list(node.circuits.entries.keys())[0]
        entry = node.circuits.entries[inbound_cid]
        assert entry["key"] is not None
        assert entry["next_hop"] is not None
        assert entry["outbound_cid"] is not None
        all_inbound_cids.add(inbound_cid)

    assert len(all_inbound_cids) == len(fwd_path), "Inbound CIDs must be unique per hop"

    print("[PASS] Circuit install: per-hop link CIDs installed, all unique.")


def test_circuit_reply_end_to_end():
    """Full circuit reply: forward installs state, exit streams tokens back."""
    sim = MixnetTestNetwork(num_nodes=6)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:4]
    rply_relays = sim.node_ids()[4:5]

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"prompt")

    result = sim.route_forward(fwd_path, header, payload)
    assert result is not None

    tokens = [b"Hello", b" world", b"!", b" How", b" are", b" you?"]
    for i, token in enumerate(tokens):
        packet = sim.route_circuit_reply(
            fwd_path, client_inbound, None, i + 1, token)
        assert packet is not None, f"Circuit reply failed for token {i}"

        decrypted = client.decrypt_circuit(packet)
        assert decrypted == token, f"Token {i}: {decrypted!r} != {token!r}"

    print(f"[PASS] Circuit reply: {len(tokens)} tokens streamed and decrypted.")


def test_circuit_reply_multi_hop():
    """Circuit reply through 5 hops."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:5]
    rply_relays = sim.node_ids()[5:7]

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"deep path")

    result = sim.route_forward(fwd_path, header, payload)
    assert result is not None

    packet = sim.route_circuit_reply(
        fwd_path, client_inbound, None, 1, b"deep token")
    assert packet is not None
    assert client.decrypt_circuit(packet) == b"deep token"

    print("[PASS] Circuit reply: 5-hop path works.")


def test_circuit_nonce_rejection():
    """Client rejects replayed or regressed nonces."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    rply_relays = []

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"nonce test")

    sim.route_forward(fwd_path, header, payload)
    # route_circuit_reply handles exit lookup internally
    

    p1 = sim.route_circuit_reply(fwd_path, client_inbound, None, 5, b"five")
    assert p1 is not None
    assert client.decrypt_circuit(p1) == b"five"

    # Nonce regression — rejected at relay level
    p2 = sim.route_circuit_reply(fwd_path, client_inbound, None, 3, b"three")
    assert p2 is None

    # Nonce replay — also rejected at relay level
    p3 = sim.route_circuit_reply(fwd_path, client_inbound, None, 5, b"replay")
    assert p3 is None

    # Higher nonce — accepted (gap from 5 to 10 is fine)
    p4 = sim.route_circuit_reply(fwd_path, client_inbound, None, 10, b"ten")
    assert p4 is not None
    assert client.decrypt_circuit(p4) == b"ten"

    print("[PASS] Circuit nonce: replay and regression rejected, gaps accepted.")


def test_circuit_corruption_detection():
    """Client detects corrupted circuit packets via magic field."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    rply_relays = []

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"corruption test")

    sim.route_forward(fwd_path, header, payload)
    # route_circuit_reply handles exit lookup internally
    

    packet = sim.route_circuit_reply(fwd_path, client_inbound, None, 1, b"ok")
    corrupted = bytearray(packet)
    corrupted[30] ^= 0xFF
    assert client.decrypt_circuit(bytes(corrupted)) is None

    good = sim.route_circuit_reply(fwd_path, client_inbound, None, 2, b"good")
    assert client.decrypt_circuit(good) == b"good"

    print("[PASS] Circuit corruption: tampered packet rejected, good packet accepted.")


def test_circuit_stats():
    """Circuit processing increments node stats."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"stats")

    sim.route_forward(fwd_path, header, payload)
    # route_circuit_reply handles exit lookup internally

    for i in range(5):
        sim.route_circuit_reply(
            fwd_path, client_inbound, None, i + 1, b"tok")

    stats = sim.stats()
    assert stats["circuit"] > 0

    print(f"[PASS] Circuit stats: {stats['circuit']} circuit hops tracked.")


def test_circuit_reestablish_trigger():
    """3 consecutive corrupted packets triggers CircuitCorrupted exception."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"reestablish test")

    sim.route_forward(fwd_path, header, payload)
    # route_circuit_reply handles exit lookup internally
    

    # Send 3 consecutive corrupted packets
    for i in range(3):
        packet = sim.route_circuit_reply(fwd_path, client_inbound, None, i + 1, b"tok")
        corrupted = bytearray(packet)
        corrupted[30] ^= 0xFF
        if i < 2:
            assert client.decrypt_circuit(bytes(corrupted)) is None
        else:
            try:
                client.decrypt_circuit(bytes(corrupted))
                assert False, "Should have raised CircuitCorrupted"
            except CircuitCorrupted as e:
                assert e.link_cid == client_inbound

    # Circuit is removed — subsequent packets return None (no entry)
    good = sim.route_circuit_reply(fwd_path, client_inbound, None, 10, b"late")
    assert client.decrypt_circuit(good) is None

    # But client can re-establish with a new circuit
    header2, payload2, client_inbound2 = client.create_repliable_with_circuit(
        fwd_path, [], b"reestablished")
    sim.route_forward(fwd_path, header2, payload2)
    # route_circuit_reply handles exit lookup internally

    packet2 = sim.route_circuit_reply(
        fwd_path, client_inbound2, None, 1, b"back online")
    assert client.decrypt_circuit(packet2) == b"back online"

    print("[PASS] Circuit reestablish: 3 corruptions triggers exception, re-establish works.")


def test_per_hop_link_cid_unlinkability():
    """Non-adjacent relays MUST NOT see the same link_cid on the wire."""
    sim = MixnetTestNetwork(num_nodes=8)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:5]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"unlinkability test")

    sim.route_forward(fwd_path, header, payload)

    # Collect each node's inbound and outbound CIDs
    hop_cids = {}
    for nid in fwd_path:
        node = sim.nodes[nid]
        assert node.circuits.size() == 1
        inbound_cid = list(node.circuits.entries.keys())[0]
        entry = node.circuits.entries[inbound_cid]
        hop_cids[nid] = {
            "inbound": inbound_cid,
            "outbound": entry["outbound_cid"],
        }

    # Link binding: each hop's outbound must equal the next hop's inbound
    for i in range(len(fwd_path) - 1):
        this_hop = hop_cids[fwd_path[i]]
        next_hop_toward_client = hop_cids[fwd_path[i + 1]] if i + 1 < len(fwd_path) else None
        # In the return path (reverse), fwd_path[i+1].outbound should equal fwd_path[i].inbound
        # because return goes exit→...→relay0→client

    # Reverse to get return-path order: exit, relay3, relay2, relay1, relay0
    return_order = list(reversed(fwd_path))
    for i in range(len(return_order) - 1):
        sender = hop_cids[return_order[i]]
        receiver = hop_cids[return_order[i + 1]]
        assert sender["outbound"] == receiver["inbound"], \
            f"Link binding broken: {return_order[i]!r}.outbound != {return_order[i+1]!r}.inbound"

    # Last relay's outbound must equal client_inbound
    last_relay = hop_cids[return_order[-1]]
    assert last_relay["outbound"] == client_inbound, \
        "Last relay outbound must equal client inbound"

    # NON-ADJACENT collusion test: no inbound_cid appears at more than one hop
    all_inbound = [hop_cids[nid]["inbound"] for nid in fwd_path]
    assert len(set(all_inbound)) == len(all_inbound), "Inbound CIDs must be globally unique"

    # Non-adjacent hops must not share any CID (inbound or outbound)
    for i in range(len(fwd_path)):
        for j in range(i + 2, len(fwd_path)):
            cids_i = {hop_cids[fwd_path[i]]["inbound"], hop_cids[fwd_path[i]]["outbound"]}
            cids_j = {hop_cids[fwd_path[j]]["inbound"], hop_cids[fwd_path[j]]["outbound"]}
            shared = cids_i & cids_j
            # Adjacent hops (i, i+1) MAY share one CID (the binding link).
            # Non-adjacent hops (distance >= 2) MUST NOT share any.
            assert not shared, \
                f"Non-adjacent hops {i} and {j} share CID(s): {shared!r}"

    # Test-network round-trip: stream a token through and verify it works.
    # route_circuit_reply handles exit lookup internally
    packet = sim.route_circuit_reply(
        fwd_path, client_inbound, None, 1, b"unlinkable token")
    assert client.decrypt_circuit(packet) == b"unlinkable token"

    print("[PASS] Per-hop link CIDs: binding invariants hold, non-adjacent hops unlinkable.")


# ═══════════════════════════════════════════════════════════════════
# Phase 4: Streaming integration
# ═══════════════════════════════════════════════════════════════════


def test_stream_tokens_end_to_end():
    """Full streaming flow: forward installs circuit, exit streams tokens via CircuitStream."""
    sim = MixnetTestNetwork(num_nodes=6)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:4]
    rply_relays = sim.node_ids()[4:5]

    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"stream prompt")

    result = sim.route_forward(fwd_path, header, payload)
    assert result is not None

    stream, _ = sim.create_circuit_stream(fwd_path, client_inbound)
    assert stream is not None

    tokens = [b"The", b" quick", b" brown", b" fox", b" jumps",
              b" over", b" the", b" lazy", b" dog", b"."]
    received = []
    for token in tokens:
        packet = sim.stream_token(fwd_path, stream, token)
        assert packet is not None
        decrypted = client.decrypt_circuit(packet)
        assert decrypted == token
        received.append(decrypted)

    assert b"".join(received) == b"The quick brown fox jumps over the lazy dog."

    print(f"[PASS] Stream: {len(tokens)} tokens streamed and reassembled.")


def test_stream_keepalive():
    """Keepalive packets round-trip as empty tokens."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"keepalive test")

    sim.route_forward(fwd_path, header, payload)

    stream, _ = sim.create_circuit_stream(fwd_path, client_inbound)
    keepalive_packet = stream.keepalive()
    assert len(keepalive_packet) == sim.params.payload_size

    relay_path = list(reversed(fwd_path[:-1]))
    for nid in relay_path:
        result = sim.nodes[nid].process_circuit_packet(keepalive_packet)
        assert result is not None
        _, keepalive_packet = result

    result = client.decrypt_circuit(keepalive_packet)
    assert result == b""

    real_packet = sim.stream_token(fwd_path, stream, b"after keepalive")
    assert client.decrypt_circuit(real_packet) == b"after keepalive"

    print("[PASS] Keepalive: empty packet round-trips, subsequent tokens work.")


def test_stream_large_chunked():
    """Large data auto-chunked into multiple circuit packets."""
    sim = MixnetTestNetwork(num_nodes=4, payload_size=512)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"chunk test")

    sim.route_forward(fwd_path, header, payload)

    stream, _ = sim.create_circuit_stream(fwd_path, client_inbound)
    large_data = b"X" * 1000

    packets = stream.send_chunked(large_data)
    assert len(packets) > 1

    reassembled = b""
    for pkt in packets:
        relay_path = list(reversed(fwd_path[:-1]))
        for nid in relay_path:
            result = sim.nodes[nid].process_circuit_packet(pkt)
            _, pkt = result
        chunk = client.decrypt_circuit(pkt)
        assert chunk is not None
        reassembled += chunk

    assert reassembled == large_data

    print(f"[PASS] Chunked: {len(large_data)} bytes into {len(packets)} packets, reassembled.")


def test_stream_and_surb_coexist():
    """Circuit streaming and SURB reply work in the same session."""
    sim = MixnetTestNetwork(num_nodes=6)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:4]
    rply_relays = sim.node_ids()[4:5]

    # Circuit-bearing request
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, rply_relays, b"dual mode request")

    result = sim.route_forward(fwd_path, header, payload)
    assert result is not None
    routing, flag, msg, surb_info = result
    assert msg == b"dual mode request"
    assert surb_info is not None

    # Stream tokens via circuit
    stream, _ = sim.create_circuit_stream(fwd_path, client_inbound)
    packet = sim.stream_token(fwd_path, stream, b"streamed token")
    assert client.decrypt_circuit(packet) == b"streamed token"

    # SURB reply also works (separate mechanism)
    from tenet.packet.OutfoxClient import surb_use
    surb_header, surb_key = surb_info
    rply_h, rply_p = surb_use(sim.params, (surb_header, surb_key), b"surb reply")
    rply_h, rply_p = sim.route_reply(rply_relays, rply_h, rply_p)
    assert client.receive_reply(rply_h, rply_p) == b"surb reply"

    print("[PASS] Coexistence: circuit stream and SURB reply both work in same session.")


def test_type_byte_dispatch():
    """MixNode.process_packet dispatches on byte 0."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"dispatch test")

    # Forward packet via process_packet with 0x00 prefix
    raw_fwd = b'\x00' + header + payload
    node = sim.nodes[fwd_path[0]]
    result = node.process_packet(raw_fwd, is_last=False)
    assert result is not None
    routing, flag, (next_h, next_p) = result

    # Finish the forward to install circuits
    sim.route_forward(fwd_path, header, payload)

    # Circuit packet via process_packet (already has 0x01 prefix)
    stream, _ = sim.create_circuit_stream(fwd_path, client_inbound)
    circuit_pkt = stream.send(b"dispatched token")
    # Process at last relay (fwd_path[-2])
    relay_nid = fwd_path[-2]
    result = sim.nodes[relay_nid].process_packet(circuit_pkt)
    assert result is not None
    next_hop, forwarded = result

    print("[PASS] Type dispatch: 0x00 → forward, 0x01 → circuit.")


def test_paced_stream_flattens_token_burst():
    """PacedCircuitStream spreads an instant token burst across fixed intervals."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"paced burst")

    sim.route_forward(fwd_path, header, payload)

    paced, _ = sim.create_paced_circuit_stream(fwd_path, client_inbound, interval_ms=50)
    tokens = [f"t{idx}".encode() for idx in range(6)]
    for token in tokens:
        paced.offer(token)
    paced.close()

    emit_times = []
    received = []
    for tick in range(400):
        for packet in sim.stream_paced_due(fwd_path, paced, tick):
            emit_times.append(tick)
            token = client.decrypt_circuit(packet)
            assert token is not None
            if token:
                received.append(token)

    assert received == tokens
    assert len(emit_times) == len(tokens)
    for earlier, later in zip(emit_times, emit_times[1:]):
        assert later - earlier >= 50


def test_paced_stream_keepalive_fills_idle_gap():
    """Active paced sessions emit keepalives on empty cadence ticks."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"paced idle")

    sim.route_forward(fwd_path, header, payload)

    paced, _ = sim.create_paced_circuit_stream(fwd_path, client_inbound, interval_ms=40)
    paced.offer(b"only")

    seen = []
    for tick in range(200):
        for packet in sim.stream_paced_due(fwd_path, paced, tick):
            seen.append((tick, client.decrypt_circuit(packet)))

    assert seen[0] == (0, b"only")
    assert (40, b"") in seen


def test_paced_drain_all_delivers_burst():
    """drain_all + stream_paced_drain returns full payload after close()."""
    sim = MixnetTestNetwork(num_nodes=4)
    client = sim.create_client(b"alice")

    fwd_path = sim.node_ids()[:3]
    header, payload, client_inbound = client.create_repliable_with_circuit(
        fwd_path, [], b"drain")

    sim.route_forward(fwd_path, header, payload)

    paced, _ = sim.create_paced_circuit_stream(fwd_path, client_inbound, interval_ms=30)
    for part in (b"abc", b"def", b"ghi"):
        paced.offer(part)
    paced.close()

    out = bytearray()
    for packet in sim.stream_paced_drain(fwd_path, paced, start_ms=0):
        chunk = client.decrypt_circuit(packet)
        if chunk:
            out.extend(chunk)

    assert bytes(out) == b"abcdefghi"


if __name__ == "__main__":
    print("=" * 60)
    print("tenet Mixnet Packet Tests")
    print("=" * 60)
    print()

    test_forward_through_test_nodes()
    test_repliable_round_trip()
    test_signed_message()
    test_dummy_traffic()
    test_multiple_clients()
    test_tampered_header_rejected()
    test_tagged_payload_rejected()
    test_circuit_table()
    test_exit_node_discovery()
    test_capability_based_routing()
    test_exit_with_api_call()
    test_network_stats()

    print()
    print("--- Phase 2: Circuit Streaming ---")
    test_circuit_install_on_forward()
    test_circuit_reply_end_to_end()
    test_circuit_reply_multi_hop()
    test_circuit_nonce_rejection()
    test_circuit_corruption_detection()
    test_circuit_stats()
    test_circuit_reestablish_trigger()

    print()
    print("--- Phase 4: Streaming ---")
    test_stream_tokens_end_to_end()
    test_stream_keepalive()
    test_stream_large_chunked()
    test_stream_and_surb_coexist()
    test_type_byte_dispatch()
    test_paced_stream_flattens_token_burst()
    test_paced_stream_keepalive_fills_idle_gap()
    test_paced_drain_all_delivers_burst()

    print()
    print("=" * 60)
    print("ALL MIXNET TESTS PASSED")
    print("=" * 60)
