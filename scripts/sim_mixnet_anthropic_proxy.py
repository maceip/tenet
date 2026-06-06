"""In-process MixnetSim proxy between Claude CLI and Anthropic API.

Usage:
  ANTHROPIC_API_KEY=sk-ant-... python3 sim_mixnet_anthropic_proxy.py

Then in another terminal:
  ANTHROPIC_BASE_URL=http://127.0.0.1:8000 ANTHROPIC_API_KEY=none claude

The proxy intercepts HTTP requests, routes the prompt through a simulated
Outfox mixnet (forward path), then streams the LLM response back token-by-
token through symmetric return circuits (streaming return path).

Non-streaming responses use SURB single-shot reply as fallback.
No UDP/QUIC sockets or separate relay processes are used here.
"""

import json
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from sphinxmix.mixnet import MixnetSim
from sphinxmix.OutfoxClient import surb_use

REAL_API_BASE = "https://api.anthropic.com"
REAL_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8000"))
NUM_MIX_NODES = 5
FWD_HOPS = 3


class MixnetProxy:
    """Wraps the mixnet simulator with forward/reply routing."""

    def __init__(self):
        self.sim = MixnetSim(num_nodes=NUM_MIX_NODES, payload_size=32768)
        self.client = self.sim.create_client(b"proxy_client__")
        self.fwd_path = self.sim.node_ids()[:FWD_HOPS]
        self.rply_relays = self.sim.node_ids()[FWD_HOPS:]
        print(f"[mixnet] {NUM_MIX_NODES} nodes, fwd={FWD_HOPS} hops")

    def route_request(self, request_bytes):
        """Route request through forward path. Returns (msg, surb_info, stream, client_inbound)."""
        header, payload, client_inbound = self.client.create_repliable_with_circuit(
            self.fwd_path, self.rply_relays, request_bytes)

        result = self.sim.route_forward(self.fwd_path, header, payload)
        if result is None:
            return None, None, None, None

        _, _, msg, surb_info = result

        stream, _ = self.sim.create_circuit_stream(self.fwd_path, client_inbound)
        return msg, surb_info, stream, client_inbound

    def stream_chunk(self, stream, chunk):
        """Send one chunk through circuit. Returns decrypted bytes or None."""
        packet = self.sim.stream_token(self.fwd_path, stream, chunk)
        if packet is None:
            return None
        return self.client.decrypt_circuit(packet)

    def route_surb_reply(self, surb_info, reply_bytes):
        """Single-shot SURB reply fallback."""
        surb_header, surb_key = surb_info
        rh, rp = surb_use(self.sim.params, (surb_header, surb_key), reply_bytes)
        rh, rp = self.sim.route_reply(self.rply_relays, rh, rp)
        if rh is None:
            return None
        return self.client.receive_reply(rh, rp)


mixnet = MixnetProxy()


def make_streaming_api_call(method, path, headers_dict, body=None):
    """Make API call, return (status, headers, response_obj) without reading body."""
    url = REAL_API_BASE + path

    filtered = {}
    for k, v in headers_dict.items():
        if k.lower() in ("host", "content-length", "transfer-encoding"):
            continue
        filtered[k] = v
    filtered["x-api-key"] = REAL_API_KEY
    if "anthropic-version" not in {k.lower(): k for k in filtered}:
        filtered["anthropic-version"] = "2023-06-01"

    req = Request(url, data=body, headers=filtered, method=method)
    try:
        resp = urlopen(req, timeout=120)
        return resp.status, dict(resp.headers), resp
    except HTTPError as e:
        return e.code, dict(e.headers), e


class ProxyHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _handle(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        is_streaming = False
        if body:
            try:
                req_json = json.loads(body)
                is_streaming = req_json.get("stream", False)
            except (json.JSONDecodeError, AttributeError):
                pass

        request_meta = json.dumps({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
        }).encode()

        request_payload = request_meta + b"\n---BODY---\n" + body if body else request_meta

        t0 = time.time()

        if len(request_payload) > mixnet.sim.params.payload_size - 1024:
            self.send_error(413, "Payload too large for mixnet packet")
            return

        msg_bytes, surb_info, stream, client_inbound = mixnet.route_request(request_payload)
        if msg_bytes is None:
            self.send_error(502, "Mixnet forward routing failed")
            return

        t_fwd = time.time() - t0

        if b"\n---BODY---\n" in msg_bytes:
            meta_part, body_part = msg_bytes.split(b"\n---BODY---\n", 1)
        else:
            meta_part, body_part = msg_bytes, None

        meta = json.loads(meta_part)

        status, resp_headers, resp = make_streaming_api_call(
            meta["method"], meta["path"], meta["headers"], body_part)

        t_api_start = time.time()

        if is_streaming and status == 200 and stream:
            self._handle_streaming(status, resp_headers, resp, stream, t0, t_fwd)
        else:
            self._handle_buffered(status, resp_headers, resp, stream, surb_info,
                                  client_inbound, t0, t_fwd)

    def _handle_streaming(self, status, resp_headers, resp, stream, t0, t_fwd):
        """Stream SSE events through circuit packets token-by-token."""
        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() in ("transfer-encoding", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("X-Mixnet-Reply-Mode", "circuit-stream")
        self.send_header("X-Mixnet-Fwd-Ms", f"{t_fwd * 1000:.1f}")
        self.end_headers()

        chunks_sent = 0
        bytes_sent = 0
        try:
            for line in resp:
                if not line:
                    continue
                chunk = line if isinstance(line, bytes) else line.encode()

                decrypted = mixnet.stream_chunk(stream, chunk)
                if decrypted is not None:
                    self.wfile.write(decrypted)
                    self.wfile.flush()
                    chunks_sent += 1
                    bytes_sent += len(decrypted)
        except (BrokenPipeError, ConnectionResetError):
            pass

        t_total = time.time() - t0
        stats = mixnet.sim.stats()
        print(f"[mixnet] SSE stream: {chunks_sent} chunks, {bytes_sent} bytes, "
              f"fwd={t_fwd*1000:.1f}ms total={t_total*1000:.0f}ms "
              f"hops={stats['forward']}+{stats['circuit']}")

    def _handle_buffered(self, status, resp_headers, resp, stream, surb_info,
                         client_inbound, t0, t_fwd):
        """Buffer full response, send through circuit or SURB."""
        resp_body = resp.read()
        t_api = time.time() - t0 - t_fwd

        if stream and len(resp_body) <= stream.max_token_size:
            decrypted = mixnet.stream_chunk(stream, resp_body)
            if decrypted is not None:
                resp_body = decrypted
            reply_mode = "circuit"
        elif surb_info and len(resp_body) <= mixnet.sim.params.payload_size - 1024:
            reply_msg = mixnet.route_surb_reply(surb_info, resp_body)
            if reply_msg is not None:
                resp_body = reply_msg
            reply_mode = "surb"
        else:
            reply_mode = "direct"

        t_rply = time.time() - t0 - t_fwd - t_api

        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() in ("transfer-encoding", "content-encoding", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("X-Mixnet-Reply-Mode", reply_mode)
        self.send_header("X-Mixnet-Fwd-Ms", f"{t_fwd * 1000:.1f}")
        self.send_header("X-Mixnet-Rply-Ms", f"{t_rply * 1000:.1f}")
        self.end_headers()
        self.wfile.write(resp_body)

        stats = mixnet.sim.stats()
        print(f"[mixnet] {reply_mode}: {len(resp_body)} bytes, "
              f"fwd={t_fwd*1000:.1f}ms api={t_api*1000:.0f}ms rply={t_rply*1000:.1f}ms "
              f"hops={stats['forward']}")

    def log_message(self, format, *args):
        pass


def main():
    if not REAL_API_KEY:
        print("ERROR: Set ANTHROPIC_API_KEY to your real API key")
        print("Usage: ANTHROPIC_API_KEY=sk-ant-... python3 sim_mixnet_anthropic_proxy.py")
        sys.exit(1)

    server = HTTPServer(("127.0.0.1", LISTEN_PORT), ProxyHandler)
    print(f"[proxy] listening on http://127.0.0.1:{LISTEN_PORT}")
    print(f"[proxy] forwarding to {REAL_API_BASE}")
    print(f"[proxy] streaming: SSE events → circuit packets → token-by-token")
    print()
    print("Run in another terminal:")
    print(f'  ANTHROPIC_BASE_URL=http://127.0.0.1:{LISTEN_PORT} ANTHROPIC_API_KEY=none claude')
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[proxy] shutting down")
        stats = mixnet.sim.stats()
        print(f"[proxy] total: {stats['forward']} forward hops, {stats['circuit']} circuit hops")
        server.server_close()


if __name__ == "__main__":
    main()
