"""Local QUIC demo for P-OR Expert Mode.

**HARNESS ONLY — not production wire.**

Uses JSON/base64 frames over H3 WebSocket for orchestration convenience.
Production daemons use canonical binary wire (``por.wire_frame``) via
``por relay`` / ``por expert`` / ``por run``.

This module proves QUIC/H3 plumbing and Expert Mode trace shape.
Do not build production features on top of this module.
"""

from __future__ import annotations

import argparse
import asyncio
import base64 as _base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

from sphinxmix.OutfoxClient import packet_create
from sphinxmix.OutfoxNode import (
    circuit_packet_create,
    circuit_packet_decrypt,
    circuit_packet_process,
    outfox_process,
)
from sphinxmix.OutfoxParams import OutfoxParams

from .envelope import PromptRequestEnvelope
from .quic_transport import (
    H3WebSocketClient,
    H3WebSocketServer,
    POR_H3_ALPN,
    QuicEndpoint,
    make_client_config,
    make_server_config,
    write_localhost_self_signed_cert,
)
from .config import DEFAULT_PAYLOAD_SIZE, DEFAULT_ROUTING_SIZE
from .node_runtime import build_native_forward_plan


def _b64e(data: bytes) -> str:
    return _base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return _base64.b64decode(data.encode("ascii"))
from .provider import ProviderError, expert_reply_chunks
from .udp_demo import (
    DemoResult,
    _collect_node_logs,
    _node_ids,
    _plan_demo_route,
    _reserve_ports,
)


TRANSPORT_NAME = "h3_websocket_over_quic"
MAX_QUIC_FRAME_SIZE = 65535


def run_demo(node_count: int = 4, timeout: float = 10.0) -> DemoResult:
    """Run Expert Mode over local QUIC node processes."""

    return asyncio.run(_run_demo_async(node_count=node_count, timeout=timeout))


async def _run_demo_async(node_count: int, timeout: float) -> DemoResult:
    if node_count < 3 or node_count > 5:
        raise ValueError("demo supports 3-5 local node processes")

    with tempfile.TemporaryDirectory(prefix="por-quic-demo-") as tmp:
        tmp_path = Path(tmp)
        cert_path, key_path = write_localhost_self_signed_cert(
            tmp_path / "localhost.crt",
            tmp_path / "localhost.key",
        )
        params = OutfoxParams(payload_size=DEFAULT_PAYLOAD_SIZE, routing_size=DEFAULT_ROUTING_SIZE, max_hops=5)
        node_ids = _node_ids(node_count)
        ports = _reserve_ports(len(node_ids) + 1)
        client_addr = ("127.0.0.1", ports[-1])

        nodes = {}
        for node_id, port in zip(node_ids, ports[:-1]):
            pk, sk = params.kem.keygen()
            nodes[node_id] = {
                "host": "127.0.0.1",
                "port": port,
                "kem_pk": pk.hex(),
                "kem_sk": sk.hex(),
            }

        config = {
            "transport": {
                "name": TRANSPORT_NAME,
                "certfile": str(cert_path),
                "keyfile": str(key_path),
                "max_frame_size": MAX_QUIC_FRAME_SIZE,
            },
            "params": {
                "payload_size": DEFAULT_PAYLOAD_SIZE,
                "routing_size": DEFAULT_ROUTING_SIZE,
                "max_hops": 5,
            },
            "client": {"host": client_addr[0], "port": client_addr[1]},
            "nodes": nodes,
        }
        config_path = tmp_path / "demo_config.json"
        config_path.write_text(json.dumps(config, sort_keys=True, indent=2), encoding="utf-8")

        procs = _start_nodes(config_path, node_ids)
        try:
            await asyncio.sleep(0.75)
            selected_peer_id, degraded, fallback_used, prompt, expertise, prepared = _plan_demo_route(tmp_path)
            if selected_peer_id not in nodes or prepared.envelope is None:
                response_text = (
                    f"[wire-harness frontier_fallback] prompt_len={len(prompt)} "
                    "expert_used=no reason=no selected expert peer"
                )
                client_logs = (
                    f"client event=expert_plan transport={TRANSPORT_NAME} "
                    "selected=none degraded_anonymity=false fallback_used=true"
                )
                return DemoResult(
                    selected_peer_id="",
                    degraded_anonymity=degraded,
                    fallback_used=True,
                    response_text=response_text,
                    node_logs="",
                    client_logs=client_logs,
                )

            relay_path = [nid for nid in node_ids if nid.startswith("relay")][:2]
            forward_path = relay_path + [selected_peer_id]
            response_text, client_logs = await _send_prompt_and_receive_stream(
                params=params,
                config=config,
                client_addr=client_addr,
                forward_path=forward_path,
                envelope=prepared.envelope,
                timeout=timeout,
            )
        finally:
            await _shutdown_nodes(config, node_ids)
            node_logs = _collect_node_logs(procs)

    return DemoResult(
        selected_peer_id=selected_peer_id,
        degraded_anonymity=degraded,
        fallback_used=fallback_used,
        response_text=response_text,
        node_logs=node_logs,
        client_logs=client_logs,
    )


async def node_main(config_path: str, node_id: str) -> int:
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    params_cfg = config["params"]
    params = OutfoxParams(
        payload_size=params_cfg["payload_size"],
        routing_size=params_cfg["routing_size"],
        max_hops=params_cfg["max_hops"],
    )
    node_cfg = config["nodes"][node_id]
    sk = bytes.fromhex(node_cfg["kem_sk"])
    pk = bytes.fromhex(node_cfg["kem_pk"])
    circuits: dict[str, dict[str, object]] = {}
    stop = asyncio.Event()
    tasks: set[asyncio.Task] = set()

    def handler(data: bytes) -> None:
        task = asyncio.create_task(
            _handle_node_frame(config, params, node_id, sk, pk, circuits, stop, data)
        )
        tasks.add(task)

        def done(completed: asyncio.Task) -> None:
            tasks.discard(completed)
            exc = completed.exception()
            if exc is not None:
                print(f"node={node_id} event=task_error error={exc!r}", flush=True)

        task.add_done_callback(done)
        return None

    transport = config["transport"]
    server = H3WebSocketServer(
        QuicEndpoint(node_cfg["host"], node_cfg["port"]),
        configuration=make_server_config(
            transport["certfile"],
            transport["keyfile"],
            alpn=POR_H3_ALPN,
            max_datagram_frame_size=transport["max_frame_size"],
        ),
        websocket_handler=handler,
        buffer_messages=True,
    )
    await server.start()
    print(
        f"node={node_id} event=started transport={TRANSPORT_NAME} "
        f"addr={node_cfg['host']}:{node_cfg['port']}",
        flush=True,
    )
    await stop.wait()
    await asyncio.sleep(0.1)
    server.close()
    return 0


async def _handle_node_frame(config, params, node_id, sk, pk, circuits, stop, data: bytes) -> None:
    frame = json.loads(data.decode("utf-8"))
    kind = frame.get("kind")
    if kind == "shutdown":
        print(f"node={node_id} event=shutdown transport={TRANSPORT_NAME}", flush=True)
        stop.set()
        return
    if kind == "forward":
        await _handle_forward(config, params, node_id, sk, pk, circuits, frame)
    elif kind == "circuit":
        await _handle_circuit(config, params, node_id, circuits, frame)


async def _handle_forward(config, params, node_id, sk, pk, circuits, frame):
    header = _b64d(frame["header"])
    payload = _b64d(frame["payload"])
    circuit_installed = {}

    def _on_circuit(inbound_cid, circuit_key, next_hop, outbound_cid, ttl):
        cid_hex = inbound_cid.hex()
        nh = next_hop.rstrip(b"\x00").decode("ascii", errors="replace")
        circuits[cid_hex] = {
            "key": circuit_key.hex(),
            "outbound_cid": outbound_cid.hex(),
            "next_id": nh,
            "high_watermark": -1,
            "last_active": time.time(),
        }
        circuit_installed["inbound_cid"] = cid_hex
        circuit_installed["return_next"] = nh

    try:
        hop_result = outfox_process(
            params, sk, pk, (header, payload), is_last=False, on_circuit=_on_circuit
        )
    except ValueError as exc:
        print(f"node={node_id} event=forward_rejected reason={exc}", flush=True)
        return

    if hop_result is None:
        print(f"node={node_id} event=forward_expired_or_invalid", flush=True)
        return

    routing_info, _flag, next_packet = hop_result
    next_id = routing_info.rstrip(b"\x00").decode("ascii", errors="replace")

    next_header, next_payload = next_packet
    cid_log = circuit_installed.get("inbound_cid", "")[:8]
    return_next = circuit_installed.get("return_next", "")
    if next_id and next_header:
        print(
            "node={node} event=forward_hop transport={transport} next={next_id} link_cid={cid} "
            "return_next={return_next} prompt_visible=no".format(
                node=node_id,
                transport=TRANSPORT_NAME,
                next_id=next_id,
                cid=cid_log,
                return_next=return_next,
            ),
            flush=True,
        )
        await _send_quic_frame(config, next_id, {
            "kind": "forward",
            "header": _b64e(next_header),
            "payload": _b64e(next_payload),
        })
        return

    final_result = outfox_process(
        params, sk, pk, (header, payload), is_last=True, on_circuit=_on_circuit
    )
    if final_result is None:
        print(f"node={node_id} event=exit_rejected", flush=True)
        return

    _routing, _flag, msg, _surb_info = final_result
    envelope = PromptRequestEnvelope.from_json(msg)
    prompt = envelope.prompt_text()
    expertise = envelope.intent_descriptor.get("requested_expertise") or "auto"
    degraded = bool(envelope.intent_descriptor.get("degraded_anonymity"))
    exit_cid = circuit_installed.get("inbound_cid", "")
    exit_entry = circuits.get(exit_cid)
    if exit_entry is None:
        print(f"node={node_id} event=exit_missing_circuit link_cid={exit_cid[:8]}", flush=True)
        return
    exit_key = bytes.fromhex(exit_entry["key"])
    exit_outbound = bytes.fromhex(exit_entry["outbound_cid"])

    print(
        "node={node} event=expert_exit transport={transport} selected=yes prompt_visible=yes "
        "expertise={expertise!r} return_next={return_next} link_cid={cid} degraded={degraded}".format(
            node=node_id,
            transport=TRANSPORT_NAME,
            expertise=expertise,
            return_next=exit_entry["next_id"],
            cid=exit_cid[:8],
            degraded=str(degraded).lower(),
        ),
        flush=True,
    )
    try:
        chunks = expert_reply_chunks(envelope, node_id)
    except ProviderError as exc:
        print(
            f"node={node_id} event=provider_error retryable={str(exc.retryable).lower()} reason={exc!s}",
            flush=True,
        )
        chunks = [f"[provider_error] peer={node_id} status={exc.status} message={exc}"]
    for seq, chunk in enumerate(chunks):
        plain = json.dumps({"seq": seq, "data": chunk, "done": False}).encode("utf-8")
        await _stream_return_chunk(config, params, exit_entry["next_id"], exit_outbound, seq, plain, exit_key)
        await asyncio.sleep(0.05)

    done_seq = len(chunks)
    done = json.dumps({"seq": done_seq, "data": "", "done": True}).encode("utf-8")
    await _stream_return_chunk(config, params, exit_entry["next_id"], exit_outbound, done_seq, done, exit_key)


async def _handle_circuit(config, params, node_id, circuits, frame):
    packet = _b64d(frame["packet"])
    inbound_cid = packet[1:17].hex()
    nonce = int.from_bytes(packet[17:25], "big")
    entry = circuits.get(inbound_cid)
    seq = frame.get("seq", -1)

    if entry is None:
        print(f"node={node_id} event=circuit_missing link_cid={inbound_cid[:8]} seq={seq}", flush=True)
        return
    if nonce <= int(entry.get("high_watermark", -1)):
        print(f"node={node_id} event=circuit_replay link_cid={inbound_cid[:8]} seq={seq}", flush=True)
        return
    entry["high_watermark"] = nonce

    key = bytes.fromhex(entry["key"])
    outbound_cid = bytes.fromhex(entry["outbound_cid"])
    next_id = entry["next_id"]
    processed = circuit_packet_process(params, key, packet, outbound_link_cid=outbound_cid)
    if processed is None:
        print(f"node={node_id} event=circuit_malformed link_cid={inbound_cid[:8]} seq={seq}", flush=True)
        return
    _inbound, _nonce, forwarded = processed
    print(
        f"node={node_id} event=circuit_hop transport={TRANSPORT_NAME} link_cid={inbound_cid[:8]} "
        f"seq={seq} next={next_id} payload_visible=no",
        flush=True,
    )
    await _send_quic_frame(config, next_id, {
        "kind": "circuit",
        "seq": seq,
        "packet": _b64e(forwarded),
    })


async def _stream_return_chunk(config, params, next_id, outbound_cid, seq, plaintext, exit_key):
    packet = circuit_packet_create(params, outbound_cid, seq, plaintext, [exit_key])
    await _send_quic_frame(config, next_id, {
        "kind": "circuit",
        "seq": seq,
        "packet": _b64e(packet),
    })


async def _send_prompt_and_receive_stream(
    params,
    config,
    client_addr,
    forward_path,
    envelope: PromptRequestEnvelope,
    timeout,
):
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    transport = config["transport"]
    client_server = H3WebSocketServer(
        QuicEndpoint(client_addr[0], client_addr[1]),
        configuration=make_server_config(
            transport["certfile"],
            transport["keyfile"],
            alpn=POR_H3_ALPN,
            max_datagram_frame_size=transport["max_frame_size"],
        ),
        websocket_handler=lambda data: queue.put_nowait(data) or None,
        buffer_messages=True,
    )
    await client_server.start()

    try:
        route_infos, circuit_setup, client_peel_keys = build_native_forward_plan(forward_path)
        keys = [bytes.fromhex(config["nodes"][node_id]["kem_pk"]) for node_id in forward_path]
        header, payload = packet_create(
            params,
            route_infos,
            keys,
            envelope.to_json().encode("utf-8"),
            circuit_setup=circuit_setup,
        )

        await _send_quic_frame(config, forward_path[0], {
            "kind": "forward",
            "header": _b64e(header),
            "payload": _b64e(payload),
        })

        chunks = []
        logs = [
            f"client event=send_prepared_envelope transport={TRANSPORT_NAME} "
            f"selected={envelope.selected_peer_id or 'none'} "
            f"forward_path={'/'.join(forward_path)}",
        ]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = await asyncio.wait_for(queue.get(), timeout=max(0.1, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                continue
            frame = json.loads(data.decode("utf-8"))
            if frame.get("kind") != "circuit":
                continue
            plain = circuit_packet_decrypt(params, client_peel_keys, _b64d(frame["packet"]))
            if plain is None:
                logs.append("client event=stream_corrupt")
                continue
            chunk = json.loads(plain.decode("utf-8"))
            logs.append(
                f"client event=stream_chunk transport={TRANSPORT_NAME} "
                f"seq={chunk['seq']} bytes={len(chunk['data'])}"
            )
            if chunk.get("done"):
                break
            chunks.append(chunk["data"])
        else:
            raise TimeoutError("timed out waiting for streamed QUIC return path")

        return "".join(chunks), "\n".join(logs)
    finally:
        client_server.close()
        await asyncio.sleep(0)


async def _send_quic_frame(config: dict, target_id: str, frame: dict) -> None:
    if target_id == "client":
        target = config["client"]
    else:
        target = config["nodes"][target_id]

    transport = config["transport"]
    endpoint = QuicEndpoint(target["host"], target["port"])
    async with H3WebSocketClient(
        endpoint,
        configuration=make_client_config(
            verify_tls=False,
            dev_allow_insecure_tls=True,
            alpn=POR_H3_ALPN,
            max_datagram_frame_size=transport["max_frame_size"],
        ),
        authority=f"localhost:{endpoint.port}",
        path="/por",
    ) as client:
        client.send(json.dumps(frame).encode("utf-8"), end_stream=True)
        await asyncio.sleep(0.05)


def _start_nodes(config_path: Path, node_ids: Sequence[str]) -> list[subprocess.Popen]:
    procs = []
    for node_id in node_ids:
        procs.append(
            subprocess.Popen(
                [sys.executable, "-m", "por.quic_demo", "node", "--config", str(config_path), "--node-id", node_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
    return procs


async def _shutdown_nodes(config: dict, node_ids: Sequence[str]) -> None:
    for node_id in node_ids:
        try:
            await _send_quic_frame(config, node_id, {"kind": "shutdown"})
        except Exception:
            continue


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local QUIC P-OR demo.")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    node = sub.add_parser("node")
    node.add_argument("--config", required=True)
    node.add_argument("--node-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.cmd == "node":
        return asyncio.run(node_main(args.config, args.node_id))

    result = run_demo()
    print("demo event=response_begin")
    print(result.response_text)
    print("demo event=response_end")
    print("demo event=client_logs_begin")
    print(result.client_logs)
    print("demo event=client_logs_end")
    print("demo event=node_logs_begin")
    print(result.node_logs, end="")
    print("demo event=node_logs_end")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
