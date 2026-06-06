"""On-device proof that the full tenet (por) client runs on Android.

Two checks, both logged to logcat (the harness greps for the markers):
  1. Native-stack self-test: the cross-compiled/pure-Python crypto deps load and
     run (msgpack, libsodium/X25519, pyaes AES-CTR, dilithium-py ML-DSA-65).
  2. Full client round-trip: a real client -> relay -> expert -> client exchange
     over localhost UDP using the actual `por` runtime (Outfox packets,
     ML-DSA-signed payloads, layered AES-CTR, return circuit). The server-side
     LLM call is stubbed — on a real network the model runs on the expert's
     server, never on the client device.
"""

from __future__ import annotations

import socket
import threading


def native_selftest() -> None:
    import msgpack
    import cffi  # noqa: F401  (pulls libffi)
    import nacl.bindings as nb
    import pyaes
    from dilithium_py.ml_dsa import ML_DSA_65

    assert msgpack.unpackb(msgpack.packb({"tenet": 1})) == {"tenet": 1}
    print("TENET-SELFTEST msgpack ok", flush=True)

    assert len(nb.crypto_scalarmult_base(b"\x11" * 32)) == 32
    print("TENET-SELFTEST libsodium/x25519 ok", flush=True)

    ctr = pyaes.Counter(initial_value=0)
    assert len(pyaes.AESModeOfOperationCTR(b"\x00" * 16, counter=ctr).encrypt(b"hello")) == 5
    print("TENET-SELFTEST aes-ctr/pyaes ok", flush=True)

    pub, sec = ML_DSA_65.keygen()
    assert ML_DSA_65.verify(pub, b"tenet", ML_DSA_65.sign(sec, b"tenet"))
    print("TENET-SELFTEST ml_dsa_65 sign/verify ok", flush=True)


def full_client_roundtrip() -> str:
    from tenet.experts.client import send_prepared_envelope
    from tenet.config import ClusterConfig
    from tenet.envelope import PromptRequestEnvelope
    from tenet.mixnet.node_runtime import WireNodeRuntime
    from tenet.packet.OutfoxParams import AES_CTR_BACKEND, ML_DSA_BACKEND, OutfoxParams

    # Stub the server-side LLM reply (runs on the expert, not the device).
    # Injected via reply_handler (Seam A) — the mixnet no longer calls the LLM.
    def _stub_reply(envelope, peer_id):
        return ["on-device expert reply: hello from tenet"]

    def bind() -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        return s

    relay_s, expert_s, client_s = bind(), bind(), bind()
    params = OutfoxParams(payload_size=2048, routing_size=16, max_hops=5)
    rpk, rsk = params.kem.keygen()
    epk, esk = params.kem.keygen()
    cluster = ClusterConfig.from_dict(
        {
            "params": {"payload_size": 2048, "routing_size": 16, "max_hops": 5},
            "client": {"host": "127.0.0.1", "port": client_s.getsockname()[1]},
            "nodes": {
                "relay1": {
                    "host": "127.0.0.1", "port": relay_s.getsockname()[1],
                    "kem_pk": rpk.hex(), "kem_sk": rsk.hex(), "role": "relay",
                },
                "expert1": {
                    "host": "127.0.0.1", "port": expert_s.getsockname()[1],
                    "kem_pk": epk.hex(), "kem_sk": esk.hex(), "role": "expert",
                },
            },
        }
    )
    relay_rt = WireNodeRuntime(cluster, "relay1", role="relay")
    expert_rt = WireNodeRuntime(cluster, "expert1", role="expert", reply_handler=_stub_reply)
    stop = threading.Event()
    for rt, sock in ((relay_rt, relay_s), (expert_rt, expert_s)):
        threading.Thread(
            target=rt.serve_on_socket, args=(sock,), kwargs={"stop": stop}, daemon=True
        ).start()

    print(f"TENET-CLIENT backends aes={AES_CTR_BACKEND} ml_dsa={ML_DSA_BACKEND}", flush=True)
    envelope = PromptRequestEnvelope.visible_prompt(
        prompt="What is tenet?", selected_peer_id="expert1", requested_expertise="general"
    )
    try:
        response, _logs = send_prepared_envelope(
            cluster=cluster,
            forward_path=["relay1", "expert1"],
            envelope=envelope,
            timeout=8.0,
            client_sock=client_s,
        )
    finally:
        stop.set()
    return response


def main():
    print("TENET-NATIVE-STACK starting", flush=True)
    try:
        native_selftest()
        print("TENET-NATIVE-STACK-OK", flush=True)
        response = full_client_roundtrip()
        print(f"TENET-CLIENT response: {response!r}", flush=True)
        if "hello from tenet" in response:
            print("TENET-FULL-CLIENT-OK", flush=True)
        else:
            print("TENET-FULL-CLIENT-FAIL: unexpected response", flush=True)
    except Exception as exc:
        import traceback

        print(f"TENET-FULL-CLIENT-FAIL: {exc}", flush=True)
        traceback.print_exc()
        raise
