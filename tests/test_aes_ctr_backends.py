"""The AES-CTR payload cipher must be byte-identical across backends.

`tenet.packet.OutfoxParams` uses `cryptography` (Rust+OpenSSL) when available and
falls back to `pycryptodome` (plain C) — e.g. on Android. The wire format must
not depend on which backend is active, so the two must agree exactly.
"""

from __future__ import annotations

import os

import pytest

from tenet.packet.OutfoxParams import AES_CTR_BACKEND, OutfoxParams


def test_active_backend_aes_ctr_roundtrips_via_lioness():
    p = OutfoxParams(payload_size=512)
    key = os.urandom(p.k)
    msg = os.urandom(256)
    assert p.se_dec(key, p.se_enc(key, msg)) == msg
    assert AES_CTR_BACKEND in {"cryptography", "pycryptodome", "pyaes"}


def test_cryptography_and_pycryptodome_aes_ctr_are_byte_identical():
    crypto = pytest.importorskip("cryptography")
    pycdome = pytest.importorskip("Crypto")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from Crypto.Cipher import AES as PyAES
    from Crypto.Util import Counter

    for _ in range(20):
        key = os.urandom(16)
        iv = os.urandom(16)
        data = os.urandom(os.urandom(1)[0] + 1)

        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        a = enc.update(data) + enc.finalize()

        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        b = PyAES.new(key, PyAES.MODE_CTR, counter=ctr).encrypt(data)

        assert a == b
        assert len(a) == len(data)
