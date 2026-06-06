"""ML-DSA-65 signatures must interoperate across the two backends.

`tenet.packet.OutfoxParams` uses `pqcrypto` (PQClean) when available and falls back
to pure-Python `dilithium-py` (e.g. on Android, where pqcrypto's cffi build
won't cross-compile cleanly). Both implement FIPS 204 ML-DSA-65 with identical
key/signature encodings, so a signature made by one must verify under the other
— otherwise an Android client couldn't talk to native nodes.
"""

from __future__ import annotations

import pytest

from tenet.packet.OutfoxParams import (
    ML_DSA_BACKEND,
    dilithium_generate_keypair,
    dilithium_sign,
    dilithium_verify,
)


def test_active_backend_signs_and_verifies():
    pk, sk = dilithium_generate_keypair()
    sig = dilithium_sign(sk, b"forward-payload")
    assert dilithium_verify(pk, b"forward-payload", sig) is not False
    assert ML_DSA_BACKEND in {"pqcrypto", "dilithium-py"}


def test_pqcrypto_and_dilithium_py_signatures_interoperate():
    pq = pytest.importorskip("pqcrypto.sign.ml_dsa_65")
    pytest.importorskip("dilithium_py")
    from dilithium_py.ml_dsa import ML_DSA_65

    msg = b"tenet-forward-payload"

    # PQClean signs -> pure-Python verifies
    pk, sk = pq.generate_keypair()
    assert ML_DSA_65.verify(pk, msg, pq.sign(sk, msg))

    # pure-Python signs -> PQClean verifies
    pk2, sk2 = ML_DSA_65.keygen()
    assert pq.verify(pk2, msg, ML_DSA_65.sign(sk2, msg)) is not False
